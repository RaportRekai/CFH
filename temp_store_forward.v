`timescale 1ns / 1ps

module packet_store_forward #(
    parameter DATA_WIDTH    = 64,
    parameter KEEP_WIDTH    = (DATA_WIDTH/8),
    parameter RX_USER_WIDTH = 1,
    parameter START_BYTE    = 42  // first UDP payload byte for Eth+IPv4+UDP, no VLAN/options
)(
    input  wire                        clk,
    input  wire                        rst,

    input  wire [1:0]                  s_start_packet,
    input  wire [DATA_WIDTH-1:0]       s_axis_tdata,
    input  wire [KEEP_WIDTH-1:0]       s_axis_tkeep,
    input  wire                        s_axis_tvalid,
    input  wire                        s_axis_tlast,
    input  wire [RX_USER_WIDTH-1:0]    s_axis_tuser,

    output reg  [1:0]                  m_start_packet,
    output reg  [DATA_WIDTH-1:0]       m_axis_tdata,
    output reg  [KEEP_WIDTH-1:0]       m_axis_tkeep,
    output reg                         m_axis_tvalid,
    output reg                         m_axis_tlast,
    output reg  [RX_USER_WIDTH-1:0]    m_axis_tuser
);

localparam BYTE_CNT_W   = 16;
localparam KEEP_CNT_W   = $clog2(KEEP_WIDTH+1);
localparam BYTE_IDX_W   = (KEEP_WIDTH > 1) ? $clog2(KEEP_WIDTH) : 1;

// Added only for tuser storage
localparam MAX_PACKET_BYTES = 1514;
localparam MAX_BEATS = (MAX_PACKET_BYTES + KEEP_WIDTH - 1) / KEEP_WIDTH;

reg [BYTE_CNT_W-1:0] byte_counter = {BYTE_CNT_W{1'b0}};

reg [KEEP_CNT_W-1:0] valid_bytes;
reg [BYTE_CNT_W-1:0] beat_start;
reg [BYTE_IDX_W-1:0] byte_index_in_beat;
reg [DATA_WIDTH-1:0] modified_tdata;



// modified packets after analysis
wire [1514*8-1:0]m_packet_bytes;




// Added only for tuser storage: one tuser per stored beat
reg [MAX_BEATS*RX_USER_WIDTH-1:0] packet_tuser;

reg start_packet_accept;
reg [7:0]beat_counter;
wire [7:0]mod_beat_counter;
reg [7:0]write_beat_count;
reg valid_packet_buffer;
reg [7:0]last_tkeep;
wire [7:0]mod_last_tkeep;

//packet analysis control registers
reg start_analysis;
wire drop_packet;
wire valid_packet;

reg send_phase;
reg send_phase_warmup;
reg send_phase_shutdown;
/////////////////////////////////
localparam PHASE_IDLE    = 2'd0,
           PHASE_CAPTURE = 2'd1,
           PHASE_ANALYZE = 2'd2,
           PHASE_SEND    = 2'd3;
           

reg [1:0] phase;




////////////////////////
reg  [7:0]  parent_r_add;
reg  [7:0]  parent_w_add;
reg  [63:0] parent_data_in;
reg         parent_write_en;

wire [7:0]  ana_r_add;
wire [7:0]  ana_w_add;
wire [63:0] ana_data_in;
wire        ana_write_en;

wire [7:0]  bram_r_add;
wire [7:0]  bram_w_add;
wire [63:0] bram_data_in;
wire        bram_write_en;
wire [63:0] data_out;

assign bram_r_add    = (phase == PHASE_ANALYZE) ? ana_r_add    : parent_r_add;
assign bram_w_add    = (phase == PHASE_ANALYZE) ? ana_w_add    : parent_w_add;
assign bram_data_in  = (phase == PHASE_ANALYZE) ? ana_data_in  : parent_data_in;
assign bram_write_en = (phase == PHASE_ANALYZE) ? ana_write_en : parent_write_en;



////////////CFH HEADER INSERTION PARAMETERS



localparam [7:0]  CFH_MSG     = 8'd4,
localparam [7:0]  TTL         = 8'd4,
localparam [31:0] LB_ID       = 32'd4,
localparam [31:0] RDMA_CONFIG = 32'd4,
localparam [31:0] HOST_ID     = 32'd4,
localparam [15:0] EXTRA_LEN   = 16'd14,   // bytes to be inserted later by parent
localparam [3:0]  THRESH      = 4'd5


localparam [7:0] CFH_B0 = LB_ID[7:0];
localparam [7:0] CFH_B1 = LB_ID[15:8];
localparam [7:0] CFH_B2 = LB_ID[23:16];
localparam [7:0] CFH_B3 = LB_ID[31:24];


localparam [7:0] CFH_B4 = RDMA_CONFIG[7:0];
localparam [7:0] CFH_B5 = RDMA_CONFIG[15:8];
localparam [7:0] CFH_B6 = RDMA_CONFIG[23:16];
localparam [7:0] CFH_B7 = RDMA_CONFIG[31:24];


localparam [7:0] CFH_B8 = HOST_ID[7:0];
localparam [7:0] CFH_B9 = HOST_ID[15:8];
localparam [7:0] CFH_B10 = HOST_ID[23:16];
localparam [7:0] CFH_B11 = HOST_ID[31:24];


localparam [7:0] CFH_B12 = TTL;
localparam [7:0] CFH_B13 = CFH_MSG;


localparam CFH_HEADER = {CFH_B0, CFH_B1, CFH_B2, CFH_B3, CFH_B4, CFH_B5, CFH_B6, CFH_B7, CFH_B8, CFH_B9, CFH_B10, CFH_B11, CFH_B12, CFH_B13};
localparam WRITE_CFH_BEATS = 42/8;
localparam BYTE_START =42%8;
////////////////////////

//packet analysis module
wire need_cfh_header;
reg write_cfh;
reg cfh_header_stage_1;
reg cfh_header_stage_2;
reg send_phase_shutdown_2;
reg [63:0] saved_data_out;
reg [63-BYTE_START*8:0] for_next_clk;
reg [15:0] orig_total_bytes;
reg [15:0] new_total_bytes;
reg [3:0]  orig_last_valid_bytes;
reg [3:0]  new_last_valid_bytes;


analyse_stored_packet analyse_packet_inst (
    .clk(clk),
    .rst(rst),
    .start_analysis(start_analysis),

    .beat_counter(beat_counter),
    .last_tkeep(last_tkeep),

    .r_add(ana_r_add),
    .w_add(ana_w_add),
    .data_in(ana_data_in),
    .data_out(data_out),
    .write_en(ana_write_en),

    .drop_packet(drop_packet),
    .valid(valid_packet),
    .need_cfh_header(need_cfh_header),
    .mod_beat_counter(mod_beat_counter),
    .mod_last_tkeep(mod_last_tkeep)
);



bram bram_inst(
.clk(clk),
.rst(1'b0),
.data_in(bram_data_in),
.data_out(data_out),
.w_add(bram_w_add),
.r_add(bram_r_add),
.write_en(bram_write_en)
);

always @(posedge clk) begin
    if (rst)
    begin
        phase <= PHASE_IDLE;
        
        packet_tuser<=0;               // added
        beat_counter<=0;
        start_packet_accept<=0;
        start_analysis <= 0;
        valid_packet_buffer<=0;
        write_beat_count<=0;
        last_tkeep<=0;
        parent_r_add <= 0;
        parent_w_add <= 0;
        parent_data_in <= 0;
        parent_write_en <= 0;
        m_start_packet<=0;
        m_axis_tdata<=0;
        m_axis_tkeep<=0;
        m_axis_tvalid<=0;
        m_axis_tlast<=0;
        m_axis_tuser<=0;
        send_phase<=0;
        cfh_header_stage_1 <= 0;
        cfh_header_stage_2 <= 0;
        saved_data_out     <= 0;
        for_next_clk       <= 0;
    end
    else begin
     
        // lock valid packets in a reg and only accept when send_phase = 0
        parent_write_en <= 0;
        if (send_phase == 0)
        begin
            if (valid_packet == 1 && drop_packet == 0)
            begin
                phase <= PHASE_SEND;
                write_cfh <= need_cfh_header;
                cfh_header_stage_1 <= 0;
                cfh_header_stage_2 <= 0;
                saved_data_out     <= 0;
                for_next_clk       <= 0;
                send_phase_warmup<=1;
                parent_r_add <= 0;
                write_beat_count <= 0;
            end
            else if (valid_packet == 1 && drop_packet == 1)
            begin
                phase <= PHASE_IDLE;
                valid_packet_buffer <= 0;
                beat_counter <= 0;
                start_packet_accept <= 0;
                send_phase <= 0;
            end
        end
        
        // Starting to store packets
        // add additional condition if phase  == PHASE_IDLE
        if (s_start_packet!=0 && valid_packet_buffer==0 && phase == PHASE_IDLE)
        begin
            m_axis_tdata<=64'b0;
            m_axis_tkeep<=8'b0;
            m_axis_tvalid<=0;
            m_axis_tuser<=0;           // changed: do not mirror live input during idle
            m_axis_tlast<=0;
            
            start_packet_accept <= 1;
            if (s_axis_tvalid)
            begin
                phase <= PHASE_CAPTURE; 
                parent_write_en <=1;
                parent_data_in <= s_axis_tdata;
                parent_w_add <= 0;
                packet_tuser[0 +: RX_USER_WIDTH] <= s_axis_tuser;   // added
                beat_counter<=1;
            end
        end
        // proceeding to store packet in the buffer
        else if (start_packet_accept == 1 && s_axis_tvalid && s_axis_tlast==0)
        begin
            
            packet_tuser[beat_counter*RX_USER_WIDTH +: RX_USER_WIDTH] <= s_axis_tuser; // added
            beat_counter <= beat_counter+1;
            parent_write_en <=1;
            parent_data_in <= s_axis_tdata;
            parent_w_add <= beat_counter;
            m_axis_tdata<=64'b0;
            m_axis_tkeep<=8'b0;
            m_axis_tvalid<=0;
            m_axis_tuser<=0;       // changed
            m_axis_tlast<=0;
        
        end
        // packet has been stored
        else if (s_axis_tlast && start_packet_accept == 1 && s_axis_tvalid)
        begin
            packet_tuser[beat_counter*RX_USER_WIDTH +: RX_USER_WIDTH] <= s_axis_tuser; // added
            valid_packet_buffer<=1;
            write_beat_count<=0;
            last_tkeep<=s_axis_tkeep;
            
            parent_write_en <= 1;
            parent_data_in <= s_axis_tdata;
            parent_w_add  <= beat_counter;
            
            // call packet analysis module here
            start_analysis <=1;
    
            
            m_axis_tdata<=64'b0;
            m_axis_tkeep<=8'b0;
            m_axis_tvalid<=0;
            m_axis_tuser<=0;       // changed
            m_axis_tlast<=0;
            start_packet_accept<=0;
        end
        
        else if (start_analysis == 1)
        begin
            start_analysis <= 0;
            //valid_packet_buffer<=0;
            phase <= PHASE_ANALYZE;
           
           
        end
        else if (send_phase_warmup == 1)
        begin
            send_phase <=1;
            send_phase_warmup<=0;
            parent_r_add <= write_beat_count+1;
            write_beat_count<=write_beat_count+1;
            
        end
    else if (send_phase == 1)
    begin
        phase <= PHASE_SEND;

        // stop analysis
        start_analysis <= 0;

        if (write_beat_count == 1)
            m_start_packet <= 2'b01;
        else
            m_start_packet <= 0;

        // keep your tested 2-cycle-prefire scheme
        parent_r_add <= write_beat_count + 1;

        // replay stored tuser using your existing indexing convention
        m_axis_tuser  <= packet_tuser[(write_beat_count-1)*RX_USER_WIDTH +: RX_USER_WIDTH];
        m_axis_tvalid <= 1'b1;
        m_axis_tlast  <= 1'b0;
        m_axis_tkeep  <= 8'hFF;

        // ---------------------------------------------------------
        // CFH insertion path
        // ---------------------------------------------------------
        if ((write_cfh == 1'b1) && (write_beat_count <= WRITE_CFH_BEATS))
        begin
            // unchanged beats before insertion point
            m_axis_tdata <= data_out;
        end
        else if ((write_cfh == 1'b1) &&
                (cfh_header_stage_1 == 1'b0) &&
                (cfh_header_stage_2 == 1'b0))
        begin
            // first beat where header starts:
            // keep first BYTE_START bytes from original beat,
            // then append first part of CFH header
            m_axis_tdata <= {CFH_HEADER[63-BYTE_START*8:0], data_out[0 +: BYTE_START*8]};

            // save remaining bytes of this original beat for later shifted output
            for_next_clk <= data_out[63:BYTE_START*8];

            // next cycle emits the remaining CFH bytes
            cfh_header_stage_1 <= 1'b1;
        end
        else if (cfh_header_stage_1 == 1'b1)
        begin
            // second CFH beat: pure remaining header bytes
            m_axis_tdata <= CFH_HEADER[111:64-BYTE_START*8];

            // IMPORTANT:
            // while we are outputting this extra CFH beat, BRAM has already advanced.
            // capture that data_out so we do not lose the first post-header source beat.
            saved_data_out <= data_out;

            cfh_header_stage_1 <= 1'b0;
            cfh_header_stage_2 <= 1'b1;
        end
        else if (cfh_header_stage_2 == 1'b1)
        begin
            // shifted path stays active for the rest of the packet
            // emit low BYTE_START bytes from saved_data_out
            // and remaining bytes from previous carry
            m_axis_tdata <= {saved_data_out[0 +: BYTE_START*8], for_next_clk};

            // update carry for next shifted beat
            for_next_clk <= saved_data_out[63:BYTE_START*8];

            // capture next BRAM word for the next shifted beat
            saved_data_out <= data_out;
        end
        else
        begin
            // no CFH insertion
            m_axis_tdata <= data_out;
        end

        // exactly one increment per output beat
        write_beat_count <= write_beat_count + 1;

        // your existing shutdown convention:
        // this cycle is the one before the final tlast cycle
        if (mod_beat_counter == write_beat_count)
        begin
            m_axis_tkeep <= 8'hFF;
            send_phase_shutdown <= 1'b1;
            send_phase <= 1'b0;
        end
    end

    else if (send_phase_shutdown == 1)
    begin
        m_axis_tlast  <= 1'b1;
        m_axis_tvalid <= 1'b1;

        // mod_last_tkeep must already correspond to the FINAL packet size
        m_axis_tkeep <= mod_last_tkeep;

        // final beat must also come from shifted path when CFH insertion is active
        if ((write_cfh == 1'b1) && (cfh_header_stage_2 == 1'b1))
        begin
            m_axis_tdata <= {saved_data_out[0 +: BYTE_START*8], for_next_clk};

            // one reasonable choice: keep tuser aligned to your output-side indexing
            m_axis_tuser <= packet_tuser[(write_beat_count-1)*RX_USER_WIDTH +: RX_USER_WIDTH];
        end
        else
        begin
            m_axis_tdata <= data_out;
            m_axis_tuser <= packet_tuser[(write_beat_count-1)*RX_USER_WIDTH +: RX_USER_WIDTH];
        end

        valid_packet_buffer <= 0;
        beat_counter <= 0;
        send_phase_shutdown <= 0;

        // clear CFH pipeline state after final beat
        cfh_header_stage_1 <= 0;
        cfh_header_stage_2 <= 0;
        saved_data_out     <= 0;
        for_next_clk       <= 0;
    end      
            
        
        else if (m_axis_tlast ==1)
        begin
            phase <= PHASE_IDLE;
            start_packet_accept <= 0;
            m_start_packet <= 0;
            m_axis_tlast<=0;
            m_axis_tvalid<=0;
            m_axis_tdata<=0;
            m_axis_tkeep<=0;
            m_axis_tuser<=0;       // changed
        end
    end
 end

/////////////////////////////////

endmodule