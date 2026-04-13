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


////////////////////////

//packet analysis module
wire        need_cfh_header;

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
    end
    else begin
     
        // lock valid packets in a reg and only accept when send_phase = 0
        parent_write_en <= 0;
        if (send_phase == 0)
        begin
            if (valid_packet == 1 && drop_packet == 0)
            begin
                phase<=PHASE_SEND;
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
            start_analysis <=0;
            
            if (write_beat_count ==0)
                m_start_packet<=2'b01;
            else
                m_start_packet<=0;
            
            m_axis_tdata <= data_out;
            parent_r_add <= write_beat_count+1;
            m_axis_tuser <= packet_tuser[write_beat_count*RX_USER_WIDTH+:RX_USER_WIDTH];
            
            m_axis_tvalid<=1;
            
            // changed: replay stored tuser for this beat - we might have to test the behaviour when we set it to 0
            //m_axis_tuser<=0;//packet_tuser[write_beat_count*RX_USER_WIDTH +: RX_USER_WIDTH];
            
            // we have to change write beat count
            write_beat_count<=write_beat_count+1;
            if (mod_beat_counter == write_beat_count)
            begin
                m_axis_tkeep<=8'hFF;
                send_phase_shutdown<=1;
                send_phase<=0;
            end
            else
            begin
                m_axis_tlast<=0;
                m_axis_tkeep<= 8'hFF;
            end
            
        end
        
        else if (send_phase_shutdown==1)
        begin
            m_axis_tlast <= 1'b1;
            m_axis_tkeep<= mod_last_tkeep;
            valid_packet_buffer<=0;
            beat_counter<=0;
            send_phase_shutdown<=0;
            m_axis_tdata <= data_out;
            m_axis_tuser <= packet_tuser[write_beat_count*RX_USER_WIDTH+:RX_USER_WIDTH];
            
            
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