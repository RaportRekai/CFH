`timescale 1ns / 1ps
/*
The module should now have two kinds of buffers
one for packet descriptor - we only need where the packet begins and where it ends
other for packet data - we keep track of tkeep tdata and tuser for each beat
the data width for tdata beat is 64 bits
the data width for tkeep beat is 8 bits
the data width for tuser beat is ?
the data widht for tlast is 1 bit
the data width for index of the start beat of packet will be log2(TOTAL_SPACE/64)
same would be the data widht for end beat of packet

and the packet data is a circular buffer while the packet descriptor is a fifo,
when packets arrive we do make an entry into the packet tdata,tkeep,tuser,tlast ring buffers and also to the packet descriptor fifo.
subsequent beats dont have an entry into the packet descriptor fifo until the last beat of the packet arrives, 
then we make an entry into the packet descriptor fifo with the length of the packet.
the data memory buffers can have its own write and read pointers
the PD memory buffer should have its own write and read pointers

*/
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

reg [1514*8-1:0]packet_bytes;

// Added only for tuser storage: one tuser per stored beat
reg [MAX_BEATS*RX_USER_WIDTH-1:0] packet_tuser;

reg start_packet_accept;
reg [7:0]beat_counter;
reg [7:0]write_beat_count;
reg valid_packet_buffer;
reg [7:0]last_tkeep;

/////////////////////////////////

always @(posedge clk) begin
if (rst)begin
packet_bytes<=0;
packet_tuser<=0;               // added
beat_counter<=0;
start_packet_accept<=0;
valid_packet_buffer<=0;
write_beat_count<=0;
last_tkeep<=0;
m_start_packet<=0;
m_axis_tdata<=0;
m_axis_tkeep<=0;
m_axis_tvalid<=0;
m_axis_tlast<=0;
m_axis_tuser<=0;
end
else begin
    // Starting to store packets
    if (s_start_packet!=0 && valid_packet_buffer==0)
    begin
    m_axis_tdata<=64'b0;
    m_axis_tkeep<=8'b0;
    m_axis_tvalid<=0;
    m_axis_tuser<=0;           // changed: do not mirror live input during idle
    m_axis_tlast<=0;
    
    start_packet_accept <= 1;
        if (s_axis_tvalid)
        begin
            packet_bytes[63:0] <= s_axis_tdata;
            packet_tuser[0 +: RX_USER_WIDTH] <= s_axis_tuser;   // added
            beat_counter<=1;
        end
    end
    // proceeding to store packet in the buffer
    else if (start_packet_accept == 1 && s_axis_tvalid && s_axis_tlast==0)
    begin
        packet_bytes[beat_counter*64+:64] <= s_axis_tdata;
        packet_tuser[beat_counter*RX_USER_WIDTH +: RX_USER_WIDTH] <= s_axis_tuser; // added
        beat_counter <= beat_counter+1;
        
        m_axis_tdata<=64'b0;
        m_axis_tkeep<=8'b0;
        m_axis_tvalid<=0;
        m_axis_tuser<=0;       // changed
        m_axis_tlast<=0;
    
    end
    // packet has been stored
    else if (s_axis_tlast && start_packet_accept == 1 && s_axis_tvalid)
    begin
        packet_bytes[beat_counter*64+:64]<= s_axis_tdata;
        packet_tuser[beat_counter*RX_USER_WIDTH +: RX_USER_WIDTH] <= s_axis_tuser; // added
        valid_packet_buffer<=1;
        write_beat_count<=0;
        last_tkeep<=s_axis_tkeep;
        
        m_axis_tdata<=64'b0;
        m_axis_tkeep<=8'b0;
        m_axis_tvalid<=0;
        m_axis_tuser<=0;       // changed
        m_axis_tlast<=0;
        start_packet_accept<=0;
    end
    
    else if (valid_packet_buffer)
    begin
        if (write_beat_count ==0)
            m_start_packet<=2'b01;
        else
            m_start_packet<=0;
        
        m_axis_tdata<=packet_bytes[write_beat_count*64+:64];
        
        m_axis_tvalid<=1;
        
        // changed: replay stored tuser for this beat
        m_axis_tuser<=packet_tuser[write_beat_count*RX_USER_WIDTH +: RX_USER_WIDTH];
        
        write_beat_count<=write_beat_count+1;
        if (beat_counter == write_beat_count)
        begin
            m_axis_tlast <= 1'b1;
            m_axis_tkeep<= last_tkeep;
            valid_packet_buffer<=0;
            beat_counter<=0;
        end
        else
        begin
            m_axis_tlast<=0;
            m_axis_tkeep<= 8'hFF;
        end
        
    end
    else if (m_axis_tlast ==1)
    begin
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