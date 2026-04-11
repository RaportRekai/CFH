`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04/04/2026 06:01:24 PM
// Design Name: 
// Module Name: analyse_stored_packet
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module analyse_stored_packet #( parameter
// Packet identification fields
IPV4_PROT_NO_BYTE = 184,
TCP_DEST_PORT = 288,
IP_CHECK = 96,

// Packet Scraping fields bit index
STRIP_DATA_A = 432, // 8 bit
STRIP_DATA_B = 440, // 32 bit
STRIP_DATA_C = 472, // 32 bit

// Packet header reform fields bit index
UDP_LEN = 304, // 16 bits
IP_LEN  = 128,// 16 bits
UDP_CKS = 320, // 16 bits
IP_CKS = 192, // 16 bits


// Data for CFH
CFH_MSG = 8'd4,
TTL = 8'd4,
LB_ID = 32'd4, 
RDMA_CONFIG = 32'd4,
HOST_ID = 32'd4,
EXTRA_LEN = 16'd14 ,//in bytes
THRESH = 5
)
(
input clk,
input [1514*8-1:0] packet_bytes,
input start_analysis,
output reg [1514*8-1:0] modified_packet_bytes,
output reg drop_packet,
output reg valid,
output reg [7:0] mod_beat_counter,
input [7:0] beat_counter,
input [7:0] last_tkeep,
output reg [7:0]mod_last_tkeep

);
    

// store state
reg [1514*8-1:0] modified_packet_bytes_next;
reg drop_packet_next;    
reg valid_next;
reg [7:0] mod_beat_counter_next;
reg [7:0] mod_last_tkeep_next;

reg enable_cks;

// scrape checksum
reg [15:0] ip_checksum;
reg [15:0] udp_checksum;

reg [3:0] score;

//Telemetry scraping
reg [7:0] host_tel_data_A;
reg [31:0] host_tel_data_B;
reg [31:0] host_tel_data_C;


initial 
begin
    enable_cks <= 0;
    drop_packet_next<=0;
    score<=6;
end
//PREfire UDP checksum
localparam [15:0] CFH_W0 = LB_ID[31:16];
localparam [15:0] CFH_W1 = LB_ID[15:0];

localparam [15:0] CFH_W2 = RDMA_CONFIG[31:16];
localparam [15:0] CFH_W3 = RDMA_CONFIG[15:0];

localparam [15:0] CFH_W4 = HOST_ID[31:16];
localparam [15:0] CFH_W5 = HOST_ID[15:0];

localparam [15:0] CFH_W6 = {TTL, CFH_MSG};

localparam [15:0] OLD_UDP_DST_PORT = 16'd4791;
localparam [15:0] NEW_UDP_DST_PORT = 16'd49112;


function automatic [15:0] add1c16;
    input [15:0] a;
    input [15:0] b;
    reg [16:0] sum;
begin
    sum = a + b;
    add1c16 = sum[15:0] + sum[16];
end
endfunction


localparam [15:0] UDP_PORT_DELTA =
    add1c16(~OLD_UDP_DST_PORT, NEW_UDP_DST_PORT);

localparam [15:0] CFH_SUM_0 =
    add1c16(CFH_W0, CFH_W1);

localparam [15:0] CFH_SUM_1 =
    add1c16(CFH_W2, CFH_W3);

localparam [15:0] CFH_SUM_2 =
    add1c16(CFH_W4, CFH_W5);

localparam [15:0] CFH_SUM_3 =
    add1c16(CFH_W6, EXTRA_LEN);

localparam [15:0] CFH_CONST_SUM =
    add1c16(
        add1c16(CFH_SUM_0, CFH_SUM_1),
        add1c16(CFH_SUM_2, CFH_SUM_3)
    );

localparam [15:0] PRECOMP_UDP_DELTA =
    add1c16(UDP_PORT_DELTA, CFH_CONST_SUM);

localparam [15:0] PRECOMP_UDP_DELTA_CONST =
    add1c16(PRECOMP_UDP_DELTA,16'd14);

    
    


    
always @(posedge clk)
begin

    // Packet identification
    

    //Type A - status packets 
    /*
    This data comes from the the atlas machine to the software load balancer. 
    It houses telemetry information that the fpga uses later on.
    
    IPV4_PROT_NO_BYTE = 112+64+8;//8 bits has to be 6
    TCP_DEST_PORT = 272+16 //16 bits has to be 10001
    STRIP_DATA_A = 432;//8 bits
    STRIP_DATA_B = 440;//32 bits
    STRIP_DATA_C = 472;//32 bits
    */
        
    // Scrape from packet and drop
    if (start_analysis == 1)
    begin
    modified_packet_bytes_next<= packet_bytes;
    valid_next<=1;
    mod_beat_counter_next<=beat_counter;
    mod_last_tkeep_next<= last_tkeep;
//    begin
//        valid_next<=1;
//        mod_beat_counter_next<=beat_counter;
//        mod_last_tkeep_next<= last_tkeep;
//        // check for ipv4
//        if (packet_bytes[IP_CHECK +:16] == 16'h800)
//        begin
//            if(packet_bytes[IPV4_PROT_NO_BYTE +:8] == 8'd6)
//            begin
//                if(packet_bytes[TCP_DEST_PORT +:16] == 16'd10001)
//                begin
                    
//                    // Packet scraping
                    
//                    host_tel_data_A <= packet_bytes[STRIP_DATA_A+:8];
//                    host_tel_data_B <= packet_bytes[STRIP_DATA_B+:32];
//                    host_tel_data_C <= packet_bytes[STRIP_DATA_C+:32];
                    
//                    //drop the packet
                    
//                    modified_packet_bytes_next <= 0;
//                    drop_packet_next<=1;
//                end
                
//                else
//                begin
//                    modified_packet_bytes_next<=packet_bytes;
//                    drop_packet_next<=0;
//                end
//            end
       
    
    
//        //Type B - CFH Distress
//        /*
//        This data comes from the the atlas machine to the software load balancer. 
//        It houses telemetry information that the fpga uses later on.
        
//        IPV4_PROT_NO_BYTE = 112+64+8;//8 bits has to be 
//        TCP_DEST_PORT = 272+16 //16 bits has to be 4791
//        STRIP_DATA_A = 432;//8 bits
//        STRIP_DATA_B = 440;//32 bits
//        STRIP_DATA_C = 472;//32 bits
//        */
        
        
//        // Stage 1: modify the packet
        
//            else if(packet_bytes[IPV4_PROT_NO_BYTE+:8] == 8'd17)
//            begin
//                drop_packet_next<=0;
//                if(packet_bytes[TCP_DEST_PORT+:16] == 16'd4791)
//                begin
//                    if (score>THRESH)
//                    begin
//                    // Packet mod
//                        modified_packet_bytes_next[IP_LEN-1:0] <= packet_bytes[IP_LEN-1:0];
//                        modified_packet_bytes_next[IP_LEN+:16] <= EXTRA_LEN + packet_bytes[IP_LEN+:16];
//                        modified_packet_bytes_next[TCP_DEST_PORT-1:IP_LEN+16-1]<= packet_bytes[TCP_DEST_PORT-1:IP_LEN+16-1];
//                        modified_packet_bytes_next[TCP_DEST_PORT+:16] <= 16'd49112;
//                        modified_packet_bytes_next[UDP_LEN+:16] <= EXTRA_LEN + packet_bytes[UDP_LEN+:16];
//                        modified_packet_bytes_next[272+64+(EXTRA_LEN)*8-1:272+64] <= {LB_ID,
//                                                        RDMA_CONFIG,
//                                                        HOST_ID,
//                                                        TTL,
//                                                        CFH_MSG};
//                        modified_packet_bytes_next[1514*8-1:272+64+(EXTRA_LEN)*8] <= packet_bytes[1514*8-1:272+64];
                        
//                        // we will have to strip the current cksum and use it for calculation in the next clk cycle
//                        ip_checksum <= ~packet_bytes[IP_CKS:+16];
//                        udp_checksum <= ~packet_bytes[UDP_CKS:+16];
                        
//                        // update beat_counter
//                        // we have to find the number of bytes still left in the axis and then adjust accordingly
//                        if (last_tkeep == 8'b1)
//                        begin
//                            mod_last_tkeep_next<=8'b1111111;
//                            mod_beat_counter_next <= beat_counter+1;
//                        end
//                        else if (last_tkeep == 8'b11)
//                        begin
//                            mod_last_tkeep_next<=8'b11111111;
//                            mod_beat_counter_next <= beat_counter+1;
//                        end
//                        else if (last_tkeep == 8'b111)
//                        begin
//                            mod_last_tkeep_next<=8'b1;
//                            mod_beat_counter_next <= beat_counter+2;
//                        end
//                        else if (last_tkeep == 8'b1111)
//                        begin
//                            mod_last_tkeep_next<=8'b11;
//                            mod_beat_counter_next <= beat_counter+2;
//                        end
//                        else if (last_tkeep == 8'b11111)
//                        begin
//                            mod_last_tkeep_next<=8'b111;
//                            mod_beat_counter_next <= beat_counter+2;
//                        end
//                        else if (last_tkeep == 8'b111111)
//                        begin
//                            mod_last_tkeep_next<=8'b1111;
//                            mod_beat_counter_next <= beat_counter+2;
//                        end
//                        else if (last_tkeep == 8'b1111111)
//                        begin
//                            mod_last_tkeep_next<=8'b11111;
//                            mod_beat_counter_next <= beat_counter+2;
//                        end
//                        else if (last_tkeep == 8'b11111111)
//                        begin
//                            mod_last_tkeep_next<=8'b111111;
//                            mod_beat_counter_next <= beat_counter+2;
//                        end
                  
//                        // enable checksum on the modified packet
//                        enable_cks <= 1;
//                    end
//                    else
//                        modified_packet_bytes_next <= packet_bytes;
                       
//                end
//                else
//                    modified_packet_bytes_next <= packet_bytes;
//            end
            
            
            
//            else
//            begin
//                modified_packet_bytes_next <= packet_bytes;
//                drop_packet_next<=0;
//            end
            
//        end
        
//        else
//        begin
//            modified_packet_bytes_next <= packet_bytes;
//            drop_packet_next<=0;
//        end
            
    end
    
    else
    begin
        
        valid_next<=0;
        //reset registers
        modified_packet_bytes_next <=0;
        ip_checksum<=0;
        udp_checksum<=0;
        drop_packet_next<=0;
        
    end 
    
    
    // Stage 2: checksum recalculate stage
    if (valid_next==1)
    begin
        if(enable_cks == 1)
        begin
            
            modified_packet_bytes[IP_CKS-1:0] <= modified_packet_bytes_next[IP_CKS-1:0];
            modified_packet_bytes[IP_CKS:+16]<= ~add1c16(ip_checksum,16'd14);
            modified_packet_bytes[UDP_CKS-1:IP_CKS+16] <= modified_packet_bytes_next[UDP_CKS-1:IP_CKS+16];
            modified_packet_bytes[UDP_CKS:+16]<= ~add1c16(udp_checksum,PRECOMP_UDP_DELTA_CONST);
            modified_packet_bytes[1514*8-1:UDP_CKS+16] <= modified_packet_bytes_next[1514*8-1:UDP_CKS+16];
            enable_cks <=0;
            drop_packet<=0;
    
            
        end
        
        else if(drop_packet_next == 1)
        begin
            modified_packet_bytes <= 0;
            drop_packet<=1;
            drop_packet_next<=0; 
        end
             
        else
        begin
            modified_packet_bytes <= modified_packet_bytes_next;
            drop_packet<=0;
        end
    
    end
    
    
    mod_beat_counter<=mod_beat_counter_next;
    valid <= valid_next;
    mod_last_tkeep<=mod_last_tkeep_next;
    

end
endmodule
  


