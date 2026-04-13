`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04/12/2026 03:52:30 PM
// Design Name: 
// Module Name: bram
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


module bram( 
input clk,
input rst,
input [7:0] r_add,
output reg [63:0] data_out,
input [63:0] data_in,
input [7:0] w_add,
input write_en
    );
    
    reg [63:0] packet_mem [0:189];
    initial
    begin
        
    end
    always @(posedge clk)
    begin
        if(rst)
        begin
           data_out <= 0;
        end
        
        else
        begin
            if(write_en == 1)
            begin
                packet_mem[w_add] <= data_in;
            end
            data_out<=packet_mem[r_add];            
            
        end
    end
endmodule
