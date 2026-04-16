`timescale 1ns / 1ps

module tb_packet_store_forward;

    parameter DATA_WIDTH    = 64;
    parameter KEEP_WIDTH    = 8;
    parameter RX_USER_WIDTH = 1;

    reg                         clk;
    reg                         rst;

    reg  [1:0]                  s_start_packet;
    reg  [DATA_WIDTH-1:0]       s_axis_tdata;
    reg  [KEEP_WIDTH-1:0]       s_axis_tkeep;
    reg                         s_axis_tvalid;
    reg                         s_axis_tlast;
    reg  [RX_USER_WIDTH-1:0]    s_axis_tuser;

    wire [1:0]                  m_start_packet;
    wire [DATA_WIDTH-1:0]       m_axis_tdata;
    wire [KEEP_WIDTH-1:0]       m_axis_tkeep;
    wire                        m_axis_tvalid;
    wire                        m_axis_tlast;
    wire [RX_USER_WIDTH-1:0]    m_axis_tuser;

    integer i;
    integer out_pkt_count;
    integer out_beat_count;

    reg [7:0] pkt1 [0:1499];
    reg [7:0] pkt2 [0:55];
    reg [7:0] pkt3 [0:63];

    reg [63:0] temp_data;
    reg [7:0]  temp_keep;

    // -------------------------------------------------------------------------
    // DUT
    // -------------------------------------------------------------------------
    packet_store_forward #(
        .DATA_WIDTH(DATA_WIDTH),
        .KEEP_WIDTH(KEEP_WIDTH),
        .RX_USER_WIDTH(RX_USER_WIDTH),
        .START_BYTE(42)
    ) dut (
        .clk(clk),
        .rst(rst),

        .s_start_packet(s_start_packet),
        .s_axis_tdata(s_axis_tdata),
        .s_axis_tkeep(s_axis_tkeep),
        .s_axis_tvalid(s_axis_tvalid),
        .s_axis_tlast(s_axis_tlast),
        .s_axis_tuser(s_axis_tuser),

        .m_start_packet(m_start_packet),
        .m_axis_tdata(m_axis_tdata),
        .m_axis_tkeep(m_axis_tkeep),
        .m_axis_tvalid(m_axis_tvalid),
        .m_axis_tlast(m_axis_tlast),
        .m_axis_tuser(m_axis_tuser)
    );

    // -------------------------------------------------------------------------
    // clock
    // -------------------------------------------------------------------------
    initial begin
        clk = 1'b0;
        forever #5 clk = ~clk;
    end

    // -------------------------------------------------------------------------
    // immediate clear: use only before clocked traffic starts
    // -------------------------------------------------------------------------
    task clear_inputs_now;
    begin
        s_start_packet = 2'b00;
        s_axis_tdata   = 64'd0;
        s_axis_tkeep   = 8'd0;
        s_axis_tvalid  = 1'b0;
        s_axis_tlast   = 1'b0;
        s_axis_tuser   = 1'b0;
    end
    endtask

    // -------------------------------------------------------------------------
    // clocked clear: use only after @(posedge clk)
    // -------------------------------------------------------------------------
    task clear_inputs_clk;
    begin
        s_start_packet <= 2'b00;
        s_axis_tdata   <= 64'd0;
        s_axis_tkeep   <= 8'd0;
        s_axis_tvalid  <= 1'b0;
        s_axis_tlast   <= 1'b0;
        s_axis_tuser   <= 1'b0;
    end
    endtask

    // -------------------------------------------------------------------------
    // wait N cycles
    // -------------------------------------------------------------------------
    task wait_cycles;
        input integer n;
        integer k;
    begin
        for (k = 0; k < n; k = k + 1)
            @(posedge clk);
    end
    endtask

    // -------------------------------------------------------------------------
    // Packet 1 : Type A, 1500 bytes
    // IPv4 + TCP + dst port 10001
    // Expected: dropped
    // -------------------------------------------------------------------------
    task init_pkt1;
    begin
        for (i = 0; i < 1500; i = i + 1)
            pkt1[i] = 8'h00;

        // Ethernet
        pkt1[0]  = 8'h5B; // rev8(8'hDA)
        pkt1[1]  = 8'h40; // rev8(8'h02)
        pkt1[2]  = 8'hC0; // rev8(8'h03)
        pkt1[3]  = 8'h20; // rev8(8'h04)
        pkt1[4]  = 8'hA0; // rev8(8'h05)
        pkt1[5]  = 8'h60; // rev8(8'h06)

        pkt1[6]  = 8'h5A; // rev8(8'h5A)
        pkt1[7]  = 8'h88; // rev8(8'h11)
        pkt1[8]  = 8'h48; // rev8(8'h12)
        pkt1[9]  = 8'hC8; // rev8(8'h13)
        pkt1[10] = 8'h28; // rev8(8'h14)
        pkt1[11] = 8'hA8; // rev8(8'h15)

        pkt1[12] = 8'h10; // rev8(8'h08)
        pkt1[13] = 8'h00; // rev8(8'h00)   EtherType = IPv4

        // IPv4 header
        pkt1[14] = 8'hA2; // rev8(8'h45)   version + IHL
        pkt1[15] = 8'h00; // rev8(8'h00)
        pkt1[16] = 8'h00; // rev8(8'h00)
        pkt1[17] = 8'h3C; // rev8(8'h3C)   IP total length = 0x003C
        pkt1[18] = 8'h48; // rev8(8'h12)
        pkt1[19] = 8'h2C; // rev8(8'h34)
        pkt1[20] = 8'h00; // rev8(8'h00)
        pkt1[21] = 8'h00; // rev8(8'h00)
        pkt1[22] = 8'h02; // rev8(8'h40)   TTL
        pkt1[23] = 8'h88; // rev8(8'h11)   Protocol = UDP
        pkt1[24] = 8'hD5; // rev8(8'hAB)   IP checksum placeholder
        pkt1[25] = 8'hB3; // rev8(8'hCD)
        pkt1[26] = 8'h50; // rev8(8'h0A)
        pkt1[27] = 8'h80; // rev8(8'h01)
        pkt1[28] = 8'h80; // rev8(8'h01)
        pkt1[29] = 8'h80; // rev8(8'h01)
        pkt1[30] = 8'h50; // rev8(8'h0A)
        pkt1[31] = 8'h80; // rev8(8'h01)
        pkt1[32] = 8'h80; // rev8(8'h01)
        pkt1[33] = 8'h40; // rev8(8'h02)

        // UDP header begins at byte 34
        pkt1[34] = 8'h48; // rev8(8'h12)   src port high
        pkt1[35] = 8'h2C; // rev8(8'h34)   src port low
        pkt1[36] = 8'h48; // rev8(8'h12)   dst port high
        pkt1[37] = 8'hED; // rev8(8'hB7)   dst port low = 4791
        pkt1[38] = 8'h00; // rev8(8'h00)   UDP length high
        pkt1[39] = 8'h14; // rev8(8'h28)   UDP length low = 0x0028
        pkt1[40] = 8'h48; // rev8(8'h12)   UDP checksum placeholder high
        pkt1[41] = 8'h2C; // rev8(8'h34)   UDP checksum placeholder low

        // Payload bytes 42 onwards
        // these are also bit-reversed per byte
        pkt1[42] = 8'h54; // rev8(8'h2A)
        pkt1[43] = 8'hD4; // rev8(8'h2B)
        pkt1[44] = 8'h34; // rev8(8'h2C)
        pkt1[45] = 8'hB4; // rev8(8'h2D)
        pkt1[46] = 8'h74; // rev8(8'h2E)
        pkt1[47] = 8'hF4; // rev8(8'h2F)
        pkt1[48] = 8'h0C; // rev8(8'h30)
        pkt1[49] = 8'h8C; // rev8(8'h31)
        pkt1[50] = 8'h4C; // rev8(8'h32)
        pkt1[51] = 8'hCC; // rev8(8'h33)
        pkt1[52] = 8'h2C; // rev8(8'h34)
        pkt1[53] = 8'hAC; // rev8(8'h35)
        pkt1[54] = 8'h6C; // rev8(8'h36)
        pkt1[55] = 8'hEC; // rev8(8'h37)
        pkt1[56] = 8'h1C; // rev8(8'h38)
        pkt1[57] = 8'h9C; // rev8(8'h39)
        pkt1[58] = 8'h5C; // rev8(8'h3A)
        pkt1[59] = 8'hDC; // rev8(8'h3B)

        for (i = 60; i < 1500; i = i + 1)
            pkt1[i] = 8'h00;
    end
endtask

    // -------------------------------------------------------------------------
    // Packet 2 : Type B, 1500 bytes
    // IPv4 + UDP + dst port 4791
    // Expected: modified and forwarded
    // -------------------------------------------------------------------------
task init_pkt2;
begin
    for (i = 0; i < 1500; i = i + 1)
        pkt1[i] = 8'h00;

    // Ethernet header
    // Destination MAC = 10:70:fd:cb:5d:9f
    pkt2[0]  = 8'h10;
    pkt2[1]  = 8'h70;
    pkt2[2]  = 8'hFD;
    pkt2[3]  = 8'hCB;
    pkt2[4]  = 8'h5D;
    pkt2[5]  = 8'h9F;

    // Source MAC = 10:70:fd:cb:5d:af
    pkt2[6]  = 8'h10;
    pkt2[7]  = 8'h70;
    pkt2[8]  = 8'hFD;
    pkt2[9]  = 8'hCB;
    pkt2[10] = 8'h5D;
    pkt2[11] = 8'hAF;

    // EtherType = IPv4
    pkt2[12] = 8'h08;
    pkt2[13] = 8'h00;

    // IPv4 header
    pkt2[14] = 8'h45;   // Version/IHL
    pkt2[15] = 8'h00;   // DSCP/ECN

    pkt2[16] = 8'h00;
    pkt2[17] = 8'h2A;   // Total Length = 42 bytes

    pkt2[18] = 8'h6A;
    pkt2[19] = 8'hC4;   // Identification

    pkt2[20] = 8'h40;
    pkt2[21] = 8'h00;   // Flags/Fragment offset

    pkt2[22] = 8'h40;   // TTL = 64
    pkt2[23] = 8'h11;   // Protocol = UDP

    pkt2[24] = 8'h4E;
    pkt2[25] = 8'h93;   // IP checksum

    // Source IP = 192.168.0.16
    pkt2[26] = 8'hC0;
    pkt2[27] = 8'hA8;
    pkt2[28] = 8'h00;
    pkt2[29] = 8'h10;

    // Destination IP = 192.168.0.11
    pkt2[30] = 8'hC0;
    pkt2[31] = 8'hA8;
    pkt2[32] = 8'h00;
    pkt2[33] = 8'h0B;

    // UDP header
    pkt2[34] = 8'hAF;
    pkt2[35] = 8'hB6;   // Source port = 44982

    pkt2[36] = 8'h12;
    pkt2[37] = 8'hB7;   // Destination port = 4791

    pkt2[38] = 8'h00;
    pkt2[39] = 8'h16;   // UDP length = 22 bytes

    pkt2[40] = 8'h81;
    pkt2[41] = 8'h93;   // UDP checksum

    // Payload = "hello over udp"
    pkt2[42] = 8'h68;   // h
    pkt2[43] = 8'h65;   // e
    pkt2[44] = 8'h6C;   // l
    pkt2[45] = 8'h6C;   // l
    pkt2[46] = 8'h6F;   // o
    pkt2[47] = 8'h20;   // space
    pkt2[48] = 8'h6F;   // o
    pkt2[49] = 8'h76;   // v
    pkt2[50] = 8'h65;   // e
    pkt2[51] = 8'h72;   // r
    pkt2[52] = 8'h20;   // space
    pkt2[53] = 8'h75;   // u
    pkt2[54] = 8'h64;   // d
    pkt2[55] = 8'h70;   // p
end
endtask
    // -------------------------------------------------------------------------
    // Packet 3 : minimum Ethernet frame, 64 bytes
    // Non-Type-A / Non-Type-B
    // Expected: forwarded unchanged
    // -------------------------------------------------------------------------
task init_pkt3;
begin
    for (i = 0; i < 1500; i = i + 1)
        pkt3[i] = 8'h00;

    // Ethernet
    pkt3[0]  = 8'h08; // rev8(8'h10)
    pkt3[1]  = 8'h0E; // rev8(8'h70)
    pkt3[2]  = 8'hBF; // rev8(8'hFD)
    pkt3[3]  = 8'hD3; // rev8(8'hCB)
    pkt3[4]  = 8'hBA; // rev8(8'h5D)
    pkt3[5]  = 8'hF9; // rev8(8'h9F)

    pkt3[6]  = 8'h08; // rev8(8'h10)
    pkt3[7]  = 8'h0E; // rev8(8'h70)
    pkt3[8]  = 8'hBF; // rev8(8'hFD)
    pkt3[9]  = 8'hD3; // rev8(8'hCB)
    pkt3[10] = 8'hBA; // rev8(8'h5D)
    pkt3[11] = 8'hF5; // rev8(8'hAF)

    pkt3[12] = 8'h10; // rev8(8'h08)
    pkt3[13] = 8'h00; // rev8(8'h00)   EtherType = IPv4

    // IPv4 header
    pkt3[14] = 8'hA2; // rev8(8'h45)
    pkt3[15] = 8'h00; // rev8(8'h00)
    pkt3[16] = 8'h00; // rev8(8'h00)
    pkt3[17] = 8'h54; // rev8(8'h2A)   total length = 0x002A
    pkt3[18] = 8'hB4; // rev8(8'h2D)
    pkt3[19] = 8'hFA; // rev8(8'h5F)
    pkt3[20] = 8'h02; // rev8(8'h40)
    pkt3[21] = 8'h00; // rev8(8'h00)
    pkt3[22] = 8'h02; // rev8(8'h40)   TTL = 64
    pkt3[23] = 8'h88; // rev8(8'h11)   Protocol = UDP
    pkt3[24] = 8'hD1; // rev8(8'h8B)
    pkt3[25] = 8'h1F; // rev8(8'hF8)   IP checksum

    // Source IP = 192.168.0.16
    pkt3[26] = 8'h03; // rev8(8'hC0)
    pkt3[27] = 8'h15; // rev8(8'hA8)
    pkt3[28] = 8'h00; // rev8(8'h00)
    pkt3[29] = 8'h08; // rev8(8'h10)

    // Destination IP = 192.168.0.11
    pkt3[30] = 8'h03; // rev8(8'hC0)
    pkt3[31] = 8'h15; // rev8(8'hA8)
    pkt3[32] = 8'h00; // rev8(8'h00)
    pkt3[33] = 8'hD0; // rev8(8'h0B)

    // UDP header
    pkt3[34] = 8'h61; // rev8(8'h86)
    pkt3[35] = 8'h50; // rev8(8'h0A)   src port = 34314
    pkt3[36] = 8'h48; // rev8(8'h12)
    pkt3[37] = 8'hED; // rev8(8'hB7)   dst port = 4791
    pkt3[38] = 8'h00; // rev8(8'h00)
    pkt3[39] = 8'h68; // rev8(8'h16)   UDP length = 22
    pkt3[40] = 8'h81; // rev8(8'h81)
    pkt3[41] = 8'hC9; // rev8(8'h93)   UDP checksum

    // Payload = "hello over udp"
    pkt3[42] = 8'h16; // rev8(8'h68)   h
    pkt3[43] = 8'hA6; // rev8(8'h65)   e
    pkt3[44] = 8'h36; // rev8(8'h6C)   l
    pkt3[45] = 8'h36; // rev8(8'h6C)   l
    pkt3[46] = 8'hF6; // rev8(8'h6F)   o
    pkt3[47] = 8'h04; // rev8(8'h20)   space
    pkt3[48] = 8'hF6; // rev8(8'h6F)   o
    pkt3[49] = 8'h6E; // rev8(8'h76)   v
    pkt3[50] = 8'hA6; // rev8(8'h65)   e
    pkt3[51] = 8'h4E; // rev8(8'h72)   r
    pkt3[52] = 8'h04; // rev8(8'h20)   space
    pkt3[53] = 8'hAE; // rev8(8'h75)   u
    pkt3[54] = 8'h26; // rev8(8'h64)   d
    pkt3[55] = 8'h0E; // rev8(8'h70)   p

    for (i = 56; i < 1500; i = i + 1)
        pkt3[i] = 8'h00;
end
endtask

    // -------------------------------------------------------------------------
    // send packet
    // posedge-only stimulus
    // behaves like a registered source:
    // beat launched on one posedge, consumed by DUT on next posedge
    // -------------------------------------------------------------------------
    task send_packet;
        input integer pkt_id;
        input integer pkt_len;
        integer beat;
        integer num_beats;
        integer j;
        integer idx;
    begin
        num_beats = (pkt_len + 7) / 8;

        for (beat = 0; beat < num_beats; beat = beat + 1) begin
            temp_data = 64'd0;
            temp_keep = 8'd0;

            for (j = 0; j < 8; j = j + 1) begin
                idx = beat*8 + j;
                if (idx < pkt_len) begin
                    if (pkt_id == 1)
                        temp_data[j*8 +: 8] = pkt1[idx];
                    else if (pkt_id == 2)
                        temp_data[j*8 +: 8] = pkt2[idx];
                    else
                        temp_data[j*8 +: 8] = pkt3[idx];

                    temp_keep[j] = 1'b1;
                end
            end

            @(posedge clk);
            s_start_packet <= (beat == 0) ? 2'b01 : 2'b00;
            s_axis_tdata   <= temp_data;
            s_axis_tkeep   <= temp_keep;
            s_axis_tvalid  <= 1'b1;
            s_axis_tlast   <= (beat == num_beats-1) ? 1'b1 : 1'b0;
            s_axis_tuser   <= 1'b1;
        end

        @(posedge clk);
        clear_inputs_clk();
    end
    endtask

    // -------------------------------------------------------------------------
    // output monitor
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            out_pkt_count  <= 0;
            out_beat_count <= 0;
        end
        else begin
            if (m_axis_tvalid) begin
                $display("[%0t] OUT beat=%0d start=%b keep=%02h last=%b data=%016h user=%0h",
                         $time, out_beat_count, m_start_packet, m_axis_tkeep,
                         m_axis_tlast, m_axis_tdata, m_axis_tuser);

                out_beat_count <= out_beat_count + 1;

                if (m_axis_tlast) begin
                    out_pkt_count  <= out_pkt_count + 1;
                    out_beat_count <= 0;
                    $display("[%0t] ---- END OF OUTPUT PACKET %0d ----",
                             $time, out_pkt_count + 1);
                end
            end
        end
    end

    // -------------------------------------------------------------------------
    // stimulus
    // -------------------------------------------------------------------------
    initial begin
        clear_inputs_now();
        rst = 1'b1;

        init_pkt1();
        init_pkt2();
        init_pkt3();

        wait_cycles(5);
        @(posedge clk);
        rst <= 1'b0;

        wait_cycles(10);

        $display("==================================================");
        $display("Sending Packet 1 : 1500B Type A (expected DROP)");
        $display("==================================================");
        send_packet(1, 1500);

        wait_cycles(400);

        $display("==================================================");
        $display("Sending Packet 2 : 1500B Type B (expected FORWARD/MODIFY)");
        $display("==================================================");
        send_packet(2, 56);

        wait_cycles(400);

        $display("==================================================");
        $display("Sending Packet 3 : 64B minimum Ethernet frame");
        $display("==================================================");
        send_packet(3, 64);

        wait_cycles(400);

        $display("==================================================");
        $display("Simulation finished");
        $display("Output packet count = %0d", out_pkt_count);
        $display("Expected output packet count = 2");
        $display("==================================================");

        $finish;
    end

endmodule