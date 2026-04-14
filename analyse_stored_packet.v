`timescale 1ns / 1ps

module analyse_stored_packet #(
    // Packet identification fields (bit indices in packet bitstream)
    parameter IPV4_PROT_NO_BYTE = 184,   // 8 bits
    parameter TCP_DEST_PORT     = 288,   // actually UDP dest port in your path, 16 bits
    parameter IP_CHECK          = 96,

    // Packet scraping fields bit index
    parameter STRIP_DATA_A      = 432,   // 8 bit
    parameter STRIP_DATA_B      = 440,   // 32 bit
    parameter STRIP_DATA_C      = 472,   // 32 bit

    // Packet header reform fields bit index
    parameter UDP_LEN           = 304,   // 16 bits
    parameter IP_LEN            = 128,   // 16 bits
    parameter UDP_CKS           = 320,   // 16 bits
    parameter IP_CKS            = 192,   // 16 bits

    // Data for CFH decision / checksum delta
    parameter [7:0]  CFH_MSG     = 8'd4,
    parameter [7:0]  TTL         = 8'd4,
    parameter [31:0] LB_ID       = 32'd4,
    parameter [31:0] RDMA_CONFIG = 32'd4,
    parameter [31:0] HOST_ID     = 32'd4,
    parameter [15:0] EXTRA_LEN   = 16'd14,   // bytes to be inserted later by parent
    parameter [3:0]  THRESH      = 4'd5
)(
    input  wire        clk,
    input  wire        rst,
    input  wire        start_analysis,

    // original packet length info from parent
    input  wire [7:0]  beat_counter,
    input  wire [7:0]  last_tkeep,

    // BRAM interface
    output reg  [7:0]  r_add,
    output reg  [7:0]  w_add,
    output reg  [63:0] data_in,
    input  wire [63:0] data_out,
    output reg         write_en,

    // decision / status outputs
    output reg         drop_packet,
    output reg         valid,
    output reg         need_cfh_header,

    // this module only tells parent the new eventual packet size
    output reg  [7:0]  mod_beat_counter,
    output reg  [7:0]  mod_last_tkeep,

    // optional scraped telemetry for other packet type
    output reg  [7:0]  host_tel_data_A,
    output reg  [31:0] host_tel_data_B,
    output reg  [31:0] host_tel_data_C
);

    // -------------------------------------------------------------------------
    // word indices for BRAM (64-bit words)
    // -------------------------------------------------------------------------

    localparam [7:0] WORD_IP_HDR0   = (IP_LEN / 64);         // word containing IP length and protocol = word 2
    localparam [7:0] WORD_IP_CKS    = (IP_CKS / 64);         // word containing IP checksum = word 3
    localparam [7:0] WORD_UDP_HDR   = (TCP_DEST_PORT / 64);  // word containing UDP dst port and UDP length = word 4
    localparam [7:0] WORD_UDP_CKS   = (UDP_CKS / 64);        // word containing UDP checksum = word 5
    localparam [7:0] WORD_UDP_PAY0  = 8'd5;                  // first UDP payload byte is also in word 5

    // destination IP spans bytes 30..33
    // bytes 30,31 are in word 3; bytes 32,33 are in word 4
    localparam [7:0] WORD_IP_DST_HI = 8'd3;
    localparam [7:0] WORD_IP_DST_LO = 8'd4;

    // -------------------------------------------------------------------------
    // checksum precompute
    // kept only so structure stays intact; not used in this experiment
    // -------------------------------------------------------------------------

    localparam [15:0] OLD_UDP_DST_PORT = 16'd4791;
    localparam [15:0] NEW_UDP_DST_PORT = 16'd49112;

    localparam [15:0] CFH_W0 = LB_ID[31:16];
    localparam [15:0] CFH_W1 = LB_ID[15:0];
    localparam [15:0] CFH_W2 = RDMA_CONFIG[31:16];
    localparam [15:0] CFH_W3 = RDMA_CONFIG[15:0];
    localparam [15:0] CFH_W4 = HOST_ID[31:16];
    localparam [15:0] CFH_W5 = HOST_ID[15:0];
    localparam [15:0] CFH_W6 = {TTL, CFH_MSG};

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
        add1c16(PRECOMP_UDP_DELTA, 16'd14);

    localparam [4:0]
        IDLE                    = 5'd0,

        CHECK_PROT_NO           = 5'd1,
        CHECK_PROT_NO_WAIT      = 5'd2,

        CHECK_DEST_PORT         = 5'd3,
        CHECK_DEST_PORT_WAIT    = 5'd4,

        EDIT_IP_LEN             = 5'd5,
        EDIT_IP_LEN_WAIT        = 5'd6,

        EDIT_UDP_DEST_PORT      = 5'd7,
        EDIT_UDP_DEST_PORT_WAIT = 5'd8,

        EDIT_UDP_LEN            = 5'd9,
        EDIT_UDP_LEN_WAIT       = 5'd10,

        EDIT_IP_CKS             = 5'd11,
        EDIT_IP_CKS_WAIT        = 5'd12,

        EDIT_UDP_CKS            = 5'd13,
        EDIT_UDP_CKS_WAIT       = 5'd14,

        DONE                    = 5'd15,
        DROP_PKT                = 5'd16;

    reg [4:0] state;

    // -------------------------------------------------------------------------
    // reverse bits helpers
    // kept only because they existed in the module; not used for this experiment
    // -------------------------------------------------------------------------

    function automatic [15:0] reverse_bits_16;
        input [15:0] x;
    begin
        reverse_bits_16 = {
            x[0],  x[1],  x[2],  x[3],
            x[4],  x[5],  x[6],  x[7],
            x[8],  x[9],  x[10], x[11],
            x[12], x[13], x[14], x[15]
        };
    end
    endfunction

    function automatic [7:0] reverse_bits_8;
        input [7:0] x;
    begin
        reverse_bits_8 = {
            x[0], x[1], x[2], x[3],
            x[4], x[5], x[6], x[7]
        };
    end
    endfunction

    // -------------------------------------------------------------------------
    // local registers
    // -------------------------------------------------------------------------

    reg [3:0]  score;
    reg [15:0] old_bytes;
    reg [15:0] new_bytes;
    reg cfh_candidate;

    // extracted destination IP in normal byte order:
    // [31:24]=byte30, [23:16]=byte31, [15:8]=byte32, [7:0]=byte33
    reg [31:0] dst_ip_bytes;

    initial begin
        state            <= IDLE;
        score            <= 4'd6;

        r_add            <= 8'd0;
        w_add            <= 8'd0;
        data_in          <= 64'd0;
        write_en         <= 1'b0;

        drop_packet      <= 1'b0;
        valid            <= 1'b0;
        need_cfh_header  <= 1'b0;

        mod_beat_counter <= 8'd0;
        mod_last_tkeep   <= 8'd0;

        host_tel_data_A  <= 8'd0;
        host_tel_data_B  <= 32'd0;
        host_tel_data_C  <= 32'd0;

        old_bytes        <= 16'd0;
        new_bytes        <= 16'd0;

        cfh_candidate    <= 1'b0;
        dst_ip_bytes     <= 32'd0;
    end

    always @(posedge clk) begin
        if (rst) begin
            state            <= IDLE;
            score            <= 4'd6;

            r_add            <= 8'd0;
            w_add            <= 8'd0;
            data_in          <= 64'd0;
            write_en         <= 1'b0;

            drop_packet      <= 1'b0;
            valid            <= 1'b0;
            need_cfh_header  <= 1'b0;

            mod_beat_counter <= 8'd0;
            mod_last_tkeep   <= 8'd0;

            host_tel_data_A  <= 8'd0;
            host_tel_data_B  <= 32'd0;
            host_tel_data_C  <= 32'd0;

            old_bytes        <= 16'd0;
            new_bytes        <= 16'd0;

            cfh_candidate    <= 1'b0;
            dst_ip_bytes     <= 32'd0;
        end
        else begin
            // defaults each cycle
            write_en         <= 1'b0;
            valid            <= 1'b0;
            drop_packet      <= 1'b0;
            need_cfh_header  <= 1'b0;
            mod_beat_counter <= beat_counter;
            mod_last_tkeep   <= last_tkeep;

            case (state)

                IDLE: begin
                    if (start_analysis == 1) begin
                        state         <= CHECK_PROT_NO_WAIT;
                        r_add         <= WORD_IP_HDR0;
                        cfh_candidate <= 1'b0;
                        dst_ip_bytes  <= 32'd0;
                    end
                end

                // -------------------------------------------------------------
                // CHECK_PROT_NO
                // protocol byte is at bit offset 56 in word 2
                // -------------------------------------------------------------
                CHECK_PROT_NO_WAIT: begin
                    state <= CHECK_PROT_NO;
                end

                CHECK_PROT_NO: begin
                    if (data_out[56 +: 8] == 8'd17) begin
                        // UDP packet: first read word 3 to get bytes 30 and 31
                        r_add <= WORD_IP_DST_HI;
                        state <= CHECK_DEST_PORT_WAIT;
                    end
                    else begin
                        state <= DONE;
                    end
                end

                // -------------------------------------------------------------
                // CHECK_DEST_PORT
                // repurposed: extract destination IP bytes 30 and 31 from word 3
                // word 3 contains bytes 24..31
                // byte30 = data_out[48 +: 8]
                // byte31 = data_out[56 +: 8]
                // -------------------------------------------------------------
                CHECK_DEST_PORT_WAIT: begin
                    state <= CHECK_DEST_PORT;
                end

                CHECK_DEST_PORT: begin
                    dst_ip_bytes[31:24] <= data_out[48 +: 8];
                    dst_ip_bytes[23:16] <= data_out[56 +: 8];

                    // now read word 4 to get bytes 32 and 33
                    r_add <= WORD_IP_DST_LO;
                    state <= EDIT_IP_LEN_WAIT;
                end

                // -------------------------------------------------------------
                // EDIT_IP_LEN
                // repurposed: finish extracting destination IP bytes 32 and 33
                // word 4 contains bytes 32..39
                // byte32 = data_out[0 +: 8]
                // byte33 = data_out[8 +: 8]
                // -------------------------------------------------------------
                EDIT_IP_LEN_WAIT: begin
                    state <= EDIT_IP_LEN;
                end

                EDIT_IP_LEN: begin
                    dst_ip_bytes[15:8] <= data_out[0 +: 8];
                    dst_ip_bytes[7:0]  <= data_out[8 +: 8];

                    // now read the payload word so we can overwrite bytes 42..45
                    r_add <= WORD_UDP_PAY0;
                    state <= EDIT_UDP_DEST_PORT_WAIT;
                end

                // -------------------------------------------------------------
                // EDIT_UDP_DEST_PORT
                // repurposed: write destination IP bytes into payload bytes 42..45
                //
                // word 5 contains bytes 40..47
                // byte42 = data_out[23:16]
                // byte43 = data_out[31:24]
                // byte44 = data_out[39:32]
                // byte45 = data_out[47:40]
                //
                // Per your request:
                // - extract without reversing
                // - write without reversing
                // -------------------------------------------------------------
                EDIT_UDP_DEST_PORT_WAIT: begin
                    state <= EDIT_UDP_DEST_PORT;
                end

                EDIT_UDP_DEST_PORT: begin
                    data_in <= {
                        data_out[63:48],      // bytes 46,47 unchanged
                        dst_ip_bytes[7:0],    // byte45
                        dst_ip_bytes[15:8],   // byte44
                        dst_ip_bytes[23:16],  // byte43
                        dst_ip_bytes[31:24],  // byte42
                        data_out[15:0]        // bytes 40,41 unchanged
                    };

                    w_add    <= WORD_UDP_PAY0;
                    write_en <= 1'b1;

                    // keep remaining states in the FSM, but stale
                    state <= EDIT_UDP_LEN_WAIT;
                end

                // -------------------------------------------------------------
                // EDIT_UDP_LEN
                // stale in this experiment
                // -------------------------------------------------------------
                EDIT_UDP_LEN_WAIT: begin
                    state <= EDIT_UDP_LEN;
                end

                EDIT_UDP_LEN: begin
                    state <= EDIT_IP_CKS_WAIT;
                end

                // -------------------------------------------------------------
                // EDIT_IP_CKS
                // stale in this experiment
                // -------------------------------------------------------------
                EDIT_IP_CKS_WAIT: begin
                    state <= EDIT_IP_CKS;
                end

                EDIT_IP_CKS: begin
                    state <= EDIT_UDP_CKS_WAIT;
                end

                // -------------------------------------------------------------
                // EDIT_UDP_CKS
                // stale in this experiment
                // -------------------------------------------------------------
                EDIT_UDP_CKS_WAIT: begin
                    state <= EDIT_UDP_CKS;
                end

                EDIT_UDP_CKS: begin
                    state <= DONE;
                end

                // -------------------------------------------------------------
                // DONE
                // -------------------------------------------------------------
                DONE: begin
                    valid <= 1'b1;
                    need_cfh_header <= cfh_candidate;
                    state <= IDLE;
                end

                // -------------------------------------------------------------
                // DROP
                // -------------------------------------------------------------
                DROP_PKT: begin
                    drop_packet <= 1'b1;
                    valid       <= 1'b1;
                    state       <= IDLE;
                end

                default: begin
                    state <= IDLE;
                end
            endcase
        end
    end

endmodule