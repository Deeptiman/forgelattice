`include "const.v"

module key_expand(
 input  wire clk,
 input  wire rst_n,
 input  wire start,  // single-cycle start pulse
 input  wire [127:0] master_key, // 128-bit master key
 output reg [127:0] round_key [0:10], // 11 round keys (Round 0 to 10)
 output reg done
);

    reg [31:0] w [0:43]; // 44 words (11 round keys x 4 words)
    reg [5:0] i;
    reg [2:0] state;

    wire [31:0] temp_rot;
    wire [31:0] temp_sub;
    wire [31:0] temp_rcon;
    wire [31:0] new_key_word;

    aes_const const_inst();

    assign temp_rot = {w[i-1][23:0], w[i-1][31:24]};

    assign temp_sub[31:24] = const_inst.aes_sbox(temp_rot[31:24]);
    assign temp_sub[23:16] = const_inst.aes_sbox(temp_rot[23:16]);
    assign temp_sub[15:8]  = const_inst.aes_sbox(temp_rot[15:8]);
    assign temp_sub[7:0]   = const_inst.aes_sbox(temp_rot[7:0]);

    assign temp_rcon = const_inst.Rcon[(i/4)-1];

    assign new_key_word = ((i%4) == 0) ? (temp_sub ^ temp_rcon) : w[i-1];

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            done <= 1'b0;
            i <= 6'd0;
            state <= 3'd0;
        end else begin
            case (state)
                0: begin // Load master key
                    if (start) begin
                        done <= 1'b0;
                        w[0] <= master_key[127:96];
                        w[1] <= master_key[95:64];
                        w[2] <= master_key[63:32];
                        w[3] <= master_key[31:0];
                        round_key[0] <= master_key;
                        i <= 6'd4;
                        state <= 1;
                    end
                end
                1: begin // Key expansion
                    if (i < 44) begin
                        w[i] <= new_key_word ^ w[i-4];
                        i <= i + 1;
                    end else begin
                        // Store all 11 round keys
                        for (integer j = 0; j< 11; j = j+1)
                            round_key[j] <= {w[j*4], w[j*4+1], w[j*4+2], w[j*4+3]};
                        done <= 1'b1;
                        state <= 0;
                    end
                end
            endcase
        end
    end

endmodule