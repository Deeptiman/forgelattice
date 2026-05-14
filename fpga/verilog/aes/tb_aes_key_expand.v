`timescale 1ns/1ps

module tb_aes_key_expand;

// Inputs
reg clk;
reg rst_n;
reg start;
reg [127:0] master_key;

// Outputs
wire [127:0] round_key [0:10];
wire done;

// Instantiate the Key Expansion module
key_expand dut(
    .clk                (clk),
    .rst_n              (rst_n),
    .start              (start),
    .master_key         (master_key),
    .round_key          (round_key),
    .done               (done)
);

// Clock generation (100 MHz)
initial begin
    clk = 0;
    forever #5 clk = ~clk; // 10 ns period
end

// Test vector (NIST standard AES-128 key)
// localparam [127:0] TEST_KEY = 128'h2b7e151628aed2a6abf7158809cf4f3c;

reg [127:0] test_keys [0:3];

initial begin
    // Test Vector 1 (NIST standard)
    test_keys[0] = 128'h2b7e151628aed2a6abf7158809cf4f3c;

    // Test Vector 2
    test_keys[1] = 128'h000102030405060708090a0b0c0d0e0f;

    // Test Vector 3
    test_keys[2] = 128'h603deb1015ca71be2b73aef0857d7781;

    // Test Vector 4
    test_keys[3] = 128'h8e73b0f7da0e6452c810f32b809079e5;

    $display("=== AES-128 Key Expansion Multi-Key Testbench Started ===");

    rst_n = 0;
    start = 0;
    master_key = 0;

    #20 rst_n = 1;

    for (int i = 0; i< 4; i = i+1) begin
        // Apply test key
        master_key = test_keys[i];

        // Start expansion
        #20 start = 1;
        #10 start = 0;

        // Wait for done
        wait(done == 1);

        // Print first 4 round keys as example
        $display("Round 0: %h", round_key[0]);
        $display("Round 1: %h", round_key[1]);
        $display("Round 2: %h", round_key[2]);
        $display("Round 3: %h", round_key[3]);

        #50; // Small delay before next key
    end

    $display("=== Testbench Finished ===");
    $finish;
end

// Optional: Dump waveform
initial begin
    $dumpfile("tb_aes_key_expand.vcd");
    $dumpvars(0, tb_aes_key_expand);
end

endmodule