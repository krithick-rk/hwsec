module test_formal(
    input clk,
    input reset,
    input [7:0] data_in,
    output reg [7:0] data_out
);
    always @(posedge clk) begin
        if (reset)
            data_out <= 8'h00;
        else
            data_out <= data_in;
    end

`ifdef FORMAL
    always @(posedge clk) begin
        // Flawed invariant to trigger counterexample: data_out should never be 8'hFF
        if (!reset)
            assert(data_out != 8'hFF);
    end
`endif

endmodule
