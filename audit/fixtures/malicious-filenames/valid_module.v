// Harmless Verilog dummy module for injection testing
module test_module (
    input clk,
    input rst,
    output reg [7:0] out
);
    always @(posedge clk or posedge rst) begin
        if (rst)
            out <= 8'h00;
        else
            out <= out + 1'b1;
    end
endmodule
