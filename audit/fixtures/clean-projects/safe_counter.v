// Clean 8-bit synchronous counter with asynchronous active-high reset
module safe_counter (
    input wire clk,
    input wire rst,
    input wire enable,
    output reg [7:0] count
);
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            count <= 8'd0;
        end else if (enable) begin
            count <= count + 8'd1;
        end
    end
endmodule
