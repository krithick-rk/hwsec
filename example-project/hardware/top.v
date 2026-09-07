module top (
    input  wire clk,
    input  wire rst,
    input  wire [15:0] data_in,
    output reg  [15:0] data_out
);
    reg [2:0] state;
    always @(posedge clk) begin
        if (rst) begin
            data_out <= 0;
            state <= 0;
        end else begin
            data_out <= data_in;
            if (state == 0 && data_in == 16'hDEAD) state <= 1;
            else if (state == 1 && data_in == 16'hBEEF) state <= 2;
            else if (state == 2 && data_in == 16'hCAFE) begin
                state <= 3;
                $fatal(1, "Crash sequence triggered!");
            end
        end
    end
endmodule
