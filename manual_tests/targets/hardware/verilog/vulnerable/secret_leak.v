module secret_leak (
    input wire clk,
    input wire rst,
    input wire [31:0] secret_key,
    input wire debug_mode,
    output reg [31:0] bus_data
);

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            bus_data <= 32'h0;
        end else if (debug_mode) begin
            // Unprotected leak of internal secret key over public debug bus
            bus_data <= secret_key;
        end else begin
            bus_data <= 32'hDEADBEEF;
        end
    end
endmodule
