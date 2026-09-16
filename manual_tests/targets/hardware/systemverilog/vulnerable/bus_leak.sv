interface bus_if (input logic clk);
    logic [31:0] secret_reg;
    logic [31:0] data_out;
    logic debug_en;

    modport target (
        input clk, secret_reg, debug_en,
        output data_out
    );
endinterface

module bus_leak (bus_if.target bus);
    always_ff @(posedge bus.clk) begin
        if (bus.debug_en)
            bus.data_out <= bus.secret_reg; // Leak secret register over interface
        else
            bus.data_out <= 32'h0;
    end
endmodule
