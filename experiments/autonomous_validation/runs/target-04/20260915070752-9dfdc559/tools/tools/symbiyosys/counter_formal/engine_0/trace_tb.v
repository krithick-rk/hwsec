`ifndef VERILATOR
module testbench;
  reg [4095:0] vcdfile;
  reg clock;
`else
module testbench(input clock, output reg genclock);
  initial genclock = 1;
`endif
  reg genclock = 1;
  reg [31:0] cycle = 0;
  reg [0:0] PI_reset;
  wire [0:0] PI_clk = clock;
  reg [7:0] PI_data_in;
  counter UUT (
    .reset(PI_reset),
    .clk(PI_clk),
    .data_in(PI_data_in)
  );
`ifndef VERILATOR
  initial begin
    if ($value$plusargs("vcd=%s", vcdfile)) begin
      $dumpfile(vcdfile);
      $dumpvars(0, testbench);
    end
    #5 clock = 0;
    while (genclock) begin
      #5 clock = 0;
      #5 clock = 1;
    end
  end
`endif
  initial begin
`ifndef VERILATOR
    #1;
`endif
    // UUT.$auto$async2sync.\cc:107:execute$12  = 1'b0;
    // UUT.$auto$async2sync.\cc:116:execute$16  = 1'b1;
    UUT.data_out = 8'b11111111;

    // state 0
    PI_reset = 1'b0;
    PI_data_in = 8'b00000000;
  end
  always @(posedge clock) begin
    // state 1
    if (cycle == 0) begin
      PI_reset <= 1'b0;
      PI_data_in <= 8'b00000000;
    end

    genclock <= cycle < 1;
    cycle <= cycle + 1;
  end
endmodule
