import fs from 'fs';

export function generateHarness(headerPath) {
    if (!fs.existsSync(headerPath)) return "";

    const content = fs.readFileSync(headerPath, 'utf-8');
    const lines = content.split('\n');

    let clkPort = null;
    let rstPort = null;
    let isRstActiveLow = false;
    
    let inputs = [];

    const inRegex = /^\s*VL_IN(8|16|64|W)?\(&([a-zA-Z0-9_]+),\s*(\d+),\s*(\d+)(?:,\s*(\d+))?\);/;

    for (const line of lines) {
        const match = line.match(inRegex);
        if (match) {
            const type = match[1] || '32'; // empty means VL_IN which is uint32_t
            const name = match[2];
            const msb = parseInt(match[3]);
            const lsb = parseInt(match[4]);
            const words = match[5] ? parseInt(match[5]) : 0;
            
            let byteSize = 0;
            let isArray = false;
            
            if (type === '8') byteSize = 1;
            else if (type === '16') byteSize = 2;
            else if (type === '32') byteSize = 4;
            else if (type === '64') byteSize = 8;
            else if (type === 'W') {
                byteSize = words * 4;
                isArray = true;
            }

            const lowerName = name.toLowerCase();
            if (lowerName === 'clk' || lowerName === 'clock') {
                clkPort = name;
            } else if (lowerName === 'rst' || lowerName === 'reset') {
                rstPort = name;
                isRstActiveLow = false;
            } else if (lowerName === 'rst_n' || lowerName === 'reset_n' || lowerName === 'resetn') {
                rstPort = name;
                isRstActiveLow = true;
            } else {
                inputs.push({ name, byteSize, isArray });
            }
        }
    }

    let code = `#include "Vtop.h"
#include "verilated.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Override vl_fatal to abort() so AFL++ catches Verilog assertions
void vl_fatal(const char* filename, int linenum, const char* hier, const char* msg) {
    Verilated::fatalOnVpiError();
    abort();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    
    Verilated::commandArgs(0, (const char**)nullptr);
    Verilated::fatalOnError(false);
    
    Vtop* top = new Vtop;
`;

    if (rstPort) {
        code += `    // Reset sequence\n`;
        code += `    top->${rstPort} = ${isRstActiveLow ? '0' : '1'};\n`;
        if (clkPort) {
            code += `    top->${clkPort} = 0; top->eval();\n`;
            code += `    top->${clkPort} = 1; top->eval();\n`;
        } else {
            code += `    top->eval();\n`;
        }
        code += `    top->${rstPort} = ${isRstActiveLow ? '1' : '0'};\n`;
    }

    code += `    size_t ptr = 0;\n`;
    
    if (clkPort) {
        code += `    // Multi-cycle evaluation\n`;
        code += `    while (ptr < size) {\n`;
        
        for (const inp of inputs) {
            if (inp.isArray) {
                code += `        if (ptr + ${inp.byteSize} <= size) { memcpy(top->${inp.name}, data + ptr, ${inp.byteSize}); ptr += ${inp.byteSize}; } else break;\n`;
            } else {
                code += `        if (ptr + ${inp.byteSize} <= size) { memcpy(&top->${inp.name}, data + ptr, ${inp.byteSize}); ptr += ${inp.byteSize}; } else break;\n`;
            }
        }
        
        code += `        top->${clkPort} = 0; top->eval();\n`;
        code += `        top->${clkPort} = 1; top->eval();\n`;
        code += `    }\n`;
    } else {
        code += `    // Combinational evaluation\n`;
        for (const inp of inputs) {
            if (inp.isArray) {
                code += `    if (ptr + ${inp.byteSize} <= size) { memcpy(top->${inp.name}, data + ptr, ${inp.byteSize}); ptr += ${inp.byteSize}; }\n`;
            } else {
                code += `    if (ptr + ${inp.byteSize} <= size) { memcpy(&top->${inp.name}, data + ptr, ${inp.byteSize}); ptr += ${inp.byteSize}; }\n`;
            }
        }
        code += `    top->eval();\n`;
    }

    code += `    delete top;\n    return 0;\n}\n`;
    return code;
}
