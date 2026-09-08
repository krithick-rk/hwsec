import { SymbiYosysTool } from './src/domains/hardware/tools/symbiyosys.js';
import path from 'path';

(async () => {
    const s = new SymbiYosysTool();
    const result = await s.run({
        files: ['quality-benchmark/hardware/verification-benchmarks/design.v'],
        outputDir: 'test-symbiyosys',
        timeout: 10000
    });
    console.log(result);
})();
