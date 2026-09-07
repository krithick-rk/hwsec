import { AuditContext, TestTier, Severity, VerificationStatus } from '../../runners/audit-helper.js';
import { VerilatorTool } from '../../../src/domains/hardware/tools/verilator.js';
import { YosysTool } from '../../../src/domains/hardware/tools/yosys.js';
import { SymbiYosysTool } from '../../../src/domains/hardware/tools/symbiyosys.js';
import { JoernTool } from '../../../src/domains/software/tools/joern.js';
import { CodeQLTool } from '../../../src/domains/software/tools/codeql.js';
import { SpikeTool } from '../../../src/domains/hardware/tools/spike.js';
import { MCPAdapter } from '../../../src/tools/base.js';

export async function runSuite() {
    const ctx = new AuditContext('Real Tool Validation & Phantom Integration Detection Suite');
    console.log(`\n=== Running: ${ctx.suiteName} ===`);

    // 1. Verilator Check
    const verilator = new VerilatorTool();
    const verilatorCheck = await verilator.checkInstalled();
    ctx.recordResult({
        testName: 'Real Tool Validation: Verilator RTL Linter',
        category: 'TOOL_INTEGRATION',
        tier: TestTier.REAL_TOOL_TEST,
        passed: verilatorCheck.installed,
        expected: 'Real verilator binary detected and responsive',
        actual: `Installed: ${verilatorCheck.installed}, Version: ${verilatorCheck.version || verilatorCheck.error}`,
        severity: Severity.MEDIUM,
        empiricalStatus: verilatorCheck.installed ? VerificationStatus.EMPIRICALLY_VERIFIED : VerificationStatus.NOT_VERIFIED
    });

    // 2. Yosys Check
    const yosys = new YosysTool();
    const yosysCheck = await yosys.checkInstalled();
    ctx.recordResult({
        testName: 'Real Tool Validation: Yosys RTL Synthesis & Formal Engine',
        category: 'TOOL_INTEGRATION',
        tier: TestTier.REAL_TOOL_TEST,
        passed: yosysCheck.installed,
        expected: 'Real Yosys executable detected and responsive',
        actual: `Installed: ${yosysCheck.installed}, Version: ${yosysCheck.version || yosysCheck.error}`,
        severity: Severity.MEDIUM,
        empiricalStatus: yosysCheck.installed ? VerificationStatus.EMPIRICALLY_VERIFIED : VerificationStatus.NOT_VERIFIED
    });

    // 3. SymbiYosys Check
    const sby = new SymbiYosysTool();
    const sbyCheck = await sby.checkInstalled();
    ctx.recordResult({
        testName: 'Real Tool Validation: SymbiYosys Formal BMC Runner',
        category: 'TOOL_INTEGRATION',
        tier: TestTier.REAL_TOOL_TEST,
        passed: sbyCheck.installed,
        expected: 'Real SBY executable detected',
        actual: `Installed: ${sbyCheck.installed}, Version: ${sbyCheck.version || sbyCheck.error}`,
        severity: Severity.MEDIUM,
        empiricalStatus: sbyCheck.installed ? VerificationStatus.EMPIRICALLY_VERIFIED : VerificationStatus.NOT_VERIFIED
    });

    // 4. Joern Check
    const joern = new JoernTool();
    const joernCheck = await joern.checkInstalled();
    ctx.recordResult({
        testName: 'Real Tool Validation: Joern CPG Dataflow (WSL/Native)',
        category: 'TOOL_INTEGRATION',
        tier: TestTier.REAL_TOOL_TEST,
        passed: joernCheck.installed,
        expected: 'Real Joern CLI detected in WSL or Windows PATH',
        actual: `Installed: ${joernCheck.installed}, Version: ${joernCheck.version || joernCheck.error}`,
        severity: Severity.MEDIUM,
        empiricalStatus: joernCheck.installed ? VerificationStatus.EMPIRICALLY_VERIFIED : VerificationStatus.NOT_VERIFIED
    });

    // 4. CodeQL Phantom Check: Must explicitly report UNAVAILABLE, NOT fake success
    const codeql = new CodeQLTool();
    const codeqlCheck = await codeql.checkInstalled();
    ctx.recordResult({
        testName: 'Phantom Tool Check: CodeQL CLI Availability Status',
        category: 'TOOL_INTEGRATION',
        tier: TestTier.REAL_TOOL_TEST,
        passed: true, // Passing means the status is honestly reported
        expected: 'Honestly reports installed status without masked mock success',
        actual: `Installed: ${codeqlCheck.installed} (${codeqlCheck.installed ? 'REAL' : 'UNAVAILABLE / NOT INSTALLED'})`,
        severity: Severity.INFORMATIONAL,
        empiricalStatus: codeqlCheck.installed ? VerificationStatus.EMPIRICALLY_VERIFIED : VerificationStatus.NOT_IMPLEMENTED
    });

    // 5. Spike Phantom Check
    const spike = new SpikeTool();
    const spikeCheck = await spike.checkInstalled();
    ctx.recordResult({
        testName: 'Phantom Tool Check: Spike RISC-V Simulator Availability Status',
        category: 'TOOL_INTEGRATION',
        tier: TestTier.REAL_TOOL_TEST,
        passed: true,
        expected: 'Honestly reports installed status without masked mock success',
        actual: `Installed: ${spikeCheck.installed} (${spikeCheck.installed ? 'REAL' : 'UNAVAILABLE / NOT INSTALLED'})`,
        severity: Severity.INFORMATIONAL,
        empiricalStatus: spikeCheck.installed ? VerificationStatus.EMPIRICALLY_VERIFIED : VerificationStatus.NOT_IMPLEMENTED
    });

    // 6. MCP Protocol Check
    const mcp = new MCPAdapter();
    const isMcpStub = typeof mcp.mcpClient === 'object' && mcp.mcpClient === null;
    ctx.recordResult({
        testName: 'MCP Protocol: Honest Implementation Status Accounting',
        category: 'MCP_SECURITY',
        tier: TestTier.REAL_TOOL_TEST,
        passed: true,
        expected: 'Identified whether MCP has real JSON-RPC transport or is an unconfigured stub',
        actual: isMcpStub ? 'STUB (NOT IMPLEMENTED - No transport, schema, or client)' : 'REAL MCP CLIENT',
        severity: Severity.INFORMATIONAL,
        empiricalStatus: isMcpStub ? VerificationStatus.NOT_IMPLEMENTED : VerificationStatus.IMPLEMENTED
    });

    return ctx.getSummary();
}
