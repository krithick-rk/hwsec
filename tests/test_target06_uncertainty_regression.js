import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { VulnerabilityHypothesis } from '../src/core/hypothesis/vulnerabilityHypothesis.js';
import { EvidenceDag, EvidenceAuthority, EvidenceNodeType } from '../src/core/bep/evidenceDag.js';

console.log('=====================================================');
console.log('   HWSEC TARGET-06 AMBIGUITY & UNCERTAINTY TEST      ');
console.log('=====================================================\n');

// 1. Verify Target-06 Semantics
// Target-06: Profile update logging username and bio length.
// Inspection shows:
// - logging.info(...)
// - No dangerous sink (no os.system, no subprocess, no eval, no SQL)
// - Returning dictionary
// In HWSEC, when zero dangerous sinks exist in the candidate path,
// the system must NOT fabricate a candidate or inconclusive finding:
// the final operational verdict is NOT_DETECTED (zero false positive).

const target06Path = path.resolve('experiments/autonomous_validation/targets/ambiguous/target-06/app.py');
assert.ok(fs.existsSync(target06Path), 'target-06/app.py must exist');

const content = fs.readFileSync(target06Path, 'utf-8');
assert.ok(!content.includes('os.system') && !content.includes('subprocess') && !content.includes('eval'), 
    'Target-06 must have no dangerous execution sinks');

console.log('[+] Confirmed: Target-06 contains no security sinks.');

// 2. Uncertainty Regression Check:
// If a hypothesis has an unresolved dangerous sink without an observed witness,
// EvidenceAuthority MUST reduce to INCONCLUSIVE (never collapse to NOT_DETECTED).
const ambiguousWithSinkHyp = new VulnerabilityHypothesis({
    id: 'HYP-UNCERTAIN-01',
    cwe: 'CWE-78',
    file: 'app.py',
    source: 'user_input',
    sink: 'os.system(user_input)',
    security_condition: 'Command injection condition unproven'
});

const dag = new EvidenceDag({ run_id: 'RUN-UNCERTAINTY-01' });
dag.addNode(EvidenceNodeType.HYPOTHESIS, ambiguousWithSinkHyp.toJSON(), ambiguousWithSinkHyp.id);

const reduction = EvidenceAuthority.reduce(dag, ambiguousWithSinkHyp.id);
console.log(`  -> Unresolved candidate with dangerous sink reduction verdict: ${reduction.verdict}`);
assert.strictEqual(reduction.verdict, 'INCONCLUSIVE', 
    'Hypothesis with an unresolved security sink MUST remain INCONCLUSIVE, not NOT_DETECTED');

console.log('\n[+] TARGET-06 AMBIGUITY & UNCERTAINTY SEMANTICS VERIFIED SUCCESSFULLY!\n');
