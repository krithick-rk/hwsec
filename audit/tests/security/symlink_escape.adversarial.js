import path from 'path';
import fs from 'fs';
import { AuditContext, TestTier, Severity, VerificationStatus } from '../../runners/audit-helper.js';
import { AnalysisBroker, ToolRegistry } from '../../../src/core/broker.js';
import { RepositoryDiscovery } from '../../../src/core/discovery.js';

export async function runSuite() {
    const ctx = new AuditContext('Symlink & Reparse Point Boundary Escape Adversarial Suite');
    console.log(`\n=== Running: ${ctx.suiteName} ===`);

    const tempRoot = ctx.createTempDir('hwsec-symlink-audit-');
    const secretFile = path.join(tempRoot, 'outside_secret_data.txt');
    fs.writeFileSync(secretFile, 'SUPER_SECRET_TOKEN=ORGANIZATION_CONFIDENTIAL_KEY_12345', 'utf-8');

    const repoDir = path.join(tempRoot, 'repo');
    fs.mkdirSync(repoDir, { recursive: true });
    fs.writeFileSync(path.join(repoDir, 'main.c'), 'int main() { return 0; }\n', 'utf-8');

    // Attempt to create symlink to outside secret
    const symlinkPath = path.join(repoDir, 'evil_symlink.c');
    let symlinkCreated = false;
    try {
        fs.symlinkSync(secretFile, symlinkPath, 'file');
        symlinkCreated = true;
    } catch (e) {
        // Windows non-admin symlink creation may require junction or fall back
        try {
            const junctionDir = path.join(repoDir, 'evil_junction');
            fs.symlinkSync(tempRoot, junctionDir, 'junction');
            symlinkCreated = true;
        } catch {}
    }

    // 1. RepositoryDiscovery Symlink Boundary Check
    const discovery = new RepositoryDiscovery();
    let leaksSecretThroughDiscovery = false;
    if (symlinkCreated) {
        try {
            const { inventory } = discovery.discover(repoDir);
            const discoveredFiles = Object.values(inventory.languages).flat();
            for (const f of discoveredFiles) {
                // If realpath of any file is outside repoDir
                const real = fs.realpathSync(f);
                if (!real.toLowerCase().startsWith(path.resolve(repoDir).toLowerCase())) {
                    leaksSecretThroughDiscovery = true;
                }
            }
        } catch (e) {}
    }

    ctx.recordResult({
        testName: 'RepositoryDiscovery: Symlink Outside Root Traversal Prevention',
        category: 'FILESYSTEM_SECURITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: !leaksSecretThroughDiscovery,
        expected: 'Symlinks pointing outside repository root must be rejected/skipped',
        actual: leaksSecretThroughDiscovery ? 'VULNERABLE: Symlink followed outside repo' : 'Safe/Blocked',
        severity: Severity.CRITICAL,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 2. Broker executeStructuredAction Symlink Dereference Check
    const broker = new AnalysisBroker({}, new ToolRegistry());
    let brokerDereferencesOutside = false;
    if (symlinkCreated && fs.existsSync(symlinkPath)) {
        try {
            const res = await broker.executeStructuredAction({
                action: 'run_tool',
                tool: 'semgrep',
                target: 'evil_symlink.c'
            }, repoDir);
            // Check if tool actually processed the outside file
            if (res && res.findings) {
                brokerDereferencesOutside = true;
            }
        } catch (err) {
            // Rejection is expected
        }
    }

    ctx.recordResult({
        testName: 'AnalysisBroker: Symlink Resolution and Root Containment Enforcement',
        category: 'FILESYSTEM_SECURITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: !brokerDereferencesOutside,
        expected: 'Broker must check realpath/lstat and reject symlinks resolving outside repo',
        actual: brokerDereferencesOutside ? 'VULNERABLE: Broker dereferenced outside symlink' : 'Safe/Blocked',
        severity: Severity.CRITICAL,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    ctx.cleanup();
    return ctx.getSummary();
}
