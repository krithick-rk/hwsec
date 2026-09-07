import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

export const TestTier = {
    UNIT_TEST: 'UNIT TEST',
    INTEGRATION_TEST: 'INTEGRATION TEST',
    ADVERSARIAL_TEST: 'ADVERSARIAL TEST',
    REAL_TOOL_TEST: 'REAL TOOL TEST',
    END_TO_END_TEST: 'END-TO-END TEST',
    PERFORMANCE_TEST: 'PERFORMANCE TEST',
    REGRESSION_TEST: 'REGRESSION TEST'
};

export const VerificationStatus = {
    IMPLEMENTED: 'IMPLEMENTED',
    TESTED: 'TESTED',
    EMPIRICALLY_VERIFIED: 'EMPIRICALLY VERIFIED',
    NOT_VERIFIED: 'NOT VERIFIED',
    NOT_IMPLEMENTED: 'NOT IMPLEMENTED'
};

export const Severity = {
    CRITICAL: 'CRITICAL',
    HIGH: 'HIGH',
    MEDIUM: 'MEDIUM',
    LOW: 'LOW',
    INFORMATIONAL: 'INFORMATIONAL'
};

export class AuditContext {
    constructor(suiteName, options = {}) {
        this.suiteName = suiteName;
        this.options = options;
        this.results = [];
        this.startTime = Date.now();
        this.tempDirs = [];
    }

    createTempDir(prefix = 'hwsec-audit-') {
        const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
        this.tempDirs.push(tmp);
        return tmp;
    }

    cleanup() {
        for (const dir of this.tempDirs) {
            try {
                if (fs.existsSync(dir)) {
                    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
                }
            } catch {}
        }
    }

    recordResult({
        testName,
        category,
        tier = TestTier.ADVERSARIAL_TEST,
        passed,
        expected,
        actual,
        severity = Severity.HIGH,
        empiricalStatus = VerificationStatus.EMPIRICALLY_VERIFIED,
        reproductionArtifact = null,
        details = null
    }) {
        const item = {
            suite: this.suiteName,
            testName,
            category,
            tier,
            passed: !!passed,
            expected: String(expected),
            actual: String(actual),
            severity,
            empiricalStatus,
            reproductionArtifact,
            details,
            timestamp: new Date().toISOString()
        };
        this.results.push(item);
        
        const badge = passed ? '\x1b[32m[PASS]\x1b[0m' : '\x1b[31m[FAIL]\x1b[0m';
        const tierBadge = `\x1b[36m[${tier}]\x1b[0m`;
        console.log(`  ${badge} ${tierBadge} ${testName} (${category})`);
        if (!passed) {
            console.log(`     -> Expected: ${expected}`);
            console.log(`     -> Actual:   ${actual}`);
            if (details) console.log(`     -> Details:  ${details}`);
        }
        return item;
    }

    getSummary() {
        const total = this.results.length;
        const passed = this.results.filter(r => r.passed).length;
        const failed = total - passed;
        const durationMs = Date.now() - this.startTime;
        return {
            suite: this.suiteName,
            total,
            passed,
            failed,
            durationMs,
            results: this.results
        };
    }
}
