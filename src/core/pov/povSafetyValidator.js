/**
 * HWSEC PoV Subsystem - Safety Validator
 * 
 * Enforces Sections 7 & 25 (Safe PoV Boundary and Security Review):
 * Rejects weaponized exploits, reverse shells, external callbacks,
 * destructive commands, persistence, and credential theft.
 */

export class PovSafetyValidator {
    /**
     * Inspects a candidate PoV proposal, script content, or execution command.
     * @param {Object} proposal
     * @param {string} [proposal.command]
     * @param {string} [proposal.scriptContent]
     * @param {string} [proposal.payload]
     * @returns {{ safe: boolean, violations: string[] }}
     */
    static validate(proposal = {}) {
        const violations = [];
        const stringifyVal = (v) => {
            if (!v) return '';
            if (typeof v === 'object') return JSON.stringify(v);
            return String(v);
        };
        const textToScan = [
            stringifyVal(proposal.command),
            stringifyVal(proposal.scriptContent),
            stringifyVal(proposal.payload),
            stringifyVal(proposal.witness_input)
        ].join('\n');

        // 1. Block Reverse Shells & Remote Connect-Backs
        const reverseShellPatterns = [
            /(?:bash|sh|zsh)\s+-i/i,
            /\/bin\/(?:ba)?sh['"]?,\s*['"]-i/i,
            /\/dev\/tcp\/[^\s/]+/i,
            /\b(nc|ncat|netcat|socat)\b.*(\s+-e|\s+-c|\s+\d{1,5}\b)/i,
            /socket\.connect\(/i,
            /powershell.*(-enc|-encodedcommand|downloadstring|iex\(|invoke-expression)/i,
            /\bmkfifo\b.*\/tmp/i,
            /0<&\d+;?\s*exec/i
        ];
        for (const p of reverseShellPatterns) {
            if (p.test(textToScan)) {
                violations.push(`Reverse shell or interactive remote shell construct detected: ${p.toString()}`);
            }
        }

        // 2. Block Outbound Arbitrary Network Access (Permit localhost only)
        const externalNetworkPatterns = [
            /https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i,
            /\b(ftp|ssh|telnet|tftp)\s+[^\s]+/i,
            /\b(curl|wget)\s+(?!.*(localhost|127\.0\.0\.1|0\.0\.0\.0))/i
        ];
        for (const p of externalNetworkPatterns) {
            if (p.test(textToScan)) {
                violations.push(`Outbound external network connection detected: ${p.toString()}`);
            }
        }

        // 3. Block Destructive Filesystem Operations
        const destructivePatterns = [
            /\brm\s+(-rf|-fr|--recursive)\s+(\/|~|\$HOME|\.\.)/i,
            /\b(mkfs|dd\s+if=.*of=\/dev|format\s+[a-z]:)/i,
            /\bchmod\s+(-R\s+)?777\s+\//i,
            />\s*\/dev\/([sh]d[a-z]|nvme)/i
        ];
        for (const p of destructivePatterns) {
            if (p.test(textToScan)) {
                violations.push(`Destructive filesystem operation detected: ${p.toString()}`);
            }
        }

        // 4. Block Credential Theft & Persistence
        const credentialAndPersistencePatterns = [
            /\/etc\/(shadow|gshadow)/i,
            /\b(id_rsa|id_ed25519|authorized_keys)\b/i,
            /\/var\/spool\/cron/i,
            /\/etc\/crontab/i,
            /reg\s+add\s+HK(LM|CU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i
        ];
        for (const p of credentialAndPersistencePatterns) {
            if (p.test(textToScan)) {
                violations.push(`Credential harvesting or persistence construct detected: ${p.toString()}`);
            }
        }

        return {
            safe: violations.length === 0,
            violations
        };
    }

    /**
     * Checks if a command injection PoV adheres to the controlled side-effect principle.
     * (E.g. creating a local temporary marker file instead of running arbitrary payloads)
     */
    static sanitizeCommandInjectionPayload(targetTempDir, markerName = 'hwsec_pov_marker.tmp') {
        const markerPath = `${targetTempDir}/${markerName}`.replace(/\\/g, '/');
        return {
            safePayload: `; touch ${markerPath} || echo marker > ${markerPath}`,
            markerPath,
            verificationCheck: (fsModule) => fsModule.existsSync(markerPath)
        };
    }
}
