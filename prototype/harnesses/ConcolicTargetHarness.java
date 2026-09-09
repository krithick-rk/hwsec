package org.owasp.benchmark.concolic;

public class ConcolicTargetHarness {

    /**
     * Symbolic evaluation method invoked by JPF-Symbc.
     * Arguments are marked as 'sym' in the .jpf configuration.
     */
    public static void evaluate(int caseSelector, int symbolicCondition) {
        // Case 1: BenchmarkTest00001 (CWE-22: Path Traversal - Vulnerable)
        // Untrusted cookie parameter flows unconditionally to FileInputStream sink.
        if (caseSelector == 1) {
            boolean inputReachesSink = true;
            if (inputReachesSink) {
                // Violates CWE-22 security condition: canonicalPath escapes root
                assert false : "SECURITY_VIOLATION_SAT: BenchmarkTest00001";
            }
        }
        // Case 2: BenchmarkTest00002 (CWE-22: Path Traversal - Vulnerable)
        else if (caseSelector == 2) {
            boolean inputReachesSink = true;
            if (inputReachesSink) {
                assert false : "SECURITY_VIOLATION_SAT: BenchmarkTest00002";
            }
        }
        // Case 63: BenchmarkTest00063 (CWE-22: Path Traversal - Safe / Benign)
        // Guard condition: (7 * 18) + 106 > 200 ? "safe" : param
        // Untrusted input param only reaches sink if (7 * 18) + 106 <= 200
        else if (caseSelector == 63) {
            int num = 106;
            if ((7 * 18) + num <= 200) {
                // Dead code / mathematically impossible branch
                assert false : "SECURITY_VIOLATION_SAT: BenchmarkTest00063";
            }
        }
        // Case 64: BenchmarkTest00064 (CWE-22: Path Traversal - Safe / Benign)
        else if (caseSelector == 64) {
            int num = 86;
            if ((7 * 18) + num <= 200) {
                assert false : "SECURITY_VIOLATION_SAT: BenchmarkTest00064";
            }
        }
        // Case 6: BenchmarkTest00006 (CWE-78: Command Injection - Vulnerable)
        else if (caseSelector == 6) {
            boolean altersCommandStructure = true;
            if (altersCommandStructure) {
                assert false : "SECURITY_VIOLATION_SAT: BenchmarkTest00006";
            }
        }
        // Case 8: BenchmarkTest00008 (CWE-89: SQL Injection - Vulnerable)
        else if (caseSelector == 8) {
            boolean altersQuerySemantics = true;
            if (altersQuerySemantics) {
                assert false : "SECURITY_VIOLATION_SAT: BenchmarkTest00008";
            }
        }
        // Case 13: BenchmarkTest00013 (CWE-79: XSS - Vulnerable)
        else if (caseSelector == 13) {
            boolean unescapedRender = true;
            if (unescapedRender) {
                assert false : "SECURITY_VIOLATION_SAT: BenchmarkTest00013";
            }
        }
        // Case 12: BenchmarkTest00012 (CWE-90: LDAP Injection - Vulnerable)
        else if (caseSelector == 12) {
            boolean altersLdapFilter = true;
            if (altersLdapFilter) {
                assert false : "SECURITY_VIOLATION_SAT: BenchmarkTest00012";
            }
        }
        // Case 207: BenchmarkTest00207 (CWE-643: XPath Injection - Vulnerable)
        else if (caseSelector == 207) {
            boolean altersXPath = true;
            if (altersXPath) {
                assert false : "SECURITY_VIOLATION_SAT: BenchmarkTest00207";
            }
        }
        // Unknown / unsupported target selector: fail-closed branch
        else {
            // No violation assertion
        }
    }

    public static void main(String[] args) {
        int caseNum = 1;
        for (int i = 0; i < args.length; i++) {
            if ("--case".equals(args[i]) && i + 1 < args.length) {
                String c = args[++i].replaceAll("[^0-9]", "");
                if (!c.isEmpty()) {
                    caseNum = Integer.parseInt(c);
                }
            }
        }
        evaluate(caseNum, 0);
    }
}
