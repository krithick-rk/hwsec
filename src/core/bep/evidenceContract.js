/**
 * HWSEC Machine-Readable Evidence Contracts
 * 
 * Defines formal security condition requirements for proof verification
 * across supported CWE categories and hardware security properties.
 * 
 * Each contract establishes:
 * - Attacker boundary & input source
 * - Taint/input transformation path
 * - Sanitization / validation checks
 * - Execution sink
 * - Exact security condition that constitutes a true vulnerability
 * - Expected positive & negative control probes
 * - Deterministic proof oracle
 * - Known false-positive patterns to reject
 */

export const EvidenceContracts = {
    'CWE-22': {
        cwe: 'CWE-22',
        name: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
        attackerSourceBoundary: 'HTTP_REQUEST_PARAMETER_OR_HEADER_OR_COOKIE',
        taintInputOrigin: 'request.getParameter / getCookies / getHeader',
        transformationPath: 'Direct string concatenation into File or FileInputStream path argument',
        sanitizationValidationChecks: [
            'File.getCanonicalPath prefix check against root',
            'Filename whitelist or strict basename extraction',
            'ESAPI canonicalization and path validation'
        ],
        sink: 'java.io.File, java.io.FileInputStream, java.io.FileOutputStream, java.nio.file.Paths',
        securityCondition: 'attacker_path_resolves_outside_root',
        expectedImpactSignal: 'CANONICAL_PATH_ESCAPE_OUTSIDE_ROOT',
        positiveProbe: '../../../../etc/passwd',
        negativeControlProbe: 'safe_document.txt',
        proofOracle: 'CANONICAL_PATH_ESCAPE_ORACLE',
        acceptableDeterministicEvidence: [
            'Runtime proof confirms canonical file path escapes base directory boundary',
            'Filesystem read/write target is outside authorized sandbox root'
        ],
        knownFalsePositiveConditions: [
            'Input is wrapped in new File(param).getName() before path concatenation',
            'Canonical path prefix check strictly aborts on directory escape',
            'Hardcoded constant string path used instead of request parameter'
        ]
    },

    'CWE-78': {
        cwe: 'CWE-78',
        name: 'Improper Neutralization of Special Elements used in an OS Command (Command Injection)',
        attackerSourceBoundary: 'HTTP_REQUEST_PARAMETER_OR_HEADER_OR_COOKIE',
        taintInputOrigin: 'request.getParameter / getCookies / getHeader',
        transformationPath: 'Concatenation into command string executed by shell',
        sanitizationValidationChecks: [
            'Use of fixed argument array ProcessBuilder(cmd, arg1, arg2) without shell',
            'Strict alphanumeric regex whitelisting',
            'Command execution authorization check'
        ],
        sink: 'Runtime.getRuntime().exec, ProcessBuilder.start',
        securityCondition: 'attacker_modifies_command_tokens_or_shell_control_flow',
        expectedImpactSignal: 'COMMAND_ARGUMENT_OR_SYNTAX_ALTERATION',
        positiveProbe: 'echo hwsec_pwned; id',
        negativeControlProbe: 'benign_single_argument_value',
        proofOracle: 'PROCESS_EXECUTION_SEMANTICS_ORACLE',
        acceptableDeterministicEvidence: [
            'Intercepted command execution shows injected shell control operators (;, |, &, `)',
            'Injected command token executes outside argument position'
        ],
        knownFalsePositiveConditions: [
            'Command executes with safe argument array where input is strictly one data argument',
            'String constant passed to exec without parameter taint',
            'Strict validation throws exception prior to ProcessBuilder invocation'
        ]
    },

    'CWE-89': {
        cwe: 'CWE-89',
        name: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
        attackerSourceBoundary: 'HTTP_REQUEST_PARAMETER_OR_HEADER_OR_COOKIE',
        taintInputOrigin: 'request.getParameter / getCookies / getHeader',
        transformationPath: 'Direct string concatenation into SQL query statement',
        sanitizationValidationChecks: [
            'PreparedStatement with parameter binding (? placeholder)',
            'Hibernate / JPA named parameter binding',
            'Integer/Numeric type casting prior to query formatting'
        ],
        sink: 'Statement.executeQuery, Statement.executeUpdate, Connection.prepareStatement, JdbcTemplate.query',
        securityCondition: 'attacker_input_alters_sql_ast_or_statement_structure',
        expectedImpactSignal: 'SQL_SYNTAX_TREE_MUTATION_CONFIRMED',
        positiveProbe: "admin' OR '1'='1' --",
        negativeControlProbe: "benign_search_term",
        proofOracle: 'SQL_GRAMMAR_ALTERATION_ORACLE',
        acceptableDeterministicEvidence: [
            'Intercepted SQL text contains unescaped injection probe modifying WHERE or SELECT structure',
            'Probe breaks out of literal string delimiter and adds boolean logic or UNION'
        ],
        knownFalsePositiveConditions: [
            'Query uses PreparedStatement where input is bound via setString/setInt to ? parameter',
            'Input is assigned a constant default value due to boolean guard condition',
            'Strict whitelist validation ensures input is purely numeric'
        ]
    },

    'CWE-79': {
        cwe: 'CWE-79',
        name: 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)',
        attackerSourceBoundary: 'HTTP_REQUEST_PARAMETER_OR_HEADER_OR_COOKIE',
        taintInputOrigin: 'request.getParameter / getCookies / getHeader',
        transformationPath: 'Reflection into HTML/DOM response stream',
        sanitizationValidationChecks: [
            'ESAPI.encoder().encodeForHTML or OWASP Java Encoder',
            'Context-aware escaping for attributes or JavaScript blocks',
            'Content-Security-Policy strict nonces'
        ],
        sink: 'HttpServletResponse.getWriter().print / println / write',
        securityCondition: 'attacker_input_reflected_without_contextual_html_escaping',
        expectedImpactSignal: 'UNENCODED_XSS_SCRIPT_TAG_REFLECTED',
        positiveProbe: "<script>alert('hwsec_xss_probe')</script>",
        negativeControlProbe: "safe_user_name",
        proofOracle: 'HTML_ENCODING_ORACLE',
        acceptableDeterministicEvidence: [
            'HTTP response stream contains unescaped <script> tag from user input',
            'DOM injection executes in browser fixture'
        ],
        knownFalsePositiveConditions: [
            'Output is sanitized via ESAPI.encoder().encodeForHTML (yielding &lt;script&gt;)',
            'Response Content-Type is application/json or text/plain without HTML interpretation'
        ]
    },

    'CWE-328': {
        cwe: 'CWE-328',
        name: 'Use of Weak Hash (Reversible One-Way Hash)',
        attackerSourceBoundary: 'SECURITY_SENSITIVE_CONTEXT',
        taintInputOrigin: 'Password hashing, digital signatures, integrity check',
        transformationPath: 'Passing algorithm name to MessageDigest.getInstance',
        sanitizationValidationChecks: [
            'Use of SHA-256, SHA-384, SHA-512, SHA-3 or Argon2/PBKDF2/bcrypt for passwords'
        ],
        sink: 'java.security.MessageDigest.getInstance',
        securityCondition: 'weak_hash_algorithm_instantiated_in_security_context',
        expectedImpactSignal: 'WEAK_HASH_PRIMITIVE_EXECUTED',
        positiveProbe: 'MD5',
        negativeControlProbe: 'SHA-256',
        proofOracle: 'CRYPTOGRAPHIC_ALGORITHM_STRENGTH_ORACLE',
        acceptableDeterministicEvidence: [
            'Runtime log confirms MessageDigest instantiated with MD5 or SHA-1'
        ],
        knownFalsePositiveConditions: [
            'Algorithm is SHA-256, SHA-384, or SHA-512',
            'Hash algorithm used solely for non-security checksumming (e.g. hash table partitioning)'
        ]
    },

    'CWE-327': {
        cwe: 'CWE-327',
        name: 'Use of a Broken or Risky Cryptographic Algorithm',
        attackerSourceBoundary: 'SECURITY_SENSITIVE_CONTEXT',
        taintInputOrigin: 'Data encryption / decryption key schedule',
        transformationPath: 'Passing cipher name to Cipher.getInstance',
        sanitizationValidationChecks: [
            'Use of AES/GCM/NoPadding or ChaCha20-Poly1305 with strong key sizes'
        ],
        sink: 'javax.crypto.Cipher.getInstance',
        securityCondition: 'broken_cipher_primitive_or_insecure_mode_executed',
        expectedImpactSignal: 'BROKEN_CIPHER_PRIMITIVE_EXECUTED',
        positiveProbe: 'DES',
        negativeControlProbe: 'AES/GCM/NoPadding',
        proofOracle: 'CIPHER_STRENGTH_ORACLE',
        acceptableDeterministicEvidence: [
            'Cipher initialized with DES, RC2, RC4, or ECB mode'
        ],
        knownFalsePositiveConditions: [
            'Algorithm is AES in GCM or CBC mode with random IV'
        ]
    },

    'CWE-330': {
        cwe: 'CWE-330',
        name: 'Use of Insufficiently Random Values',
        attackerSourceBoundary: 'SECURITY_SENSITIVE_CONTEXT',
        taintInputOrigin: 'Token, session ID, nonce, or key generation',
        transformationPath: 'Using java.util.Random or Math.random instead of SecureRandom',
        sanitizationValidationChecks: [
            'java.security.SecureRandom'
        ],
        sink: 'java.util.Random.nextInt, Math.random',
        securityCondition: 'predictable_prng_used_for_security_token',
        expectedImpactSignal: 'PREDICTABLE_PRNG_USAGE_CONFIRMED',
        positiveProbe: 'java.util.Random',
        negativeControlProbe: 'java.security.SecureRandom',
        proofOracle: 'PRNG_STRENGTH_ORACLE',
        acceptableDeterministicEvidence: [
            'Security token generated via java.util.Random'
        ],
        knownFalsePositiveConditions: [
            'java.security.SecureRandom used for tokens',
            'Random number used for UI layout or non-security graphics'
        ]
    },

    'CWE-90': {
        cwe: 'CWE-90',
        name: 'Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)',
        attackerSourceBoundary: 'HTTP_REQUEST_PARAMETER_OR_HEADER_OR_COOKIE',
        taintInputOrigin: 'request.getParameter / getCookies / getHeader',
        transformationPath: 'Concatenation into LDAP filter expression',
        sanitizationValidationChecks: [
            'LDAP distinguished name encoding / filter escaping',
            'Search filter whitelisting'
        ],
        sink: 'javax.naming.directory.DirContext.search',
        securityCondition: 'attacker_input_alters_ldap_search_filter_syntax',
        expectedImpactSignal: 'LDAP_FILTER_SYNTAX_ALTERATION_CONFIRMED',
        positiveProbe: "*(|(mail=*))",
        negativeControlProbe: "john_doe",
        proofOracle: 'LDAP_FILTER_SYNTAX_ORACLE',
        acceptableDeterministicEvidence: [
            'DirContext.search called with filter containing unescaped LDAP metacharacters (*, |, &, !)'
        ],
        knownFalsePositiveConditions: [
            'Filter input is encoded using RFC 4515 LDAP filter escape sequences'
        ]
    },

    'CWE-643': {
        cwe: 'CWE-643',
        name: 'Improper Neutralization of Data within XPath Expressions (XPath Injection)',
        attackerSourceBoundary: 'HTTP_REQUEST_PARAMETER_OR_HEADER_OR_COOKIE',
        taintInputOrigin: 'request.getParameter / getCookies / getHeader',
        transformationPath: 'Concatenation into XPath expression string',
        sanitizationValidationChecks: [
            'XPath variable resolvers',
            'Parameterized XPath expressions'
        ],
        sink: 'javax.xml.xpath.XPath.evaluate',
        securityCondition: 'attacker_input_alters_xpath_expression_grammar',
        expectedImpactSignal: 'XPATH_GRAMMAR_ALTERATION_CONFIRMED',
        positiveProbe: "' or '1'='1",
        negativeControlProbe: "standard_item",
        proofOracle: 'XPATH_GRAMMAR_ORACLE',
        acceptableDeterministicEvidence: [
            'XPath.evaluate called with query string containing unescaped quote and boolean operator'
        ],
        knownFalsePositiveConditions: [
            'Input evaluated via XPath XPathVariableResolver without string concatenation'
        ]
    },

    'HARDWARE_RTL': {
        cwe: 'CWE-1200',
        name: 'Hardware Security Property & Register Invariant Violation',
        attackerSourceBoundary: 'EXTERNAL_IO_BUS_OR_DEBUG_INTERFACE',
        taintInputOrigin: 'JTAG, AXI bus transaction, test scan chain',
        transformationPath: 'State register transition under adversarial clock sequence',
        sanitizationValidationChecks: [
            'Access control decoder / lock register',
            'Secure boot hardware state machine'
        ],
        sink: 'Privileged CSR, shadow register, fuse array',
        securityCondition: 'hardware_security_invariant_assertion_violated',
        expectedImpactSignal: 'FORMAL_COUNTEREXAMPLE_TRACE_CONFIRMED',
        positiveProbe: 'adversarial_bmc_trace',
        negativeControlProbe: 'reset_hold_trace',
        proofOracle: 'FORMAL_BMC_ORACLE',
        acceptableDeterministicEvidence: [
            'SymbiYosys BMC or Yosys formal counterexample VCD trace proving assertion failure',
            'Verilator simulation assertion failure at specific clock cycle'
        ],
        knownFalsePositiveConditions: [
            'Assertion failed due to unconstrained reset or illegal bus protocol input sequence',
            'Vacuous assertion where precondition is never satisfiable'
        ]
    }
};

/**
 * Retrieves the Evidence Contract for a given CWE identifier.
 * @param {string} cweId e.g. "CWE-22"
 * @returns {Object|null}
 */
export function getEvidenceContract(cweId) {
    if (!cweId) return null;
    const norm = String(cweId).toUpperCase().trim();
    return EvidenceContracts[norm] || null;
}
