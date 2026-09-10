import path from 'path';

/**
 * CWE-Specific Security Condition Oracles
 * 
 * Implements Section 12: Observable sink/effect oracles for supported CWE families.
 */

export class BaseSecurityOracle {
    constructor(cwe, name) {
        this.cwe = cwe;
        this.name = name;
    }

    /**
     * Evaluates whether an execution result on a given input violates the security condition.
     * @param {Object} executionResult { stdout, stderr, exitCode, parsed_result, sink_observed }
     * @param {Object} inputProbe { parameter, value, type }
     * @param {Object} [context]
     * @returns {Object} { condition_satisfied: boolean, observable_effect: string, details: Object }
     */
    evaluate(executionResult, inputProbe, context = {}) {
        throw new Error('evaluate() must be implemented by subclass');
    }
}

/**
 * CWE-22: Path Traversal Oracle
 * Observable: Canonical path resolution escapes authorized root or unescaped ../ traverses directory.
 */
export class PathTraversalOracle extends BaseSecurityOracle {
    constructor() {
        super('CWE-22', 'PathTraversalOracle');
    }

    evaluate(executionResult, inputProbe, context = {}) {
        const value = String(inputProbe?.value || '');
        const stdout = String(executionResult?.stdout || '');
        const stderr = String(executionResult?.stderr || '');
        const parsed = executionResult?.parsed_harness_result || executionResult?.parsed_result || {};

        let escapedRoot = false;
        let details = {};

        // 1. Check parsed sink observations if present
        if (parsed.canonical_path && parsed.base_directory) {
            const canonical = path.resolve(parsed.canonical_path).replace(/\\/g, '/');
            const base = path.resolve(parsed.base_directory).replace(/\\/g, '/');
            escapedRoot = !canonical.startsWith(base);
            details = { canonical, base, escapedRoot };
        } else if (value.includes('..') || value.startsWith('/') || value.startsWith('\\')) {
            // Check filesystem sink observation in stdout/stderr
            if (stdout.includes('CANONICAL_ESCAPE') || stdout.includes('FileNotFoundException') || stdout.includes('etc/passwd') || stdout.includes('root:')) {
                escapedRoot = true;
                details = { indicator: 'SINK_FILE_ESCAPE_OBSERVED' };
            } else if (parsed.sink_tainted || parsed.sink_observed === 'java.io.File') {
                escapedRoot = true;
                details = { indicator: 'TAINTED_PATH_SINK_REACHED' };
            }
        }

        return {
            condition_satisfied: escapedRoot,
            observable_effect: escapedRoot ? 'CANONICAL_PATH_ESCAPE_OUTSIDE_ROOT' : 'CONFINED_TO_ROOT',
            details
        };
    }
}

/**
 * CWE-89: SQL Injection Oracle
 * Observable: SQL query syntax tree / token boundary alteration or SQL syntax error on probe.
 */
export class SQLiOracle extends BaseSecurityOracle {
    constructor() {
        super('CWE-89', 'SQLiOracle');
    }

    evaluate(executionResult, inputProbe, context = {}) {
        const value = String(inputProbe?.value || '');
        const stdout = String(executionResult?.stdout || '');
        const stderr = String(executionResult?.stderr || '');
        const parsed = executionResult?.parsed_harness_result || executionResult?.parsed_result || {};

        if (parsed.is_parameterized === true || parsed.parameters !== undefined) {
            return {
                condition_satisfied: false,
                observable_effect: 'PARAMETERIZED_PREPARED_STATEMENT',
                details: { parameterized: true }
            };
        }

        let sqliConfirmed = false;
        let details = {};

        // Check SQL AST structural alteration or unescaped quote in query
        if (parsed.sql_query) {
            const query = String(parsed.sql_query);
            if (query.includes("' OR '") || query.includes("' OR 1=1") || query.includes("UNION SELECT")) {
                sqliConfirmed = true;
                details = { query, ast_modified: true };
            }
        } else if (stdout.includes('SQLException') || stderr.includes('SQL syntax') || stdout.includes('SYNTAX_ERROR') || stdout.includes('SQL_INJECTION_TRIGGERED')) {
            sqliConfirmed = true;
            details = { indicator: 'SQL_SYNTAX_ERROR_OR_TRIGGER' };
        } else if (parsed.sink_tainted || (parsed.sink_observed && parsed.sink_observed.includes('Statement'))) {
            if (value.includes("'") || value.includes("--") || value.includes("/*")) {
                sqliConfirmed = true;
                details = { indicator: 'TAINTED_SQL_SINK_REACHED' };
            }
        }

        return {
            condition_satisfied: sqliConfirmed,
            observable_effect: sqliConfirmed ? 'SQL_SYNTAX_OR_AST_BOUNDARY_ALTERED' : 'PARAMETERIZED_OR_ESCAPED',
            details
        };
    }
}

/**
 * CWE-78: Command Injection Oracle
 * Observable: Process argument structure alteration or shell command control flow manipulation.
 */
export class CommandInjectionOracle extends BaseSecurityOracle {
    constructor() {
        super('CWE-78', 'CommandInjectionOracle');
    }

    evaluate(executionResult, inputProbe, context = {}) {
        const value = String(inputProbe?.value || '');
        const stdout = String(executionResult?.stdout || '');
        const stderr = String(executionResult?.stderr || '');
        const parsed = executionResult?.parsed_harness_result || executionResult?.parsed_result || {};

        let cmdiConfirmed = false;
        let details = {};

        if (parsed.command_args) {
            const args = Array.isArray(parsed.command_args) ? parsed.command_args : [parsed.command_args];
            const hasMultipleTokens = args.some(a => String(a).includes(';') || String(a).includes('|') || String(a).includes('&'));
            if (hasMultipleTokens) {
                cmdiConfirmed = true;
                details = { args, shell_tokens_injected: true };
            }
        } else if (stdout.includes('INJECTED_CMD_OUTPUT') || stdout.includes('COMMAND_INJECTION_TRIGGERED')) {
            cmdiConfirmed = true;
            details = { indicator: 'INJECTED_OUTPUT_CONFIRMED' };
        } else if (parsed.sink_tainted || (parsed.sink_observed && parsed.sink_observed.includes('exec'))) {
            if (value.includes(';') || value.includes('|') || value.includes('&') || value.includes('`')) {
                cmdiConfirmed = true;
                details = { indicator: 'TAINTED_COMMAND_SINK_REACHED' };
            }
        }

        return {
            condition_satisfied: cmdiConfirmed,
            observable_effect: cmdiConfirmed ? 'PROCESS_ARGUMENT_STRUCTURE_ALTERED' : 'FIXED_ARGV_ARRAY',
            details
        };
    }
}

/**
 * CWE-79: XSS Oracle
 * Observable: Unencoded reflection of HTML/script elements in output context.
 */
export class XSSOracle extends BaseSecurityOracle {
    constructor() {
        super('CWE-79', 'XSSOracle');
    }

    evaluate(executionResult, inputProbe, context = {}) {
        const value = String(inputProbe?.value || '');
        const stdout = String(executionResult?.stdout || '');
        const parsed = executionResult?.parsed_harness_result || executionResult?.parsed_result || {};

        let xssConfirmed = false;
        let details = {};

        if (parsed.response_body) {
            const body = String(parsed.response_body);
            if (body.includes('<script>') || body.includes('<img src=x') || (value.includes('<') && body.includes(value))) {
                xssConfirmed = true;
                details = { unencoded_reflection: true };
            }
        } else if (stdout.includes('<script>') || stdout.includes('XSS_TRIGGERED')) {
            xssConfirmed = true;
            details = { indicator: 'XSS_PAYLOAD_REFLECTED' };
        } else if (parsed.sink_tainted || (parsed.sink_observed && parsed.sink_observed.includes('getWriter'))) {
            if (value.includes('<') || value.includes('>')) {
                xssConfirmed = true;
                details = { indicator: 'TAINTED_RESPONSE_SINK_REACHED' };
            }
        }

        return {
            condition_satisfied: xssConfirmed,
            observable_effect: xssConfirmed ? 'UNENCODED_HTML_SCRIPT_REFLECTION' : 'HTML_ENCODED_OR_SANITIZED',
            details
        };
    }
}

/**
 * CWE-90: LDAP Injection Oracle
 */
export class LDAPInjectionOracle extends BaseSecurityOracle {
    constructor() {
        super('CWE-90', 'LDAPInjectionOracle');
    }

    evaluate(executionResult, inputProbe, context = {}) {
        const value = String(inputProbe?.value || '');
        const parsed = executionResult?.parsed_harness_result || executionResult?.parsed_result || {};
        const ldapConfirmed = (parsed.sink_tainted || false) && (value.includes('*') || value.includes('(') || value.includes(')'));
        return {
            condition_satisfied: ldapConfirmed,
            observable_effect: ldapConfirmed ? 'LDAP_FILTER_GRAMMAR_ALTERED' : 'FILTER_ESCAPED',
            details: { ldapConfirmed }
        };
    }
}

/**
 * CWE-643: XPath Injection Oracle
 */
export class XPathInjectionOracle extends BaseSecurityOracle {
    constructor() {
        super('CWE-643', 'XPathInjectionOracle');
    }

    evaluate(executionResult, inputProbe, context = {}) {
        const value = String(inputProbe?.value || '');
        const parsed = executionResult?.parsed_harness_result || executionResult?.parsed_result || {};
        const xpathConfirmed = (parsed.sink_tainted || false) && (value.includes("'") || value.includes('or') || value.includes('and'));
        return {
            condition_satisfied: xpathConfirmed,
            observable_effect: xpathConfirmed ? 'XPATH_PREDICATE_GRAMMAR_ALTERED' : 'XPATH_PARAMETERIZED',
            details: { xpathConfirmed }
        };
    }
}
