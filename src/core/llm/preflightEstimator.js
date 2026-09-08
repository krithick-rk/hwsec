import fs from 'fs';
import path from 'path';

/**
 * Supported language and domain classifications
 */
const LANGUAGE_DOMAINS = {
    'verilog': 'hardware',
    'systemverilog': 'hardware',
    'v': 'hardware',
    'sv': 'hardware',
    'vh': 'hardware',
    'svh': 'hardware',
    'c': 'software',
    'cpp': 'software',
    'h': 'software',
    'hpp': 'software',
    'cc': 'software',
    'cxx': 'software',
    'python': 'software',
    'py': 'software',
    'java': 'software',
    'go': 'software',
    'rust': 'software',
    'rs': 'software',
    'javascript': 'software',
    'typescript': 'software',
    'js': 'software',
    'ts': 'software',
    'json': 'config',
    'yaml': 'config',
    'yml': 'config',
    'xml': 'config',
    'toml': 'config'
};

const EXTENSION_TO_LANG = {
    '.v': 'verilog',
    '.sv': 'systemverilog',
    '.vh': 'verilog',
    '.svh': 'systemverilog',
    '.c': 'c',
    '.h': 'c',
    '.cpp': 'cpp',
    '.hpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.py': 'python',
    '.java': 'java',
    '.go': 'go',
    '.rs': 'rust',
    '.js': 'javascript',
    '.ts': 'typescript',
    '.json': 'json',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.xml': 'xml',
    '.toml': 'toml',
    '.md': 'markdown',
    '.txt': 'text'
};

/**
 * Lightweight syntactic & AST pattern regexes for complexity scoring
 */
const HARDWARE_PATTERNS = {
    modules: /\b(module|macromodule|primitive)\b/g,
    processes: /\b(always|always_ff|always_comb|always_latch|initial)\b/g,
    assignments: /\b(assign|deassign|force|release)\b/g,
    branches: /\b(if|else|case|casex|casez|default)\b/g,
    stateMachines: /\b(typedef\s+enum|state|fsm|next_state)\b/gi,
    formalProperties: /\b(assert|assume|cover|restrict|property|sequence)\b/g,
    subroutines: /\b(task|function)\b/g,
    hierarchies: /\b(generate|for|genvar|interface|modport)\b/g
};

const SOFTWARE_PATTERNS = {
    branches: /\b(if|else|switch|case|default|catch|except|match)\b/g,
    loops: /\b(for|while|do|loop)\b/g,
    subroutines: /\b(def|fn|function|func|void|int|char|auto|public|private|protected)\s+[a-zA-Z0-9_]+\s*\(/g,
    classesAndStructs: /\b(class|struct|interface|trait|enum|union|typedef)\b/g,
    memoryOps: /\b(malloc|calloc|realloc|free|memcpy|strcpy|strncpy|sprintf|snprintf|strcat|new|delete)\b/g,
    concurrencyOps: /\b(pthread|std::thread|mutex|lock|synchronized|go\s+[a-zA-Z0-9_]|async|await|chan)\b/g,
    securityPrimitives: /\b(system|exec|execve|popen|eval|subprocess|os\.system|crypto|aes|sha256|hmac|sign)\b/g
};

/**
 * Pass 1: Pre-Flight Token & Workload Estimator
 * Scans repository files immediately following discovery, estimates token counts,
 * and analyzes structural complexity for intelligent bin-packing and scheduling.
 */
export class PreflightEstimator {
    /**
     * @param {Object} [config]
     * @param {number} [config.charsPerToken=3.8] Character heuristic ratio
     * @param {number} [config.maxFileSize=10485760] Maximum file size in bytes (10MB)
     */
    constructor(config = {}) {
        this.config = config;
        this.charsPerToken = config.chars_per_token || config.charsPerToken || 3.8;
        this.maxFileSize = config.max_file_size_bytes || config.maxFileSize || 10485760;
    }

    /**
     * Estimates token count for a raw string.
     * @param {string} text
     * @returns {number}
     */
    estimateTokenCount(text) {
        if (!text || typeof text !== 'string') return 0;
        const len = text.length;
        if (len === 0) return 0;

        // Baseline character heuristic
        const baseEstimate = len / this.charsPerToken;

        // Account for high symbol/whitespace density in source code
        const specialCharCount = (text.match(/[{}[\]();:<>=!+\-*/&|^%~,.]/g) || []).length;
        const symbolMultiplier = 1.0 + Math.min((specialCharCount / len) * 0.4, 0.25);

        return Math.max(1, Math.ceil(baseEstimate * symbolMultiplier));
    }

    /**
     * Classifies programming / HDL language from extension or string.
     * @param {string} langOrPath
     * @returns {string}
     */
    classifyLanguage(langOrPath) {
        if (!langOrPath) return 'c';
        const lower = langOrPath.toLowerCase();
        if (LANGUAGE_DOMAINS[lower]) return lower;
        const ext = path.extname(lower);
        if (ext && EXTENSION_TO_LANG[ext]) {
            return EXTENSION_TO_LANG[ext];
        }
        return 'c';
    }

    /**
     * Classifies domain from language name or file path.
     * @param {string} langOrPath
     * @returns {'hardware'|'software'|'config'|'other'}
     */
    classifyDomain(langOrPath) {
        if (!langOrPath) return 'other';
        const lower = langOrPath.toLowerCase();
        if (LANGUAGE_DOMAINS[lower]) return LANGUAGE_DOMAINS[lower];

        const ext = path.extname(lower);
        if (ext && EXTENSION_TO_LANG[ext]) {
            const lang = EXTENSION_TO_LANG[ext];
            return LANGUAGE_DOMAINS[lang] || 'other';
        }

        return 'other';
    }

    /**
     * Analyzes AST / syntactic patterns and computes a complexity score.
     * @param {string} content
     * @param {string} domain
     * @param {number} loc
     * @returns {{complexity: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL', astNodeCount: number, branchCount: number, score: number}}
     */
    analyzeComplexity(content, domain, loc) {
        if (!content || loc <= 0) {
            return { complexity: 'LOW', astNodeCount: 0, branchCount: 0, score: 0 };
        }

        let branchCount = 0;
        let astNodeCount = 0;
        let securityCount = 0;

        if (domain === 'hardware') {
            for (const [key, regex] of Object.entries(HARDWARE_PATTERNS)) {
                const matches = (content.match(regex) || []).length;
                astNodeCount += matches;
                if (key === 'branches' || key === 'stateMachines') {
                    branchCount += matches;
                }
                if (key === 'formalProperties') {
                    securityCount += matches * 2;
                }
            }
        } else if (domain === 'software') {
            for (const [key, regex] of Object.entries(SOFTWARE_PATTERNS)) {
                const matches = (content.match(regex) || []).length;
                astNodeCount += matches;
                if (key === 'branches' || key === 'loops') {
                    branchCount += matches;
                }
                if (key === 'memoryOps' || key === 'securityPrimitives' || key === 'concurrencyOps') {
                    securityCount += matches;
                }
            }
        } else {
            // Config / other: base on line count and brackets
            astNodeCount = (content.match(/[{}[\]]/g) || []).length;
            branchCount = 0;
        }

        const score = Math.round((loc * 0.15) + (branchCount * 1.8) + (astNodeCount * 0.5) + (securityCount * 2.5));

        let complexity = 'LOW';
        if (score >= 200 || loc >= 1000 || branchCount >= 40) {
            complexity = 'CRITICAL';
        } else if (score >= 80 || loc >= 300 || branchCount >= 15) {
            complexity = 'HIGH';
        } else if (score >= 25 || loc >= 50 || branchCount >= 4) {
            complexity = 'MEDIUM';
        }

        return {
            complexity,
            astNodeCount,
            branchCount,
            score
        };
    }

    /**
     * Estimates workload for a single file.
     * @param {string} filePath
     * @param {string} [content] Optional pre-loaded content
     * @param {Object} [metadata] Optional existing metadata (loc, size, relativePath)
     * @returns {Object} FileProfile
     */
    estimateFile(filePath, content = null, metadata = {}) {
        const resolvedPath = path.resolve(filePath);
        let fileContent = content;
        let sizeBytes = metadata.size || 0;

        if (fileContent === null && fs.existsSync(resolvedPath)) {
            try {
                const stat = fs.statSync(resolvedPath);
                sizeBytes = stat.size;
                if (sizeBytes <= this.maxFileSize) {
                    fileContent = fs.readFileSync(resolvedPath, 'utf-8');
                }
            } catch {
                fileContent = '';
            }
        }

        if (fileContent === null) fileContent = '';

        const ext = path.extname(filePath).toLowerCase();
        const language = metadata.language || EXTENSION_TO_LANG[ext] || 'unknown';
        const domain = this.classifyDomain(language);

        const lines = fileContent.split('\n');
        const loc = metadata.loc !== undefined 
            ? metadata.loc 
            : lines.filter(l => l.trim().length > 0).length;

        const charCount = fileContent.length;
        const estimatedTokens = this.estimateTokenCount(fileContent);
        const complexityAnalysis = this.analyzeComplexity(fileContent, domain, loc);

        return {
            path: resolvedPath,
            relativePath: metadata.relativePath || path.basename(filePath),
            filename: path.basename(filePath),
            extension: ext,
            language,
            domain,
            sizeBytes,
            charCount,
            loc,
            estimatedTokens,
            complexity: complexityAnalysis.complexity,
            astNodeCount: complexityAnalysis.astNodeCount,
            branchCount: complexityAnalysis.branchCount,
            complexityScore: complexityAnalysis.score
        };
    }

    /**
     * Estimates workload across an array of file paths or file metadata objects.
     * @param {Array<string|Object>} fileList
     * @param {Object} [options]
     * @returns {{files: Array<Object>, summary: Object}}
     */
    estimateFiles(fileList = [], options = {}) {
        const files = [];
        const complexityBreakdown = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
        const domainBreakdown = { hardware: 0, software: 0, config: 0, other: 0 };
        const languageBreakdown = {};

        let totalTokens = 0;
        let totalLoc = 0;
        let totalBytes = 0;
        let maxFileTokens = 0;
        let largestFile = null;

        for (const item of fileList) {
            const filePath = typeof item === 'string' ? item : item.path;
            const content = typeof item === 'object' && item.content !== undefined ? item.content : null;
            const metadata = typeof item === 'object' ? item : {};

            const profile = this.estimateFile(filePath, content, metadata);
            files.push(profile);

            totalTokens += profile.estimatedTokens;
            totalLoc += profile.loc;
            totalBytes += profile.sizeBytes;

            if (profile.estimatedTokens > maxFileTokens) {
                maxFileTokens = profile.estimatedTokens;
                largestFile = profile.relativePath || profile.path;
            }

            complexityBreakdown[profile.complexity] = (complexityBreakdown[profile.complexity] || 0) + 1;
            domainBreakdown[profile.domain] = (domainBreakdown[profile.domain] || 0) + 1;

            if (!languageBreakdown[profile.language]) {
                languageBreakdown[profile.language] = { files: 0, tokens: 0, loc: 0 };
            }
            languageBreakdown[profile.language].files++;
            languageBreakdown[profile.language].tokens += profile.estimatedTokens;
            languageBreakdown[profile.language].loc += profile.loc;
        }

        const totalFiles = files.length;
        const avgTokensPerFile = totalFiles > 0 ? Math.round(totalTokens / totalFiles) : 0;

        const summary = {
            totalFiles,
            totalTokens,
            totalLoc,
            totalBytes,
            avgTokensPerFile,
            maxFileTokens,
            largestFile,
            complexityBreakdown,
            domainBreakdown,
            languageBreakdown
        };

        return { files, summary };
    }

    /**
     * Estimates workload directly from a RepositoryDiscovery inventory structure.
     * @param {Object} inventory
     * @param {string} [rootDir]
     * @returns {{files: Array<Object>, summary: Object}}
     */
    estimateInventory(inventory, rootDir = null) {
        if (!inventory || typeof inventory !== 'object') {
            return this.estimateFiles([]);
        }

        const fileItems = [];
        const languages = inventory.languages || {};
        const metadataMap = inventory.file_metadata || {};

        for (const [lang, paths] of Object.entries(languages)) {
            for (const p of paths) {
                const meta = metadataMap[p] || {};
                fileItems.push({
                    path: p,
                    language: lang,
                    loc: meta.loc,
                    size: meta.size,
                    relativePath: meta.relativePath || (rootDir ? path.relative(rootDir, p) : path.basename(p))
                });
            }
        }

        return this.estimateFiles(fileItems);
    }

    /**
     * Estimates tokens, runtime, complexity, and feasibility for verifying / reproducing a finding.
     * Calculates the Exploitability Triage metrics:
     *  - exploitability_score
     *  - evidence_completeness
     *  - attacker_control_score
     *  - reachability_score
     *  - environment_feasibility
     *  - novelty_value
     *  - estimated_cost
     *  - triage_decision
     *
     * @param {Object} finding Candidate finding
     * @param {Object} [options]
     * @returns {Object} FindingExploitEstimation
     */
    estimateFindingExploitCost(finding, options = {}) {
        if (!finding) throw new Error('[PreflightEstimator] finding is required');

        const severity = (finding.severity || 'MEDIUM').toUpperCase();
        const severityWeights = {
            'CRITICAL': 1.0,
            'HIGH': 0.8,
            'MEDIUM': 0.5,
            'LOW': 0.2,
            'INFO': 0.05
        };
        const sevWeight = severityWeights[severity] ?? 0.5;

        // Evidence completeness
        const evidenceList = finding.evidence || finding.supporting_evidence || [];
        const sourceLocs = finding.source_locations || [];
        let evidenceCompleteness = 0.1;
        if (evidenceList.length > 0) evidenceCompleteness += Math.min(0.4, evidenceList.length * 0.2);
        if (sourceLocs.length > 0 && (sourceLocs[0].startLine || sourceLocs[0].line)) evidenceCompleteness += 0.3;
        if (evidenceList.some(e => e.raw_evidence || e.artifact_path)) evidenceCompleteness += 0.2;
        evidenceCompleteness = Math.min(1.0, Math.round(evidenceCompleteness * 100) / 100);

        // Language & Domain detection
        const lang = (finding.language || (sourceLocs[0]?.path ? this.classifyLanguage(sourceLocs[0].path) : null) || 'c').toLowerCase();
        const domain = this.classifyDomain(lang);

        // Attacker control score: analyze finding title, description, code, CWE
        const textToAnalyze = `${finding.title || ''} ${finding.description || ''} ${finding.cwe_id || ''}`.toLowerCase();
        let attackerControlScore = 0.5;
        if (/(input|user|param|argv|req|packet|payload|taint|external|header|query|untrusted)/i.test(textToAnalyze)) {
            attackerControlScore = 0.85;
        } else if (/(register|reg_|port|bus|din|rx|uart|spi|i2c|axi)/i.test(textToAnalyze)) {
            attackerControlScore = 0.80;
        } else if (/(internal|static|assert_never|dead_code|unused|unreachable)/i.test(textToAnalyze)) {
            attackerControlScore = 0.20;
        }

        // Reachability score: graph path length or source location analysis
        const graphPathLength = finding.graph_path_length ?? finding.graphPathLength ?? (finding.evidence?.[0]?.raw_evidence?.path_length || 3);
        let reachabilityScore = 0.6;
        if (graphPathLength <= 2) {
            reachabilityScore = 0.95;
        } else if (graphPathLength <= 5) {
            reachabilityScore = 0.75;
        } else if (graphPathLength <= 10) {
            reachabilityScore = 0.50;
        } else {
            reachabilityScore = 0.30;
        }

        // Environment feasibility: can we safely execute in isolated local environment?
        let environmentFeasibility = 0.95;
        const isUnsafeExternal = /(aws|gcp|azure|production|prod|s3|cloud|external api|remote host|192\.168\.|10\.|http:\/\/|https:\/\/)/i.test(textToAnalyze) &&
                                 !/(localhost|127\.0\.0\.1|mock|fixture|dummy|test)/i.test(textToAnalyze);
        if (isUnsafeExternal) {
            environmentFeasibility = 0.10;
        }

        // Novelty value: rare CWEs or formal assertions
        let noveltyValue = 0.5;
        if (/(cwe-1234|cwe-119|cwe-78|cwe-22|cwe-287|formal_bmc|hardware_backdoor|side_channel)/i.test(textToAnalyze)) {
            noveltyValue = 0.85;
        }

        // Token estimation with granular stage breakdown
        const baseInputTokens = 1200;
        const codeSnippetLength = (finding.codeSnippet || '').length;
        const snippetTokens = codeSnippetLength > 0 ? Math.round(codeSnippetLength / this.charsPerToken) : 800;
        const evidenceTokens = evidenceList.length * 250;
        const maxInputTokens = Math.min(8000, baseInputTokens + snippetTokens + evidenceTokens);
        const maxOutputTokens = domain === 'hardware' ? 2048 : 1536;
        
        // Granular token breakdown as required by Section 5 (reasoning, artifact generation, validation)
        const reasoningTokens = Math.round(maxInputTokens * 0.55);
        const artifactGenTokens = Math.round(maxInputTokens * 0.30) + maxOutputTokens;
        const validationTokens = Math.round(maxInputTokens * 0.15) + Math.round(maxOutputTokens * 0.5);
        const totalEstimatedTokens = maxInputTokens + maxOutputTokens;

        // Estimated runtime in seconds
        let estimatedRuntimeSeconds = 10;
        if (domain === 'hardware') {
            estimatedRuntimeSeconds = 30; // formal BMC / yosys verification
        } else if (lang === 'c' || lang === 'cpp') {
            estimatedRuntimeSeconds = 15; // compilation + ASan
        } else {
            estimatedRuntimeSeconds = 8;
        }

        // Overall exploitability score & proof priority score
        const confidence = typeof finding.confidence === 'number' ? finding.confidence : 0.6;
        const exploitabilityScore = Math.round((
            0.30 * sevWeight +
            0.25 * attackerControlScore +
            0.25 * reachabilityScore +
            0.10 * evidenceCompleteness +
            0.10 * confidence
        ) * 100) / 100;

        const proofPriorityScore = exploitabilityScore;

        // Expected retries and estimated latency
        const expectedRetries = (exploitabilityScore >= 0.70) ? 2 : 1;
        const estimatedLatencyMs = (domain === 'hardware' ? 4500 : 2500);

        // Estimated cost (USD) based on token estimates
        // OpenRouter / Gemini blended pricing (~$0.0006 per 1k input, ~$0.002 per 1k output)
        const estimatedCost = Math.round(((maxInputTokens * 0.0006 + maxOutputTokens * 0.002) / 1000) * 100000) / 100000;

        // Triage decision & Proof Eligibility
        let triageDecision;
        let triageReason;
        let proofEligibility = 'NOT_ELIGIBLE';

        if (environmentFeasibility < 0.2 || isUnsafeExternal) {
            triageDecision = 'UNSAFE_TARGET';
            triageReason = 'Target involves external systems, production infrastructure, or unsafe actions. Execution blocked.';
            proofEligibility = 'UNSAFE_TARGET';
        } else if (sevWeight < 0.3 && evidenceCompleteness < 0.4) {
            triageDecision = 'NO_POC';
            triageReason = 'Low severity and low evidence completeness. Retaining as Candidate.';
            proofEligibility = 'NOT_ELIGIBLE';
        } else if (exploitabilityScore >= 0.70 && reachabilityScore >= 0.70) {
            triageDecision = 'MINIMAL_POC';
            triageReason = 'High confidence, high reachability, local trigger feasible. Schedule minimal PoC generation.';
            proofEligibility = 'ELIGIBLE';
        } else if (sevWeight >= 0.8 && reachabilityScore < 0.70) {
            triageDecision = 'TARGETED_PROOF';
            triageReason = 'High severity with ambiguous reachability. Schedule targeted bounded proof only.';
            proofEligibility = 'ELIGIBLE';
        } else if (exploitabilityScore >= 0.50) {
            triageDecision = 'MINIMAL_POC';
            triageReason = 'Moderate exploitability score with sufficient evidence. Schedule bounded reproduction.';
            proofEligibility = 'ELIGIBLE';
        } else {
            triageDecision = 'NO_POC';
            triageReason = 'Insufficient exploitability score or evidence. Retaining as Candidate.';
            proofEligibility = 'NOT_ELIGIBLE';
        }

        const reasoningSummary = `[${proofEligibility}] ${triageReason} (Priority: ${(proofPriorityScore * 100).toFixed(0)}%, Reachability: ${(reachabilityScore * 100).toFixed(0)}%, Domain: ${domain}/${lang})`;

        return {
            findingId: finding.id,
            severity,
            language: lang,
            domain,
            proof_priority_score: proofPriorityScore,
            proof_eligibility: proofEligibility,
            reasoning_summary: reasoningSummary,
            metrics: {
                exploitability_score: exploitabilityScore,
                evidence_completeness: evidenceCompleteness,
                attacker_control_score: attackerControlScore,
                reachability_score: reachabilityScore,
                environment_feasibility: environmentFeasibility,
                novelty_value: noveltyValue,
                estimated_cost: estimatedCost
            },
            resourceEstimation: {
                reasoning_tokens: reasoningTokens,
                artifact_generation_tokens: artifactGenTokens,
                validation_tokens: validationTokens,
                maxInputTokens,
                maxOutputTokens,
                totalEstimatedTokens,
                estimatedLatencyMs,
                estimatedRuntimeSeconds,
                expectedRetries,
                sandboxResources: {
                    memory_limit_mb: 512,
                    cpu_limit_cores: 1,
                    network: 'none'
                },
                estimatedCostUsd: estimatedCost
            },
            triageDecision,
            triageReason
        };
    }
}
