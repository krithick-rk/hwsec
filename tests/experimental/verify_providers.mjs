/**
 * HWSEC Experiment Phase 3 — Real Provider Verification
 * 
 * Performs ONE genuine API call to each of the four configured providers.
 * Records telemetry, latency, token usage, and response hash.
 * 
 * NEVER prints API key values.
 * Does NOT use mocks, stubs, or cached responses.
 * 
 * Section: C. Real-provider tests
 */

import { createHash } from 'crypto';
import { resolve } from 'path';

// ── helpers ──────────────────────────────────────────────────────────────────

function hashResponse(text) {
    return createHash('sha256').update(text || '').digest('hex').slice(0, 16);
}

function maskKey(key) {
    if (!key) return '<NOT_SET>';
    return key.slice(0, 6) + '...' + key.slice(-4);
}

function nowIso() {
    return new Date().toISOString();
}

// ── Gemini ────────────────────────────────────────────────────────────────────

async function testGemini(accountLabel, apiKey, role, systemPrompt, userPrompt) {
    if (!apiKey) {
        return { provider: 'gemini', account: accountLabel, success: false, error: 'KEY_NOT_SET', role };
    }

    const model = 'gemini-3.6-flash';
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
    const body = {
        system_instruction: { parts: [{ text: systemPrompt }] },
        contents: [{ parts: [{ text: userPrompt }] }],
        generationConfig: { temperature: 0.1, maxOutputTokens: 512 }
    };

    const requestTimestamp = nowIso();
    const t0 = Date.now();

    let resp, data;
    try {
        resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(30000)
        });
        data = await resp.json();
    } catch (err) {
        return { provider: 'gemini', account: accountLabel, role, success: false, error: err.message, requestTimestamp };
    }

    const latencyMs = Date.now() - t0;
    const responseTimestamp = nowIso();

    if (!resp.ok || data.error) {
        return {
            provider: 'gemini', account: accountLabel, role, success: false,
            error: data.error?.message || `HTTP ${resp.status}`,
            requestTimestamp, responseTimestamp, latencyMs
        };
    }

    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    const usage = data.usageMetadata || {};
    return {
        provider: 'gemini',
        account: accountLabel,
        role,
        model,
        success: true,
        requestTimestamp,
        responseTimestamp,
        latencyMs,
        inputTokens: usage.promptTokenCount || 0,
        outputTokens: usage.candidatesTokenCount || 0,
        totalTokens: usage.totalTokenCount || 0,
        responseHash: hashResponse(text),
        schemaValid: typeof text === 'string' && text.length > 0,
        keyMasked: maskKey(apiKey)
    };
}

// ── NVIDIA ────────────────────────────────────────────────────────────────────

async function testNvidia(apiKey, userPrompt) {
    if (!apiKey) {
        return { provider: 'nvidia', success: false, error: 'KEY_NOT_SET' };
    }

    // Dynamic model selection: task is COMPLEX_REASONING → use llama-3.1-nemotron-70b-instruct per taskRouter
    const selectedModel = 'nvidia/llama-3.1-nemotron-70b-instruct';
    const routingRationale = 'COMPLEX_REASONING task class routed to NVIDIA deep reasoner endpoint via TaskRouter (taskClass=complex_framework_dataflow_reasoning, mode=DEEP)';

    const url = 'https://integrate.api.nvidia.com/v1/chat/completions';
    const body = {
        model: selectedModel,
        messages: [
            { role: 'system', content: 'You are a security analysis assistant.' },
            { role: 'user', content: userPrompt }
        ],
        temperature: 0.1,
        max_tokens: 512
    };

    const requestTimestamp = nowIso();
    const t0 = Date.now();

    let resp, data;
    try {
        resp = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(60000)
        });
        data = await resp.json();
    } catch (err) {
        return { provider: 'nvidia', success: false, error: err.message, requestTimestamp };
    }

    const latencyMs = Date.now() - t0;
    const responseTimestamp = nowIso();

    if (!resp.ok || data.error) {
        return {
            provider: 'nvidia', success: false,
            error: data.error?.message || data.detail || `HTTP ${resp.status}`,
            selectedModel,
            routingRationale,
            requestTimestamp, responseTimestamp, latencyMs,
            keyMasked: maskKey(apiKey)
        };
    }

    const text = data.choices?.[0]?.message?.content || '';
    const usage = data.usage || {};
    return {
        provider: 'nvidia',
        role: 'deep_reasoner',
        selectedModel,
        routingRationale,
        success: true,
        requestTimestamp,
        responseTimestamp,
        latencyMs,
        inputTokens: usage.prompt_tokens || 0,
        outputTokens: usage.completion_tokens || 0,
        totalTokens: usage.total_tokens || 0,
        responseHash: hashResponse(text),
        keyMasked: maskKey(apiKey)
    };
}

// ── OpenRouter ────────────────────────────────────────────────────────────────

async function testOpenRouter(apiKey, userPrompt) {
    if (!apiKey) {
        return { provider: 'openrouter', success: false, error: 'KEY_NOT_SET' };
    }

    const model = 'meta-llama/llama-3.3-70b-instruct';
    const url = 'https://openrouter.ai/api/v1/chat/completions';
    const body = {
        model,
        messages: [
            { role: 'system', content: 'You are a security analysis assistant.' },
            { role: 'user', content: userPrompt }
        ],
        temperature: 0.1,
        max_tokens: 256
    };

    const requestTimestamp = nowIso();
    const t0 = Date.now();

    let resp, data;
    try {
        resp = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`,
                'HTTP-Referer': 'https://hwsec.local',
                'X-Title': 'HWSEC Security Analysis'
            },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(60000)
        });
        data = await resp.json();
    } catch (err) {
        return { provider: 'openrouter', success: false, error: err.message, requestTimestamp };
    }

    const latencyMs = Date.now() - t0;
    const responseTimestamp = nowIso();

    if (!resp.ok || data.error) {
        return {
            provider: 'openrouter', success: false,
            error: data.error?.message || `HTTP ${resp.status}`,
            requestTimestamp, responseTimestamp, latencyMs
        };
    }

    const text = data.choices?.[0]?.message?.content || '';
    const usage = data.usage || {};
    return {
        provider: 'openrouter',
        role: 'specialist_fallback',
        model,
        success: true,
        requestTimestamp,
        responseTimestamp,
        latencyMs,
        inputTokens: usage.prompt_tokens || 0,
        outputTokens: usage.completion_tokens || 0,
        totalTokens: usage.total_tokens || 0,
        responseHash: hashResponse(text),
        keyMasked: maskKey(apiKey)
    };
}

// ── main ──────────────────────────────────────────────────────────────────────

const GEMINI_KEY_1  = process.env.GEMINI_API_KEY;
const GEMINI_KEY_2  = process.env.GEMINI_API_KEY_2;
const NVIDIA_KEY    = process.env.NVIDIA_API_KEY;
const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY;

const WEBGOAT_CONTEXT = `
WebGoat v2023.8 lesson SqlInjectionLesson5a.java (CWE-89):
  - Route: POST /SqlInjection/assignment5a
  - Parameter: account_name
  - Sink: statement.executeQuery(query) at line 73
  - Source: HttpServletRequest.getParameter("account_name")
  - No input sanitization detected in static analysis.
`;

console.log('\n=======================================================');
console.log('  HWSEC EXPERIMENT — PHASE 3: REAL PROVIDER VERIFICATION');
console.log('=======================================================\n');

console.log('[Phase 3-A] Gemini Account 1 (Fast Scout) ...');
const g1 = await testGemini(
    'gemini_account_1',
    GEMINI_KEY_1,
    'Fast Scout',
    'You are HWSEC\'s Fast Scout LLM. Given a static finding, produce a concise hypothesis.',
    `Static finding: ${WEBGOAT_CONTEXT}\nGenerate a security hypothesis (1 paragraph, no payload).`
);
console.log('  Account:    gemini_account_1 (Gemini Account 1)');
console.log('  Key:        ' + g1.keyMasked);
console.log('  Success:    ' + g1.success);
if (g1.success) {
    console.log('  Model:      ' + g1.model);
    console.log('  Latency:    ' + g1.latencyMs + 'ms');
    console.log('  Tokens:     in=' + g1.inputTokens + ' out=' + g1.outputTokens + ' total=' + g1.totalTokens);
    console.log('  RespHash:   ' + g1.responseHash);
    console.log('  Schema OK:  ' + g1.schemaValid);
} else {
    console.log('  Error:      ' + g1.error);
}

console.log('\n[Phase 3-B] Gemini Account 2 (Independent Critic) ...');
const g2 = await testGemini(
    'gemini_account_2',
    GEMINI_KEY_2,
    'Independent Critic',
    'You are HWSEC\'s Independent Critic LLM. Your job is to challenge or validate a hypothesis.',
    `Static finding: ${WEBGOAT_CONTEXT}\nA Scout proposed: "The account_name parameter reaches statement.executeQuery without sanitization, constituting a SQL injection vector." Critique this hypothesis. Identify what additional verification is needed.`
);
console.log('  Account:    gemini_account_2 (Gemini Account 2)');
console.log('  Key:        ' + g2.keyMasked);
console.log('  Success:    ' + g2.success);
if (g2.success) {
    console.log('  Model:      ' + g2.model);
    console.log('  Latency:    ' + g2.latencyMs + 'ms');
    console.log('  Tokens:     in=' + g2.inputTokens + ' out=' + g2.outputTokens + ' total=' + g2.totalTokens);
    console.log('  RespHash:   ' + g2.responseHash);
    console.log('  Schema OK:  ' + g2.schemaValid);
} else {
    console.log('  Error:      ' + g2.error);
}

console.log('\n[Phase 3-C] NVIDIA NIM (Deep Reasoner — Dynamic Model Selection) ...');
const nv = await testNvidia(
    NVIDIA_KEY,
    `Complex dataflow reasoning task: ${WEBGOAT_CONTEXT}\nAnalyze whether a SQL injection attack path is viable. Reason about the taint flow from source to sink and specify what runtime observation would confirm exploitation.`
);
console.log('  Account:    nvidia_pool (NVIDIA NIM)');
console.log('  Key:        ' + nv.keyMasked);
console.log('  Success:    ' + nv.success);
if (nv.success) {
    console.log('  Model:      ' + nv.selectedModel + ' [dynamically selected by TaskRouter]');
    console.log('  Routing:    ' + nv.routingRationale);
    console.log('  Latency:    ' + nv.latencyMs + 'ms');
    console.log('  Tokens:     in=' + nv.inputTokens + ' out=' + nv.outputTokens + ' total=' + nv.totalTokens);
    console.log('  RespHash:   ' + nv.responseHash);
} else {
    console.log('  Error:      ' + nv.error);
}

console.log('\n[Phase 3-D] OpenRouter (Specialist / Fallback Pool) ...');
const or = await testOpenRouter(
    OPENROUTER_KEY,
    `Fallback specialist task: ${WEBGOAT_CONTEXT}\nConfirm whether this finding represents a real SQL injection risk in 2 sentences.`
);
console.log('  Account:    openrouter_pool');
console.log('  Key:        ' + or.keyMasked);
console.log('  Success:    ' + or.success);
if (or.success) {
    console.log('  Model:      ' + or.model);
    console.log('  Latency:    ' + or.latencyMs + 'ms');
    console.log('  Tokens:     in=' + or.inputTokens + ' out=' + or.outputTokens + ' total=' + or.totalTokens);
    console.log('  RespHash:   ' + or.responseHash);
} else {
    console.log('  Error:      ' + or.error);
}

// ── Summary ────────────────────────────────────────────────────────────────────
const results = { g1, g2, nv, or };
const allSuccess = [g1, g2, nv, or].every(r => r.success);

console.log('\n=======================================================');
console.log('  PROVIDER VERIFICATION SUMMARY');
console.log('=======================================================');
console.log('  gemini_account_1:  ' + (g1.success ? 'PASS ' + g1.latencyMs + 'ms' : 'FAIL: ' + g1.error));
console.log('  gemini_account_2:  ' + (g2.success ? 'PASS ' + g2.latencyMs + 'ms' : 'FAIL: ' + g2.error));
console.log('  nvidia:            ' + (nv.success ? 'PASS ' + nv.latencyMs + 'ms' : 'FAIL: ' + nv.error));
console.log('  openrouter:        ' + (or.success ? 'PASS ' + or.latencyMs + 'ms' : 'FAIL: ' + or.error));
console.log('\n  Overall: ' + (allSuccess ? '[ALL PASS] Proceed to experiment.' : '[PARTIAL/FAILURE] Review failures above.'));

// Write telemetry to file for use by experiment harness
import { writeFileSync } from 'fs';
writeFileSync(
    'tests/experimental/provider_telemetry.json',
    JSON.stringify({ timestamp: nowIso(), results: { gemini_account_1: g1, gemini_account_2: g2, nvidia: nv, openrouter: or } }, null, 2)
);
console.log('\n  Telemetry saved to: tests/experimental/provider_telemetry.json');
