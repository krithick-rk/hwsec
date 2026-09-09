import { loadConfig } from './src/core/config.js';
import { LLMGateway } from './src/core/llm/gateway.js';
import { createHash } from 'node:crypto';
import fs from 'node:fs';

async function runTest() {
    const config = loadConfig();
    const gw = new LLMGateway(config, null, 'interpreter');
    
    console.log('--- HWSEC LIVE LLM PROOF TEST ---');
    console.log('Gateway isAvailable:', gw.isAvailable());
    
    const results = [];
    
    // Test 1: Default/Preferred Provider (NVIDIA if configured, or router choice)
    const t0 = Date.now();
    try {
        const prompt = 'Return a short JSON object: {"status": "ok", "probe": "audit_verification"}';
        const res = await gw.generateContent('You are an automated security auditor.', prompt, null, { taskType: 'classification' });
        const latency = Date.now() - t0;
        const text = res.text || '';
        const hash = createHash('sha256').update(text).digest('hex');
        
        const capture = {
            provider: res.provider,
            actual_model_identifier: res.model,
            timestamp: new Date().toISOString(),
            request_trace_id: res.telemetry?.requestId || res.usage?.id || 'N/A',
            latency_ms: latency,
            input_tokens: res.usage?.input_tokens ?? res.usage?.prompt_tokens ?? null,
            output_tokens: res.usage?.output_tokens ?? res.usage?.completion_tokens ?? null,
            fallback_used: res.telemetry?.fallbackUsed || false,
            worker: 'interpreter (TaskType: classification)',
            response_hash: hash,
            response_snippet: text.trim().slice(0, 100)
        };
        console.log('Test 1 Result:', JSON.stringify(capture, null, 2));
        results.push({ test: 'Primary Provider', status: 'VERIFIED', capture });
    } catch (e) {
        console.error('Test 1 Failed:', e.message);
        results.push({ test: 'Primary Provider', status: 'FAILED', error: e.message });
    }

    // Test 2: Test OpenRouter specifically if available
    if (gw.router.providers.openrouter && gw.router.providers.openrouter.isAvailable()) {
        const t0_or = Date.now();
        try {
            const orProvider = gw.router.providers.openrouter;
            const resOr = await orProvider.generateChat({
                model: 'meta-llama/llama-3.3-70b-instruct',
                systemPrompt: 'You are an automated auditor.',
                userPrompt: 'Reply with JSON: {"provider": "openrouter", "verified": true}'
            });
            const latency_or = Date.now() - t0_or;
            const textOr = resOr.text || '';
            const hashOr = createHash('sha256').update(textOr).digest('hex');
            const captureOr = {
                provider: 'openrouter',
                actual_model_identifier: resOr.model || 'meta-llama/llama-3.3-70b-instruct',
                timestamp: new Date().toISOString(),
                request_trace_id: resOr.usage?.id || 'N/A',
                latency_ms: latency_or,
                input_tokens: resOr.usage?.prompt_tokens ?? null,
                output_tokens: resOr.usage?.completion_tokens ?? null,
                fallback_used: false,
                worker: 'direct_openrouter_test',
                response_hash: hashOr,
                response_snippet: textOr.trim().slice(0, 100)
            };
            console.log('Test 2 (OpenRouter) Result:', JSON.stringify(captureOr, null, 2));
            results.push({ test: 'OpenRouter Provider', status: 'VERIFIED', capture: captureOr });
        } catch (e) {
            console.error('Test 2 (OpenRouter) Failed:', e.message);
            results.push({ test: 'OpenRouter Provider', status: 'FAILED', error: e.message });
        }
    } else {
        results.push({ test: 'OpenRouter Provider', status: 'UNAVAILABLE' });
    }

    // Test 3: Test Gemini specifically if available
    if (gw.router.providers.gemini && gw.router.providers.gemini.isAvailable()) {
        const t0_gem = Date.now();
        try {
            const gemProvider = gw.router.providers.gemini;
            const resGem = await gemProvider.generateChat({
                model: 'gemini-2.5-flash',
                systemPrompt: 'You are an automated auditor.',
                userPrompt: 'Reply with JSON: {"provider": "gemini", "verified": true}'
            });
            const latency_gem = Date.now() - t0_gem;
            const textGem = resGem.text || '';
            const hashGem = createHash('sha256').update(textGem).digest('hex');
            const captureGem = {
                provider: 'gemini',
                actual_model_identifier: resGem.model || 'gemini-2.5-flash',
                timestamp: new Date().toISOString(),
                request_trace_id: 'N/A',
                latency_ms: latency_gem,
                input_tokens: resGem.usage?.prompt_tokens ?? null,
                output_tokens: resGem.usage?.completion_tokens ?? null,
                fallback_used: false,
                worker: 'direct_gemini_test',
                response_hash: hashGem,
                response_snippet: textGem.trim().slice(0, 100)
            };
            console.log('Test 3 (Gemini) Result:', JSON.stringify(captureGem, null, 2));
            results.push({ test: 'Gemini Provider', status: 'VERIFIED', capture: captureGem });
        } catch (e) {
            console.error('Test 3 (Gemini) Failed:', e.message);
            results.push({ test: 'Gemini Provider', status: 'FAILED', error: e.message });
        }
    }

    // Save proof artifact
    fs.writeFileSync('./scratch_live_llm_proof.json', JSON.stringify(results, null, 2));
    console.log('Artifact saved: scratch_live_llm_proof.json');
}

runTest().catch(console.error);
