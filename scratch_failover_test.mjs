import { loadConfig } from './src/core/config.js';
import { LLMGateway } from './src/core/llm/gateway.js';
import { ModelRouter } from './src/core/llm/modelRouter.js';

async function testFailover() {
    const config = loadConfig();
    const gw = new LLMGateway(config, null, 'interpreter');

    console.log('--- CONTROLLED LLM PROVIDER FAILOVER TEST ---');
    
    // Simulate primary provider failure by corrupting its apiKey/endpoint temporarily in router
    const primaryName = gw.router.registry.findBestModel({ provider: 'gemini' }) ? 'gemini' : 'openrouter';
    console.log('Original active providers:', Object.keys(gw.router.providers).filter(k => gw.router.providers[k].isAvailable()));
    
    // Invalidate primary provider's availability
    const originalGemini = gw.router.providers.gemini;
    gw.router.providers.gemini = {
        isAvailable: () => false,
        generateChat: async () => { throw new Error('Simulated primary provider outage (HTTP 503)'); }
    };
    
    try {
        const res = await gw.execute({
            taskType: 'classification',
            systemPrompt: 'You are an auditor.',
            userPrompt: 'Reply with JSON: {"failover": true}'
        });
        console.log('Failover succeeded! Received response from provider:', res.provider, 'model:', res.model);
        console.log('Telemetry fallbackUsed:', res.telemetry?.fallbackUsed);
        return { success: true, providerUsed: res.provider, modelUsed: res.model };
    } catch (err) {
        console.error('Failover failed:', err.message);
        return { success: false, error: err.message };
    } finally {
        gw.router.providers.gemini = originalGemini;
    }
}

testFailover().then(r => console.log('Result:', JSON.stringify(r)));
