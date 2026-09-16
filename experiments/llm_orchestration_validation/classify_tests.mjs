/**
 * HWSEC LLM Orchestration Validation - Phase 3: Mock vs Live Classification
 * 
 * Inspects all existing test files across tests/ and tests/experimental/
 * Classifies each test into:
 *   - MOCKED: Uses synthetic providers, stubs, spies, canned responses, or in-memory fakes.
 *   - LIVE: Makes real external HTTP network requests to live provider APIs without stubs.
 *   - MIXED: Contains both offline synthetic unit scenarios and optional/conditional live calls.
 * 
 * Strictly segregates:
 *   A. Orchestration Logic Validation
 *   B. Real Provider Operational Validation
 */

import fs from 'fs';
import path from 'path';

function inspectFile(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const filename = path.basename(filePath);

    const hasLiveFetch = content.includes('fetch(') || content.includes('generateChat(') || content.includes('execute(');
    const hasMockKeywords = /mock|stub|fake|synthetic|dummy|canned|fixture/i.test(content);
    const hasNetworkCall = /https:\/\/(generativelanguage|integrate\.api\.nvidia|openrouter\.ai)/.test(content);
    const hasMockProvider = /MockLLMProvider|MockProvider|fakeProvider|createMock/i.test(content);

    let classification = 'MOCKED';
    let rationale = '';

    if (filename.includes('verify_providers') || filename.includes('scratch_live_llm_proof') || filename.includes('probe_providers')) {
        classification = 'LIVE';
        rationale = 'Makes direct HTTP calls to real provider endpoints with live API keys and evaluates external response';
    } else if (filename.includes('adversarial_llm_team') || filename.includes('wp12_gateway') || filename.includes('wp2_nvidia')) {
        if (content.includes('Mock') || content.includes('mock') || !hasNetworkCall) {
            classification = 'MOCKED';
            rationale = 'Tests orchestration, circuit breaker, or budget logic using local mock classes or synthetic responses';
        } else {
            classification = 'MIXED';
            rationale = 'Mixes mocked unit validation with fallback provider integration';
        }
    } else if (hasNetworkCall && hasMockKeywords) {
        classification = 'MIXED';
        rationale = 'Contains mock harnesses alongside real provider endpoints';
    } else if (hasNetworkCall) {
        classification = 'LIVE';
        rationale = 'Calls external provider endpoint without mocking';
    } else {
        classification = 'MOCKED';
        rationale = 'Deterministic offline execution using local components and fixtures';
    }

    // Determine category: LLM-specific vs Non-LLM
    const isLlmTest = /llm|provider|gateway|model|prompt|debate|consensus|scout|critic|reasoner|token_budget/i.test(content) ||
                      /llm|gateway|nvidia|gemini/i.test(filename);

    return {
        file: filename,
        path: filePath,
        isLlmTest,
        classification,
        rationale
    };
}

function runClassification() {
    console.log('=====================================================');
    console.log('  HWSEC PHASE 3: MOCK VS LIVE TEST CLASSIFICATION');
    console.log('=====================================================\n');

    const testDirs = ['tests', 'tests/experimental'];
    const inspected = [];

    for (const d of testDirs) {
        if (!fs.existsSync(d)) continue;
        const files = fs.readdirSync(d);
        for (const f of files) {
            const fullPath = path.join(d, f);
            if (fs.statSync(fullPath).isFile() && (f.endsWith('.js') || f.endsWith('.mjs'))) {
                inspected.push(inspectFile(fullPath));
            }
        }
    }

    const llmTests = inspected.filter(t => t.isLlmTest);
    const nonLlmTests = inspected.filter(t => !t.isLlmTest);

    const sectionA_OrchestrationLogic = llmTests.filter(t => t.classification === 'MOCKED');
    const sectionB_RealProviderOperational = llmTests.filter(t => t.classification === 'LIVE');
    const sectionMixed = llmTests.filter(t => t.classification === 'MIXED');

    console.log(`[Summary] Total Test Files Inspected: ${inspected.length}`);
    console.log(`  -> LLM-Related Tests: ${llmTests.length}`);
    console.log(`  -> Section A (Orchestration Logic / Mocked): ${sectionA_OrchestrationLogic.length}`);
    console.log(`  -> Section B (Real Provider Operational / Live): ${sectionB_RealProviderOperational.length}`);
    console.log(`  -> Mixed Tests: ${sectionMixed.length}`);
    console.log(`  -> Non-LLM Deterministic Tests: ${nonLlmTests.length}\n`);

    console.log('--- SECTION A: ORCHESTRATION LOGIC VALIDATION (MOCKED / OFFLINE) ---');
    for (const t of sectionA_OrchestrationLogic) {
        console.log(`  [MOCKED] ${t.file}: ${t.rationale}`);
    }

    console.log('\n--- SECTION B: REAL PROVIDER OPERATIONAL VALIDATION (LIVE) ---');
    for (const t of sectionB_RealProviderOperational) {
        console.log(`  [LIVE]   ${t.file}: ${t.rationale}`);
    }

    if (sectionMixed.length > 0) {
        console.log('\n--- MIXED VALIDATION (CONTAINING BOTH MODES) ---');
        for (const t of sectionMixed) {
            console.log(`  [MIXED]  ${t.file}: ${t.rationale}`);
        }
    }

    const outputData = {
        timestamp: new Date().toISOString(),
        totalInspected: inspected.length,
        llmTestsCount: llmTests.length,
        breakdown: {
            mockedCount: sectionA_OrchestrationLogic.length,
            liveCount: sectionB_RealProviderOperational.length,
            mixedCount: sectionMixed.length,
            nonLlmDeterministicCount: nonLlmTests.length
        },
        sectionA_orchestrationLogicMocked: sectionA_OrchestrationLogic,
        sectionB_realProviderOperationalLive: sectionB_RealProviderOperational,
        sectionMixed,
        allTests: inspected
    };

    const outPath = path.resolve('reports/llm_orchestration/mock_vs_live_classification.json');
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(outputData, null, 2), 'utf-8');
    console.log(`\n[+] Classification saved to: ${outPath}`);

    return outputData;
}

runClassification();
