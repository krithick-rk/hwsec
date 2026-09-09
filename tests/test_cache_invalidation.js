import assert from 'assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { ContentAddressedCacheManager } from '../src/core/knowledge/cacheManager.js';

console.log('[*] Running Phase 11: Content-Addressed Cache Invalidation Tests...');

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hwsec-cache-test-'));
const cacheDir = path.join(tempDir, 'cache');
const cache = new ContentAddressedCacheManager(cacheDir);

const fileA = path.join(tempDir, 'ModuleA.java');
const fileB = path.join(tempDir, 'ModuleB.java');
const fileC = path.join(tempDir, 'ModuleC.java');

fs.writeFileSync(fileA, 'public class ModuleA { int x = 1; }');
fs.writeFileSync(fileB, 'public class ModuleB { int y = 2; }');
fs.writeFileSync(fileC, 'public class ModuleC { int z = 3; }');

// 1. Create cache entries
const keyAB = cache.computeCacheKey({ files: [fileA, fileB], toolId: 'semgrep', toolVersion: '1.0' });
const keyC = cache.computeCacheKey({ files: [fileC], toolId: 'semgrep', toolVersion: '1.0' });

cache.set({ cacheKey: keyAB, files: [fileA, fileB], data: { findings: ['FindingAB'] } });
cache.set({ cacheKey: keyC, files: [fileC], data: { findings: ['FindingC'] } });

// Verify both are cached
const cachedAB1 = cache.get(keyAB);
const cachedC1 = cache.get(keyC);

assert(cachedAB1 !== null, 'Entry AB should be cached');
assert.strictEqual(cachedAB1.data.findings[0], 'FindingAB');
assert.strictEqual(cachedAB1.metadata.reuse_reason, 'CONTENT_AND_CONFIG_IDENTICAL_MATCH');

assert(cachedC1 !== null, 'Entry C should be cached');
assert.strictEqual(cachedC1.data.findings[0], 'FindingC');

console.log('[+] Initial cache hits verified.');

// 2. Modify fileA only
fs.writeFileSync(fileA, 'public class ModuleA { int x = 999; /* modified */ }');

// 3. Confirm only affected analysis (keyAB) is invalidated, and unaffected (keyC) remains valid!
const cachedAB2 = cache.get(keyAB);
const cachedC2 = cache.get(keyC);

assert.strictEqual(cachedAB2, null, 'Entry AB must be invalidated after modifying fileA');
assert(cachedC2 !== null, 'Entry C must remain valid when fileA changes!');
assert.strictEqual(cachedC2.data.findings[0], 'FindingC');

console.log('[+] Granular invalidation confirmed: keyAB invalidated, keyC preserved.');

// Cleanup
try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (_) {}
console.log('✅ Phase 11: Content-Addressed Cache Invalidation Test Passed!');
