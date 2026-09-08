import assert from 'assert';
import path from 'path';
import fs from 'fs';
import { BenchmarkManager, BenchmarkCrawler } from '../src/core/benchmark.js';

console.log("=== Running HWSEC Benchmark Crawler & Ground Truth Tests ===");

// 1. Test Benchmark Configuration Loading
console.log("[Test 1] Testing BenchmarkManager config loading and skipped targets...");
const manager = new BenchmarkManager();
const active = manager.getActiveBenchmarks();
const skipped = manager.getSkippedBenchmarks();

assert(active.length > 0, "Must have active installed benchmarks");
assert(skipped.length >= 3, "Must have at least 3 skipped benchmarks (bigvul, diversevul, juliet java)");

const skippedKeys = skipped.map(s => s.key);
console.log(`  -> Skipped targets: ${skippedKeys.join(', ')}`);
assert(skippedKeys.includes('c/bigvul'), "c/bigvul must be skipped");
assert(skippedKeys.includes('c/diversevul'), "c/diversevul must be skipped");
assert(skippedKeys.includes('java/juliet'), "java/juliet must be skipped");
console.log("  -> Configuration loading and skipping verified.");

// 2. Test Safe Handling of Missing / Skipped Directories (No Throw)
console.log("[Test 2] Testing error suppression for missing directories on skipped datasets...");
for (const s of skipped) {
    // If the directory does not exist or is empty, getActiveBenchmarks must not include it
    const isInActive = active.some(a => a.key === s.key);
    assert.strictEqual(isInActive, false, `Skipped dataset ${s.key} must not be present in active benchmarks`);
}
console.log("  -> Missing-path error suppression verified.");

// 3. Test High-Performance Crawler Stability across Datasets
console.log("[Test 3] Testing BenchmarkCrawler stability and memory consumption...");
const crawler = new BenchmarkCrawler();

// Test crawling Juliet C (106,093 files)
const julietC = active.find(a => a.key === 'c/juliet');
assert(julietC, "Juliet C benchmark must be present in active list");

const t0 = Date.now();
const julietCRes = crawler.crawlDirectory(julietC.resolvedPath);
const crawlDuration = Date.now() - t0;

console.log(`  -> Crawled ${julietCRes.totalFiles.toLocaleString()} files in ${crawlDuration}ms`);
console.log(`  -> Memory Heap: Start ${julietCRes.memory.startHeapMb}MB, Peak ${julietCRes.memory.peakHeapMb}MB, End ${julietCRes.memory.endHeapMb}MB`);

assert(julietCRes.totalFiles > 100000, "Juliet C must have >100,000 files");
assert(julietCRes.memory.peakHeapMb < 250, "Peak heap memory during crawl must remain under 250MB");
console.log("  -> Crawler performance and memory stability verified.");

// 4. Test Ground Truth Path Resolution & Sanity Validation
console.log("[Test 4] Validating 100% on-disk file existence for all ground truth entries...");
const validation = manager.validateGroundTruth();

console.log(`  -> Total ground truth entries: ${validation.total_entries.toLocaleString()}`);
console.log(`  -> Valid on-disk paths: ${validation.valid_entries.toLocaleString()}`);
console.log(`  -> Missing paths: ${validation.missing_entries}`);

assert.strictEqual(validation.missing_entries, 0, "No ground truth entries may reference missing files");
assert.strictEqual(validation.passed, true, "Ground truth validation must pass 100%");
assert(validation.total_entries > 60000, "Must contain >60,000 verified entries across datasets");

for (const [ds, stat] of Object.entries(validation.breakdown)) {
    console.log(`     * ${ds.padEnd(16)}: ${stat.valid} / ${stat.total} verified`);
    assert.strictEqual(stat.missing, 0, `Dataset ${ds} must have 0 missing files`);
}

console.log("\n[PASS] All Benchmark Crawler & Ground Truth tests passed successfully!\n");
