import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const baseDir = __dirname;

console.log('======================================================');
console.log('  HWSEC Quality Benchmark Automated Setup & Ingestion ');
console.log('======================================================\n');

// 1. Exact Directory Structure Specification
const directories = [
    'c/juliet',
    'c/bigvul',
    'c/diversevul',
    'cpp/juliet',
    'cpp/bigvul',
    'cpp/diversevul',
    'java/juliet',
    'java/owasp-benchmark',
    'java/vul4j',
    'java/webgoat',
    'java/vulnerableapp',
    'go/go-test-bench',
    'python/pygoat',
    'cross-project/selected-real-projects',
    'manifests'
];

console.log('[*] Phase 1: Creating target directory structure...');
for (const dir of directories) {
    const fullPath = path.join(baseDir, dir);
    if (!fs.existsSync(fullPath)) {
        fs.mkdirSync(fullPath, { recursive: true });
        console.log(`  [+] Created directory: ${dir}`);
    } else {
        console.log(`  [=] Directory exists: ${dir}`);
    }
}

// 2. Automated Git Repository Targets
const autoTargets = [
    {
        name: 'OWASP Benchmark Java',
        dir: 'java/owasp-benchmark',
        repo: 'https://github.com/OWASP-Benchmark/BenchmarkJava.git'
    },
    {
        name: 'Vul4J (Java reproducible vulnerabilities)',
        dir: 'java/vul4j',
        repo: 'https://github.com/tuhh-softsec/vul4j.git'
    },
    {
        name: 'OWASP WebGoat',
        dir: 'java/webgoat',
        repo: 'https://github.com/WebGoat/WebGoat.git'
    },
    {
        name: 'SasanLabs VulnerableApp',
        dir: 'java/vulnerableapp',
        repo: 'https://github.com/SasanLabs/VulnerableApp.git'
    },
    {
        name: 'Go Test Bench',
        dir: 'go/go-test-bench',
        repo: 'https://github.com/Contrast-Security-OSS/go-test-bench.git'
    },
    {
        name: 'OWASP PyGoat',
        dir: 'python/pygoat',
        repo: 'https://github.com/adeyosemanputra/pygoat.git'
    }
];

console.log('\n[*] Phase 2: Fetching automated public benchmark repositories...');
const successes = [];
const skipped = [];
const failures = [];

for (const target of autoTargets) {
    const targetPath = path.join(baseDir, target.dir);
    const gitDir = path.join(targetPath, '.git');
    
    console.log(`\n -> Processing ${target.name} (${target.dir})...`);
    
    if (fs.existsSync(gitDir)) {
        console.log(`    [!] Skipping clone: Repository already initialized at ${target.dir}`);
        skipped.push(target);
        continue;
    }

    try {
        const contents = fs.readdirSync(targetPath);
        if (contents.length > 0) {
            console.log(`    [*] Cleaning pre-existing empty folder structure for clone...`);
            fs.rmSync(targetPath, { recursive: true, force: true });
        }

        console.log(`    [*] Executing: git clone --depth 1 ${target.repo} ${target.dir}`);
        execSync(`git clone --depth 1 ${target.repo} "${targetPath}"`, {
            stdio: 'inherit',
            cwd: baseDir
        });
        console.log(`    [+] Successfully cloned ${target.name}`);
        successes.push(target);
    } catch (err) {
        console.error(`    [-] Failed to clone ${target.name}: ${err.message}`);
        failures.push({ ...target, error: err.message });
    }
}

console.log('\n======================================================');
console.log(' AUTOMATED FETCH SUMMARY');
console.log('======================================================');
console.log(`  - Successfully Cloned: ${successes.length}`);
console.log(`  - Pre-existing / Skipped: ${skipped.length}`);
console.log(`  - Failed: ${failures.length}`);
console.log('\nFor datasets requiring manual download/extraction (NIST Juliet, Big-Vul, DiverseVul),');
console.log('please refer to MANUAL_SETUP.md in the quality-benchmark directory.\n');
