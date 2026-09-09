import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

/**
 * Phase 1 Build Manager
 * 
 * Enforces reproducible, isolated Java 8 build of the benchmark subset.
 * Records comprehensive build provenance: JDK version, Maven version,
 * repository commit, dependency state, and output artifact hashes.
 */
export class BuildManager {
    constructor(benchmarkRoot = null, wslDistro = 'Ubuntu') {
        this.wslDistro = wslDistro;
        this.benchmarkRoot = benchmarkRoot || '/home/intern/hwsec-workspace/BenchmarkJava';
        this.mavenJdk = '/usr/lib/jvm/java-21-openjdk-amd64';
        this.targetJdk = '/usr/lib/jvm/java-8-openjdk-amd64';
    }

    /**
     * Executes WSL command and returns stdout.
     */
    execWsl(cmd) {
        const res = spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '-c', cmd], {
            encoding: 'utf8',
            maxBuffer: 10 * 1024 * 1024
        });
        return {
            status: res.status,
            stdout: res.stdout || '',
            stderr: res.stderr || ''
        };
    }

    /**
     * Inspects build environment and returns version metadata.
     */
    inspectEnvironment() {
        const jdkRes = this.execWsl(`${this.targetJdk}/bin/java -version 2>&1`);
        const mavenRes = this.execWsl(`export JAVA_HOME=${this.mavenJdk}; mvn -version 2>&1`);
        const gitRes = this.execWsl(`cd ${this.benchmarkRoot} && git rev-parse HEAD 2>&1 || echo "NO_GIT"`);

        return {
            target_jdk: {
                path: this.targetJdk,
                version: jdkRes.stdout.split('\n')[0].trim()
            },
            maven_toolchain: {
                java_home: this.mavenJdk,
                version: mavenRes.stdout.split('\n')[0].trim()
            },
            repository_revision: gitRes.stdout.trim()
        };
    }

    /**
     * Executes the reproducible benchmark build and returns provenance record.
     */
    executeBuild() {
        const envInfo = this.inspectEnvironment();
        const buildCommand = `export JAVA_HOME=${this.mavenJdk}; cd ${this.benchmarkRoot} && mvn compile dependency:build-classpath -Dspotless.check.skip=true -Dspotless.apply.skip=true -Dmdep.outputFile=target/dependency-classpath.txt`;

        const startTime = new Date().toISOString();
        const res = this.execWsl(buildCommand);
        const endTime = new Date().toISOString();

        if (res.status !== 0) {
            throw new Error(`Benchmark build failed with code ${res.status}: ${res.stderr || res.stdout}`);
        }

        // Also compile the prototype harness classes into target/classes
        const harnessCompileCmd = `bash /mnt/e/Intern/hwsec/prototype/build/ensure_harnesses.sh`;
        const harnessRes = this.execWsl(harnessCompileCmd);
        if (harnessRes.status !== 0) {
            throw new Error(`Harness compilation failed: ${harnessRes.stderr || harnessRes.stdout}`);
        }

        // Compute hashes of key build artifacts
        const artifactHashes = {};
        const pomRes = this.execWsl(`sha256sum ${this.benchmarkRoot}/pom.xml | awk '{print $1}'`);
        artifactHashes['pom.xml'] = pomRes.stdout.trim();

        const cpRes = this.execWsl(`sha256sum ${this.benchmarkRoot}/target/dependency-classpath.txt | awk '{print $1}'`);
        artifactHashes['dependency-classpath.txt'] = cpRes.stdout.trim();

        const harnessResHash = this.execWsl(`sha256sum ${this.benchmarkRoot}/target/classes/org/owasp/benchmark/harness/HarnessRunner.class | awk '{print $1}'`);
        artifactHashes['HarnessRunner.class'] = harnessResHash.stdout.trim();

        const provenance = {
            build_id: `BUILD-${crypto.randomBytes(4).toString('hex')}`,
            started_at: startTime,
            completed_at: endTime,
            exit_code: res.status,
            environment: envInfo,
            build_command: buildCommand,
            artifact_hashes: artifactHashes,
            status: 'SUCCESS'
        };

        const manifestDir = path.resolve('prototype/manifests');
        fs.mkdirSync(manifestDir, { recursive: true });
        fs.writeFileSync(path.join(manifestDir, 'build_provenance.json'), JSON.stringify(provenance, null, 2));

        return provenance;
    }
}
