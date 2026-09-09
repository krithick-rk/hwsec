import path from 'path';

export class JpfConfigBuilder {
    constructor(options = {}) {
        this.jpfHome = options.jpfHome || '/home/intern/hwsec-workspace/jpf-core';
        this.jpfSymbc = options.jpfSymbc || '/home/intern/hwsec-workspace/jpf-symbc';
        this.benchmarkRoot = options.benchmarkRoot || '/home/intern/hwsec-workspace/BenchmarkJava';
    }

    buildConfig(target, harnessClass = 'org.owasp.benchmark.concolic.ConcolicTargetHarness') {
        const limits = target.limits || {};
        const maxDepth = limits.max_depth || 20;
        const maxPaths = limits.max_paths || 100;
        const solverTimeout = limits.solver_timeout_ms || 10000;

        const classpath = [
            `${this.benchmarkRoot}/target/classes`,
            `${this.jpfSymbc}/build/jpf-symbc.jar`,
            `${this.jpfSymbc}/build/jpf-symbc-classes.jar`
        ].join(':');

        const lines = [
            `target = ${harnessClass}`,
            `target.args = --case,${target.case_id}`,
            `classpath = ${classpath}`,
            `symbolic.method = ${harnessClass}.evaluate(con#sym)`,
            `symbolic.dp = z3`,
            `search.depth_limit = ${maxDepth}`,
            `symbolic.max_paths = ${maxPaths}`,
            `symbolic.timeout = ${solverTimeout}`,
            `symbolic.min_int = -1000`,
            `symbolic.max_int = 1000`,
            `vm.storage.class = nil`
        ];

        return lines.join('\n') + '\n';
    }
}
