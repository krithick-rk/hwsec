import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { RuntimeExecutor } from '../../runtime/runtimeExecutor.js';

export class ConcolicReplayValidator {
    constructor(options = {}) {
        this.runtimeExecutor = new RuntimeExecutor(options);
        this.artifactsDir = path.resolve(options.artifactsDir || 'prototype/artifacts/concolic');
    }

    replayConcolicResult(concolicResult) {
        if (concolicResult.status !== 'SAT' || !concolicResult.generated_input) {
            return {
                case_id: concolicResult.case_id,
                replayed: false,
                status: `SKIPPED_${concolicResult.status}`,
                reason: 'Only SAT results with concrete generated inputs can be replayed'
            };
        }

        const caseId = concolicResult.case_id;
        const payload = concolicResult.generated_input.raw_value;

        // Execute against explicit Java 8 RuntimeExecutor from Phase 1
        const execResult = this.runtimeExecutor.executeCase(caseId, payload);

        const replayArtifact = {
            case_id: caseId,
            target_id: concolicResult.target_id,
            replayed: true,
            status: execResult.execution.exit_code === 0 ? 'REPRODUCED' : 'DIVERGED',
            concrete_payload: payload,
            exit_code: execResult.execution.exit_code,
            sink_events: execResult.execution.parsed_harness_result?.sink_events || [],
            stdout_sha256: execResult.execution.stdout_sha256,
            stderr_sha256: execResult.execution.stderr_sha256,
            timestamp: new Date().toISOString()
        };

        const replayPath = path.join(this.artifactsDir, `${caseId}_replay.json`);
        fs.writeFileSync(replayPath, JSON.stringify(replayArtifact, null, 2), 'utf8');

        return replayArtifact;
    }
}
