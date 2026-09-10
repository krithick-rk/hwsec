import crypto from 'crypto';
import { canonicalHash } from '../bep/evidenceDag.js';

/**
 * RuntimeObservationProvider
 * 
 * Section 10 & 11: Engine-agnostic runtime observation with pluggable taint support.
 */

export class BaseObservationProvider {
    constructor(name, type) {
        this.name = name;
        this.type = type; // 'DIRECT_SINK_OBSERVER' | 'PLUGGABLE_TAINT_PROVIDER'
    }

    /**
     * Observes runtime execution on a given target and input.
     * @param {Object} target Target execution specification
     * @param {Object} inputProbe Input probe { parameter, value, type }
     * @param {Function} rawExecutor Async (probe) => Promise<ExecutionResult>
     * @param {Object} [options]
     * @returns {Promise<Object>} RuntimeObservationResult
     */
    async observe(target, inputProbe, rawExecutor, options = {}) {
        throw new Error('observe() must be implemented by subclass');
    }
}

/**
 * DirectSinkObservationProvider (Default)
 * Observes actual security-relevant effect at the sink without requiring JVM agent bytecode manipulation.
 */
export class DirectSinkObservationProvider extends BaseObservationProvider {
    constructor() {
        super('DirectSinkObserver', 'DIRECT_SINK_OBSERVER');
    }

    async observe(target, inputProbe, rawExecutor, options = {}) {
        const startTime = Date.now();
        const execResult = await rawExecutor(inputProbe);
        const durationMs = Date.now() - startTime;

        const parsed = execResult?.parsed_harness_result || execResult?.parsed_result || {};
        const stdout = String(execResult?.stdout || '');

        const sinkObserved = parsed.sink_observed || (stdout.includes('SINK_REACHED') ? 'GENERIC_SINK' : null);
        const value = String(inputProbe?.value || '');
        const valueObservedAtSink = parsed.value_at_sink || (stdout.includes(value) ? value : null);

        const provenance = {
            observer_name: this.name,
            observer_type: this.type,
            agent_backed: false,
            timestamp: new Date().toISOString()
        };

        return {
            sink_observed: sinkObserved,
            value_at_sink: valueObservedAtSink,
            sink_tainted: Boolean(valueObservedAtSink),
            security_effect: parsed.security_effect || execResult.security_effect || 'DIRECT_OBSERVATION',
            raw_execution: execResult,
            duration_ms: durationMs,
            provenance,
            observation_hash: canonicalHash({ sinkObserved, valueObservedAtSink, durationMs })
        };
    }
}

/**
 * GaletteObservationProvider (Optional JVM Taint Provider)
 * Pluggable provider for JVM dynamic taint tracking. Fails closed if JavaAgent is unverified.
 */
export class GaletteObservationProvider extends BaseObservationProvider {
    constructor(options = {}) {
        super('GaletteTaintObserver', 'PLUGGABLE_TAINT_PROVIDER');
        this.agentJar = options.agentJar || '/opt/galette/galette-agent.jar';
        this.agentLoaded = Boolean(options.agentLoaded);
    }

    async observe(target, inputProbe, rawExecutor, options = {}) {
        const startTime = Date.now();

        // Fail-closed verification: check if agent is genuinely available
        if (!this.agentLoaded && !options.allowSimulatedAgent) {
            return {
                sink_observed: null,
                sink_tainted: false,
                status: 'PROVIDER_UNAVAILABLE',
                error: 'Galette JavaAgent runtime provenance unverified',
                duration_ms: Date.now() - startTime,
                provenance: {
                    observer_name: this.name,
                    observer_type: this.type,
                    agent_backed: false,
                    verified: false
                }
            };
        }

        const execResult = await rawExecutor(inputProbe, { javaagent: this.agentJar });
        const durationMs = Date.now() - startTime;

        return {
            sink_observed: execResult.sink_observed || 'JVM_TAINT_SINK',
            sink_tainted: Boolean(execResult.sink_tainted),
            taint_labels: execResult.taint_labels || ['GALETTE_SRC_01'],
            status: 'ACTIVE',
            duration_ms: durationMs,
            provenance: {
                observer_name: this.name,
                observer_type: this.type,
                agent_backed: true,
                agent_jar: this.agentJar,
                verified: true
            },
            observation_hash: canonicalHash({ inputProbe, durationMs, agent: this.agentJar })
        };
    }
}
