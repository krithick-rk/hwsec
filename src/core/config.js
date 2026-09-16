import fs from 'fs';
import path from 'path';

/**
 * Loads a .env file into process.env if present
 */
export function loadEnvFile(envPath = null) {
    const candidates = [
        envPath,
        path.resolve(process.cwd(), '.env'),
        path.resolve(process.cwd(), '.env.local'),
        path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-zA-Z]:)/, '$1')), '../../.env')
    ].filter(Boolean);

    for (const p of candidates) {
        if (fs.existsSync(p)) {
            try {
                const content = fs.readFileSync(p, 'utf-8');
                for (const line of content.split('\n')) {
                    const trimmed = line.trim();
                    if (!trimmed || trimmed.startsWith('#')) continue;
                    const eqIdx = trimmed.indexOf('=');
                    if (eqIdx > 0) {
                        const key = trimmed.slice(0, eqIdx).trim();
                        let val = trimmed.slice(eqIdx + 1).trim();
                        // Strip quotes if present
                        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
                            val = val.slice(1, -1);
                        }
                        if (!process.env[key]) {
                            process.env[key] = val;
                        }
                    }
                }
                break;
            } catch {}
        }
    }
}

// Auto-load .env on module load
loadEnvFile();

/**
 * Recursively interpolates ${ENV_VAR} placeholders in config objects
 */
function interpolateEnv(val) {
    if (typeof val === 'string') {
        return val.replace(/\$\{([A-Z0-9_]+)\}/g, (match, varName) => {
            return process.env[varName] || '';
        });
    }
    if (Array.isArray(val)) {
        return val.map(interpolateEnv);
    }
    if (val && typeof val === 'object') {
        const out = {};
        for (const [k, v] of Object.entries(val)) {
            out[k] = interpolateEnv(v);
        }
        return out;
    }
    return val;
}

/**
 * Auto-detects OSS CAD Suite tool paths from environment variables.
 * Resolution order: OSS_CAD_SUITE -> YOSYSHQ_ROOT -> no-op (tools unavailable).
 * Never falls back to a hardcoded machine-specific path.
 */
function enrichToolPaths(config) {
    if (!config.tool_paths) {
        config.tool_paths = {};
    }

    // Resolve OSS CAD Suite root from environment variables only.
    const suiteRoot = process.env.OSS_CAD_SUITE || process.env.YOSYSHQ_ROOT || null;
    if (suiteRoot && fs.existsSync(suiteRoot)) {
        const binDir = path.join(suiteRoot, 'bin');
        if (fs.existsSync(binDir)) {
            const isWin = process.platform === 'win32';
            if (!config.tool_paths.sby) {
                const sby = path.join(binDir, isWin ? 'sby.exe' : 'sby');
                if (fs.existsSync(sby)) config.tool_paths.sby = sby.replace(/\\/g, '/');
            }
            if (!config.tool_paths.yosys) {
                const yosys = path.join(binDir, isWin ? 'yosys.exe' : 'yosys');
                if (fs.existsSync(yosys)) config.tool_paths.yosys = yosys.replace(/\\/g, '/');
            }
            if (!config.tool_paths.verilator) {
                // Verilator on Windows ships as verilator_bin.exe; the shell wrapper is absent.
                const verilatorBin = path.join(binDir, isWin ? 'verilator_bin.exe' : 'verilator');
                if (fs.existsSync(verilatorBin)) config.tool_paths.verilator = path.join(binDir, isWin ? 'verilator' : 'verilator').replace(/\\/g, '/');
            }
        }
    }
    // If no suite root is found, tool_paths are left empty — adapters will
    // fall through to WSL/PATH discovery or report UNAVAILABLE gracefully.

    return config;
}

export function loadConfig(configPath) {
    loadEnvFile();
    let config = {};

    if (fs.existsSync(configPath)) {
        let raw = fs.readFileSync(configPath, 'utf-8');
        try {
            // Strip BOM if present
            raw = raw.replace(/^\uFEFF/, '');
            config = JSON.parse(raw);
        } catch (e) {
            console.error(`[!] Failed to parse config file ${configPath}:`, e.message);
            return {};
        }
    }

    config = interpolateEnv(config);
    config = enrichToolPaths(config);

    // Fall back to process.env for standard providers if still empty
    if (config.llm_providers?.nvidia && !config.llm_providers.nvidia.api_key && process.env.NVIDIA_API_KEY) {
        config.llm_providers.nvidia.api_key = process.env.NVIDIA_API_KEY;
    }
    if (config.llm_providers?.gemini && !config.llm_providers.gemini.api_key && (process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY)) {
        config.llm_providers.gemini.api_key = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
    }

    return config;
}

/**
 * Returns a sanitized copy of the config safe for logging, telemetry, or reports.
 */
export function sanitizeConfig(config) {
    if (!config || typeof config !== 'object') return config;
    const sanitized = JSON.parse(JSON.stringify(config));

    function redact(obj) {
        for (const k of Object.keys(obj)) {
            if (typeof obj[k] === 'object' && obj[k] !== null) {
                redact(obj[k]);
            } else if (typeof obj[k] === 'string' && (k.includes('api_key') || k.includes('secret') || k.includes('password'))) {
                obj[k] = obj[k] ? '[REDACTED]' : '';
            }
        }
    }

    redact(sanitized);
    return sanitized;
}