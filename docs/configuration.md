# HWSEC Configuration Reference

HWSEC is configured via two files: `.env` (credentials and tool paths) and `config.json` (model routing, budgets, and tool configuration).

---

## `.env` — Environment Variables

Copy `.env.example` to `.env` and populate with your credentials. **Never commit `.env`.**

### LLM Provider Keys

| Variable | Required | Description |
|---|---|---|
| `NVIDIA_API_KEY` | Optional | [NVIDIA NIM](https://build.nvidia.com/) API key |
| `GEMINI_API_KEY` | Optional | Google Gemini API key (Account 1) |
| `GEMINI_API_KEY_2` | Optional | Gemini key (Account 2 — pool redundancy) |
| `GEMINI_API_KEY_3` | Optional | Gemini key (Account 3 — pool redundancy) |
| `OPENROUTER_API_KEY` | Optional | [OpenRouter](https://openrouter.ai/) API key |

At least one provider key is required for LLM-assisted analysis. If no keys are available, HWSEC runs in deterministic-only mode (static analysis without LLM hypothesis generation).

### Hardware Tool Paths

| Variable | Description | Example |
|---|---|---|
| `OSS_CAD_SUITE` | Path to OSS CAD Suite installation root | `/opt/oss-cad-suite` |
| `YOSYSHQ_ROOT` | Alternative: YosysHQ distribution root | `/opt/yosyshq` |
| `JOERN_HOME` | Path to Joern installation root | `/opt/joern` |

If `OSS_CAD_SUITE` or `YOSYSHQ_ROOT` is set, HWSEC auto-configures paths for `verilator`, `yosys`, and `sby`. If neither is set, tools fall back to system PATH.

### Vector Memory

| Variable | Description | Default |
|---|---|---|
| `QDRANT_URL` | Qdrant REST API URL | `http://localhost:6333` |
| `QDRANT_API_KEY` | Qdrant API key (for hosted Qdrant) | — |

---

## `config.json` — Framework Configuration

### Full Schema

```json
{
  "llm_providers": {
    "default": {
      "provider": "gemini",
      "api_key": "${GEMINI_API_KEY}",
      "model": "gemini-2.5-flash"
    },
    "nvidia": {
      "api_key": "${NVIDIA_API_KEY}",
      "base_url": "https://integrate.api.nvidia.com/v1",
      "model": "meta/llama-3.3-70b-instruct"
    },
    "gemini": {
      "api_key": "${GEMINI_API_KEY}",
      "model": "gemini-2.5-flash"
    },
    "openrouter": {
      "api_key": "${OPENROUTER_API_KEY}",
      "model": "meta-llama/llama-3.3-70b-instruct"
    }
  },
  "models": {
    "fast":             { "provider": "gemini",     "model": "gemini-2.5-flash" },
    "reasoning":        { "provider": "nvidia",     "model": "deepseek-ai/deepseek-r1" },
    "verifier":         { "provider": "gemini",     "model": "gemini-2.5-pro" },
    "exploit_writer":   { "provider": "openrouter", "model": "meta-llama/llama-3.3-70b-instruct" },
    "exploit_verifier": { "provider": "gemini",     "model": "gemini-2.5-flash" }
  },
  "tool_paths": {
    "verilator": "${OSS_CAD_SUITE}/bin/verilator",
    "yosys":     "${OSS_CAD_SUITE}/bin/yosys",
    "sby":       "${OSS_CAD_SUITE}/bin/sby",
    "joern":     "${JOERN_HOME}/joern-cli",
    "codeql":    "codeql",
    "spike":     "spike"
  },
  "qdrant": {
    "url":     "http://localhost:6333",
    "enabled": false
  },
  "token_budgets": {
    "max_cost_usd": 10.0,
    "rate_limits": {
      "gemini":     30,
      "openrouter": 20,
      "nvidia":     5
    }
  },
  "exploit_verifier": {
    "enabled":             true,
    "max_attempts":        3,
    "max_runtime_seconds": 120,
    "max_tokens":          16000,
    "network":             "none",
    "sandbox":             "strict",
    "allow_poc_execution": true
  }
}
```

### Field Reference

#### `llm_providers`

| Field | Description |
|---|---|
| `default` | Default provider used when no task-specific routing applies |
| `nvidia.base_url` | NVIDIA NIM endpoint (default: `https://integrate.api.nvidia.com/v1`) |
| `gemini.model` | Default Gemini model for this provider |

`${ENV_VAR}` placeholders in string values are interpolated from environment at load time.

#### `models`

Task-specific model routing. Roles:

| Role | Used For |
|---|---|
| `fast` | Quick triage, suspicion scoring |
| `reasoning` | Deep hypothesis generation, complex dataflow |
| `verifier` | Critique and validation of findings |
| `exploit_writer` | Proof-of-impact test generation |
| `exploit_verifier` | Sandbox execution review |

#### `tool_paths`

Explicit binary paths. Supports `${ENV_VAR}` interpolation. If a path does not exist, the tool is reported `UNAVAILABLE` — no error is thrown.

#### `qdrant`

| Field | Description | Default |
|---|---|---|
| `url` | Qdrant REST endpoint | `http://localhost:6333` |
| `enabled` | Whether to use vector memory | `false` |

#### `token_budgets`

| Field | Description |
|---|---|
| `max_cost_usd` | Hard cap on estimated LLM spend per analysis run |
| `rate_limits.gemini` | Max requests per minute to Gemini |
| `rate_limits.openrouter` | Max requests per minute to OpenRouter |
| `rate_limits.nvidia` | Max requests per minute to NVIDIA NIM |

#### `exploit_verifier`

Controls the `ProofSandbox` behavior:

| Field | Description |
|---|---|
| `enabled` | Whether to attempt proof-of-impact execution |
| `max_attempts` | Max times to retry a failing proof attempt |
| `max_runtime_seconds` | Hard timeout per sandbox execution |
| `max_tokens` | Max tokens for proof code generation |
| `network` | Network policy for sandbox (`none` = no outbound) |
| `sandbox` | Sandbox mode (`strict` = credential stripping + network neutralization) |
| `allow_poc_execution` | Whether to run compiled proof code. Set `false` to generate but not execute |

---

## Configuration Loading Priority

Config values are resolved in this order (later wins):

1. Built-in defaults (in `src/core/config.js`)
2. `config.json` values
3. `${ENV_VAR}` interpolation from `.env` / environment
4. `OSS_CAD_SUITE` / `JOERN_HOME` env vars (auto-enrich tool paths)
5. Direct `process.env` fallback for provider API keys

---

## Minimal Configuration (Gemini Only)

The smallest working configuration:

**.env**
```bash
GEMINI_API_KEY=your_key_here
```

**config.json**
```json
{
  "llm_providers": {
    "default": { "provider": "gemini", "api_key": "${GEMINI_API_KEY}", "model": "gemini-2.5-flash" }
  }
}
```

This enables: static analysis (Semgrep, if installed), LLM hypothesis generation, and evidence-based verdict reduction. Hardware tools require `OSS_CAD_SUITE`.
