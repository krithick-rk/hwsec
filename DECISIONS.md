# HWSEC Architectural Decisions Log

Generated: 2026-09-08T10:55:11+05:30

---

## ADR-001: Three-Provider LLM Gateway (nvidia → gemini → openrouter)

**Date**: 2026-09-08
**Status**: Accepted

**Context**: The improved architecture spec requires multi-provider routing for redundancy, failover, and capacity balancing. The existing gateway supported only nvidia↔gemini bilateral swap.

**Decision**: Add OpenRouterProvider as a third provider. Fallback chain is ordered: nvidia (primary) → gemini → openrouter. All three providers are checked in priority order during both availability checks and execution-time failures.

**Rationale**: OpenRouter provides access to many model families (Llama, Claude, Gemini) via a single OpenAI-compatible endpoint — useful when both NVIDIA and Gemini are rate-limited or unavailable.

**Constraints**: Per spec §15, multiple credentials must NOT be used to evade provider limits. The pool is for authorized redundancy and failover only.

---

## ADR-002: Gemini Multi-Key Credential Pool

**Date**: 2026-09-08
**Status**: Accepted

**Context**: The spec provides two Gemini API keys (GEMINI_API_KEY, GEMINI_API_KEY_2) for separate authorized projects.

**Decision**: GeminiProvider now reads up to 9 keys from env (GEMINI_API_KEY through GEMINI_API_KEY_9) and config array llm_providers.gemini.api_keys. Keys are used in round-robin order. On 401/403 (auth failure), the next key is tried immediately rather than retrying the same key.

**Rationale**: Maximizes availability across authorized projects; aligns with spec §15 capacity balancing and redundancy goals.

**Constraints**: Keys are not used to exceed individual project quotas. Each key represents a separate authorized project.

---

## ADR-003: 6-Level Adaptive Escalation Engine

**Date**: 2026-09-08
**Status**: Accepted

**Context**: The spec (§6) requires explicit analysis levels preventing unconditional expensive tool execution on every file.

**Decision**: Implemented src/core/escalation/adaptiveEscalation.js with EscalationLevel enum (0–5) and determineEscalationLevel() function. Level is determined by: (1) suspicion score threshold, (2) analyzer disagreement boost (+1), (3) coverage gap boost (+1), (4) budget ratio caps, (5) novelty mode gates.

**Rationale**: Prevents wasted compute on low-suspicion files. Only files scoring ≥ 0.65 get targeted formal/fuzz analysis; ≥ 0.80 get novelty exploration (when budget allows).

**Thresholds (configurable)**:
- 0.20 → STATIC_DEEPENING
- 0.35 → GRAPH_REACHABILITY
- 0.50 → SEMANTIC_REASONING
- 0.65 → TARGETED_DYNAMIC_FORMAL
- 0.80 → NOVELTY_EXPLORATION

---

## ADR-004: Evidence Integrity — LLM Self-Certification Rejection

**Date**: Previous session
**Status**: Accepted (previously recorded, retained here)

**Context**: The spec (§12) requires E0-E5 evidence ladder to be strict; LLM output cannot directly create verified evidence.

**Decision**: In LayeredVerifier._evaluateRawFinding(), any finding with source_tool in ['llm', 'deep_reasoning', 'hypothesis_generator'] or llm_certified: true is forced to E1 candidate at best, requiring a dynamic counterexample to advance.

**Rationale**: Prevents precision collapse from LLM hallucinations being treated as verified findings. Aligns with spec §23: "Do not treat LLM output as proof".

---

## ADR-005: Skipped Manual Benchmark Datasets

**Date**: Previous session
**Status**: Accepted (user instruction)

**Context**: Three benchmark datasets require manual download and are not available in the current environment: c/bigvul/, c/diversevul/, java/juliet/.

**Decision**: These are marked SKIPPED/DISABLED in manifests/benchmark_config.json. The framework does not error on missing paths for these datasets.

**Rationale**: User explicitly confirmed: "We are proceeding WITHOUT the three manual datasets."

---

## ADR-006: No CodeQL Fabrication

**Date**: Previous session
**Status**: Accepted

**Context**: CodeQL CLI is not installed in the current environment.

**Decision**: CodeQL adapter returns explicit UNAVAILABLE status and produces no results. No synthetic or fabricated findings are generated.

**Rationale**: Spec §23: "Do not fabricate tool output when a binary is unavailable." Returning UNAVAILABLE enables disagreement detection (other tools flagged, CodeQL clean).

---

## ADR-007: Controlled Proof-of-Impact Engine & Anti-Exploit Principles

**Date**: 2026-09-08
**Status**: Accepted

**Context**: Master prompt requires validation of candidate findings through reproducible execution without generating weaponized payloads or exploiting external systems.

**Decision**: Implement `ControlledProofVerifier` with strict Anti-Exploit principles:
- Only generates minimal unit regression tests, bounded SVA assertions, and minimal deterministic inputs (e.g. 5-byte crash string, off-by-one boundary test).
- Rejects generation of payloads with shellcode, remote shell triggers, persistence, or network pivot logic.
- Preserves failed reproduction findings as Candidate level (`FAILED_TO_REPRODUCE`); never deletes candidate records.

---

## ADR-008: Pre-Flight Token Estimation & Dynamic Scheduler

**Date**: 2026-09-08
**Status**: Accepted

**Context**: LLM execution and verification requires disciplined token budgeting, prioritization, and rate limit compliance.

**Decision**: Implement `preflightEstimator.js` and `dynamicTokenScheduler.js`:
- OpenRouter API key (`sk-or-v1-018...`) provisioned for code/proof writing at 20 RPM.
- Gemini API key (`AQ.Ab8RN6...`) provisioned for pre-flight triage and verification pool at 30 RPM.
- Dynamic token allocation divides budgets into `reasoning_tokens`, `artifact_generation_tokens`, and `validation_tokens`.
- Candidates prioritized by severity, reachability, confidence, and reproducibility feasibility; low-priority candidates marked `DEFER` or `SKIP` when token/time budget is exhausted.

---

## ADR-009: Ephemeral Proof Sandbox with Loopback Neutralization & Credential Stripping

**Date**: 2026-09-08
**Status**: Accepted

**Context**: Code execution during dynamic reproduction must not leak host secrets or target external networks or cloud environments.

**Decision**: Implement `ProofSandbox`:
- Automatically scrubs all sensitive environment variables (`*KEY*`, `*TOKEN*`, `*SECRET*`, `*AUTH*`, `*PASS*`).
- Sets `HWSEC_ISOLATED=1` and directs proxy environment variables to `http://127.0.0.1:0`.
- Command safety inspection explicitly blocks AWS S3, GCP, Azure endpoints, non-loopback IP addresses, and remote curl/wget transfers.
- Hard timeout enforcement kills execution and cleans up per-run temp directories on exit.

---

## ADR-010: Structural Evidence Validation over Naive Text Matching

**Date**: 2026-09-08
**Status**: Accepted

**Context**: Naive substring searches for words like "crash", "error", or "fail" cause catastrophic false positives.

**Decision**: Implement structural regex and diagnostic parsing:
- Memory corruption verified via AddressSanitizer headers (`ERROR: AddressSanitizer: heap-buffer-overflow`, stack traces, shadow bytes).
- RTL hardware bugs verified via SymbiYosys BMC counterexample traces, step numbers, and VCD dumps.
- Software assertion failures verified via test framework exit codes and stack traces (e.g. PyTest `AssertionError`).
- SHA-256 cryptographic digests generated for every proof artifact to prevent cross-run artifact replay attacks.
