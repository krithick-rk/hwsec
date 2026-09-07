# HWSEC Architectural Decisions

## Goal
Evolve HWSEC from an RTL-focused analyzer into a unified, evidence-driven, multi-language security analysis platform (supporting Python, Java, C, C++, Go, and Verilog) while preserving existing RTL capabilities.

---

## Key Remediated Architectural Decisions

### 1. Separation of Planning and Human Approval Gate
- **Problem**: `hwsec analyze` previously invoked LLM hypothesis generation, specification ingestion, and invariant synthesis before human authorization, burning API tokens and violating architectural safety boundaries.
- **Decision**: `hwsec analyze` is strictly lightweight. It performs directory validation, recursive inventory discovery, language detection, tool capability probing via `AnalysisBroker`, budget estimation, and generates `plan.md` and `analysis.json`.
- **State Transition**: State machine is strictly enforced: `CREATED -> PLANNING -> PLANNED -> APPROVED -> RUNNING -> COMPLETED`. Only `hwsec proceed <analysis-id>` transitions from `PLANNED` to `APPROVED` and launches execution. Accidental double execution or running without valid approval is rejected.

### 2. Local Persistent Storage (SQLite via `node:sqlite`)
- **Problem**: Analysis state previously resided solely as fragmented JSON files in `hwsec-output/`. Inter-run incremental analysis and historical querying were impossible.
- **Decision**: Selected Node.js built-in `node:sqlite` standard library module (available natively in Node v22.5+ / v24+). This provides zero-dependency, transactional relational storage on Windows and Linux without C++ compilation hurdles.
- **Authoritative State**: 12 relational tables store projects, analysis runs, files, tool runs, structured evidence, hypotheses, findings, verification results, code graph nodes/edges, token ledger, and audit events. JSON/Markdown artifacts remain as exported views.

### 3. Incremental Analysis & SHA-256 Fingerprinting
- **Decision**: Every discovered file is SHA-256 fingerprinted. The database tracks previous runs and file hashes. When files remain unchanged, deterministic tool results can be safely reused with explicit provenance reasons. Modifications invalidate dependent artifacts.

### 4. Analysis Broker & Capability-Based Dispatch
- **Problem**: The Planner was tightly coupled to hardware tools, directly instantiating `VerilatorTool`, `YosysTool`, and `AflTool`.
- **Decision**: Introduced `AnalysisBroker` (`src/core/broker.js`) and `ToolRegistry`. The Planner requests abstract capabilities (e.g. `sast_pattern_scan`, `rtl_lint`, `deep_dataflow`), and the Broker resolves and dispatches to registered adapters.
- **Domain Separation**: Hardware tools are organized in `src/domains/hardware/tools/` (`verilator.js`, `yosys.js`, `afl.js`, `symbiyosys.js`, `spike.js`), and software tools in `src/domains/software/tools/` (`semgrep.js`, `codeql.js`, `joern.js`). Backward-compatible re-exports preserve existing imports.

### 5. Generalized ToolAdapter & Model Context Protocol (MCP) Integration
- **Decision**: `ToolAdapter` (`src/tools/base.js`) was generalized to support `run({ files, language, capability, config, outputDir, timeout, environment })` alongside legacy positional parameters. Subclasses `LocalProcessAdapter` and `MCPAdapter` allow execution via local binaries or remote MCP servers without passing unsanitized shell commands.
- **Security Guardrails**: Structured actions (`run_tool`) enforce path containment strictly within repository roots to prevent path traversal attacks.

### 6. Provider-Agnostic LLM Architecture & NVIDIA Model Routing
- **Problem**: The system was hardcoded to a single Gemini client.
- **Decision**: Implemented provider-agnostic architecture (`src/core/llm/`) with NVIDIA NIM as first-class provider (`NvidiaProvider`), supporting OpenAI-compatible endpoints with `NVIDIA_API_KEY`, alongside `GeminiProvider` fallback.
- **Task-Based Routing**: Workers never request models by name. They call `modelRouter.execute({ taskType, ... })`. The `ModelRegistry` matches task profiles (e.g., `verification`, `novelty_analysis`, `cwe_classification`) to the best-suited model based on reasoning, coding, cost tier, and context window requirements.

### 7. Global Token & Cost Budget Controller
- **Decision**: `BudgetController` tracks prompt tokens, completion tokens, total tokens, and estimated USD cost, writing each event to the SQLite `token_ledger`.
- **Enforcement Thresholds**:
  - `< 80%`: Normal execution.
  - `80–90%`: Throttle expensive exploratory calls.
  - `90–95%`: Terminate novelty exploration; preserve remaining budget exclusively for verification.
  - `>= 100%`: Block discretionary LLM calls, with bounded emergency allowance only for critical verifier completion.

### 8. Layered Technical Verifier (Eliminating Substring Matching)
- **Problem**: Previous verification elevated findings to verified status if CWE keywords or substring text appeared in tool stdout/stderr.
- **Decision**: Substring confirmation was completely removed. Replaced with `LayeredVerifier` adhering to technical verification levels:
  - `E0`: Claim Only (unsupported, marked `REFUTED` or `INCONCLUSIVE`).
  - `E1`: Tool Observation (static warning present, held at `CANDIDATE`).
  - `E2`: Reproducible Artifact (concrete crash trace or simulation log exists).
  - `E3`: Semantic Match (artifact reproduces claimed violation, elevated to `VERIFIED`).
  - `E4/E5`: Security Relevance & Attacker Reachability established.

### 9. Suspicion & Analyzer Disagreement Engine
- **Decision**: `SuspicionEngine` (`src/core/suspicion/engine.js`) calculates normalized suspicion scores (0.0 to 1.0) combining static severity weights, sensitive keyword density (sources/sinks), graph dataflow paths, and analyzer disagreement (`DisagreementDetector`). Top 20% suspicious paths are prioritized for targeted reasoning instead of scanning entire repositories blindly.

### 10. Separated RAG Knowledge Sources & Graph Layer
- **Decision**: Local knowledge retrieval (`src/core/knowledge/rag.js`) maintains three distinct stores: Security Knowledge (CWEs/secure patterns), Project Knowledge (specifications/README), and Audit Memory (past verified findings and refuted hypotheses). `CodeGraph` (`src/core/graph/codeGraph.js`) models entities, relations, and discovers attack paths connecting sources to sinks.

### 11. Bounded Novelty Modes
- **Decision**: Supported `--novelty off|minimal|standard|deep`. Default is `standard`. Invariant synthesis and novel hypothesis formulation only run during execution (`proceed`) on prioritized suspicious targets.

### 12. Credential Hardening & Unified LLM Gateway
- **Problem**: API keys were previously committed in plaintext in `config.json`, and dual LLM paths existed (`LLMClient` vs `ModelRouter`).
- **Decision**: Sanitized `config.json` and migrated all secrets to environment variables (`NVIDIA_API_KEY`, `GEMINI_API_KEY`) and git-ignored `.env`. Implemented `sanitizeConfig` to redact secrets in logs, reports, and database records.
- **Unified Gateway**: Created `LLMGateway` (`src/core/llm/gateway.js`) consolidating model routing, budget control, telemetry auditing, and provider fallbacks. Refactored `LLMClient` as a drop-in adapter over `LLMGateway`, converging all LLM consumers into a single audited entrypoint.

### 13. Real Joern CPG Adapter Integration
- **Problem**: Joern was previously a stub returning empty findings. Joern interactive REPL hung when probed with `--version`.
- **Decision**: Implemented real Joern integration via `JoernTool` (`src/domains/software/tools/joern.js`) leveraging Joern v4 installed in WSL (`/home/intern/bin/joern/joern-cli`).
- **CPG & Query Pipeline**: The adapter generates CPGs deterministically using `joern-parse`, executes structured security queries with `joern_query.sc` to detect memory bugs (`strcpy`, `sprintf`), command injections (`system`, `popen`), and parameter-to-sink reachability. Results are parsed into standardized `Finding` and `Evidence` instances with references to generated `cpg.bin`. Unsupported files are cleanly skipped.

### 14. Real CodeQL Database, Query & SARIF Integration
- **Problem**: CodeQL adapter was a stub returning empty findings without checking installation or parsing output.
- **Decision**: Implemented real `CodeQLTool` (`src/domains/software/tools/codeql.js`).
- **Capabilities & Caching**: Supports multi-language source scanning (Python, Java, C/C++, Go, JS). Automatically calculates input source SHA-256 fingerprints to cache CodeQL database creation (`hwsec_source_hash.txt`). Implemented full SARIF v2.1.0 parser converting CWE tags, rule descriptors, physical source locations, and code snippets into normalized `Finding` objects.
- **Honest State Handling**: Adheres strictly to the no-fake policy: if CodeQL CLI is absent from the host, returns explicit `UNAVAILABLE` status with diagnostic reason rather than empty passes or mock findings.

### 15. Real SymbiYosys Formal Verification Adapter
- **Problem**: SymbiYosys adapter was a stub returning empty findings. Execution in Windows without OSS CAD Suite library environment failed with DLL error 3221225595.
- **Decision**: Implemented real `SymbiYosysTool` (`src/domains/hardware/tools/symbiyosys.js`).
- **Execution Environment**: Configured automatic environment resolution targeting `oss-cad-suite` root, injecting `bin`, `lib`, and `PYTHON_EXECUTABLE` into process environment.
- **Formal BMC & Trace Extraction**: Implemented automatic `.sby` configuration generation supporting bounded model checking (`smtbmc`). Parsed concrete assertion failures, linking failing RTL line numbers and emitting concrete counterexample waveform traces (`trace.vcd`, `trace_tb.v`, `trace.smtc`) as verifiable technical evidence.

### 16. Real Spike RISC-V ISA Simulator Adapter
- **Problem**: Spike adapter was a stub returning empty findings without instruction simulation or divergence detection logic.
- **Decision**: Implemented real `SpikeTool` (`src/domains/hardware/tools/spike.js`).
- **Simulation & Divergence Engine**: Parses instruction commit logs, extracting program counters, instruction opcodes, and destination register updates. Compares Spike golden architectural traces against RTL co-simulation traces to flag register and PC divergences as verified security violations.
- **Strict Availability Handling**: When Spike binary is not present on the host or when no RISC-V ELF is provided, cleanly returns `UNAVAILABLE` or `SKIPPED` without synthesizing fraudulent findings.

### 17. Qdrant Vector Semantic Memory & RAG Integration
- **Problem**: HWSEC RAG retrieval previously relied solely on in-memory substring keyword matching. Qdrant was listed as a dependency but completely unintegrated.
- **Decision**: Implemented `HWSECQdrantMemory` (`src/core/knowledge/qdrantClient.js`) and integrated it into `RAGEngine` (`src/core/knowledge/rag.js`).
- **Vector Search & Grounded State**: Connects to the local Qdrant server (`http://localhost:6333`), indexes CWE security patterns with Cosine distance, and performs semantic vector search with metadata payload filtering (`language`, `domain`, `cwe`). SQLite remains the authoritative transactional state store, while Qdrant provides fast semantic nearest-neighbor retrieval with graceful fallback to keyword matching if Qdrant is stopped.

### 18. Structured Multi-Layer Code & Evidence Graph
- **Problem**: The code graph previously mixed code symbols, hypotheses, and evidence into an untyped structure without distinct layers or explicit semantic edges.
- **Decision**: Expanded `CodeGraph` (`src/core/graph/codeGraph.js`) with explicit logical layers (`CODE`, `SECURITY`, `EVIDENCE`). Added rich node types (`CALL`, `SYMBOL`, `INVARIANT`) and explicit edge relations (`SUPPORTS`, `CONTRADICTS`, `DERIVED_FROM`, `REPRODUCES`, `REACHES`).
- **Cross-Tool Node Linking**: Added external tool ID resolution (`linkExternalNode` / `resolveExternalNode`) enabling Joern and CodeQL AST/CPG nodes to link directly to HWSEC finding and evidence records. Implemented transactional SQLite sync to `graph_nodes` and `graph_edges`.

### 19. Complete E0 through E5 Layered Verification Ladder
- **Problem**: Previously, only levels E0, E1, and E3 were exercised in the verifier. E2 (reproducible artifact without crash), E4 (security boundary relevance), and E5 (attacker reachability) were defined but dormant.
- **Decision**: Upgraded `LayeredVerifier` (`src/workers/verifier.js`) to evaluate and assign the full 6-tier technical evidence ladder:
  - `E0 (Claim Only)`: Unsupported hypotheses refuted cleanly.
  - `E1 (Tool Observation)`: Static inspection without dedicated reproducible artifact held at `CANDIDATE`.
  - `E2 (Reproducible Artifact)`: Executable/structured artifact present on disk without active crash held at `CANDIDATE`.
  - `E3 (Semantic Match)`: Artifact reproduces violation or counterexample (`VERIFIED`).
  - `E4 (Security Relevance)`: Reproducing violation establishes impact on a security boundary or invariant (`VERIFIED`, Level E4).
  - `E5 (Attacker Reachability)`: Violation proven reachable from external untrusted input via dataflow / attack path (`VERIFIED`, Level E5, Confidence 99%).

### 20. Adaptive Suspicion Scoring & Disagreement Escalation
- **Problem**: Security analysis was either run homogeneously across all files or relied on basic heuristic sorting without tiered execution depth.
- **Decision**: Enhanced `SuspicionEngine` (`src/core/suspicion/engine.js`) and `DisagreementDetector` (`src/core/suspicion/disagreement.js`).
- **Dynamic Analysis Depth**: The engine computes multi-factor suspicion (combining deterministic findings, keyword density, analyzer disagreement, graph boundary crossings, and novelty modifiers) to allocate targeted analysis depth:
  - `LOW` -> `BASELINE_ONLY`: Terminates after cheap static checks.
  - `MEDIUM` -> `CHEAP_DETERMINISTIC`: Triggers secondary lightweight static analyzer.
  - `HIGH` -> `DEEP_DATAFLOW`: Triggers deep Joern/CodeQL dataflow tracing.
  - `CRITICAL` -> `TARGETED_FORMAL_LLM`: Triggers bounded model checking (SymbiYosys) or LLM invariant synthesis only on top-ranked candidates.

### 21. Full CLI Lifecycle & Analysis Reset Command
- **Problem**: Users lacked an official command to reset or purge an analysis run, re-evaluate plans, or cleanly clear database and workspace disk state.
- **Decision**: Added `hwsec reset <analysis-id> [--delete-files]` to `src/index.js` and `deleteAnalysisRun(runId)` to `Database` (`src/core/db.js`):
  - **Soft Reset (default)**: Purges all 11 related SQLite tables (runs, files, tool_runs, evidence, hypotheses, findings, verification_results, graph_nodes, graph_edges, token_ledger, audit_events) and resets `analysis.json` status back to `PLANNED` with `execution_started = false`.
  - **Hard Reset (`--delete-files`)**: In addition to database cleanup, completely unlinks and purges the workspace directory on disk.
  - Tested across full CLI lifecycle end-to-end via `tests/test_cli_commands.js`.

### 22. Multi-Language Unified Pipeline Dispatch & Capability Segregation
- **Problem**: When expanding to 8 multi-language tools, capability overlaps (e.g., CodeQL and Joern claiming `sast_pattern_scan`) resulted in ambiguous broker dispatch and broke deterministic test assertions.
- **Decision**: Segregated primary tool capabilities cleanly:
  - `Semgrep`: `sast_pattern_scan` (lightweight AST pattern matcher across all languages).
  - `Joern`: `graph_dataflow`, `code_property_graph` (WSL/native CPG dataflow and reachability).
  - `CodeQL`: `deep_dataflow`, `taint_tracking` (SARIF-backed deep semantic query engine).
  - `SymbiYosys`: `formal_invariant_verification`, `bounded_model_check` (formal BMC).
  - `Yosys`: `rtl_formal` (RTL formal equivalence and synthesis).
  - `Verilator`: `rtl_lint` (RTL linting).
  - `Afl`: `rtl_fuzz` (coverage-guided fuzzing).
  - `Spike`: `reference_model`, `isa_simulation`, `trace_divergence_check` (golden model co-simulation).
- **Outcome**: The orchestrator in `src/index.js` seamlessly plans and dispatches all 8 tools across mixed-language codebases (C, Python, Java, Go, Verilog), proven via `tests/test_e2e_multilang.js`.









