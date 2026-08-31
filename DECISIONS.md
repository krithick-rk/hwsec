# Architectural Decisions

## Phase 1
1. **Language Choice**: Implemented in modern JavaScript (ESModules) running on Node.js. Given the lack of Python in the environment, Node.js provides a ubiquitous, lightweight runtime well-suited for CLI applications.
2. **CLI Framework**: Used `commander` for robust CLI argument parsing and `--help` generation.
3. **Schema Engine**: Defined schemas using JSDoc typings (`src/core/schema.js`) in JavaScript to provide strict typings while avoiding the compilation overhead of TypeScript in this bootstrap phase.
4. **Planning Safety**: The `Planner` aggressively builds paths and checks files but relies strictly on the `Workspace` abstraction to avoid writing files outside the auditable `hwsec-output/` directory.
5. **Tool Abstraction**: Created `ToolAdapter` base class that natively wraps external binaries (Verilator, Yosys, AFL++) and normalizes their outputs into the shared Finding/Evidence JSON schema.
