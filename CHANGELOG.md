# Changelog

## 0.3.7 — 2026-10-18

- **Expanded Hardware-Verified SIMD & P-code Lowering (`gamedecomp/ghidra_compat.py`):** Added 26 SSE2 and P-code bit-vector models (`pshufd` 2/3-arg, `pmovmskb` 1/2-arg, `punpcklbw/hbw/lwd/hwd/ldq/hdq/lqdq/hqdq`, `paddb/w/d/q`, `psubb/w/d/q`, `pcmpeqb/w/d`, `pcmpgtb/w/d`, `pminub/maxub/minsw/maxsw`, `pand/pandn/por/pxor`, `CARRY1/2/4/8`, `SCARRY1/2/4/8`, `SBORROW1/2/4/8`, `POPCOUNT`) plus 128-bit pointer-to-packed-array store lowering (`*ptr = (undefined1 [16])0x0;`), fixing `initBoard` object compilation in `2048` GCC `-O2`.
- **Structural CFG Dominance, Loop & SSA $\phi$-Placement Engine (`gamedecomp/evidence.py`):** Added basic-block CFG edge typing, Cooper–Harvey–Kennedy immediate dominators (`idom`) and post-dominators (`ipdom`), dominance frontiers, natural back-edge loop detection, backward register liveness (`live_in`/`live_out`), and Cytron–Ferrante iterated dominance frontier SSA $\phi$-node placement (`phi_candidates`).
- **Expanded WebAssembly & Native x86-64 Lifters (`gamedecomp/backends/wasm.py`, `native.py`):** Added full WASM relational comparisons (`0x46..0x4f`, `0x51..0x5a`), `eqz`, `select`, `clz`/`ctz`/`popcnt`, `shr_s`, `rotl`/`rotr`, and width/sign conversions, plus native x86-64 `inc`, `dec`, `rol`, `ror`, `bswap`, `movsxd`/`movslq`, `cdqe`/`cltq`, and `xchg`.
- **Stratified LLM Context Balancing:** Replaced naive prefix filling with alternating, stratified selection across instructions, P-code operations, metadata, and string/call cross-references while preserving ABI contracts and serialized JSON byte limits (-23.9% total token usage on the live `2048.c` benchmark).
- **Independent Unseen Holdout Audit:** Verified live DeepSeek reconstructions across 22,787 fresh random/boundary cases (`seed=20261019`, excluding all prior development seeds) with 0 divergences on verified targets.

## 0.3.6 — 2026-10-18

- Extracted Ghidra references to defined strings and external functions (including thunk resolution and import pointers) anchored to source instruction addresses.
- Added SHA-256 deduplicated evidence items with explicit UTF-8 byte budgets, truncation flags, and omission counters.
- Fixed Java JSON string escaping for UTF-16 code units and added strict Python UTF-8 validation.

## 0.3.5 — 2026-10-17

- Added post-decompilation LLM function translation into **C++17** (`g++`/`clang++`) and **Java** (`javac` + `javap` structural verification) with dedicated reports, parent job links, and SHA-256 provenance tracking.
- Added persistent Studio session history with atomic checkpoints, workspace lock files, and SHA-256 artifact integrity verification (excluding credentials and raw payloads from disk).

## 0.3.4 — 2026-10-16

- Added native **Anthropic Claude Messages API** (`/v1/messages` and `/v1/models`) support in Studio and CLI with dynamic model catalog discovery, context preflight budgeting, and cache token accounting.
- Added shared credential-leak guards preventing API keys from being passed inside URLs or model identifiers.

## 0.3.3 — 2026-10-13

- Added experimental console binary loaders: Nintendo Switch (`NSO`/`NRO`), PlayStation 1 (`PS-X EXE`), Game Boy Advance (`GBA`), GameCube/Wii (`DOL`), NES (`iNES` mapper 0), and Sega Mega Drive / Genesis linear ROMs with segment validation and Headless Ghidra language-ID mapping.

## 0.3.2 — 2026-10-12

- Localized GameDecomp Studio UI and generated reports to English; added Ollama/LM Studio presets, connection health checks, and bounded call-graph visualization.
- Added counterexample-driven semantic retry loop feeding finite oracle mismatches back to the LLM.

## 0.3.1 — 2026-10-11

- Expanded real-game DeepSeek benchmark to 22 targets across 12 builds (including `-fPIE -pie` and `-flto`), enforcing immutable ABI contracts and strict lexical/compiler gates.

## 0.3.0 — 2026-10-11

- Introduced closed-loop LLM reconstruction from binary evidence, initial Ghidra SIMD compatibility lowering (`CONCAT*`, `SUB*`, `ZEXT*`, `SEXT*`, `PSHUFLW`, `PSHUFHW`, `PSADBW`, `MOVMSKPS`), and CMake project export (`project` and `project-ai`).

## 0.2.0 — 2026-10-11

- Added Headless Ghidra integration, DWARF/C11 header generation, and the 8-build `2048.c` real-game differential benchmark (71,003 finite oracle comparisons).

## 0.1.0 — 2026-10-09

- Initial release: concurrent analysis pipeline, native x86-64 and WebAssembly lifters, DWARF/RTTI type recovery, GraphSAGE GNN classifier, and local GameDecomp Studio web UI.
