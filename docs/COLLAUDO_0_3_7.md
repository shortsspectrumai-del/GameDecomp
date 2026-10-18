# Release 0.3.7 Verification — LLM Context Balancing & Unseen Holdout Audit

Measured on October 18, 2026 on four hard targets from the real open-source game `2048.c` using fresh DeepSeek generations and a separately compiled reference oracle. Verified coverage on the 4-target live subset remains **3 / 4** (`TESTED`), matching the previous release while reducing total prompt+completion token consumption by **23.9%**.

## Stratified Context Balancing (`v0.3.6` vs `v0.3.7`)

A reproducible stress fixture containing `200` assembly instructions, `200` P-code operations, and `256` string/data cross-references demonstrated that naive prefix filling in `0.3.6` allowed reference lists to crowd out instructions and P-code. In `0.3.7`, context construction alternates across evidence categories and stratifies sampling across function entry, exit, and control-flow branch boundaries. The ABI contract remains mandatory, byte limits are enforced on serialized JSON, and omitted evidence IDs cannot be cited.

| 16,384-Byte Context Budget | Instructions | P-code Ops | Cross-Refs | Serialized Bytes |
| :--- | ---: | ---: | ---: | ---: |
| **v0.3.6 (Prefix Fill)** | 0 | 0 | 8 | 14,466 |
| **v0.3.7 (Stratified Balance)** | **13** | **6** | **6** | **14,427** |

On the 232-instruction `addRandom` (`gcc-O2-stripped`) function from `2048.c`, stratified context balancing increased instruction coverage from **51.7% → 100.0%**, P-code block coverage from **34.5% → 100.0%**, and call/data reference coverage from **50.0% → 100.0%**.

## Live DeepSeek Reconstruction Evaluation

The API key was entered via the protected in-memory local form (never stored on disk or in configuration files). The account catalog selected `deepseek-flash`; **4 attempts** were executed (1 per target, within the maximum budget of 12). The LLM received only binary evidence, ABI signature metadata, and compiler/validation feedback; original source code and the reference oracle remained strictly isolated inside the evaluator.

| Build Variant / Function | Status | Benchmark Holdout Comparisons | Divergences | Wall Time (s) |
| :--- | :--- | ---: | ---: | ---: |
| `clang-O2-debug` / `findTarget` | **TESTED** | 33,047 | **0** | 61.84 |
| `clang-O2-stripped` / `getDigitCount` | **TESTED** | 4,145 | **0** | 27.78 |
| `gcc-O2-stripped` / `moveRight` | **UNKNOWN** | 0 | — | 53.03 |
| `gcc-O0-stripped` / `countEmpty` | **TESTED** | 4,102 | **0** | 38.30 |

`moveRight` passed isolated C compilation and ABI signature checks, but minimal standalone linking failed because its callees (`rotateBoard` and `slideArray`) were not injected as external stubs. GameDecomp never injects original source helpers or unverified stubs to artificially inflate `TESTED` counts.

## Independent Final Unseen Holdout Audit

Locked prior to evaluation in `demo-output/quality-measurement-20261018/final-live-audit-plan.json`:
- **Seed:** `20261019` (`4,096` fresh random board/array states plus boundary enumerations).
- **Strict De-duplication:** All inputs from earlier development/feedback streams (`2048/128`, `2048/4096`, `5741/4096`, `89123/4096`, `20261018/4096`) are explicitly excluded.
- **Offline Execution:** Zero API calls; audit results are never fed back to the LLM.

| Reconstructed Candidate | Unseen Final Comparisons | Divergences | Final Status |
| :--- | ---: | ---: | :--- |
| `findTarget` (`clang-O2-debug`) | 14,595 | **0** | **TESTED** |
| `getDigitCount` (`clang-O2-stripped`) | 4,096 | **0** | **TESTED** |
| `moveRight` (`gcc-O2-stripped`) | 0 | — | **UNKNOWN** |
| `countEmpty` (`gcc-O0-stripped`) | 4,096 | **0** | **TESTED** |
| **Total** | **22,787** | **0** | **3 / 4 Verified** |

## Token Usage & Wall-Clock Comparison (`v0.3.2` vs `v0.3.7`)

| Metric | Previous (`v0.3.2`) | Current (`v0.3.7`) | Delta |
| :--- | ---: | ---: | ---: |
| Targets `TESTED` / Planned | 3 / 4 | 3 / 4 | — |
| Targets `UNKNOWN` | 1 | 1 | — |
| Attempts with Recorded Token Usage | 4 | 4 | — |
| Prompt Tokens | 19,091 | 19,327 | +1.2% |
| Completion Tokens | 31,204 | 18,940 | -39.3% |
| **Total Tokens** | **50,295** | **38,267** | **-23.9%** |
| Total Wall Time (4 Targets) | 151.28 s | 180.95 s | +19.6% |

## Reproduction

From a repository checkout with local Ghidra, JDK 21, and `psutil` available:

```bash
JAVA_HOME="$PWD/tools/jdk-21.0.12.1+1" python3 scripts/live_quality_check.py \
  --plan demo-output/release-0.3.1/deepseek-expanded/plan.json \
  --previous demo-output/release-0.3.1/deepseek-expanded/verification.json \
  --ghidra-home tools/ghidra_12.1.4_PUBLIC \
  --output /tmp/gamedecomp-live-check --port 8874
```

API credentials are transmitted exclusively in memory via `POST`/`stdin` and are never written to CLI arguments, preference files, or benchmark artifacts.
