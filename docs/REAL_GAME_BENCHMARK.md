# Real Open-Source Game Benchmark: `2048.c`

**Executive Summary:** Across 8 compiler/optimization/stripped builds of the complete console game [`2048.c`](https://github.com/mevdschee/2048.c) (`GCC` and `Clang`, `-O0` and `-O2`, Debug and Stripped), GameDecomp's integrated **Ghidra + SIMD Lowering pipeline** recovers **19 / 19 function bodies in all 8 variants (`152 / 152` total)**, compiles **142 / 152 functions (93.4%)** to object code (`.o`), and executes **71,003 finite differential oracle comparisons with 0 divergences** across `57 / 88` deterministic function-build pairs (`31` remaining `UNKNOWN` due to missing interprocedural callee closure or strict Clang pointer-cast rejection).

---

## Provenance & Reproducible Target

The benchmark target is pinned to commit `90343eb209e84fa9687d596f5d5eecfdf7d4df51` of [mevdschee/2048.c](https://github.com/mevdschee/2048.c):

| File | SHA-256 Checksum |
| :--- | :--- |
| [`2048.c`](https://raw.githubusercontent.com/mevdschee/2048.c/90343eb209e84fa9687d596f5d5eecfdf7d4df51/2048.c) | `90f794c675a696aa10980dd120d1f0503ee4ed33a61fef92c7df8f443f5b18a8` |
| [`LICENSE` (MIT)](https://raw.githubusercontent.com/mevdschee/2048.c/90343eb209e84fa9687d596f5d5eecfdf7d4df51/LICENSE) | `593783abd95546a2817d104b2656dd985a979a9e90da895729f211fc844b6402` |

To reproduce the benchmark from the project root:

```bash
# 1. Native fast-lifter baseline (straight-line subset only)
python3 benchmarks/real_game.py --trusted \
  --output demo-output/real-game-rerun --repeats 3 --workers 4

# 2. Full Headless Ghidra recovery matrix across all 8 variants
JAVA_HOME="$PWD/tools/jdk-21.0.12.1+1" \
python3 benchmarks/real_game.py --trusted --backend ghidra \
  --ghidra-home "$PWD/tools/ghidra_12.1.4_PUBLIC" \
  --baseline demo-output/real-game/benchmark.json \
  --output demo-output/ghidra-matrix

# 3. Finite differential verification against the reference oracle
python3 benchmarks/real_game_differential.py --trusted \
  --benchmark demo-output/ghidra-matrix/benchmark.json \
  --output demo-output/ghidra-differential

# 4. Run automated benchmark unit tests
python3 -m unittest tests.test_real_game_benchmark -v
```

---

## Methodology

The build matrix compiles `2048.c` with **GCC 13.3.0** and **Clang 18.1.3** at `-O0` and `-O2` using `-std=c11 -g -fno-pie -no-pie`. For each build, an identical copy is stripped of all symbols and DWARF metadata via `strip --strip-all`. Byte-for-byte `.text` section SHA-256 verification guarantees identical machine code between each debug/stripped pair.

The 19 functions defined in `2048.c` form the denominator. Symbol addresses from the debug builds are used **solely by the external evaluator** to score stripped binaries and are never leaked to the decompilation pipeline.

---

## 1. Headless Ghidra + SIMD Compatibility Lowering Matrix

Evaluated with **Ghidra 12.1.4** and **JDK 21** across all 8 binary variants (with LLM and GNN disabled to isolate static decompilation and SIMD lowering):

| Variant | Functions Recovered | Raw Ghidra `.o` | SIMD-Lowered `.o` (`v0.3.7`) | DWARF Signatures | Type Nodes¹ | Deterministic Functions Verified² | Finite Cases Executed | Divergences | Wall Time³ |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `gcc-O0-debug` | 19 / 19 | 17 / 19 | 17 / 19 | 19 / 19 | 44 | 11 / 11 | 13,308 | **0** | 18.06 s |
| `gcc-O0-stripped` | 19 / 19 | 18 / 19 | 18 / 19 | 0 / 19 | 0 | 11 / 11 | 13,308 | **0** | 15.65 s |
| `gcc-O2-debug` | 19 / 19 | 9 / 19 | **18 / 19** | 19 / 19 | 63 | 9 / 11 | 12,784 | **0** | 16.44 s |
| `gcc-O2-stripped` | 19 / 19 | 6 / 19 | **17 / 19** | 0 / 19 | 0 | 3 / 11 | 830 | **0** | 20.34 s |
| `clang-O0-debug` | 19 / 19 | 15 / 19 | **18 / 19** | 19 / 19 | 50 | 11 / 11 | 13,308 | **0** | 20.17 s |
| `clang-O0-stripped` | 19 / 19 | **19 / 19** | **19 / 19** | 0 / 19 | 0 | 7 / 11 | 10,164 | **0** | 19.62 s |
| `clang-O2-debug` | 19 / 19 | 6 / 19 | **17 / 19** | 19 / 19 | 88 | 2 / 11 | 567 | **0** | 16.82 s |
| `clang-O2-stripped` | 19 / 19 | 6 / 19 | **18 / 19** | 0 / 19 | 0 | 3 / 11 | 6,734 | **0** | 15.33 s |
| **Total** | **152 / 152** | **96 / 152** | **142 / 152** | **76 / 152** | — | **57 / 88** | **71,003** | **0** | — |

¹ Total DWARF type graph nodes including typedefs, qualifiers, pointers, arrays, libc types, and `termios`.
² Evaluated across the 11 deterministic game-logic functions: `getDigitCount`, `findTarget`, `slideArray`, `rotateBoard`, `moveUp`, `moveLeft`, `moveDown`, `moveRight`, `findPairDown`, `countEmpty`, and `gameEnded`. The remaining 8 functions involve terminal I/O (`termios`), `rand()` seeding, `usleep`, or interactive `main` loop state.
³ Single-run cold application cache wall time (includes headless Ghidra analysis, DWARF type extraction, object compilation, and report generation).

---

## 2. Differential Verification Protocol

- **Self-Contained Closure Linking:** The reference `2048.c` source is compiled into an isolated oracle shared library. Each recovered candidate is compiled and linked into a separate shared library containing **only recovered Ghidra function bodies** (linked with `-Wl,-z,defs` and `-Wl,-Bsymbolic` to forbid unresolved symbols or symbol interposition).
- **Full State & Canary Inspection:** For every test input, the harness compares the return value, all 4 elements of the 1D line array or all 16 cells of the $4 \times 4$ board, the `uint32_t` score, and 32-byte canary sentinels placed immediately before and after both buffers to detect out-of-bounds memory corruption.
- **Process Isolation:** Candidate shared libraries execute inside an isolated child worker process with CPU/memory `rlimit` bounds, new session isolation, timeout enforcement, and core dumps disabled.

---

## 3. Native Fast-Lifter Baseline Scope (`--backend native`)

When evaluated with `--backend native` (which intentionally targets only straight-line leaf functions without stack frames, loops, or memory calls), `0 / 19` functions in `2048.c` produce a baseline because every function in `2048.c` uses loops, branches, stack frames, or array memory accesses. This confirms why `--backend ghidra` (or `--backend auto` with Ghidra available) is the recommended backend for real native game binaries.
