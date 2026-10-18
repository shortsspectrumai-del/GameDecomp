# Post-Decompilation Function Translation (C++17 & Java)

GameDecomp Studio can translate any recovered function into **C++17** or **Java** using the same configurable LLM engine used for decompilation: a local server (Ollama, LM Studio, vLLM), DeepSeek, an OpenAI-compatible endpoint, or native Anthropic Claude Messages API. No model weights are downloaded automatically; you remain in full control of your local server or API credentials.

## Studio Workflow

1. Complete a binary analysis job and open the **Results** view.
2. Select a function and choose either the **Baseline** or **AI reconstruction** tab as the source basis.
3. Configure your LLM provider in **Settings**, choose **C++** or **Java** in the translation selector, and click **Translate function**.
4. Open the resulting **Function translation** job to inspect compilation status, compiler diagnostics, and translated source code. Click **Open original analysis** at any time to return to the parent binary analysis job.
5. Download the **Export ZIP**: `RecoveredFunction.cpp` or `RecoveredFunction.java` is included in the exported archive **only after passing strict compiler verification**. Rejected attempts and diagnostics remain inspectable in the report without being promoted as verified code.

Translation operates on the selected function (`recovered` entry point in C++17, or `public static` method inside `RecoveredFunction` in Java). Every translation records the source function ID, source basis (`baseline` vs `ai`), and SHA-256 hashes of the parent report, input body, and translated unit.

## Compiler Gates & Structural Validation

- **C++17 (`g++` / `clang++`):** Compiled to object code (`.o`) with `-std=c++17` and strict warning/syntax gates. Only standard fixed-width headers (`stdint.h`, `stddef.h`, `stdbool.h`) are permitted; inline assembly, pragmas, and unresolved machine placeholders (`BADSPACEBASE`, `unaff_*`, `in_*`, `extraout_*`) are rejected automatically.
- **Java (`javac` + `javap`):** Requires a local JDK (`JAVA_HOME` or `PATH`). Compiles with `javac -proc:none` in an isolated temporary directory with empty classpath/sourcepath, then inspects the generated `.class` file via `javap` to verify the `public static` method signature without loading or executing the class. Package declarations, `native` methods, Unicode escapes, and text blocks are rejected by the structural gate.
- **Evidence & Citation Gate:** The LLM response must cite exact evidence IDs from the source function. Missing citations, ambiguous payloads, bodies exceeding 128 KiB, or compiler errors trigger bounded retry feedback or rejection.
- **Context Preflight:** Serializes the full request payload and verifies against provider token limits (when advertised by the model catalog) before inference, reserving output budget so the source function body is never silently truncated.

> **Important:** `COMPILED` does **not** prove semantic equivalence. Pointer-to-reference lowering, unsigned integer semantics in Java, overflow behavior, struct layout, and floating-point corner cases require dedicated verification. Translated units are marked semantically `UNKNOWN` even when the parent C function was `TESTED`.

## Session History & Workspace Persistence

Use a consistent `--workspace` path across Studio sessions to preserve job history. Session checkpoints store only sanitized metadata and SHA-256 artifact hashes—API keys, raw request payloads, and credentials are never written to disk. Incomplete jobs found upon server restart are cleanly marked `FAILED · Interrupted` without triggering background processes or external API calls.
