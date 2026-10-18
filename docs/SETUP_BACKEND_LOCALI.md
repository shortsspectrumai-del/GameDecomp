# Local Backend Toolchain Setup (`Ghidra`, `JDK 21`, `.NET / ILSpy`, `CFR`)

GameDecomp runs out of the box with **zero external dependencies** for WebAssembly (`.wasm`), native x86-64 ELF fast-lifting (using system `binutils`), GraphSAGE GNN inference, and Studio UI. To unlock full multi-architecture decompilation (`Ghidra`), `.NET` assembly recovery (`ILSpy`), and Java bytecode decompilation (`CFR`), you can configure local toolchains either system-wide or inside the local `tools/` directory.

## Quick Launch with Local Toolchains

When local toolchains are placed under `tools/`, launch GameDecomp Studio with:

```bash
./start-studio.sh
# or
./scripts/run_studio_with_local_tools.sh
```

Both launcher scripts automatically detect and export `GHIDRA_HOME`, `JAVA_HOME`, `DOTNET_ROOT`, and `ilspycmd` on `PATH` without modifying your global shell profile.

| Component | Verified Version | Default Local Path | Environment Variable |
| :--- | :--- | :--- | :--- |
| **Ghidra** | `12.1.4 PUBLIC` | `tools/ghidra_12.1.4_PUBLIC` | `GHIDRA_HOME` |
| **Java JDK** | `Temurin 21.0.12.1+1` | `tools/jdk-21.0.12.1+1` | `JAVA_HOME` |
| **.NET SDK** | `10.0.401` | `tools/dotnet` | `DOTNET_ROOT` |
| **ILSpy CLI** | `11.1.0.9782` | `tools/dotnet-tools/ilspycmd` | `PATH` |

## Testing Managed (.NET / C#) Integration

To run the offline C# compilation + ILSpy decompilation + recompilation integration test:

```bash
GAMEDECOMP_TEST_DOTNET_HOME="$PWD/tools/dotnet" \
GAMEDECOMP_TEST_ILSPY_HOME="$PWD/tools/dotnet-tools" \
python3 -m unittest tests.test_managed_integration -v
```
