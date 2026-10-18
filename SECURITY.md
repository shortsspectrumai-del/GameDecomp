# Security Policy & Safe Usage Guidelines

GameDecomp `0.3.x` is a local reverse-engineering and static analysis toolkit. While static binary intake, lifting, and object compilation (`-c`) do not execute the uploaded target binary, external decompiler frontends (`Ghidra`, `ILSpy`, `CFR`) and compilers (`gcc`, `clang`, `g++`, `javac`) run as standard local user processes. Process timeouts and output size bounds are resource safeguards, **not** security sandboxes. Always analyze untrusted or potentially hostile binaries inside an isolated virtual machine or container with restricted privileges.

## Differential & Native Execution Mode (`--trusted`)

Differential verification (`--trusted` / `--verify-native`) compiles recovered candidates into shared libraries and executes them inside child worker processes to compare outputs against an oracle. **Never enable `--trusted` or `--verify-native` on untrusted or hostile binaries.** Compatibility translations and AI-reconstructed functions remain semantically `UNKNOWN` unless verified by a trusted finite oracle.

## GameDecomp Studio Web Server

GameDecomp Studio binds exclusively to loopback (`127.0.0.1` by default). All mutating HTTP endpoints require a per-session CSRF/session token and validate `Host` and `Origin` headers. Do not expose the Studio server to untrusted networks via reverse proxies or port forwarding. File uploads enforce strict byte limits, sanitize filenames against path traversal, and reject symbolic links in archives. Studio is designed as a single-user local workstation interface.

## API Key & Credential Isolation

LLM API keys entered in Studio or via `--llm-key-prompt` are held strictly in volatile memory for the active session and are never persisted to preference files, session checkpoints, or exported ZIP archives. Artifact redaction scrubs exact known secret strings from logs and reports, though arbitrary encodings cannot be guaranteed. When you configure a remote LLM provider (DeepSeek, OpenAI-compatible, or Anthropic), selected function evidence, disassembly snippets, and compiler diagnostics are transmitted to that provider's endpoint—use only trusted endpoints and review exported artifacts before sharing publicly.

## Reporting a Vulnerability

To report a security issue, please open a private security advisory on the GitHub repository. Never include live API keys or proprietary binaries in public issue reports.
