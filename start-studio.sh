#!/usr/bin/env bash
# Use the validated local tools when present; preserve explicit user settings.
set -euo pipefail
task_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$task_root"
if [[ -z "${GHIDRA_HOME:-}" && -f "$task_root/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" ]]; then
    export GHIDRA_HOME="$task_root/tools/ghidra_12.1.4_PUBLIC"
fi
if [[ -z "${JAVA_HOME:-}" && -x "$task_root/tools/jdk-21.0.12.1+1/bin/java" ]]; then
    export JAVA_HOME="$task_root/tools/jdk-21.0.12.1+1"
fi
if [[ -z "${DOTNET_ROOT:-}" ]] && ! command -v dotnet >/dev/null 2>&1 && [[ -x "$task_root/tools/dotnet/dotnet" ]]; then
    export DOTNET_ROOT="$task_root/tools/dotnet"
    export PATH="$DOTNET_ROOT:$PATH"
fi
if [[ -x "$task_root/tools/dotnet-tools/ilspycmd" ]]; then
    export PATH="$PATH:$task_root/tools/dotnet-tools"
fi
exec python3 -m gamedecomp gui "$@"
