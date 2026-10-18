"""Explain locally detected prerequisites without starting tools or providers."""


def readiness(doctor):
    backends = doctor.get('backends', {})
    tools = doctor.get('tools', {})
    checks = []
    descriptions = {
        'wasm': ('WebAssembly', 'Upload a supported MVP WebAssembly module.',
                 'Use a supported WebAssembly module; no external backend is required.'),
        'native': ('Native assembly', 'Upload ELF or PE for supported static inspection.',
                   'Install objdump and restart Studio to enable native assembly inspection.'),
        'ghidra': ('Native decompilation · Ghidra', 'Select Ghidra for native pseudocode and Pcode evidence.',
                   'Install Ghidra and its required JDK, set GHIDRA_HOME, then restart Studio.'),
        'ilspy': ('.NET · ILSpy', 'Upload a supported managed assembly and select ILSpy.',
                  'Install the .NET SDK and ilspycmd, add them to PATH, then restart Studio.'),
    }
    for identity, (label, available_step, unavailable_step) in descriptions.items():
        available = backends.get(identity, {}).get('available') is True
        checks.append({'id': identity, 'label': label,
                       'status': 'AVAILABLE' if available else 'UNAVAILABLE',
                       'next_step': available_step if available else unavailable_step})
    compiler = bool(tools.get('gcc') or tools.get('clang'))
    checks.append({'id': 'compilation', 'label': 'C/C++ compilation checks',
                   'status': 'AVAILABLE' if compiler else 'UNAVAILABLE',
                   'next_step': 'Compilation checks syntax and ABI; it does not prove behavior.' if compiler else
                   'Install GCC or Clang and restart Studio to enable C/C++ compilation checks.'})
    checks.append({'id': 'llm', 'label': 'LLM connection', 'status': 'NOT_TESTED',
                   'next_step': 'Choose a provider in Settings. For a local model, start Ollama, LM Studio or an OpenAI-compatible server, then test the connection.'})
    return {'status': 'STATIC_READY' if any(x['status']=='AVAILABLE' for x in checks[:4]) else 'NEEDS_SETUP',
            'execution': 'NOT_PERFORMED', 'model_connection': 'NOT_TESTED',
            'semantic_equivalence': 'NOT_PROVED', 'checks': checks}
