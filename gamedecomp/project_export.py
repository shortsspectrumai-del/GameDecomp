"""Export buildable translation units without inventing missing game data."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


def export_project(report: dict, output: Path) -> dict:
    project = Path(output) / 'project'
    if project.exists():
        raise FileExistsError('Project output already exists')
    candidates, excluded, dependencies = [], [], []
    for index, function in enumerate(report.get('functions', [])):
        source = function.get('source')
        metadata = function.get('metadata', {})
        language = metadata.get('language', 'c')
        preamble = metadata.get('compile_preamble', '') if report.get('backend') == 'ghidra' else ''
        reason = None
        if not source or function.get('compilation', {}).get('status') != 'COMPILED':
            reason = 'baseline not compiled; candidates are not substituted'
        elif language not in ('c', 'c++'):
            reason = 'unsupported build language'
        elif not isinstance(preamble, str) or '\0' in preamble or len(preamble.encode()) > 262144:
            reason = 'invalid compilation context'
        elif 'compile_preamble_status' in metadata and metadata['compile_preamble_status'] != 'AVAILABLE':
            reason = 'unavailable compilation context'
        match = re.search(r'\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{', source or '')
        if not match or match[1] in ('if', 'while', 'switch', 'for'):
            reason = reason or 'unrecognised function definition'
        if reason:
            excluded.append({'id': function.get('id'), 'reason': reason})
            continue
        candidates.append((index, function, source, preamble, language, match[1]))
    counts = Counter(record[5] for record in candidates)
    (project/'src').mkdir(parents=True)
    (project/'include').mkdir()
    (project/'include/abi.h').write_text('#pragma once\n#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n')
    units = []
    for index, function, source, preamble, language, symbol in candidates:
        if counts[symbol] > 1:
            excluded.append({'id': function.get('id'), 'reason': 'symbol collision: '+symbol})
            continue
        name = f'src/unit_{index:05d}'+('.cpp' if language == 'c++' else '.c')
        unit = '#include "../include/abi.h"\n'+preamble+'\n\n'+source
        (project/name).write_text(unit, encoding='utf-8')
        units.append({'id': function.get('id'), 'symbol': symbol, 'path': name, 'language': language,
                      'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
                      'preamble_sha256': hashlib.sha256(preamble.encode()).hexdigest(),
                      'unit_sha256': hashlib.sha256(unit.encode()).hexdigest(), 'semantic_status': 'UNKNOWN'})
        for declaration in preamble.splitlines():
            if declaration.strip().startswith('extern '):
                dependencies.append({'unit': name, 'declaration': declaration.strip(), 'status': 'DECLARED_ONLY'})
        for called in function.get('calls', []):
            dependencies.append({'unit': name, 'function_id': called, 'status': 'REFERENCE_OBSERVED'})
    cmake = ['cmake_minimum_required(VERSION 3.16)', 'project(GameDecompRecovered LANGUAGES C CXX)',
             'set(CMAKE_C_STANDARD 11)', 'set(CMAKE_CXX_STANDARD 17)']
    if units:
        cmake += ['add_library(recovered_objects OBJECT', *['  '+u['path'] for u in units], ')',
                  'set_target_properties(recovered_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)',
                  'if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")',
                  '  target_compile_options(recovered_objects PRIVATE "$<$<COMPILE_LANGUAGE:C>:-Werror=implicit-function-declaration>")',
                  'endif()', 'add_library(verify_link SHARED EXCLUDE_FROM_ALL $<TARGET_OBJECTS:recovered_objects>)',
                  'if(UNIX AND NOT APPLE)', '  target_link_options(verify_link PRIVATE "-Wl,-z,defs")', 'endif()']
    else:
        cmake += ['add_custom_target(recovered_objects)', 'add_custom_target(verify_link COMMAND cmake -E false)']
    (project/'CMakeLists.txt').write_text('\n'.join(cmake)+'\n')
    manifest = {'schema_version': 1, 'input_sha256': report.get('input', {}).get('sha256'),
                'complete': False, 'linking': 'NOT_VERIFIED',
                'summary': {'exported_units': len(units), 'excluded_functions': len(excluded)},
                'units': units, 'excluded': excluded, 'dependencies': dependencies,
                'limitations': ['Compilazione a oggetto distinta dal link e dal comportamento.',
                                'Nessun asset, globale o helper mancante inventato.',
                                'Un link riuscito della selezione non prova il recupero del gioco intero.']}
    (project/'manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False)+'\n')
    (project/'README.md').write_text(
        '# Progetto recuperato\n\nLe unità conservano baseline compilabili e dichiarazioni osservate. '
        'Funzioni escluse e dipendenze sono elencate nel manifest.\n\n'
        '    cmake -S . -B build\n    cmake --build build\n'
        '    cmake --build build --target verify_link\n\n'
        'Il primo build produce oggetti. verify_link richiede anche risoluzione dei simboli su Linux. '
        'Globali, librerie e helper mancanti devono essere ricostruiti da evidenze o forniti dall’utente. '
        'Gli asset, la configurazione engine e il progetto originale non sono recuperati automaticamente. '
        'complete resta false: né build né link provano equivalenza del gioco.\n', encoding='utf-8')
    return manifest
