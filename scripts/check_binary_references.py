"""Measure static reference delivery on explicit binaries without executing them.

This is an extraction/context check, not an LLM quality or equivalence benchmark.
"""
import argparse
import json
import math
from pathlib import Path
import time

from gamedecomp.ai_engine import recovery_context, validator_contract
from gamedecomp.backends.ghidra import analyze
from gamedecomp.evidence import function_context, known_evidence_ids
from gamedecomp.llm import LLMClient


def check(inputs, output, home, timeout):
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Timeout must be finite and positive')
    if output.exists():
        raise ValueError('Use a new output directory')
    output.mkdir(parents=True)
    results = []
    for index, binary in enumerate(inputs):
        started = time.monotonic()
        analysis = analyze(binary, ghidra_home=home, timeout=timeout)
        functions, counters = [], {'string_reference': 0, 'external_function_reference': 0}
        validation_totals = {key: 0 for key in ('received', 'accepted', 'rejected', 'duplicates',
            'missing_origins', 'capacity_omitted', 'omitted', 'exporter_omitted')}
        coverage_unknown, scans_truncated = 0, 0
        imported = set()
        for function in analysis.functions:
            context = function_context(function, analysis.binary_hash, {})
            references = [fact for fact in context['evidence'] if fact['kind'] in counters]
            validation = context['binary_reference_validation']
            for key in validation_totals:
                validation_totals[key] += validation[key]
            coverage_unknown += int(validation['coverage_unknown'])
            scans_truncated += int(validation['scan_truncated'] is True)
            # Rejected-only and incompletely collected functions must remain
            # visible, rather than disappearing from the quality denominator.
            if not references and not (validation['received'] or validation['rejected']
                    or validation['coverage_unknown'] or validation['scan_truncated']):
                continue
            for fact in references:
                counters[fact['kind']] += 1
                if fact['kind'] == 'external_function_reference':
                    imported.add(fact['target_name'])
            row = {'function_id': function.id, 'address': function.address,
                   'references': references, 'validation': validation,
                   'prompt': {'status': 'UNAVAILABLE'}}
            contract = validator_contract(function.source, function.metadata, function.name,
                                          function.metadata.get('language', 'c'))
            if contract:
                prompt, stats = recovery_context(context, {'status': 'UNKNOWN', 'diagnostics': [
                    'Compilation is outside the scope of this extraction benchmark']},
                    budget=16384, contract=contract)
                selected = [fact for fact in prompt['evidence'] if fact['kind'] in counters]
                known = known_evidence_ids(prompt)
                assert all(fact['id'] in known for fact in selected)
                assert stats['bytes'] <= 16384
                # request_size performs serialization only, with no HTTP call.
                client = LLMClient('http://127.0.0.1:1/v1', 'offline-preflight-fixture')
                row['prompt'] = {'status': 'AVAILABLE', 'references_included': len(selected),
                    'context_bytes': stats['bytes'], 'context_sha256': stats['sha256'],
                    'request_bytes': client.request_size(function.source or 'unrecovered', prompt)}
            functions.append(row)
        assert counters['string_reference'] > 0, 'No string references extracted'
        assert counters['external_function_reference'] > 0, 'No import references extracted'
        assert any(row['prompt'].get('references_included', 0) for row in functions), 'No references delivered to bounded prompts'
        record = {'input': str(binary.resolve()), 'binary_sha256': analysis.binary_hash,
            'seconds': time.monotonic() - started, 'functions_total': len(analysis.functions),
            'functions_with_references': sum(bool(row['references']) for row in functions), 'counts': counters,
            'validation_totals': validation_totals, 'coverage_unknown_functions': coverage_unknown,
            'scan_truncated_functions': scans_truncated,
            'import_names': sorted(imported), 'functions': functions}
        (output / f'binary-{index}.json').write_text(json.dumps(record, ensure_ascii=False, indent=2)+'\n')
        results.append({key: value for key, value in record.items() if key != 'functions'})
    summary = {'status': 'PASS', 'results': results,
        'scope': 'Ghidra static references and bounded model context only. '
                 'No generated program execution, real LLM inference or equivalence claim.'}
    (output / 'verification.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', dest='inputs', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ghidra-home', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=120)
    args = parser.parse_args()
    check(args.inputs, args.output, args.ghidra_home, args.timeout)
