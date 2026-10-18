"""Small, stable function summaries for agents inspecting a retained report."""
import json


def evidence_view(report, *, offset=0, limit=64):
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 128:
        raise ValueError('offset must be nonnegative and limit must be between 1 and 128')
    functions = report.get('functions', [])
    items = []
    for function in functions[offset:offset+limit]:
        candidate = function.get('candidate') or {}
        status = candidate.get('semantic_status', 'ABSENT')
        diagnostics = function.get('diagnostics') or []
        details_omitted = len(diagnostics) > 4
        def bounded(value, size):
            nonlocal details_omitted
            text = str(value)
            details_omitted |= len(text) > size
            return text[:size]
        step = 'Behavior remains unverified; use a trusted validator where supported.'
        if status == 'DISPROVED':
            step = 'Inspect the counterexample and repair the candidate before exporting AI source.'
        elif status == 'TESTED':
            step = 'Review the finite validation scope; tests do not establish universal equivalence.'
        elif function.get('compilation', {}).get('status') != 'COMPILED':
            step = 'Inspect compiler diagnostics and missing binary evidence before reconstruction.'
        item = {'id': bounded(function.get('id', offset+len(items)),128),
                'name': bounded(function.get('name',''),256),
                'compilation_status': bounded(function.get('compilation', {}).get('status','UNKNOWN'),32),
                'semantic_status': bounded(function.get('semantic_status','UNKNOWN'),32),
                'candidate_status': bounded(status,32),
                'diagnostics': [bounded(value,512) for value in diagnostics[:4]],
                'next_step': step}
        item['details_omitted'] = details_omitted
        # Reserve room for page metadata; never silently truncate a function.
        if len(json.dumps(items+[item],ensure_ascii=True).encode()) > 48000:
            break
        items.append(item)
    next_offset = offset+len(items)
    return {'schema_version':1, 'binary_sha256':report.get('input',{}).get('sha256'),
            'snapshot_id':report.get('snapshot_id'), 'total_units':len(functions),
            'offset':offset, 'returned_units':len(items), 'requested_limit':limit,
            'next_offset':next_offset if next_offset<len(functions) else None,
            'omitted_units':max(0,len(functions)-len(items)), 'items':items,
            'scope':'Summary only. Complete source and validation records remain in the canonical report.'}
