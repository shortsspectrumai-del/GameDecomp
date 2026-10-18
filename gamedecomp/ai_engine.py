"""Evidence-bounded contexts for LLM-led reconstruction, not equivalence proofs."""
import hashlib
from itertools import chain, zip_longest
import json
import re

from gamedecomp.binary_references import REFERENCE_KINDS


def _json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':'))


def _bounded(value, depth=0):
    if depth > 8:
        return {'omitted': 'depth budget'}
    if isinstance(value, str):
        return value if len(value.encode()) <= 8192 else value.encode()[:8000].decode('utf-8', 'ignore')+' [TRUNCATED]'
    if isinstance(value, list):
        values = [_bounded(x, depth+1) for x in value[:32]]
        return values + ([{'omitted_items': len(value)-32}] if len(value)>32 else [])
    if isinstance(value, dict):
        return {k: _bounded(v, depth+1) for k,v in list(value.items())[:128]}
    return value


def _stratified(items):
    """Visit beginning/end/middle then progressively fill intervals, deterministically."""
    if not items:
        return
    pending = [(0, len(items)-1)]
    visited = set()
    for index in (0, len(items)-1):
        if index not in visited:
            visited.add(index)
            yield items[index]
    while pending:
        next_level = []
        for low, high in pending:
            if low > high:
                continue
            middle = (low+high)//2
            if middle not in visited:
                visited.add(middle)
                yield items[middle]
            next_level.extend(((low,middle-1), (middle+1,high)))
        pending = next_level


def _interleaved(*groups):
    """Give each evidence family a turn before filling any one family."""
    for row in zip_longest(*groups):
        for fact in row:
            if fact is not None:
                yield fact


_CONTRACT_OMITTED = object()


def bounded_feedback(messages):
    """Bound diagnostic bytes explicitly; semantic chunks already fit intact."""
    selected = list(messages[:96])
    if len(messages) > 96:
        selected[-1] = 'Additional diagnostic feedback omitted due to the message budget.'
    result = []
    marker = ' [TRUNCATED FEEDBACK]'
    for message in selected:
        text = str(message)
        try:
            encoded = text.encode('utf-8')
        except UnicodeError:
            result.append('Diagnostic feedback omitted because it contains invalid Unicode.')
            continue
        if len(encoded) > 2048:
            text = encoded[:2048-len(marker)].decode('utf-8', 'ignore') + marker
        result.append(text)
    return result


def recovery_context(context, compilation, compatibility=None, *, budget=196608, support='', contract=_CONTRACT_OMITTED):
    if type(budget) is not int or not 16384 <= budget <= 1048576:
        raise ValueError('LLM context budget must be 16384..1048576 bytes')
    signature = next(x for x in context['evidence'] if x['kind']=='signature')
    metadata = dict(signature['metadata'])
    # Explicit None means the immutable baseline has no recognized contract.
    # Only legacy callers omitting this argument may derive a scalar fallback.
    if contract is _CONTRACT_OMITTED:
        contract = validator_contract(None, metadata, context.get('name', ''))
    if not contract:
        raise ValueError('Essential ABI validator contract unavailable')
    # Raw references are exported separately as validated, bounded evidence.
    metadata.pop('binary_references', None)
    metadata.pop('binary_reference_summary', None)
    pcode = metadata.pop('pcode', [])
    preamble = metadata.pop('compile_preamble', '')
    metadata['compile_preamble_summary'] = _bounded(preamble)
    metadata['pcode_total'] = len(pcode)
    signature = dict(signature, metadata=_bounded(metadata))
    facts = [x for x in context['evidence'] if x['kind'] not in ('signature', 'instruction')]
    references = [x for x in facts if x['kind'] in REFERENCE_KINDS]
    metadata_facts = [x for x in facts if x['kind'] not in REFERENCE_KINDS]
    reference_validation = context.get('binary_reference_validation', {})
    instructions = [x for x in context['evidence'] if x['kind']=='instruction']
    blocks = context.get('blocks', [])
    # Each CFG block contributes its boundaries before interior instructions.
    boundaries = {identity for block in blocks for identity in
                  (block.get('instructions', [])[:1]+block.get('instructions', [])[-1:])}
    priorities = [x for x in instructions if x['id'] in boundaries or
                  x['mnemonic'].lower().startswith(('j', 'b', 'call', 'ret'))]
    priority_ids = {x['id'] for x in priorities}
    body = [x for x in instructions if x['id'] not in priority_ids]
    pcode_facts = [{'id': f"pcode:{context['function_id']}:{index}", 'kind': 'pcode', 'operation': op}
                   for index, op in enumerate(pcode)]
    verifier = {'id': 'validation:'+context['function_id'], 'kind': 'compiler_observation',
                'baseline_status': compilation.get('status'),
                'diagnostics': compilation.get('diagnostics', [])[:24],
                'compatibility_status': (compatibility or {}).get('compilation', {}).get('status'),
                'scope': 'Compilation only; not behavioral equivalence'}
    result = {key: context[key] for key in ('binary_hash','function_id','name','snapshot_id') if key in context}
    result.update(task='reconstruct_from_binary_evidence', evidence=[signature],
        compiler_support=support,
        validator_contract=contract,
        retrieval=_bounded(context.get('retrieval', [])),
        neighbors={key: _bounded({k:v for k,v in value.items() if k!='signature'} |
                    {'signature': {k:v for k,v in value.get('signature', {}).items() if k in
                        ('signature','language','return_bits','parameter_bits','type_recovery')}})
                   for key,value in list(context.get('neighbors', {}).items())[:16]},
        context_policy={'budget_bytes': budget, 'complete': False,
            'instruction_total': len(instructions), 'pcode_total': len(pcode),
            'reference_total': reference_validation.get('received', len(references)),
            'reference_rejected': reference_validation.get('rejected', 0),
            'reference_missing_origins': reference_validation.get('missing_origins', 0),
            'reference_duplicates': reference_validation.get('duplicates', 0),
            'reference_scan_truncated': reference_validation.get('scan_truncated', False),
            'reference_coverage_unknown': reference_validation.get('coverage_unknown', False),
            'reference_exporter_omitted': reference_validation.get('exporter_omitted', 0),
            'warning': 'Omitted evidence is unknown. Do not invent missing blocks, ABI state, globals or behavior.'},
        blocks=[{'id': b['id'], 'first': b.get('instructions', [])[:1], 'last': b.get('instructions', [])[-1:],
                 'instruction_count': len(b.get('instructions', [])),
                 'successors': b.get('successors', [])[:8], 'predecessors': b.get('predecessors', [])[:8],
                 'loop_depth': b.get('loop_depth', 0)} for b in blocks[:64]])
    if len(_json(result).encode()) > budget//2:
        # Keep essential ABI contract rather than silently dropping its identity.
        result['neighbors'] = {}
        result['retrieval'] = []
        result['blocks'] = []
        signature['metadata'] = {k:_bounded(v) for k,v in metadata.items() if k in
            ('signature','export_name','return_bits','parameter_bits','language','compile_preamble_status')}
    if len(_json(result).encode()) > budget-2048:
        raise ValueError('Essential ABI context exceeds the selected budget')
    # Reserve room for counters and place signature last for stable callers.
    # References must not consume every byte before any machine semantics appear.
    # Stratify each family, then share turns without imposing fixed quotas.
    candidates = chain((verifier,), _interleaved(_stratified(priorities),
        _stratified(metadata_facts), _stratified(references), _stratified(pcode_facts),
        _stratified(body)))
    used = len(_json(result).encode())
    selected = []
    for fact in candidates:
        fact = _bounded(fact)
        size = len(_json(fact).encode())+1
        if used+size <= budget-2048:
            selected.append(fact)
            used += size
    result['evidence'] = selected+[signature]
    selected_ids = {x['id'] for x in selected}
    policy = result['context_policy']
    policy.update(instruction_included=sum(x['id'] in selected_ids for x in instructions),
                  pcode_included=sum(x['id'] in selected_ids for x in pcode_facts),
                  reference_included=sum(x['id'] in selected_ids for x in references),
                  metadata_may_be_truncated=True,
                  omitted_blocks=max(0,len(blocks)-len(result['blocks'])))
    policy['reference_omitted'] = max(0, policy['reference_total']-policy['reference_included'])
    policy['complete'] = (policy['instruction_included']==len(instructions) and
                          policy['pcode_included']==len(pcode) and not policy['metadata_may_be_truncated'])
    encoded = _json(result).encode()
    if len(encoded)>budget:
        raise ValueError('LLM context exceeded its byte budget')
    summary = dict(policy, bytes=len(encoded), sha256=hashlib.sha256(encoded).hexdigest(),
                   evidence_ids=[x['id'] for x in result['evidence']])
    return result, summary


def recovery_issues(recovery, context):
    if not recovery:
        return []
    from gamedecomp.evidence import known_evidence_ids
    known = known_evidence_ids(context)
    issues = []
    for proposal in recovery.get('renamings', [])+recovery.get('types', []):
        references = proposal.get('evidence_ids', [])
        if not references or any(identity not in known for identity in references):
            issues.append('Proposta semantica senza evidenze valide')
        name = proposal.get('suggested')
        if name is not None and not re.fullmatch(r'[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*', name, flags=re.ASCII):
            issues.append('Nome semantico non valido: '+name[:256])
    return issues


def _function_header(source, name):
    from gamedecomp.csyntax import function_header
    return function_header(source, name)


def observed_scalar_source(metadata):
    """Build only a typed scalar ABI contract observed by native/WASM frontends."""
    name = metadata.get('export_name')
    parameters, result = metadata.get('parameter_bits'), metadata.get('return_bits')
    if (not isinstance(name,str) or not re.fullmatch(r'[A-Za-z_]\w*',name,flags=re.ASCII)
            or not isinstance(parameters,list) or len(parameters)>64
            or type(result) is not int or result not in (32,64)
            or any(type(bits) is not int or bits not in (32,64) for bits in parameters)):
        return None
    args=', '.join(f'uint{bits}_t p{index}' for index,bits in enumerate(parameters)) or 'void'
    return f'uint{result}_t {name}({args}) {{}}'


def abi_check_kind(original, name, language='c', *, candidate=None):
    """Label the existing exact-type versus data-pointer-shape compiler gate."""
    headers = str(_function_header(original, name)) + str(_function_header(candidate, name) if candidate else '')
    annotated = re.search(r'__attribute__|__declspec|__(?:cdecl|stdcall|fastcall|vectorcall|thiscall)', headers)
    return 'COMPILER_ABI_SHAPE' if language == 'c' and not annotated else 'COMPILER_TYPE_IDENTITY'


def validator_contract(original, metadata, name, language='c'):
    """Describe the immutable compile gate, independently of inferred listings.

    This is a validator constraint, not proof that the frontend recovered the ABI.
    Scalar metadata is used only when no baseline body was recovered.
    """
    source = original or observed_scalar_source(metadata)
    symbol = metadata.get('export_name') or name
    if not source or language not in ('c', 'c++'):
        return None
    header = _function_header(source, symbol)
    if not header:
        return None
    result, parameters = header
    check = abi_check_kind(source, symbol, language)
    policy = ('Preserve the external symbol, scalar types and widths, argument count, callbacks and calling convention. '
              'Narrow local variables or add casts only when supported by binary evidence; do not invent conversions or suppress diagnostics using pragmas. ')
    if check == 'COMPILER_ABI_SHAPE':
        policy += ('Evidence-supported data-pointee refinements are permitted by the existing data-pointer ABI shape gate; '
                   'they remain hypotheses requiring independent layout and behavioral validation. Candidate annotations require exact type identity.')
    else:
        policy += 'Preserve exact external function type identity, including data-pointee types and annotations.'
    return {'symbol': symbol, 'declaration': f'{result} {symbol}({parameters});',
            'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
            'provenance': 'immutable_frontend_baseline' if original else 'observed_scalar_metadata',
            'language': language,
            'check': check,
            'listing_signature_scope': 'Frontend metadata.signature is an inferred listing; it does not override this validator contract.',
            'scope': 'Compilation constraint only; ABI recovery and behavioral equivalence remain unproven.',
            'repair_policy': policy}


def abi_repair_feedback(contract, proposed):
    """Actionable signature context without weakening the compiler check."""
    if not contract:
        return ['ABI validator contract unavailable; candidate remains UNKNOWN.']
    header = _function_header(proposed, contract['symbol'])
    declaration = (f"{header[0]} {contract['symbol']}({header[1]});" if header else 'UNAVAILABLE')
    return ['Expected external signature: ' + contract['declaration'],
            'Proposed external signature: ' + declaration,
            contract['repair_policy']]


def _abi_parameters(parameters):
    parts, depth, start = [], 0, 0
    for index, char in enumerate(parameters):
        depth += (char in '([')-(char in ')]')
        if char == ',' and depth == 0:
            parts.append(parameters[start:index]); start = index+1
    parts.append(parameters[start:])
    # Function-pointer callbacks retain their exact types. Data pointers and
    # array parameters share the platform data-pointer ABI, not pointee semantics.
    return ','.join('void *' if ('*' in part or '[' in part) and
                    not re.search(r'\)\s*\(', part) else part for part in parts)


def abi_assertion(original, name, language='c', *, candidate=None):
    """Check exact C types, or ABI shape allowing explicit data-pointee recovery.

    ABI shape does not validate pointee layout or behavioral equivalence. Scalar
    types, argument counts, callbacks and calling-convention annotations remain
    compiler checked. C++ retains exact function type identity.
    """
    if not original or not re.fullmatch(r'[A-Za-z_]\w*', name, flags=re.ASCII):
        return None
    header = _function_header(original, name)
    if not header:
        return None
    result_type, parameters = header
    alias = '__gd_abi_'+hashlib.sha256(original.encode()).hexdigest()[:16]
    declaration = f'\ntypedef {result_type} {alias}({parameters});\n'
    # Do not normalize annotated calling conventions or parameter attributes.
    # Exact identity is conservative for these less common ABI contracts.
    if language == 'c' and candidate is not None and abi_check_kind(original, name, language, candidate=candidate) == 'COMPILER_ABI_SHAPE':
        actual = _function_header(candidate, name)
        if actual is None:
            return None
        actual_result, actual_parameters = actual
        shape_result = lambda value: 'void *' if '*' in value else value
        declaration = (f'\ntypedef {actual_result} {alias}_actual({actual_parameters});\n'
            f'typedef {shape_result(result_type)} {alias}({_abi_parameters(parameters)});\n'
            f'typedef {shape_result(actual_result)} {alias}_shape({_abi_parameters(actual_parameters)});\n')
        return declaration+(f'_Static_assert(__builtin_types_compatible_p(__typeof__(&{name}),{alias}_actual*),"Candidate signature changed");\n'
            f'_Static_assert(__builtin_types_compatible_p({alias}*,{alias}_shape*),"Observed function ABI changed");\n')
    if language == 'c':
        return declaration+f'_Static_assert(__builtin_types_compatible_p(__typeof__(&{name}),{alias}*),"Observed function ABI changed");\n'
    if language == 'c++':
        return declaration+f'static_assert(__is_same(decltype(&{name}),{alias}*),"Observed function ABI changed");\n'
    return None
