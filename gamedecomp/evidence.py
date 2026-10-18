"""Compact CFG/evidence contexts and deterministic local retrieval."""
import hashlib
import json
import re
from pathlib import Path

from gamedecomp.models import Function
from gamedecomp.binary_references import validated_references


_GPR_ALIASES: dict[str, str] = {}
for _canon, _names in [
    ('rax', ('rax', 'eax', 'ax', 'al', 'ah')),
    ('rbx', ('rbx', 'ebx', 'bx', 'bl', 'bh')),
    ('rcx', ('rcx', 'ecx', 'cx', 'cl', 'ch')),
    ('rdx', ('rdx', 'edx', 'dx', 'dl', 'dh')),
    ('rsi', ('rsi', 'esi', 'si', 'sil')),
    ('rdi', ('rdi', 'edi', 'di', 'dil')),
    ('rbp', ('rbp', 'ebp', 'bp', 'bpl')),
    ('rsp', ('rsp', 'esp', 'sp', 'spl')),
]:
    for _n in _names:
        _GPR_ALIASES[_n] = _canon
for _idx in range(8, 16):
    for _suffix in ('', 'd', 'w', 'b'):
        _GPR_ALIASES[f'r{_idx}{_suffix}'] = f'r{_idx}'
for _idx in range(16):
    _GPR_ALIASES[f'xmm{_idx}'] = f'xmm{_idx}'

_UNCONDITIONAL_JUMPS = frozenset({'jmp', 'jmpq', 'br'})
_RETURN_TERMINATORS = frozenset({'ret', 'retq', 'iret', 'iretd', 'iretq', 'return'})
_TRAP_TERMINATORS = frozenset({'ud2', 'hlt', 'unreachable'})
_RMW_BINARY = frozenset({
    'add', 'sub', 'imul', 'and', 'or', 'xor', 'shl', 'sal', 'shr', 'sar',
    'rol', 'ror', 'adc', 'sbb', 'paddb', 'paddw', 'paddd', 'paddq',
    'psubb', 'psubw', 'psubd', 'psubq', 'pand', 'pandn', 'por', 'pxor',
})
_RMW_UNARY = frozenset({'inc', 'dec', 'neg', 'not', 'bswap'})
_PURE_WRITE = frozenset({'mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'movslq', 'lea', 'bsfl', 'bsrl', 'bsf', 'bsr', 'popcnt', 'lzcnt', 'tzcnt'})
_REG_TOKEN_RE = re.compile(r'%?\b([a-zA-Z][a-zA-Z0-9]*)\b')
_BRANCH_TARGET_RE = re.compile(r'^(?:0x)?([0-9a-fA-F]+)(?:\s+<[^>]+>)?$')


def _is_conditional_branch(mnemonic: str) -> bool:
    m = mnemonic.lower()
    if m in _UNCONDITIONAL_JUMPS:
        return False
    return m.startswith('j') or m in ('loop', 'loope', 'loopne', 'br_if')


def _is_terminator(mnemonic: str) -> bool:
    m = mnemonic.lower()
    return m in _UNCONDITIONAL_JUMPS or m in _RETURN_TERMINATORS or m in _TRAP_TERMINATORS or _is_conditional_branch(m)


def _branch_target(operands: str, valid_addresses: set[int]) -> int | None:
    clean = operands.split('#', 1)[0].strip()
    match = _BRANCH_TARGET_RE.match(clean)
    if match:
        target = int(match.group(1), 16)
        if target in valid_addresses:
            return target
    return None


def _extract_regs(expr: str) -> list[str]:
    found = []
    for match in _REG_TOKEN_RE.finditer(expr.lower()):
        canon = _GPR_ALIASES.get(match.group(1))
        if canon and canon not in found:
            found.append(canon)
    return found


def _instruction_def_use(mnemonic: str, operands: str) -> tuple[list[str], list[str]]:
    m = mnemonic.lower()
    clean = operands.split('#', 1)[0].strip()
    if m == 'local.get' and clean.isdigit():
        return [f'local_{clean}'], []
    if m in ('local.set', 'local.tee') and clean.isdigit():
        return [], [f'local_{clean}']
    if m in ('nop', 'endbr64') or m in _UNCONDITIONAL_JUMPS or _is_conditional_branch(m):
        return [], []
    if m in ('cdqe', 'cltq'):
        return ['rax'], ['rax']
    if m in ('cdq', 'cqo'):
        return ['rax'], ['rdx']
    if m in ('ret', 'retq'):
        return ['rax'], []
    if not clean:
        return [], []
    parts = [p.strip() for p in clean.split(',')]
    # Detect AT&T syntax (registers prefixed with %) vs Intel syntax
    if '%' in clean and len(parts) >= 2:
        parts = list(reversed(parts))
    uses: list[str] = []
    defs: list[str] = []
    for bracket in re.findall(r'\[([^\[\]]+)\]', clean):
        for reg in _extract_regs(bracket):
            if reg not in uses:
                uses.append(reg)
    for paren in re.findall(r'\(([^()]+)\)', clean):
        for reg in _extract_regs(paren):
            if reg not in uses:
                uses.append(reg)
    dst_is_mem = '[' in parts[0] or '(' in parts[0]
    dst_regs = [] if dst_is_mem else _extract_regs(parts[0])
    if m in ('cmp', 'test') or m.startswith(('cmp', 'test', 'ucomis', 'comis')):
        for part in parts:
            for reg in _extract_regs(part):
                if reg not in uses:
                    uses.append(reg)
        return uses, defs
    if m in ('push', 'pushq'):
        for reg in _extract_regs(parts[0]) + ['rsp']:
            if reg not in uses:
                uses.append(reg)
        return uses, ['rsp']
    if m in ('pop', 'popq'):
        if 'rsp' not in uses:
            uses.append('rsp')
        return uses, dst_regs + (['rsp'] if 'rsp' not in dst_regs else [])
    if m in ('xor', 'sub', 'pxor') and len(parts) == 2 and not dst_is_mem:
        src_regs = _extract_regs(parts[1])
        if dst_regs and parts[0].lstrip('%').lower() == parts[1].lstrip('%').lower():
            return [], dst_regs
    if m == 'xchg' and len(parts) == 2:
        for part in parts:
            for reg in _extract_regs(part):
                if reg not in uses:
                    uses.append(reg)
        for index, part in enumerate(parts):
            if '[' not in part and '(' not in part:
                for reg in _extract_regs(part):
                    if reg not in defs:
                        defs.append(reg)
        return uses, defs
    if m in _PURE_WRITE or m.startswith('set'):
        for part in parts[1:]:
            if '[' not in part and '(' not in part:
                for reg in _extract_regs(part):
                    if reg not in uses:
                        uses.append(reg)
        return uses, dst_regs
    if m in _RMW_BINARY or m.startswith('cmov'):
        for part in parts:
            if '[' not in part and '(' not in part:
                for reg in _extract_regs(part):
                    if reg not in uses:
                        uses.append(reg)
        return uses, dst_regs
    if m in _RMW_UNARY and len(parts) == 1:
        for reg in dst_regs:
            if reg not in uses:
                uses.append(reg)
        return uses, dst_regs
    return uses, defs


def _compute_dominators(entry: str, rpo: list[str], preds: dict[str, list[str]]) -> dict[str, str | None]:
    rpo_index = {node: idx for idx, node in enumerate(rpo)}
    idom: dict[str, str | None] = {entry: entry}

    def intersect(b1: str, b2: str) -> str:
        f1, f2 = b1, b2
        while f1 != f2:
            while rpo_index[f1] > rpo_index[f2]:
                f1 = idom[f1]  # type: ignore[assignment]
            while rpo_index[f2] > rpo_index[f1]:
                f2 = idom[f2]  # type: ignore[assignment]
        return f1

    changed = True
    while changed:
        changed = False
        for node in rpo:
            if node == entry:
                continue
            processed_preds = [p for p in preds.get(node, []) if p in idom]
            if not processed_preds:
                continue
            new_idom = processed_preds[0]
            for p in processed_preds[1:]:
                new_idom = intersect(p, new_idom)
            if idom.get(node) != new_idom:
                idom[node] = new_idom
                changed = True
    idom[entry] = None
    return idom


def _analyze_cfg_and_dataflow(blocks: list[dict], block_instructions: list[list], addresses: set[int]) -> tuple[dict, dict]:
    if not blocks:
        empty_cfg = {'entry': None, 'exits': [], 'edges': [], 'reachable': [], 'unreachable': [],
                     'idom': {}, 'dominator_tree': {}, 'dominance_frontiers': {}, 'ipdom': {},
                     'loops': [], 'is_reducible': True}
        empty_df = {'entry_live_registers': [], 'defined_registers': [], 'blocks': {}, 'phi_candidates': {}}
        return empty_cfg, empty_df
    addr_to_block = {block['_start_address']: block['id'] for block in blocks}
    succs: dict[str, list[str]] = {block['id']: [] for block in blocks}
    preds: dict[str, list[str]] = {block['id']: [] for block in blocks}
    edges: list[dict] = []
    exits: list[str] = []

    def add_edge(src: str, dst: str, kind: str):
        edges.append({'from': src, 'to': dst, 'kind': kind})
        if dst not in succs[src]:
            succs[src].append(dst)
        if src not in preds[dst]:
            preds[dst].append(src)

    for index, (block, insts) in enumerate(zip(blocks, block_instructions)):
        bid = block['id']
        last = insts[-1]
        m = last.mnemonic.lower()
        next_bid = blocks[index + 1]['id'] if index + 1 < len(blocks) else None
        if m in _RETURN_TERMINATORS:
            exits.append(bid)
        elif m in _TRAP_TERMINATORS:
            pass
        elif m in _UNCONDITIONAL_JUMPS:
            target = _branch_target(last.operands, addresses)
            if target is not None and target in addr_to_block:
                add_edge(bid, addr_to_block[target], 'unconditional')
        elif _is_conditional_branch(m):
            target = _branch_target(last.operands, addresses)
            if target is not None and target in addr_to_block:
                add_edge(bid, addr_to_block[target], 'branch_taken')
            if next_bid is not None:
                add_edge(bid, next_bid, 'fallthrough')
        else:
            if next_bid is not None:
                add_edge(bid, next_bid, 'fallthrough')
            else:
                exits.append(bid)

    for block in blocks:
        bid = block['id']
        block['successors'] = succs[bid]
        block['predecessors'] = preds[bid]

    entry = blocks[0]['id']
    visited: set[str] = set()
    postorder: list[str] = []
    stack: list[tuple[str, int]] = [(entry, 0)]
    visited.add(entry)
    while stack:
        node, idx = stack[-1]
        children = succs[node]
        if idx < len(children):
            stack[-1] = (node, idx + 1)
            nxt = children[idx]
            if nxt not in visited:
                visited.add(nxt)
                stack.append((nxt, 0))
        else:
            stack.pop()
            postorder.append(node)
    rpo = list(reversed(postorder))
    unreachable = [b['id'] for b in blocks if b['id'] not in visited]
    idom = _compute_dominators(entry, rpo, preds)
    dom_tree: dict[str, list[str]] = {node: [] for node in rpo}
    for node in rpo:
        parent = idom.get(node)
        if parent is not None and parent in dom_tree:
            dom_tree[parent].append(node)

    dom_frontiers: dict[str, list[str]] = {node: [] for node in rpo}
    for node in rpo:
        reach_preds = [p for p in preds[node] if p in visited]
        if len(reach_preds) >= 2:
            for p in reach_preds:
                runner: str | None = p
                while runner is not None and runner != idom[node]:
                    if node not in dom_frontiers[runner]:
                        dom_frontiers[runner].append(node)
                    runner = idom.get(runner)

    def dominates(a: str, b: str) -> bool:
        cur: str | None = b
        while cur is not None:
            if cur == a:
                return True
            cur = idom.get(cur)
        return False

    # Post-dominators via virtual exit
    exit_nodes = [b for b in rpo if b in exits or not succs[b]] or [rpo[-1]]
    v_exit = '__exit__'
    rev_preds: dict[str, list[str]] = {node: list(succs[node]) for node in rpo}
    rev_preds[v_exit] = []
    rev_succs: dict[str, list[str]] = {node: [p for p in preds[node] if p in visited] for node in rpo}
    rev_succs[v_exit] = list(exit_nodes)
    for ex in exit_nodes:
        if v_exit not in rev_preds[ex]:
            rev_preds[ex].append(v_exit)
    rev_visited: set[str] = {v_exit}
    rev_post: list[str] = []
    rev_stack: list[tuple[str, int]] = [(v_exit, 0)]
    while rev_stack:
        node, idx = rev_stack[-1]
        children = rev_succs.get(node, [])
        if idx < len(children):
            rev_stack[-1] = (node, idx + 1)
            nxt = children[idx]
            if nxt not in rev_visited:
                rev_visited.add(nxt)
                rev_stack.append((nxt, 0))
        else:
            rev_stack.pop()
            rev_post.append(node)
    rev_rpo = list(reversed(rev_post))
    raw_ipdom = _compute_dominators(v_exit, rev_rpo, rev_preds)
    ipdom = {node: (None if dom == v_exit else dom) for node, dom in raw_ipdom.items() if node != v_exit}

    # Natural loops and reducibility
    loops_by_header: dict[str, dict] = {}
    for edge in edges:
        u, v = edge['from'], edge['to']
        if u in visited and v in visited and dominates(v, u):
            edge['is_backedge'] = True
            loop = loops_by_header.setdefault(v, {'header': v, 'backedges': [], 'body': {v}})
            loop['backedges'].append(u)
            work = [u]
            while work:
                curr = work.pop()
                if curr not in loop['body']:
                    loop['body'].add(curr)
                    work.extend(p for p in preds[curr] if p in visited)

    # Check reducibility via DFS on-stack retreating edges
    is_reducible = True
    on_stack: set[str] = {entry}
    dfs_seen: set[str] = {entry}
    dfs_stack: list[tuple[str, int]] = [(entry, 0)]
    while dfs_stack:
        node, idx = dfs_stack[-1]
        children = succs[node]
        if idx < len(children):
            dfs_stack[-1] = (node, idx + 1)
            nxt = children[idx]
            if nxt in on_stack:
                if not dominates(nxt, node):
                    is_reducible = False
            elif nxt not in dfs_seen:
                dfs_seen.add(nxt)
                on_stack.add(nxt)
                dfs_stack.append((nxt, 0))
        else:
            dfs_stack.pop()
            on_stack.discard(node)

    rpo_order = {node: i for i, node in enumerate(rpo)}
    loops = []
    loop_membership: dict[str, int] = {b['id']: 0 for b in blocks}
    for header in sorted(loops_by_header, key=lambda h: rpo_order.get(h, 0)):
        info = loops_by_header[header]
        body_sorted = sorted(info['body'], key=lambda b: rpo_order.get(b, 0))
        loop_exits = [b for b in body_sorted if any(s not in info['body'] for s in succs[b])]
        for b in body_sorted:
            loop_membership[b] = loop_membership.get(b, 0) + 1
        loops.append({
            'header': header,
            'backedges': sorted(info['backedges'], key=lambda b: rpo_order.get(b, 0)),
            'body': body_sorted,
            'exits': loop_exits,
        })
    for block in blocks:
        block['loop_depth'] = loop_membership.get(block['id'], 0)
        block.pop('_start_address', None)

    # Per-block register def-use and backward liveness
    block_uses: dict[str, set[str]] = {}
    block_defs: dict[str, set[str]] = {}
    all_defs_by_reg: dict[str, set[str]] = {}
    for block, insts in zip(blocks, block_instructions):
        bid = block['id']
        uses_set: set[str] = set()
        defs_set: set[str] = set()
        seen_signatures: set[tuple[str, str]] = set()
        for inst in insts:
            sig = (inst.mnemonic, inst.operands)
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)
            u_list, d_list = _instruction_def_use(inst.mnemonic, inst.operands)
            for u in u_list:
                if u not in defs_set:
                    uses_set.add(u)
            for d in d_list:
                defs_set.add(d)
                if bid in visited:
                    all_defs_by_reg.setdefault(d, set()).add(bid)
        block_uses[bid] = uses_set
        block_defs[bid] = defs_set

    live_in: dict[str, set[str]] = {b['id']: set(block_uses[b['id']]) for b in blocks}
    live_out: dict[str, set[str]] = {b['id']: set() for b in blocks}
    changed = True
    while changed:
        changed = False
        for bid in reversed(rpo):
            new_out: set[str] = set()
            for s in succs[bid]:
                new_out.update(live_in[s])
            new_in = block_uses[bid] | (new_out - block_defs[bid])
            if new_out != live_out[bid] or new_in != live_in[bid]:
                live_out[bid] = new_out
                live_in[bid] = new_in
                changed = True

    # Iterated Dominance Frontier for SSA phi-node placement
    phi_candidates: dict[str, list[str]] = {}
    for reg, def_blocks in sorted(all_defs_by_reg.items()):
        if reg == 'rsp':
            continue
        worklist = list(def_blocks)
        has_already: set[str] = set()
        ever_on_worklist: set[str] = set(def_blocks)
        while worklist:
            x = worklist.pop()
            for y in dom_frontiers.get(x, []):
                if y not in has_already:
                    has_already.add(y)
                    if reg in live_in.get(y, set()):
                        phi_candidates.setdefault(y, []).append(reg)
                    if y not in ever_on_worklist:
                        ever_on_worklist.add(y)
                        worklist.append(y)

    cfg_summary = {
        'entry': entry,
        'exits': exits,
        'edges': edges,
        'reachable': rpo,
        'unreachable': unreachable,
        'idom': idom,
        'dominator_tree': dom_tree,
        'dominance_frontiers': dom_frontiers,
        'ipdom': ipdom,
        'loops': loops,
        'is_reducible': is_reducible,
    }
    dataflow_summary = {
        'entry_live_registers': sorted(live_in.get(entry, set()) - {'rsp'}),
        'defined_registers': sorted(all_defs_by_reg.keys() - {'rsp'}),
        'blocks': {
            b['id']: {
                'uses': sorted(block_uses[b['id']]),
                'defs': sorted(block_defs[b['id']]),
                'live_in': sorted(live_in[b['id']]),
                'live_out': sorted(live_out[b['id']]),
            }
            for b in blocks[:64]
        },
        'phi_candidates': {k: sorted(v) for k, v in phi_candidates.items()},
    }
    return cfg_summary, dataflow_summary


def function_context(function: Function, binary_hash: str, summaries: dict) -> dict:
    instructions = function.instructions
    addresses = {instruction.address for instruction in instructions}
    leaders = {instructions[0].address} if instructions else set()
    for index, instruction in enumerate(instructions):
        m = instruction.mnemonic.lower()
        if _is_conditional_branch(m) or m in _UNCONDITIONAL_JUMPS:
            target = _branch_target(instruction.operands, addresses)
            if target is not None:
                leaders.add(target)
        if _is_terminator(m) and index + 1 < len(instructions):
            leaders.add(instructions[index + 1].address)
    blocks, block_instructions, current, current_insts = [], [], None, []
    facts = []
    for instruction in instructions:
        if current is None or instruction.address in leaders:
            current = {'id': f'b:{instruction.address:x}', 'instructions': [], '_start_address': instruction.address}
            current_insts = []
            blocks.append(current)
            block_instructions.append(current_insts)
        identity = f'i:{instruction.address:x}'
        current['instructions'].append(identity)
        current_insts.append(instruction)
        facts.append({'id': identity, 'kind': 'instruction', 'address': instruction.address,
                      'mnemonic': instruction.mnemonic, 'operands': instruction.operands})
    cfg_summary, dataflow_summary = _analyze_cfg_and_dataflow(blocks, block_instructions, addresses)
    if blocks:
        facts.append({'id': f'cfg:{function.id}', 'kind': 'cfg_analysis',
                      'entry': cfg_summary['entry'], 'exits': cfg_summary['exits'],
                      'idom': cfg_summary['idom'], 'loops': cfg_summary['loops'],
                      'is_reducible': cfg_summary['is_reducible']})
        facts.append({'id': f'dataflow:{function.id}', 'kind': 'dataflow_analysis',
                      'entry_live_registers': dataflow_summary['entry_live_registers'],
                      'defined_registers': dataflow_summary['defined_registers'],
                      'phi_candidates': dataflow_summary['phi_candidates']})
    recovered = function.metadata.get('type_recovery')
    if recovered:
        facts.append({'id': 'types:' + function.id, 'kind': 'type_metadata', 'data': recovered})
    neural = function.metadata.get('gnn_prediction')
    if neural:
        facts.append({'id': f'gnn:{function.id}:machine_features', 'kind': 'gnn_input',
                      'instruction_ids': [fact['id'] for fact in facts if fact['kind'] == 'instruction'],
                      'scope': 'Statistiche osservabili delle istruzioni e larghezze ABI; nessun nome o tipo debug come feature'})
        facts.append({'id': f'gnn:{function.id}:callgraph', 'kind': 'callgraph', 'calls': function.calls})
        facts.append({'id': 'gnn:' + function.id, 'kind': 'gnn_hypothesis', 'data': neural,
                      'scope': 'Predizione statistica; non prova di tipi, nomi o equivalenza'})
    references, reference_validation = validated_references(function, binary_hash)
    facts.extend(references)
    # Raw imported metadata must not introduce duplicate or fabricated citations.
    metadata = {key: value for key, value in function.metadata.items()
                if key not in ('binary_references', 'binary_reference_summary')}
    facts.append({'id': 'signature:' + function.id, 'kind': 'signature',
                  'metadata': metadata})
    return {'binary_hash': binary_hash, 'function_id': function.id, 'name': function.name,
            'evidence': facts, 'blocks': blocks, 'cfg': cfg_summary, 'dataflow': dataflow_summary,
            'calls': function.calls,
            'binary_reference_validation': reference_validation,
            'neighbors': {key: summaries[key] for key in function.calls if key in summaries},
            'assumptions': function.diagnostics,
            'representation': 'disassembly evidence, not machine-semantics SSA'}



class KnowledgeBase:
    def __init__(self, path: Path | None = None):
        self.path = path or Path(__file__).parent / 'data' / 'signatures.json'
        data = self.path.read_bytes()
        if len(data) > 8 * 1024 * 1024:
            raise ValueError('Corpus retrieval troppo grande')
        self.version = hashlib.sha256(data).hexdigest()
        self.records = json.loads(data)
        if not isinstance(self.records, list) or len(self.records) > 10000:
            raise ValueError('Corpus retrieval non valido')
        for item in self.records:
            if not isinstance(item, dict) or not isinstance(item.get('id'), str):
                raise ValueError('Record retrieval senza ID')
            if not isinstance(item.get('terms'), list) or not all(isinstance(t, str) and t for t in item['terms']):
                raise ValueError('Termini retrieval non validi')

    def search(self, context: dict, limit: int = 6) -> list[dict]:
        text = json.dumps(context, ensure_ascii=False).lower()
        scored = []
        for record in self.records:
            score = sum(1 for term in record['terms'] if term.lower() in text)
            if score:
                scored.append((score, record['id'], record))
        return [dict(item, retrieval='lexical hint, not proof') for _, _, item in sorted(scored, key=lambda row: (-row[0], row[1]))[:limit]]


def known_evidence_ids(context: dict) -> set[str]:
    known, seen = set(), set()
    pending = [context['evidence'], context.get('retrieval', [])]
    while pending:
        value = pending.pop()
        if isinstance(value, (dict, list)):
            if id(value) in seen:
                continue
            seen.add(id(value))
        if isinstance(value, dict):
            if isinstance(value.get('id'), str):
                known.add(value['id'])
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return known


def candidate_issues(source: str, context: dict, evidence_ids: list[str]) -> list[str]:
    if len(source.encode('utf-8')) > 128 * 1024:
        return ['Candidata oltre il limite di 128 KiB']
    known = known_evidence_ids(context)
    issues = []
    if any(item not in known for item in evidence_ids):
        issues.append('La candidata cita evidenze inesistenti')
    if not evidence_ids:
        issues.append('La candidata non cita alcuna evidenza')
    from gamedecomp.csyntax import code_view, function_header
    # This gate limits accepted syntax; it does not sandbox the compiler.
    code = code_view(source)
    safe_header = re.compile(r'#\s*include\s*<(?:stdint|stddef|stdbool)\.h>\s*')
    for match in re.finditer('#', code):
        start = code.rfind('\n', 0, match.start())+1
        end = code.find('\n', match.start())
        line = code[start:end if end>=0 else len(code)]
        if not safe_header.fullmatch(line.strip()):
            issues.append('Direttive di preprocessore non ammesse nella candidata AI')
            break
    if re.search(r'\b(?:__asm__|__asm|asm|_Pragma|__pragma)\b', code):
        issues.append('Assembly inline o pragma non ammessi nella candidata AI')
    if re.search(r'\b(?:in_|unaff_|extraout_)[A-Za-z0-9_]*\b', code):
        issues.append('Stato macchina non risolto nella candidata AI')
    supplied_helpers = set(re.findall(r'\b__gd_[A-Za-z0-9_]+\b',context.get('compiler_support','')))
    helper_definitions = {}
    helper_call = re.compile(r'\s*\(')
    for helper in re.finditer(r'\b__gd_[A-Za-z0-9_]+\b', code):
        name = helper[0]
        if name in supplied_helpers and name not in helper_definitions:
            helper_definitions[name] = function_header(source,name)
        if (name not in supplied_helpers or not helper_call.match(code,helper.end())
                or helper_definitions.get(name)):
            issues.append('Identificatore riservato al verificatore ridefinito o non fornito')
            break
    metadata = next(fact['metadata'] for fact in context['evidence'] if fact['kind'] == 'signature')
    export = metadata.get('export_name')
    identity = export or context.get('name')
    if identity and not function_header(source, identity):
        issues.append('Definizione della funzione osservata non preservata o non riconosciuta')
    if export and 'return_bits' in metadata and 'parameter_bits' in metadata:
        signature = re.search(r'\b(uint(?:32|64)_t)\s+' + re.escape(export) + r'\s*\(([^)]*)\)\s*\{', code)
        expected_return = f'uint{metadata["return_bits"]}_t'
        actual_parameters = []
        if signature and signature.group(2).strip() not in ('', 'void'):
            for parameter in signature.group(2).split(','):
                match = re.fullmatch(r'\s*(uint(?:32|64)_t)\s+[A-Za-z_][A-Za-z0-9_]*\s*', parameter)
                actual_parameters.append(match.group(1) if match else None)
        expected_parameters = [f'uint{bits}_t' for bits in metadata['parameter_bits']]
        if not signature or signature.group(1) != expected_return or actual_parameters != expected_parameters:
            issues.append('Firma scalare osservata non preservata; candidata non ammessa alla compilazione')
    return issues
