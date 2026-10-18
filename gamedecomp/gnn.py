"""Auditable GraphSAGE classifier: optional CPU training, JSON/stdlib inference.

This classifier predicts a finite semantic family vocabulary, never source types
or semantic equivalence. Features contain machine observations only. The two
GraphSAGE layers concatenate a node with the mean of its callgraph neighbors;
call edges are symmetrized, and absent neighbors contribute a zero vector.
"""
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import time

from .models import Analysis


FEATURE_VERSION = 'asm-callgraph-v1'
FEATURE_NAMES = (
    'instruction_log_count', 'move_fraction', 'address_fraction', 'add_fraction',
    'subtract_fraction', 'multiply_fraction', 'divide_fraction', 'bitwise_fraction',
    'shift_fraction', 'compare_fraction', 'conditional_branch_fraction', 'jump_fraction',
    'call_fraction', 'return_fraction', 'stack_fraction', 'floating_fraction',
    'conversion_fraction', 'memory_fraction', 'immediate_fraction', 'zero_fraction',
    'register32_fraction', 'register64_fraction', 'vector_register_fraction',
    'backedge_fraction', 'block_fraction', 'outdegree_log', 'indegree_log',
    'argument_count_scaled', 'return32', 'return64', 'argument64_fraction',
    'opcode_diversity_fraction',
)
_WIDTH = len(FEATURE_NAMES)
_MAX_NODES = 20_000
_MAX_EDGES = 200_000
_MAX_MODEL_BYTES = 16 * 1024 * 1024
_MAX_DATASET_BYTES = 64 * 1024 * 1024
_REGISTER32 = re.compile(r'(?<![\w])(?:e(?:ax|bx|cx|dx|si|di|bp|sp)|r(?:[89]|1[0-5])d|w\d+)(?!\w)')
_REGISTER64 = re.compile(r'(?<![\w])(?:r(?:ax|bx|cx|dx|si|di|bp|sp|[89]|1[0-5])|x\d+)(?!\w)')
_VECTOR = re.compile(r'(?<![\w])(?:[xyz]mm\d+|[vqs]\d+)(?!\w)')
_IMMEDIATE = re.compile(r'(?:\$|#)\s*(-?(?:0x[0-9a-f]+|\d+))\b')


def _number(value, name, *, bound=1_000_000.0):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f'{name} must be a finite number')
    try:
        result = float(value)
    except (OverflowError, ValueError):
        raise ValueError(f'{name} must be a finite number') from None
    if not math.isfinite(result) or abs(result) > bound:
        raise ValueError(f'{name} is not finite or exceeds its bound')
    return result


def _integer(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f'{name} must be an integer in [{minimum}, {maximum}]')
    return value


def _check_deadline(deadline):
    if time.monotonic() >= deadline:
        raise TimeoutError('GNN inference exceeded its time budget')


def _read_json(path, limit):
    with Path(path).open('rb') as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f'JSON exceeds {limit} bytes')
    try:
        value = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON value')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f'invalid JSON: {error}') from error
    if not isinstance(value, dict):
        raise ValueError('JSON root must be an object')
    return value, raw


def build_graph(analysis: Analysis, labels: dict | None = None, group: str = '') -> dict:
    """Build a versioned numeric machine-observation and callgraph representation."""
    return _build_graph(analysis, labels, group)


def _build_graph(analysis, labels=None, group='', deadline=None):
    """Extract 32 numeric observations; names, source and debug data are ignored.

    IDs establish graph identity only. Branch destinations are used solely for
    relative backedge topology, never as numeric addresses in the feature vector.
    ABI widths are the backend's machine-level observations, not debug types.
    """
    if not isinstance(group, str) or len(group) > 1024:
        raise ValueError('group must be a short string')
    if labels is not None and not isinstance(labels, dict):
        raise ValueError('labels must be a mapping')
    if len(analysis.functions) > _MAX_NODES:
        raise ValueError('too many functions for a GNN graph')
    indices = {}
    total_instructions = 0
    for index, function in enumerate(analysis.functions):
        if deadline is not None:
            _check_deadline(deadline)
        if not isinstance(function.id, str) or not function.id or len(function.id) > 1024:
            raise ValueError('invalid function id')
        if function.id in indices:
            raise ValueError('duplicate function id')
        indices[function.id] = index
        total_instructions += len(function.instructions)
    if total_instructions > 2_000_000:
        raise ValueError('too many instructions for a GNN graph')
    edges = set()
    references = 0
    for index, function in enumerate(analysis.functions):
        if deadline is not None:
            _check_deadline(deadline)
        references += len(function.calls)
        if references > 1_000_000:
            raise ValueError('too many callgraph references')
        for target in function.calls:
            if target in indices:
                edges.add((index, indices[target]))
                if len(edges) > _MAX_EDGES:
                    raise ValueError('too many callgraph edges')
    incoming, outgoing = Counter(), Counter()
    for source, target in edges:
        outgoing[source] += 1
        incoming[target] += 1
    nodes = []
    for index, function in enumerate(analysis.functions):
        if deadline is not None:
            _check_deadline(deadline)
        count = len(function.instructions)
        denominator = max(1, count)
        counters = [0.0] * 25
        opcodes = set()
        for instruction_index, instruction in enumerate(function.instructions):
            if deadline is not None and instruction_index % 128 == 0:
                _check_deadline(deadline)
            mnemonic = instruction.mnemonic.lower()
            # objdump annotations can contain demangled identifiers, templates,
            # register-looking names, and addresses; none are machine operands.
            operand = instruction.operands.lower().split('<', 1)[0]
            if analysis.architecture in ('x86_64', 'x86', 'i386', 'x64'):
                operand = operand.split('#', 1)[0]
            # WASM family names are normalized without symbol strings.
            opcode = mnemonic.split('.')[-1]
            opcodes.add(mnemonic)
            branch = (opcode.startswith('j') and opcode not in ('jmp', 'jmpq')) or mnemonic.startswith('b.') or opcode in ('cbz', 'cbnz', 'tbz', 'tbnz', 'br_if')
            jump = opcode in ('jmp', 'jmpq', 'b', 'br')
            call = opcode in ('call', 'callq', 'bl', 'blr', 'call_indirect')
            counters[1] += opcode.startswith(('mov', 'ldr', 'ldp')) or opcode in ('local.get', 'get')
            counters[2] += opcode.startswith(('lea', 'adr'))
            counters[3] += opcode.startswith(('add', 'inc'))
            counters[4] += opcode.startswith(('sub', 'dec', 'neg'))
            counters[5] += 'mul' in opcode
            counters[6] += 'div' in opcode or 'rem' in opcode
            counters[7] += opcode.startswith(('and', 'or', 'xor', 'not', 'eor', 'bic'))
            counters[8] += opcode.startswith(('shl', 'shr', 'sal', 'sar', 'rol', 'ror', 'lsl', 'lsr', 'asr', 'rot'))
            counters[9] += opcode.startswith(('cmp', 'test', 'set', 'tst', 'cset')) or opcode in ('eq', 'ne', 'lt_s', 'lt_u', 'gt_s', 'gt_u')
            counters[10] += branch
            counters[11] += jump
            counters[12] += call
            counters[13] += opcode in ('ret', 'retq', 'return')
            counters[14] += opcode.startswith(('push', 'pop')) or opcode in ('stp', 'ldp', 'enter', 'leave')
            counters[15] += bool(_VECTOR.search(operand)) or mnemonic.startswith(('f32.', 'f64.', 'fadd', 'fsub', 'fmul', 'fdiv', 'fld', 'fst')) or opcode.endswith(('ss', 'sd', 'ps', 'pd'))
            counters[16] += opcode.startswith(('cvt', 'vcvt', 'movzx', 'movsx', 'sxt', 'uxt')) or 'convert' in opcode or 'extend' in opcode or 'wrap' in opcode
            counters[17] += ('(' in operand or '[' in operand or opcode.startswith(('ldr', 'str', 'ldp', 'stp')) or 'load' in opcode or 'store' in opcode)
            if not (branch or jump or call):
                immediates = _IMMEDIATE.findall(operand)
                if not immediates and '$' not in operand and '#' not in operand:
                    immediates = re.findall(r'(?<![\w])(-?(?:0x[0-9a-f]+|\d+))(?!\w)', operand)
                counters[18] += bool(immediates) or (mnemonic.endswith('.const') and bool(operand))
                counters[19] += any(int(value, 16 if '0x' in value else 10) == 0 for value in immediates)
            counters[20] += bool(_REGISTER32.search(operand))
            counters[21] += bool(_REGISTER64.search(operand))
            counters[22] += bool(_VECTOR.search(operand))
            if branch or jump:
                target = re.match(r'\s*(?:0x)?([0-9a-f]+)\b', operand)
                if target and int(target.group(1), 16) <= instruction.address:
                    counters[23] += 1
            counters[24] += branch or jump
        features = [math.log1p(count)] + [value / denominator for value in counters[1:25]]
        features[24] = (counters[24] + bool(count)) / denominator
        metadata = function.metadata
        bits = metadata.get('parameter_bits', [])
        if not isinstance(bits, list) or not all(type(value) is int and value in (8, 16, 32, 64, 128) for value in bits):
            bits = []
        return_bits = metadata.get('return_bits')
        features += [math.log1p(outgoing[index]), math.log1p(incoming[index]), min(len(bits), 32) / 8.0,
                     float(return_bits == 32), float(return_bits == 64),
                     sum(value == 64 for value in bits) / max(1, len(bits)), len(opcodes) / denominator]
        node = {'id': function.id, 'features': features}
        if labels is not None and function.id in labels:
            label = labels[function.id]
            if not isinstance(label, str) or not 1 <= len(label) <= 128:
                raise ValueError('invalid semantic label')
            node['label'] = label
        nodes.append(node)
    return {'group': group, 'nodes': nodes, 'edges': [list(edge) for edge in sorted(edges)]}


def _vector(value, length, name, *, scale=False):
    if not isinstance(value, list) or len(value) != length:
        raise ValueError(f'invalid {name} dimensions')
    result = [_number(item, name) for item in value]
    if scale and any(item < 1e-8 for item in result):
        raise ValueError('normalization scales must be positive and >= 1e-8')
    return result


def _validate_model(value):
    if type(value.get('schema_version')) is not int or value['schema_version'] != 1 or value.get('model_type') != 'graphsage_mean':
        raise ValueError('unsupported GNN model schema or type')
    if value.get('feature_version') != FEATURE_VERSION or value.get('feature_names') != list(FEATURE_NAMES):
        raise ValueError('unsupported GNN feature version or ordering')
    hidden = _integer(value.get('hidden_dim'), 'hidden_dim', 1, 128)
    labels = value.get('labels')
    if not isinstance(labels, list) or not 2 <= len(labels) <= 64 or not all(isinstance(label, str) and 1 <= len(label) <= 128 for label in labels) or len(set(labels)) != len(labels):
        raise ValueError('invalid model labels')
    normalization = value.get('normalization')
    if not isinstance(normalization, dict):
        raise ValueError('missing normalization')
    mean = _vector(normalization.get('mean'), _WIDTH, 'normalization mean')
    scale = _vector(normalization.get('scale'), _WIDTH, 'normalization scale', scale=True)
    layers = value.get('layers')
    if not isinstance(layers, list) or len(layers) != 2:
        raise ValueError('model requires two GraphSAGE layers')
    validated = []
    for layer, inputs, outputs in zip(layers, (_WIDTH, hidden), (hidden, len(labels))):
        if not isinstance(layer, dict) or not isinstance(layer.get('weight'), list) or len(layer['weight']) != outputs:
            raise ValueError('invalid model layer dimensions')
        weight = [_vector(row, 2 * inputs, 'layer weight') for row in layer['weight']]
        bias = _vector(layer.get('bias'), outputs, 'layer bias')
        validated.append({'weight': weight, 'bias': bias})
    return {'labels': labels, 'hidden_dim': hidden, 'normalization': {'mean': mean, 'scale': scale}, 'layers': validated}


def _neighbors(graph):
    neighbors = [set() for _ in graph['nodes']]
    for source, target in graph['edges']:
        if source != target:
            neighbors[source].add(target)
            neighbors[target].add(source)
    return [sorted(items) for items in neighbors]


def _portable_logits(graph, model, deadline):
    norm = model['normalization']
    rows = [[(value - mean) / scale for value, mean, scale in zip(node['features'], norm['mean'], norm['scale'])] for node in graph['nodes']]
    neighbors = _neighbors(graph)
    for layer_index, layer in enumerate(model['layers']):
        result = []
        for index, row in enumerate(rows):
            _check_deadline(deadline)
            connected = neighbors[index]
            if connected:
                aggregate = [sum(rows[other][column] for other in connected) / len(connected) for column in range(len(row))]
            else:
                aggregate = [0.0] * len(row)
            combined = row + aggregate
            output = [bias + sum(weight * feature for weight, feature in zip(weights, combined)) for weights, bias in zip(layer['weight'], layer['bias'])]
            if not all(math.isfinite(value) for value in output):
                raise ValueError('nonfinite model activation')
            if layer_index == 0:
                output = [max(0.0, value) for value in output]
            result.append(output)
        rows = result
    return rows


def predict(analysis: Analysis, model_path: Path, *, timeout=30) -> dict:
    """Load bounded numeric JSON and predict hypotheses without importing torch."""
    timeout = _number(timeout, 'timeout', bound=86_400)
    if timeout <= 0:
        raise ValueError('timeout must be positive')
    deadline = time.monotonic() + timeout
    value, raw = _read_json(model_path, _MAX_MODEL_BYTES)
    _check_deadline(deadline)
    model = _validate_model(value)
    graph = _build_graph(analysis, deadline=deadline)
    _check_deadline(deadline)
    logits = _portable_logits(graph, model, deadline)
    predictions = {}
    for node, scores in zip(graph['nodes'], logits):
        _check_deadline(deadline)
        offset = max(scores)
        exponentials = [math.exp(score - offset) for score in scores]
        total = sum(exponentials)
        probabilities = [item / total for item in exponentials]
        best = max(range(len(scores)), key=lambda index: scores[index])
        predictions[node['id']] = {
            'label': model['labels'][best], 'confidence': probabilities[best],
            'distribution': dict(zip(model['labels'], probabilities)),
            'evidence_ids': [f"gnn:{node['id']}:machine_features", f"gnn:{node['id']}:callgraph"],
            'status': 'HYPOTHESIS',
        }
    return {'schema_version': 1, 'model_hash': hashlib.sha256(raw).hexdigest(), 'predictions': predictions,
            'metadata': {'model_type': 'graphsage_mean', 'feature_version': FEATURE_VERSION,
                         'nodes': len(graph['nodes']), 'edges': len(graph['edges']), 'labels': model['labels'],
                         'neighbor_policy': 'undirected_unique_without_self', 'calibrated': False},
            'diagnostics': ['Neural semantic-family hypotheses are not recovered source types or equivalence proofs. Confidence is uncalibrated softmax.']}


def _validate_dataset(value):
    if type(value.get('schema_version')) is not int or value['schema_version'] != 1 or value.get('feature_version') != FEATURE_VERSION:
        raise ValueError('unsupported dataset schema or feature version')
    graphs = value.get('graphs')
    if not isinstance(graphs, list) or not 3 <= len(graphs) <= 10_000:
        raise ValueError('dataset requires 3 to 10000 graphs')
    splits = {'train': [], 'validation': [], 'test': []}
    group_splits = {}
    total_nodes, total_edges = 0, 0
    for graph in graphs:
        if not isinstance(graph, dict) or graph.get('split') not in splits:
            raise ValueError('each graph requires a train/validation/test split')
        split, group = graph['split'], graph.get('group')
        if not isinstance(group, str) or not 1 <= len(group) <= 1024:
            raise ValueError('each graph requires a nonempty source group')
        if group in group_splits and group_splits[group] != split:
            raise ValueError('source group crosses dataset splits')
        group_splits[group] = split
        nodes, edges = graph.get('nodes'), graph.get('edges')
        if not isinstance(nodes, list) or not 1 <= len(nodes) <= _MAX_NODES or not isinstance(edges, list) or len(edges) > _MAX_EDGES:
            raise ValueError('invalid graph size')
        ids, validated_nodes = set(), []
        for node in nodes:
            if not isinstance(node, dict) or not isinstance(node.get('id'), str) or not 1 <= len(node['id']) <= 1024 or node['id'] in ids:
                raise ValueError('invalid or duplicate dataset node id')
            ids.add(node['id'])
            features = _vector(node.get('features'), _WIDTH, 'dataset features')
            item = {'id': node['id'], 'features': features}
            if 'label' in node:
                label = node['label']
                if not isinstance(label, str) or not 1 <= len(label) <= 128:
                    raise ValueError('invalid dataset label')
                item['label'] = label
            validated_nodes.append(item)
        validated_edges = set()
        for edge in edges:
            if not isinstance(edge, list) or len(edge) != 2:
                raise ValueError('invalid graph edge')
            validated_edges.add(tuple(_integer(index, 'edge index', 0, len(nodes) - 1) for index in edge))
        total_nodes += len(nodes)
        total_edges += len(validated_edges)
        if total_nodes > 100_000 or total_edges > 1_000_000:
            raise ValueError('dataset exceeds total node or edge budget')
        splits[split].append({'group': group, 'nodes': validated_nodes, 'edges': sorted(validated_edges)})
    for split, items in splits.items():
        if not items or not any('label' in node for graph in items for node in graph['nodes']):
            raise ValueError(f'{split} requires labeled observations')
    labels = sorted({node['label'] for graph in splits['train'] for node in graph['nodes'] if 'label' in node})
    if not 2 <= len(labels) <= 64:
        raise ValueError('training requires 2 to 64 semantic labels')
    for split in ('validation', 'test'):
        unknown = {node['label'] for graph in splits[split] for node in graph['nodes'] if 'label' in node} - set(labels)
        if unknown:
            raise ValueError(f'{split} contains labels absent from training')
    return splits, labels


def _metrics(truth, guesses, labels, loss=None):
    matrix = [[0 for _ in labels] for _ in labels]
    for actual, predicted in zip(truth, guesses):
        matrix[actual][predicted] += 1
    per_class, scores = {}, []
    for index, label in enumerate(labels):
        true_positive = matrix[index][index]
        predicted = sum(row[index] for row in matrix)
        support = sum(matrix[index])
        precision = true_positive / predicted if predicted else 0.0
        recall = true_positive / support if support else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[label] = {'precision': precision, 'recall': recall, 'f1': f1, 'support': support}
        scores.append(f1)
    result = {'accuracy': sum(actual == predicted for actual, predicted in zip(truth, guesses)) / len(truth),
              'macro_f1': sum(scores) / len(scores), 'confusion_matrix': matrix,
              'labels': labels, 'samples': len(truth), 'per_class': per_class}
    if loss is not None:
        result['loss'] = loss
    return result


def _audit_splits(splits):
    """Report exact machine-observation overlap without inventing source leakage.

    Distinct authored functions can compile to identical observations. Groups
    still must remain disjoint; these counts reveal a separate evaluation limit.
    Graph comparisons ignore node IDs, labels and provenance, preserving order.
    """
    vectors, graphs = {}, {}
    for split, items in splits.items():
        vectors[split], graphs[split] = set(), set()
        for graph in items:
            rows = [node['features'] for node in graph['nodes']]
            for row in rows:
                vectors[split].add(tuple(row))
            canonical = json.dumps({'features': rows, 'edges': graph['edges']}, separators=(',', ':'), sort_keys=True)
            graphs[split].add(hashlib.sha256(canonical.encode()).hexdigest())
    duplicates, warnings = [], []
    for left, right in (('train', 'validation'), ('train', 'test'), ('validation', 'test')):
        shared_vectors = len(vectors[left] & vectors[right])
        shared_graphs = len(graphs[left] & graphs[right])
        duplicates.append({'splits': [left, right], 'unique_feature_vectors': shared_vectors,
                           'exact_ordered_graphs': shared_graphs})
        if shared_graphs:
            warnings.append(f'{left}/{right} share {shared_graphs} exact ordered machine-feature graphs; holdout diversity is limited.')
        elif shared_vectors:
            warnings.append(f'{left}/{right} share {shared_vectors} exact machine-feature vectors; this alone does not prove source leakage.')
    return {'source_groups_disjoint': True, 'overlap': duplicates, 'warnings': warnings,
            'graph_comparison': 'exact node-order features and topology; IDs/labels excluded, not graph isomorphism'}


def train_model(dataset_path: Path, output: Path, *, epochs=120, seed=17) -> dict:
    """Train a two-layer CPU GraphSAGE and publish JSON weights in a new directory.

    Statistics use training observations only. Validation selects the checkpoint
    by macro-F1 (then loss). The chosen checkpoint is evaluated on test once.
    """
    epochs = _integer(epochs, 'epochs', 1, 10_000)
    seed = _integer(seed, 'seed', 0, 2 ** 31 - 1)
    output = Path(output)
    if output.exists():
        raise FileExistsError(f'output already exists: {output}')
    value, raw = _read_json(dataset_path, _MAX_DATASET_BYTES)
    splits, labels = _validate_dataset(value)
    try:
        import torch
    except ImportError as error:
        raise RuntimeError('GNN training requires optional PyTorch; JSON inference does not') from error
    # CPU, single thread, forked RNG: reproducible small experiments; no GPU required.
    previous_threads = torch.get_num_threads()
    torch.set_num_threads(1)
    try:
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(seed)
            return _train(torch, splits, labels, output, epochs, seed, hashlib.sha256(raw).hexdigest())
    finally:
        torch.set_num_threads(previous_threads)


def _train(torch, splits, labels, output, epochs, seed, dataset_hash):
    train_rows = [node['features'] for graph in splits['train'] for node in graph['nodes']]
    features = torch.tensor(train_rows, dtype=torch.float32)
    means = features.mean(dim=0)
    scales = features.std(dim=0, unbiased=False).clamp_min(1e-6)
    label_index = {label: index for index, label in enumerate(labels)}

    def tensors(graphs):
        rows, targets, mask, sources, destinations = [], [], [], [], []
        for graph in graphs:
            offset = len(rows)
            for node in graph['nodes']:
                rows.append(node['features'])
                if 'label' in node:
                    mask.append(len(rows) - 1)
                    targets.append(label_index[node['label']])
            for index, neighbors in enumerate(_neighbors(graph)):
                for neighbor in neighbors:
                    sources.append(offset + neighbor)
                    destinations.append(offset + index)
        x = (torch.tensor(rows, dtype=torch.float32) - means) / scales
        source = torch.tensor(sources, dtype=torch.long)
        destination = torch.tensor(destinations, dtype=torch.long)
        degree = torch.bincount(destination, minlength=len(rows)).clamp_min(1).unsqueeze(1)
        return x, source, destination, degree, torch.tensor(mask, dtype=torch.long), torch.tensor(targets, dtype=torch.long)

    # Test tensors are constructed after checkpoint selection, to keep the
    # training/selection path independent of held-out observations.
    train_data, validation_data = tensors(splits['train']), tensors(splits['validation'])
    first = torch.nn.Linear(2 * _WIDTH, 32)
    second = torch.nn.Linear(64, len(labels))
    optimizer = torch.optim.Adam(list(first.parameters()) + list(second.parameters()), lr=0.01, weight_decay=1e-4)

    def forward(data):
        rows, source, destination, degree, mask, target = data
        for layer_index, layer in enumerate((first, second)):
            aggregated = torch.zeros_like(rows)
            if len(source):
                aggregated.index_add_(0, destination, rows[source])
            rows = layer(torch.cat((rows, aggregated / degree), dim=1))
            if layer_index == 0:
                rows = torch.relu(rows)
        return rows[mask], target

    def evaluate(data):
        with torch.no_grad():
            scores, truth = forward(data)
            loss = float(torch.nn.functional.cross_entropy(scores, truth).item())
            if not math.isfinite(loss):
                raise ValueError('training produced nonfinite loss')
            return _metrics(truth.tolist(), scores.argmax(dim=1).tolist(), labels, loss)

    initial_loss = evaluate(train_data)['loss']
    best_key, best_state, best_epoch = None, None, 0
    history = []
    for epoch in range(1, epochs + 1):
        optimizer.zero_grad(set_to_none=True)
        scores, target = forward(train_data)
        loss = torch.nn.functional.cross_entropy(scores, target)
        if not bool(torch.isfinite(loss)):
            raise ValueError('training produced nonfinite loss')
        loss.backward()
        torch.nn.utils.clip_grad_norm_(list(first.parameters()) + list(second.parameters()), 5.0)
        optimizer.step()
        validation = evaluate(validation_data)
        history.append({'epoch': epoch, 'train_loss': float(loss.item()), 'validation_loss': validation['loss'], 'validation_macro_f1': validation['macro_f1']})
        key = (validation['macro_f1'], -validation['loss'])
        if best_key is None or key > best_key:
            best_key, best_epoch = key, epoch
            best_state = [{key: tensor.detach().clone() for key, tensor in layer.state_dict().items()} for layer in (first, second)]
    last_training_loss = evaluate(train_data)['loss']
    for layer, state in zip((first, second), best_state):
        layer.load_state_dict(state)
    train_metrics, validation_metrics = evaluate(train_data), evaluate(validation_data)
    test_data = tensors(splits['test'])
    test_metrics = evaluate(test_data)
    majority = Counter(train_data[-1].tolist()).most_common(1)[0][0]
    baseline = {}
    for split, data in (('train', train_data), ('validation', validation_data), ('test', test_data)):
        truth = data[-1].tolist()
        baseline[split] = _metrics(truth, [majority] * len(truth), labels)
    model = {
        'schema_version': 1, 'model_type': 'graphsage_mean', 'feature_version': FEATURE_VERSION,
        'feature_names': list(FEATURE_NAMES), 'labels': labels, 'hidden_dim': 32,
        'normalization': {'mean': means.tolist(), 'scale': scales.tolist()},
        'layers': [{'weight': layer.weight.detach().tolist(), 'bias': layer.bias.detach().tolist()} for layer in (first, second)],
        'training': {'seed': seed, 'epochs': epochs, 'best_epoch': best_epoch, 'dataset_hash': dataset_hash},
    }
    # Validate the actual portable artifact before publishing any files.
    _validate_model(model)
    portable_scores = _portable_logits(splits['validation'][0], model, time.monotonic() + 30)
    if any(not all(math.isfinite(value) for value in row) for row in portable_scores):
        raise ValueError('portable inference validation failed')
    metrics = {
        'schema_version': 1, 'model_type': 'graphsage_mean', 'feature_version': FEATURE_VERSION,
        'dataset_hash': dataset_hash, 'seed': seed, 'labels': labels,
        'training': {'epochs': epochs, 'best_epoch': best_epoch, 'initial_loss': initial_loss,
                     'final_loss': last_training_loss, 'checkpoint_loss': train_metrics['loss'],
                     'learning_rate': 0.01, 'hidden_dim': 32, 'device': 'cpu', 'history': history},
        'train': train_metrics, 'validation': validation_metrics, 'test': test_metrics,
        'majority_baseline': {'label': labels[majority], **baseline}, 'test_evaluations': 1,
        'dataset_audit': _audit_splits(splits),
        'splits': {split: {'graphs': len(graphs), 'groups': len({graph['group'] for graph in graphs}),
                           'nodes': sum(len(graph['nodes']) for graph in graphs)} for split, graphs in splits.items()},
        'limitations': ['Synthetic/local corpus metrics do not establish accuracy on unseen games.',
                        'Predicted families are hypotheses; softmax probabilities are uncalibrated.'],
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / 'model.json').write_text(json.dumps(model, allow_nan=False, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    (output / 'metrics.json').write_text(json.dumps(metrics, allow_nan=False, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    return metrics
