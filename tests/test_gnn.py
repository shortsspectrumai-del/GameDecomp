"""Graph observations, portable inference, and actual optional neural training."""
import copy
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from gamedecomp.models import Analysis, Function, Instruction
from gamedecomp.gnn import FEATURE_NAMES, FEATURE_VERSION, build_graph, predict, train_model


def analysis(connected=False):
    functions = [
        Function('a', 'first', 0x1000, [Instruction(0x1000, 'add', '%edi,%eax'), Instruction(0x1003, 'ret', '')]),
        Function('b', 'second', 0x2000, [Instruction(0x2000, 'mov', '(%rdi),%eax'), Instruction(0x2003, 'ret', '')]),
    ]
    if connected:
        functions[0].calls = ['b']
    return Analysis('binary', 'ELF', 'x86_64', 'native', functions)


def hand_model():
    width = len(FEATURE_NAMES)
    first = [0.0] * (width * 2)
    first[width + FEATURE_NAMES.index('move_fraction')] = 1.0
    return {
        'schema_version': 1, 'model_type': 'graphsage_mean', 'feature_version': FEATURE_VERSION,
        'feature_names': list(FEATURE_NAMES), 'labels': ['arithmetic', 'memory_read'], 'hidden_dim': 1,
        'normalization': {'mean': [0.0] * width, 'scale': [1.0] * width},
        'layers': [{'weight': [first], 'bias': [0.0]},
                   {'weight': [[0.0, 0.0], [1.0, 0.0]], 'bias': [0.0, 0.0]}],
    }


class GraphFeatureTests(unittest.TestCase):
    def test_features_exclude_names_addresses_source_and_debug(self):
        original = analysis()
        renamed = copy.deepcopy(original)
        for index, function in enumerate(renamed.functions):
            function.id = 'renamed-' + str(index)
            function.name = 'arithmetic_LABEL_SECRET'
            function.address += 0x900000
            function.source = 'memory_read leaked_name'
            function.metadata['dwarf'] = {'type': 'SecretClass', 'name': 'ground_truth'}
            for instruction in function.instructions:
                instruction.address += 0x900000
        left = build_graph(original, {'a': 'arithmetic', 'b': 'memory_read'}, group='source-1')
        right = build_graph(renamed, group='source-2')
        self.assertEqual([n['features'] for n in left['nodes']], [n['features'] for n in right['nodes']])
        self.assertEqual(len(left['nodes'][0]['features']), 32)
        self.assertEqual(left['nodes'][0]['label'], 'arithmetic')
        self.assertNotIn('label', right['nodes'][0])
        self.assertTrue(all(math.isfinite(v) for n in left['nodes'] for v in n['features']))

    def test_graph_uses_call_indices_and_deduplicates_edges(self):
        value = analysis(True)
        value.functions[0].calls += ['b', 'external']
        graph = build_graph(value)
        self.assertEqual(graph['edges'], [[0, 1]])
        self.assertEqual(graph['group'], '')

    def test_duplicate_function_ids_rejected(self):
        value = analysis()
        value.functions[1].id = 'a'
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            build_graph(value)

    def test_symbol_annotations_cannot_leak_into_features(self):
        left, right = analysis(), analysis()
        left.functions[0].instructions[0].operands += ' # 1234 <plain_name>'
        right.functions[0].instructions[0].operands += ' # 9876 <xmm1<rax>::foo()>'
        self.assertEqual(build_graph(left)['nodes'][0]['features'], build_graph(right)['nodes'][0]['features'])


class PortablePredictionTests(unittest.TestCase):
    def test_message_passing_changes_prediction_and_hashes_model(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / 'model.json'
            model.write_text(json.dumps(hand_model()))
            bare = predict(analysis(), model)
            linked = predict(analysis(True), model)
            self.assertNotEqual(bare['predictions']['a']['distribution'], linked['predictions']['a']['distribution'])
            result = linked['predictions']['a']
            self.assertEqual(result['status'], 'HYPOTHESIS')
            self.assertEqual(len(linked['model_hash']), 64)
            self.assertAlmostEqual(sum(result['distribution'].values()), 1.0)
            self.assertTrue(result['evidence_ids'])

    def test_rejects_dimensions_nonfinite_and_nonpositive_scale(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / 'model.json'
            for mutation in ('shape', 'nan', 'scale', 'version'):
                value = hand_model()
                if mutation == 'shape':
                    value['layers'][0]['weight'][0].pop()
                elif mutation == 'nan':
                    value['layers'][0]['bias'][0] = float('nan')
                elif mutation == 'scale':
                    value['normalization']['scale'][0] = 0
                else:
                    value['feature_version'] = 'future'
                model.write_text(json.dumps(value))
                with self.assertRaises(ValueError, msg=mutation):
                    predict(analysis(), model)

    def test_inference_has_no_torch_import(self):
        import builtins
        real_import = builtins.__import__
        def no_torch(name, *args, **kwargs):
            if name == 'torch' or name.startswith('torch.'):
                raise AssertionError('torch imported during inference')
            return real_import(name, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / 'model.json'
            model.write_text(json.dumps(hand_model()))
            with mock.patch('builtins.__import__', side_effect=no_torch):
                self.assertEqual(len(predict(analysis(), model)['predictions']), 2)

    def test_timeout_checked_before_read(self):
        for timeout in (0, -1, float('inf'), True):
            with self.assertRaises(ValueError):
                predict(analysis(), Path('/missing'), timeout=timeout)

    def test_deadline_is_checked_during_graph_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / 'model.json'
            model.write_text(json.dumps(hand_model()))
            # start, after read, graph setup, then expiration inside node scan
            with mock.patch('gamedecomp.gnn.time.monotonic', side_effect=[0.0, 0.0, 0.0, 2.0]):
                with mock.patch('gamedecomp.gnn._portable_logits', side_effect=AssertionError('deadline must stop graph extraction')):
                    with self.assertRaises(TimeoutError):
                        predict(analysis(), model, timeout=1)

    def test_torch_and_portable_message_passing_are_numerically_equal(self):
        try:
            import torch
        except ImportError:
            self.skipTest('optional PyTorch unavailable')
        import random
        rng = random.Random(7)
        width = len(FEATURE_NAMES)
        model = hand_model()
        model['hidden_dim'] = 3
        model['layers'] = [
            {'weight': [[rng.uniform(-1, 1) for _ in range(width * 2)] for _ in range(3)], 'bias': [0.2, -0.1, 0.4]},
            {'weight': [[rng.uniform(-1, 1) for _ in range(6)] for _ in range(2)], 'bias': [-0.2, 0.3]},
        ]
        model['normalization'] = {'mean': [0.1] * width, 'scale': [0.7] * width}
        value = analysis(True)
        graph = build_graph(value)
        rows = (torch.tensor([n['features'] for n in graph['nodes']], dtype=torch.float64) - 0.1) / 0.7
        for index, layer in enumerate(model['layers']):
            # Two linked nodes; the neighbor mean is the opposite row.
            rows = torch.nn.functional.linear(torch.cat((rows, rows.flip(0)), 1),
                                              torch.tensor(layer['weight'], dtype=torch.float64),
                                              torch.tensor(layer['bias'], dtype=torch.float64))
            if index == 0:
                rows = torch.relu(rows)
        expected = torch.softmax(rows, 1).tolist()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'model.json'
            path.write_text(json.dumps(model))
            actual = predict(value, path)
        for node, probabilities in zip(graph['nodes'], expected):
            for label, probability in zip(model['labels'], probabilities):
                self.assertAlmostEqual(actual['predictions'][node['id']]['distribution'][label], probability, places=12)


class TrainingTests(unittest.TestCase):
    def dataset(self):
        graphs = []
        for split in ('train', 'validation', 'test'):
            for number in range(2):
                graph = build_graph(analysis(bool(number)), {'a': 'arithmetic', 'b': 'memory_read'}, group=f'{split}-{number}')
                graph['split'] = split
                graphs.append(graph)
        return {'schema_version': 1, 'feature_version': FEATURE_VERSION, 'graphs': graphs}

    def test_training_reduces_loss_roundtrips_and_reports_holdout(self):
        try:
            import torch  # noqa: F401
        except ImportError:
            self.skipTest('optional PyTorch unavailable')
        with tempfile.TemporaryDirectory() as directory:
            dataset = Path(directory) / 'dataset.json'
            dataset.write_text(json.dumps(self.dataset()))
            output = Path(directory) / 'trained'
            result = train_model(dataset, output, epochs=45, seed=17)
            self.assertLess(result['training']['final_loss'], result['training']['initial_loss'])
            self.assertGreaterEqual(result['test']['accuracy'], 0.75)
            self.assertIn('macro_f1', result['test'])
            self.assertIn('confusion_matrix', result['test'])
            self.assertIn('majority_baseline', result)
            self.assertEqual(result['test_evaluations'], 1)
            self.assertTrue(result['dataset_audit']['warnings'])
            self.assertTrue((output / 'metrics.json').exists())
            model = json.loads((output / 'model.json').read_text())
            self.assertEqual(model['feature_version'], FEATURE_VERSION)
            predicted = predict(analysis(), output / 'model.json')
            self.assertEqual(predicted['predictions']['a']['label'], 'arithmetic')
            self.assertEqual(predicted['predictions']['b']['label'], 'memory_read')
            with self.assertRaises(FileExistsError):
                train_model(dataset, output, epochs=1)

    def test_split_contamination_unknown_labels_and_edges_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset = Path(directory) / 'dataset.json'
            for mutation in ('group', 'label', 'edge', 'nan'):
                value = self.dataset()
                if mutation == 'group':
                    value['graphs'][-1]['group'] = value['graphs'][0]['group']
                elif mutation == 'label':
                    value['graphs'][-1]['nodes'][0]['label'] = 'unknown'
                elif mutation == 'edge':
                    value['graphs'][-1]['edges'] = [[0, 100]]
                else:
                    value['graphs'][-1]['nodes'][0]['features'][0] = float('nan')
                dataset.write_text(json.dumps(value))
                with self.assertRaises(ValueError, msg=mutation):
                    train_model(dataset, Path(directory) / ('out-' + mutation), epochs=1)
