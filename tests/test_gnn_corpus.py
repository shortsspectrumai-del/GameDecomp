"""Real compilation of authored fixtures; no generated binary is executed."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest

from gamedecomp.gnn_corpus import build_corpus


@unittest.skipUnless(shutil.which('gcc') and shutil.which('objdump'), 'GCC/binutils required')
class GNNCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='gnn corpus fixtures ')
        cls.root = Path(cls.temp.name)
        cls.dataset_path = build_corpus(cls.root / 'corpus', samples=3, seed=23)
        cls.dataset = json.loads(cls.dataset_path.read_text())
        cls.manifest = json.loads((cls.dataset_path.parent / 'manifest.json').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_binary_graphs_cover_every_label_and_have_call_edges(self):
        from gamedecomp.gnn import FEATURE_VERSION, FEATURE_NAMES
        self.assertEqual(self.dataset['schema_version'], 1)
        self.assertEqual(self.dataset['feature_version'], FEATURE_VERSION)
        expected = {'arithmetic', 'bitwise', 'comparison', 'memory_read',
                    'memory_write', 'float_math'}
        labels = {split: set() for split in ('train', 'validation', 'test')}
        for graph in self.dataset['graphs']:
            self.assertEqual(len(graph['nodes']), 12)
            self.assertGreaterEqual(len(graph['edges']), 6)
            for node in graph['nodes']:
                labels[graph['split']].add(node['label'])
                self.assertEqual(len(node['features']), len(FEATURE_NAMES))
                self.assertTrue(all(isinstance(value, (int, float)) for value in node['features']))
                self.assertGreater(sum(abs(value) for value in node['features']), 0)
        self.assertEqual(set(labels), {'train', 'validation', 'test'})
        for split, present in labels.items():
            self.assertEqual(present, expected, split)
        self.assertFalse(self.manifest['binaries_executed'])

    def test_template_groups_and_all_compilation_variants_stay_in_one_split(self):
        group_splits = {}
        for graph in self.dataset['graphs']:
            group_splits.setdefault(graph['group'], set()).add(graph['split'])
        self.assertTrue(all(len(splits) == 1 for splits in group_splits.values()))
        sources = self.manifest['sources']
        self.assertEqual(len(sources), 3)
        templates = {split: {source['template_id'] for source in sources if source['split'] == split}
                     for split in ('train', 'validation', 'test')}
        self.assertFalse(templates['train'] & templates['validation'])
        self.assertFalse(templates['train'] & templates['test'])
        self.assertFalse(templates['validation'] & templates['test'])
        for source in sources:
            variants = [binary for binary in self.manifest['binaries']
                        if binary['source_id'] == source['id']]
            self.assertEqual({item['optimization'] for item in variants}, {'O0', 'O1', 'O2'})
            self.assertEqual({item['split'] for item in variants}, {source['split']})
            self.assertEqual({item['group'] for item in variants}, {source['group']})

    def test_manifest_hashes_and_graph_provenance_match_saved_artifacts(self):
        root = self.dataset_path.parent
        for source in self.manifest['sources']:
            data = (root / source['path']).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), source['sha256'])
            # Neutral identifiers prevent semantic family words in symbol names.
            self.assertTrue(all(name.startswith('f_') for name in source['ground_truth']))
        for binary in self.manifest['binaries']:
            data = (root / binary['path']).read_bytes()
            self.assertTrue(data.startswith(b'\x7fELF'))
            self.assertEqual(hashlib.sha256(data).hexdigest(), binary['sha256'])
            graph = self.dataset['graphs'][binary['graph_index']]
            self.assertEqual(graph['binary_sha256'], binary['sha256'])
            self.assertEqual(graph['source_id'], binary['source_id'])
        self.assertTrue(self.manifest['toolchains'])
        self.assertTrue(all(item['version'] for item in self.manifest['toolchains']))

    def test_held_out_function_body_templates_are_not_training_duplicates(self):
        bodies = {split: set() for split in ('train', 'validation', 'test')}
        for source in self.manifest['sources']:
            text = (self.dataset_path.parent / source['path']).read_text()
            for line in text.splitlines():
                if not line.startswith('NOINLINE '):
                    continue
                body = line.split('{', 1)[1]
                # Ignore identifiers/constants so changing names or immediate
                # literals cannot masquerade as a held-out body template.
                body = re.sub(r'f_\d+_\d+_[hw]', 'helper', body)
                body = re.sub(r'\b(?:0x[0-9a-f]+|[0-9]+(?:\.[0-9]+)?)[uU]?\b', 'K', body)
                bodies[source['split']].add(body)
        for first, second in (('train', 'validation'), ('train', 'test'), ('validation', 'test')):
            self.assertFalse(bodies[first] & bodies[second], (first, second))

    def test_seed_reproduces_sources_splits_and_extracted_graph_features(self):
        other_path = build_corpus(self.root / 'repeated', samples=3, seed=23)
        other = json.loads(other_path.read_text())
        manifest = json.loads((other_path.parent / 'manifest.json').read_text())
        self.assertEqual([item['sha256'] for item in manifest['sources']],
                         [item['sha256'] for item in self.manifest['sources']])
        self.assertEqual(other['graphs'], self.dataset['graphs'])

    def test_existing_output_and_invalid_bounds_are_rejected_without_mutation(self):
        sentinel = self.root / 'occupied'
        sentinel.mkdir()
        (sentinel / 'keep.txt').write_text('keep')
        with self.assertRaises(ValueError):
            build_corpus(sentinel, samples=3)
        self.assertEqual((sentinel / 'keep.txt').read_text(), 'keep')
        for samples in (True, 0, 2, 257, 3.5):
            with self.subTest(samples=samples), self.assertRaises(ValueError):
                build_corpus(self.root / 'invalid', samples=samples)
        for seed in (True, -1, 2**32, 0.5):
            with self.subTest(seed=seed), self.assertRaises(ValueError):
                build_corpus(self.root / 'invalid', samples=3, seed=seed)
        for timeout in (True, 0, -1, float('inf'), float('nan')):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                build_corpus(self.root / 'invalid', samples=3, timeout=timeout)
        self.assertFalse((self.root / 'invalid').exists())

    def test_expired_global_budget_does_not_publish_a_partial_dataset(self):
        output = self.root / 'expired'
        with self.assertRaises(TimeoutError):
            build_corpus(output, samples=3, timeout=1e-9)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
