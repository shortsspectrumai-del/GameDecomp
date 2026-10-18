import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gamedecomp.models import Analysis, Function
from gamedecomp.pipeline import AnalysisConfig, run_analysis
from tests.test_wasm import wasm_fixture


class ProgressTests(unittest.TestCase):
    def test_live_counts_finish_without_claiming_compilation_is_correctness(self):
        events = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root/'add.wasm'; binary.write_bytes(wasm_fixture())
            report = run_analysis(binary, root/'out', AnalysisConfig(cache_path=root/'cache.sqlite'),
                                  progress_callback=events.append)
        self.assertGreater(len(events), 3)
        final = events[-1]['progress']
        self.assertEqual(final['stage'], 'COMPLETE')
        self.assertEqual(final['total_units'], 1)
        self.assertEqual(final['processed_units'], 1)
        self.assertEqual(final['compiled_units'], 1)
        self.assertEqual(final['tested_units'], 0)
        self.assertEqual(final['unknown_units'], 1)
        self.assertEqual(report['summary']['proved'], 0)

    def test_concurrent_units_count_once_and_observer_cannot_corrupt_work(self):
        events = []
        def observer(event):
            events.append(event)
            event['progress']['processed_units'] = 9000
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root/'add.wasm'; binary.write_bytes(wasm_fixture())
            functions = [Function(str(i), 'fn'+str(i), i,
                source='unsigned int fn'+str(i)+'(void){return 1;}', metadata={'language': 'c'}) for i in range(2)]
            analysis = Analysis(hashlib.sha256(binary.read_bytes()).hexdigest(), 'WASM', 'wasm32', 'wasm', functions)
            with patch('gamedecomp.pipeline._analyze', return_value=analysis):
                report = run_analysis(binary, root/'out', AnalysisConfig(cache_path=root/'cache.sqlite'),
                                      progress_callback=observer)
            self.assertEqual(report['summary']['total'], 2)
        self.assertEqual(events[-1]['progress']['total_units'], 2)
        # Mutated snapshots are caller-owned. A fresh run remains authoritative.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root/'add.wasm'; binary.write_bytes(wasm_fixture())
            clean = []
            run_analysis(binary, root/'out', AnalysisConfig(cache_path=root/'cache.sqlite'), progress_callback=clean.append)
            self.assertEqual(clean[-1]['progress']['processed_units'], 1)

    def test_broken_observer_does_not_break_analysis(self):
        def broken(event):
            raise RuntimeError('observer failed')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root/'add.wasm'; binary.write_bytes(wasm_fixture())
            report = run_analysis(binary, root/'out', AnalysisConfig(cache_path=root/'cache.sqlite'),
                                  progress_callback=broken)
            self.assertEqual(report['summary']['compiled'], 1)


class TelemetryContractTests(unittest.TestCase):
    def snapshot(self):
        return {'total_units': 2, 'processed_units': 1, 'compiled_units': 1,
                'ai_compiled_units': 1, 'tested_units': 0, 'rejected_units': 1,
                'unknown_units': 0, 'stage': 'PROCESSING', 'active_units': []}

    def test_invalid_or_contradictory_child_counts_are_not_displayed(self):
        from gamedecomp.progress import normalize_progress
        for key, value in [('total_units', True), ('processed_units', -1),
                           ('tested_units', 1), ('compiled_units', 3), ('stage', 'PROVED')]:
            with self.subTest(key=key):
                snapshot = self.snapshot(); snapshot[key] = value
                self.assertIsNone(normalize_progress(snapshot))

    def test_only_bounded_fields_survive_and_snapshots_are_owned(self):
        from gamedecomp.progress import normalize_progress
        snapshot = self.snapshot(); snapshot['provider_secret'] = 'must not propagate'
        snapshot['active_units'] = [{'id': 'a', 'name': 'fn', 'stage': 'VALIDATION', 'extra': 'discard'}]
        normalized = normalize_progress(snapshot)
        self.assertNotIn('provider_secret', normalized)
        self.assertNotIn('extra', normalized['active_units'][0])
        normalized['active_units'][0]['name'] = 'changed'
        self.assertEqual(snapshot['active_units'][0]['name'], 'fn')
        snapshot['active_units'] *= 9
        self.assertIsNone(normalize_progress(snapshot))
