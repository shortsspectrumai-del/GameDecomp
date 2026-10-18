import hashlib
from pathlib import Path
import tempfile
import unittest

from benchmarks.real_game_differential import write_recovered_unit
from gamedecomp.report import write_report


def record(status='DISPROVED', eligible=False):
    source = 'unsigned int fn(unsigned int x){return x+1;}'
    ai = 'unsigned int fn(unsigned int x){return x-1;}'
    digest = lambda value: hashlib.sha256(value.encode()).hexdigest()
    return {'name': 'fn', 'address': 16, 'source': source,
            'metadata': {'compile_preamble': '', 'compile_preamble_status': 'AVAILABLE'},
            'compilation': {'status': 'COMPILED'}, 'semantic_status': 'UNKNOWN', 'diagnostics': [],
            'candidate': {'source': ai, 'baseline_sha256': digest(source), 'source_sha256': digest(ai),
                          'compilation': {'status': 'COMPILED', 'abi_check': 'COMPILER_ABI_SHAPE'},
                          'semantic_status': status, 'selection_eligible': eligible,
                          'semantic_validation': {'status': status, 'scope': '<finite inputs>'}}}


class AISelectionTests(unittest.TestCase):
    def test_disproved_candidate_never_used_by_differential_writer(self):
        value = record(eligible=True)  # Even a contradictory eligibility flag cannot override DISPROVED.
        with tempfile.TemporaryDirectory() as directory:
            artifact = write_recovered_unit(value, {}, Path(directory), use_ai=True)
            self.assertEqual(artifact['source_selection'], 'conservative_baseline')
            self.assertEqual(Path(artifact['source_file']).read_text(), value['source'])

    def test_required_but_unknown_validation_never_uses_ai(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = write_recovered_unit(record('UNKNOWN'), {}, Path(directory), use_ai=True)
            self.assertEqual(artifact['source_selection'], 'conservative_baseline')

    def test_finite_tested_candidate_still_uses_ai(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = write_recovered_unit(record('TESTED', True), {}, Path(directory), use_ai=True)
            self.assertEqual(artifact['source_selection'], 'llm_reconstruction')

    def test_html_report_identifies_disproof_and_escapes_validation(self):
        value = record()
        value['compatibility'] = {'source': 'baseline support'}
        report = {'functions': [value], 'backend': 'test', 'timings': {'total_seconds': 0},
                  'summary': {'total': 1, 'recovered': 1, 'compiled': 1, 'proved': 0}, 'limitations': []}
        with tempfile.TemporaryDirectory() as directory:
            write_report(Path(directory), report)
            html = (Path(directory)/'report.html').read_text()
            self.assertIn('behavior disproved', html)
            self.assertIn('&lt;finite inputs&gt;', html)
            self.assertIn('SIMD compatibility', html)

    def test_html_finite_tests_do_not_claim_general_proof(self):
        report = {'functions': [record('TESTED', True)], 'backend': 'test',
                  'timings': {'total_seconds': 0},
                  'summary': {'total': 1, 'recovered': 1, 'compiled': 1, 'proved': 0}, 'limitations': []}
        with tempfile.TemporaryDirectory() as directory:
            write_report(Path(directory), report)
            self.assertIn('tested on finite cases', (Path(directory)/'report.html').read_text())
