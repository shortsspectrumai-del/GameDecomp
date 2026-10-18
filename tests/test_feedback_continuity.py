"""Repair retries retain trusted counterexamples and the immutable ABI contract."""
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from gamedecomp.llm import LLMError
from gamedecomp.models import Analysis, Function, Instruction
from gamedecomp.pipeline import AnalysisConfig, run_analysis
from tests.test_wasm import wasm_fixture


@unittest.skipUnless(shutil.which('gcc'), 'GCC required for authored fixture compilation')
class FeedbackContinuityTests(unittest.TestCase):
    def check_retry(self, interruption):
        wrong = 'uint32_t fn(uint32_t p){return p+2;}'
        right = 'uint32_t fn(uint32_t p){return p+1;}'
        observations = []
        validations = []

        def recover(client, source, context, feedback, **options):
            observations.append({'source': source, 'contract': context['validator_contract'],
                                 'feedback': list(feedback)})
            index = len(observations)
            if index == 2 and interruption in ('invalid_structured_response', 'output_truncated'):
                raise LLMError('Authored provider interruption', code=interruption)
            candidate = wrong if index == 1 else right
            evidence = ['i:1']
            if index == 2 and interruption == 'rejected_evidence':
                evidence = ['invented-evidence']
            if index == 2 and interruption == 'compiler_error':
                candidate = 'uint32_t fn(uint32_t p){return missing_helper(p);}'
            return {'source': candidate, 'evidence_ids': evidence, 'assumptions': []}

        def validate(function, candidate, **options):
            # These authored bodies define a finite fixture, not a general proof.
            self.assertIn(candidate['source'], (wrong, right))
            failed = candidate['source'] == wrong
            status = 'DISPROVED' if failed else 'TESTED'
            validations.append(status)
            result = {'status': status, 'candidate_source_sha256': candidate['source_sha256'],
                      'scope': 'Authored scalar fixture on input zero; no equivalence proof.',
                      'cases_checked': 1, 'mismatches': int(failed)}
            if failed:
                result['counterexample'] = {'input': [0], 'expected': 1, 'actual': 2}
            return result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root/'input.wasm'
            binary.write_bytes(wasm_fixture())
            function = Function('f', 'fn', 1, [Instruction(1, 'add', 'EDI, 1')], source=right,
                                metadata={'export_name': 'fn', 'return_bits': 32,
                                          'parameter_bits': [32], 'language': 'c'})
            analysis = Analysis(hashlib.sha256(binary.read_bytes()).hexdigest(),
                                'WASM', 'wasm32', 'wasm', [function])
            with patch('gamedecomp.pipeline._analyze', return_value=analysis), \
                 patch('gamedecomp.llm.LLMClient.model_limits', return_value={'status': 'UNAVAILABLE'}), \
                 patch('gamedecomp.llm.LLMClient.refine', recover):
                report = run_analysis(binary, root/'output', AnalysisConfig(backend='wasm',
                    cache_path=root/'cache.sqlite', llm_endpoint='http://127.0.0.1:9/v1',
                    llm_model='authored-fixture', llm_attempts=3), candidate_validator=validate)

        self.assertEqual(len(observations), 3)
        self.assertEqual(validations, ['DISPROVED', 'TESTED'])
        contract = observations[0]['contract']
        self.assertTrue(all(row['contract'] == contract for row in observations))
        chunks = [item for item in observations[1]['feedback']
                  if item.startswith('Counterexample JSON chunk ')]
        self.assertTrue(chunks, 'The first repair request must receive the counterexample')
        self.assertEqual([item for item in observations[2]['feedback']
                          if item.startswith('Counterexample JSON chunk ')], chunks,
                         'A retry must retain the exact trusted counterexample')
        self.assertTrue(any('DISPROVED' in item for item in observations[2]['feedback']))
        binding = hashlib.sha256(wrong.encode()).hexdigest()
        self.assertIn(binding, '\n'.join(observations[2]['feedback']))
        self.assertIn('previous candidate', '\n'.join(observations[2]['feedback']))
        self.assertEqual(report['functions'][0]['candidate']['semantic_status'], 'TESTED')
        self.assertEqual(report['ai_project']['summary']['exported_units'], 1)

    def test_counterexample_survives_invalid_json_retry(self):
        self.check_retry('invalid_structured_response')

    def test_counterexample_survives_truncated_output_retry(self):
        self.check_retry('output_truncated')

    def test_counterexample_survives_rejected_evidence_retry(self):
        self.check_retry('rejected_evidence')

    def test_counterexample_survives_compiler_error_retry(self):
        self.check_retry('compiler_error')
