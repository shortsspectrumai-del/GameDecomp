"""Trusted scalar callback: real test-owned ELF files, no provider requests."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from gamedecomp.cli import build_parser, main, _config, doctor
from gamedecomp.verify import verify_report


def digest(source):
    return hashlib.sha256(source.encode()).hexdigest()


@unittest.skipUnless(shutil.which('gcc'), 'GCC required for test-owned shared ELF')
class TrustedScalarValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gd-trusted-validation-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / 'original.so'
        src = self.root / 'original.c'
        src.write_text('#include <stdint.h>\n'
                       'uint32_t original_add(uint32_t a,uint32_t b){return a+b;}\n'
                       'uint64_t original_mix(uint64_t a,uint32_t b){return a*3+b;}\n')
        subprocess.run(['gcc', '-shared', '-fPIC', '-O2', str(src), '-o', str(self.binary)],
                       check=True, capture_output=True)
        self.function = {'id': 'native:1', 'name': 'original_add',
                         'source': 'uint32_t recovered_add(uint32_t a,uint32_t b){return a+b;}',
                         'selected_source': 'conservative_baseline',
                         'metadata': {'language': 'c', 'export_name': 'recovered_add',
                                      'original_symbol': 'original_add', 'return_bits': 32,
                                      'parameter_bits': [32, 32]}}

    def candidate(self, source=None):
        source = source or self.function['source']
        return {'source': source, 'source_sha256': digest(source),
                'baseline_sha256': digest(self.function.get('source') or ''),
                'compilation': {'status': 'COMPILED', 'abi_check': 'COMPILER_ABI_SHAPE'},
                'semantic_status': 'UNKNOWN', 'selection_eligible': False,
                'origin': 'llm_reconstruction_engine', 'compile_support': ''}

    def save_report(self, candidate):
        record = copy.deepcopy(self.function)
        record['candidate'] = candidate
        report = self.root / 'report.json'
        report.write_text(json.dumps({'backend': 'native',
            'input': {'sha256': hashlib.sha256(self.binary.read_bytes()).hexdigest()},
            'metadata': {'abi': 'sysv-amd64'}, 'functions': [record]}))
        return report

    def validator(self, **options):
        from gamedecomp.trusted_validation import make_trusted_scalar_validator
        return make_trusted_scalar_validator(self.binary, trusted=True, cases=32, **options)

    def test_default_verification_ignores_wrong_ai_candidate(self):
        candidate = self.candidate(self.function['source'].replace('a+b', 'a-b'))
        report = self.save_report(candidate)
        baseline = verify_report(self.binary, report, trusted=True, cases=32)
        selected = verify_report(self.binary, report, trusted=True, cases=32, use_candidates=True)
        self.assertEqual(baseline['functions'][0]['semantic_status'], 'TESTED')
        self.assertEqual(baseline['functions'][0]['source_selection'], 'conservative_baseline')
        record = selected['functions'][0]
        self.assertEqual(record['semantic_status'], 'DISPROVED')
        self.assertEqual(record['source_selection'], 'llm_candidate')
        self.assertEqual(record['source_sha256'], candidate['source_sha256'])
        self.assertEqual(record['candidate_source_sha256'], candidate['source_sha256'])
        self.assertEqual(record['mismatches'], 1)

    def test_correct_pending_candidate_is_tested_without_becoming_a_proof(self):
        candidate = self.candidate()
        result = self.validator()(self.function, candidate, timeout=5)
        self.assertEqual(result['status'], 'TESTED', result)
        self.assertEqual(result['candidate_source_sha256'], candidate['source_sha256'])
        self.assertEqual(result['cases_checked'], 32)
        self.assertEqual(result['mismatches'], 0)
        self.assertIn('return', result['scope'])
        self.assertIs(candidate['selection_eligible'], False, 'callback must not mutate caller data')

    def test_wrong_candidate_returns_first_counterexample_for_repair(self):
        candidate = self.candidate(self.function['source'].replace('a+b', 'a-b'))
        result = self.validator()(self.function, candidate, timeout=5)
        self.assertEqual(result['status'], 'DISPROVED', result)
        self.assertEqual(result['mismatches'], 1)
        self.assertGreater(result['cases_checked'], 0)
        self.assertNotEqual(result['counterexample']['original'], result['counterexample']['recovered'])

    def test_mixed_64_and_32_bit_scalar_contract_is_tested(self):
        self.function.update(name='original_mix', source='uint64_t recovered_mix(uint64_t a,uint32_t b){return a*3+b;}')
        self.function['metadata'].update(export_name='recovered_mix', original_symbol='original_mix',
                                         return_bits=64, parameter_bits=[64, 32])
        self.assertEqual(self.validator()(self.function, self.candidate(), timeout=5)['status'], 'TESTED')

    def test_candidate_without_baseline_uses_only_observed_scalar_contract(self):
        source = self.function['source']
        self.function['source'] = None
        result = self.validator()(self.function, self.candidate(source), timeout=5)
        self.assertEqual(result['status'], 'TESTED', result)

    def test_invalid_binding_or_previously_disproved_candidate_is_unknown(self):
        for field, value in [('source_sha256', '0'*64), ('baseline_sha256', '0'*64),
                             ('semantic_status', 'DISPROVED')]:
            with self.subTest(field=field):
                candidate = self.candidate(); candidate[field] = value
                result = self.validator()(self.function, candidate, timeout=5)
                self.assertEqual(result['status'], 'UNKNOWN', result)
        candidate = self.candidate(); candidate['compilation']['abi_check'] = 'UNAVAILABLE'
        self.assertEqual(self.validator()(self.function, candidate, timeout=5)['status'], 'UNKNOWN')

    def test_invalid_candidate_provenance_never_labels_baseline_as_ai(self):
        candidate = self.candidate(self.function['source'].replace('a+b', 'a-b'))
        candidate['source_sha256'] = '0'*64
        result = verify_report(self.binary, self.save_report(candidate), trusted=True, use_candidates=True)
        record = result['functions'][0]
        self.assertEqual(record['semantic_status'], 'UNKNOWN')
        self.assertEqual(record['source_sha256'], digest(candidate['source']))
        self.assertIsNone(record['candidate_source_sha256'])
        self.assertNotEqual(record['source_sha256'], digest(self.function['source']))

    def test_string_literal_cannot_supply_the_candidate_abi_signature(self):
        candidate = self.candidate(
            'static const char *bait="uint32_t recovered_add(uint32_t a,uint32_t b){";'
            'uint64_t recovered_add(uint64_t a,uint64_t b){return a+b;}')
        result = self.validator()(self.function, candidate, timeout=5)
        self.assertEqual(result['status'], 'UNKNOWN', result)
        self.assertEqual(result['cases_checked'], 0)

    def test_hanging_candidate_returns_unknown_within_timeout(self):
        candidate = self.candidate('uint32_t recovered_add(uint32_t a,uint32_t b){for(;;){}}')
        result = self.validator()(self.function, candidate, timeout=0.25)
        self.assertEqual(result['status'], 'UNKNOWN', result)
        self.assertEqual(result['cases_checked'], 0)
        self.assertEqual(result['mismatches'], 0)

    def test_invalid_worker_counterexample_does_not_leave_mismatch_evidence(self):
        candidate = self.candidate()
        payload = json.dumps({'status': 'DISPROVED', 'cases_checked': 1,
                              'counterexample': {'original': 1, 'recovered': 1}})
        with patch('gamedecomp.verify._run_bounded', side_effect=[
                (0, '', '', None), (0, payload, '', None)]):
            result = verify_report(self.binary, self.save_report(candidate), trusted=True,
                                   use_candidates=True)
        record = result['functions'][0]
        self.assertEqual(record['semantic_status'], 'UNKNOWN')
        self.assertEqual(record['cases_checked'], 0)
        self.assertEqual(record['mismatches'], 0)

    def test_changed_original_hash_is_unknown_before_loading(self):
        validator = self.validator()
        with self.binary.open('ab') as stream:
            stream.write(b'changed')
        self.assertEqual(validator(self.function, self.candidate(), timeout=5)['status'], 'UNKNOWN')

    def test_non_shared_filename_and_unsupported_width_are_unknown(self):
        renamed = self.root / 'program'; self.binary.rename(renamed); self.binary = renamed
        self.assertEqual(self.validator()(self.function, self.candidate(), timeout=5)['status'], 'UNKNOWN')
        self.binary = renamed.rename(self.root / 'original.so')
        self.function['metadata']['parameter_bits'] = [8, 32]
        self.assertEqual(self.validator()(self.function, self.candidate(), timeout=5)['status'], 'UNKNOWN')

    def test_cli_trusted_flag_wires_callable_and_cases(self):
        seen = []
        def analyze(binary, output, config, *, candidate_validator=None):
            self.assertTrue(callable(candidate_validator))
            observed = candidate_validator(self.function, self.candidate(), timeout=5)
            seen.append(observed)
            return {'summary': {'trusted_status': observed['status']}, 'timings': {}, 'cache_hit': False}
        with patch('gamedecomp.cli.run_analysis', analyze), contextlib.redirect_stdout(io.StringIO()):
            code = main(['analyze', str(self.binary), '-o', str(self.root/'out'), '--backend', 'native',
                         '--validate-trusted', '--validation-cases', '17'])
        self.assertEqual(code, 0)
        self.assertEqual(seen[0]['status'], 'TESTED')
        self.assertEqual(seen[0]['cases_checked'], 17)


class TrustedValidationConsentTests(unittest.TestCase):
    def test_lmstudio_preset_uses_loopback_and_optional_key(self):
        with patch.dict('os.environ', {}, clear=True):
            args = build_parser().parse_args(['analyze', '/unused.so', '-o', '/tmp/unused',
                                              '--llm-provider', 'lmstudio', '--llm-model', 'local-model'])
            config = _config(args)
        self.assertEqual(config.llm_endpoint, 'http://127.0.0.1:1234/v1')
        self.assertIsNone(config.llm_api_key)
        self.assertIn('lmstudio', doctor()['llm']['providers'])

    def test_trust_is_required_before_accessing_missing_input(self):
        from gamedecomp.trusted_validation import make_trusted_scalar_validator
        with self.assertRaises(PermissionError):
            make_trusted_scalar_validator(Path('/absent.so'))
        with self.assertRaises(PermissionError):
            make_trusted_scalar_validator(Path('/absent.so'), trusted=1)

    def test_cli_cases_alone_do_not_authorize_execution(self):
        with patch('gamedecomp.cli.run_analysis') as analyze, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['analyze', '/absent.so', '-o', '/tmp/unused-gd-validation',
                                   '--validation-cases', '32']), 2)
        analyze.assert_not_called()

    def test_validation_flags_are_not_accepted_by_benchmark(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            build_parser().parse_args(['benchmark', 'binary.so', '-o', 'out', '--validate-trusted'])


if __name__ == '__main__':
    unittest.main()
