"""Rejected-only functions must remain in the extraction benchmark denominator."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gamedecomp.models import Analysis
from tests.test_binary_references import fixture, string_reference, external_reference


class ReferenceBenchmarkTests(unittest.TestCase):
    def test_rejected_only_function_is_recorded_and_counted(self):
        from scripts.check_binary_references import check
        accepted = fixture([string_reference(), external_reference()])
        rejected = fixture([string_reference(from_address=999)])
        rejected.id = 'native:bad'
        analysis = Analysis('a'*64, 'ELF', 'x86_64', 'ghidra', [accepted, rejected])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'result'
            with patch('scripts.check_binary_references.analyze', return_value=analysis), contextlib.redirect_stdout(io.StringIO()):
                check([Path(directory)/'unused-input'], output, Path(directory), 30)
            result = json.loads((output/'verification.json').read_text())['results'][0]
            detail = json.loads((output/'binary-0.json').read_text())
        self.assertIn('validation_totals', result)
        self.assertEqual(result['validation_totals']['received'], 3)
        self.assertEqual(result['validation_totals']['accepted'], 2)
        self.assertEqual(result['validation_totals']['rejected'], 1)
        self.assertEqual(result['functions_with_references'], 1)
        bad = next(row for row in detail['functions'] if row['function_id'] == 'native:bad')
        self.assertEqual(bad['references'], [])
        self.assertEqual(bad['validation']['missing_origins'], 1)
