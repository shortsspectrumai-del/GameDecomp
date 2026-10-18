"""Explicitly authorized finite scalar validation for reconstruction callbacks.

Only trusted shared ELF x86-64 SysV originals and recovered unsigned scalar C
are supported. verify_report compiles and loads native code in child processes;
these resource bounds are not a security sandbox or an equivalence proof.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time

from gamedecomp.ingest import inspect_binary
from gamedecomp.verify import verify_report, _limits, _SCOPE


class _TrustedScalarValidator:
    def __init__(self, binary, cases):
        self.input = inspect_binary(binary)
        self.binary = Path(self.input['path'])
        self.cases = cases

    def __call__(self, function, candidate, *, timeout):
        started = time.monotonic()
        source = candidate.get('source', '') if isinstance(candidate, dict) else ''
        source_hash = hashlib.sha256(source.encode('utf-8')).hexdigest()
        unknown = {'status': 'UNKNOWN', 'candidate_source_sha256': source_hash,
                   'scope': _SCOPE+'; finite trusted comparison only, no memory or side-effect validation',
                   'cases_checked': 0, 'mismatches': 0}
        try:
            _limits(self.cases, timeout, 1)
            record = copy.deepcopy(function)
            record['candidate'] = copy.deepcopy(candidate)
            report = {'backend': 'native', 'input': self.input,
                      'metadata': {'abi': 'sysv-amd64'}, 'functions': [record]}
            encoded = json.dumps(report, ensure_ascii=False, allow_nan=False)
            if len(encoded.encode('utf-8')) > 32*1024*1024:
                return dict(unknown, diagnostics=['Trusted scalar validation report exceeds its size limit.'])
            with tempfile.TemporaryDirectory(prefix='gamedecomp-trusted-validator-') as directory:
                report_path = Path(directory)/'report.json'
                report_path.write_text(encoded, encoding='utf-8')
                remaining = timeout-(time.monotonic()-started)
                if remaining <= 0:
                    return dict(unknown, diagnostics=['Trusted scalar validation budget exhausted.'])
                verified = verify_report(self.binary, report_path, trusted=True, cases=self.cases,
                                         timeout=remaining, workers=1, use_candidates=True)
            observed = verified['functions'][0]
            if (observed.get('source_selection') != 'llm_candidate'
                    or observed.get('candidate_source_sha256') != source_hash
                    or observed.get('semantic_status') not in ('TESTED', 'DISPROVED')):
                return dict(unknown, diagnostics=['Candidate unavailable for trusted scalar validation.'])
            result = dict(unknown, status=observed['semantic_status'],
                          cases_checked=observed['cases_checked'],
                          mismatches=1 if observed['semantic_status']=='DISPROVED' else 0)
            if observed['semantic_status']=='DISPROVED':
                result['counterexample'] = copy.deepcopy(observed['counterexample'])
            return result
        except (ValueError, TypeError, KeyError, OSError, UnicodeError):
            # Do not reflect raw source, transport data or arbitrary exception text.
            return dict(unknown, diagnostics=['Trusted scalar validation failed or input binding changed.'])


def make_trusted_scalar_validator(binary, *, trusted=False, cases=128):
    """Bind a callback to one immutable binary hash after explicit user consent.

    Constructors and generated code can execute arbitrary native instructions.
    Trust is checked before inspecting the path; unsupported inputs remain UNKNOWN.
    """
    if trusted is not True:
        raise PermissionError('Validazione dinamica richiede trusted=True per binario e candidata fidati')
    _limits(cases, 1, 1)
    return _TrustedScalarValidator(binary, cases)
