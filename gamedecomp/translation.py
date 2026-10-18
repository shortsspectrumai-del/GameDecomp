"""Explicit post-decompilation language conversion, with no equivalence claim.

Compilers are trusted local tools, not security sandboxes. Generated code is
compiled in temporary directories and is never linked, loaded or executed.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import tempfile
import time
from pathlib import Path

from gamedecomp import __version__
from gamedecomp.csyntax import code_view
from gamedecomp.evidence import candidate_issues
from gamedecomp.llm import LLMClient, LLMError
from gamedecomp.report import write_report
from gamedecomp.semantic import candidate_is_usable
from gamedecomp.validation import _capture_compiler, compile_source

MAX_SOURCE_BYTES = 131072
MAX_REPORT_BYTES = 128 * 1024 * 1024
LANGUAGES = {'cpp': 'C++', 'java': 'Java'}


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def translation_issues(source, target, evidence_ids, source_id):
    """Conservative lexical gates; compilation is a separate check."""
    if target not in LANGUAGES:
        raise ValueError('Translation target must be cpp or java')
    if not isinstance(source, str) or not source.strip() or '\x00' in source:
        return ['Translation source is missing or invalid']
    if len(source.encode('utf-8')) > MAX_SOURCE_BYTES:
        return ['Translation source exceeds 128 KiB']
    if evidence_ids != [source_id]:
        return ['Translation must cite exactly the supplied source evidence ID']
    if target == 'cpp':
        context = {'name': 'recovered', 'evidence': [
            {'id': source_id, 'kind': 'source'},
            {'id': 'translation-contract', 'kind': 'signature', 'metadata': {}}]}
        return candidate_issues(source, context, evidence_ids)
    # Unicode preprocessing and text blocks require a full Java lexer. Refuse
    # these constructs rather than treating their contents as declarations.
    if re.search(r'\\u+[0-9a-fA-F]{4}', source) or '"""' in source:
        return ['Java Unicode escapes and text blocks are unsupported by the structural gate']
    view = code_view(source)
    issues = []
    if not re.search(r'\bpublic\s+final\s+class\s+RecoveredFunction\b', view):
        issues.append('Java requires public final class RecoveredFunction')
    if not re.search(r'\bpublic\s+static\s+(?:[\w<>?,.\[\]]+\s+)+recovered\s*\(', view):
        issues.append('Java requires a public static recovered method')
    if re.search(r'\b(?:package|native)\b', view):
        issues.append('Java packages and native methods are unsupported')
    return issues


def compile_java(source, *, timeout=30):
    """Compile without annotation processors or application/class execution."""
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError('timeout must be finite and positive')
    if not isinstance(source, str) or '\x00' in source or len(source.encode()) > MAX_SOURCE_BYTES:
        raise ValueError('Invalid or oversized Java source')
    home = os.environ.get('JAVA_HOME')
    javac = shutil.which(str(Path(home) / 'bin' / 'javac')) if home else None
    javac = javac or shutil.which('javac')
    result = {'status': 'UNKNOWN', 'diagnostics': [], 'returncode': None,
              'timed_out': False, 'output_limited': False,
              'toolchain': {'compiler': javac, 'language': 'java', 'sandboxed': False,
                            'annotation_processing': False, 'executed': False}}
    if not javac:
        result['diagnostics'] = ['No javac executable found; configure JAVA_HOME or PATH']
        return result
    try:
        check_started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix='gamedecomp-java-') as directory:
            root = Path(directory)
            empty, classes = root / 'empty', root / 'classes'
            empty.mkdir()
            classes.mkdir()
            path = root / 'RecoveredFunction.java'
            path.write_text(source, encoding='utf-8')
            command = [javac, '-proc:none', '-encoding', 'UTF-8', '-classpath', str(empty),
                       '-sourcepath', str(empty), '-d', str(classes), str(path)]
            code, output, timed_out, limited = _capture_compiler(command, directory, timeout)
            result.update(returncode=code, timed_out=timed_out, output_limited=limited)
            text = output.decode('utf-8', errors='replace').replace(directory, '<compile>')
            result['diagnostics'] = text.splitlines()
            if timed_out or limited or code < 0:
                result['diagnostics'].append('Java compilation was interrupted; result is unknown')
            elif code == 0 and (classes / 'RecoveredFunction.class').is_file():
                # Inspect declarations without loading or executing the class.
                # This prevents a nested class or quoted declaration from
                # satisfying the callable-entry gate of the outer class.
                javap = shutil.which(str(Path(javac).with_name('javap')))
                javap = javap or shutil.which('javap')
                if not javap:
                    result['diagnostics'].append('javap unavailable; callable entry is unverified')
                else:
                    inspection, declarations, expired, capped = _capture_compiler(
                        [javap, '-public', '-classpath', str(classes), 'RecoveredFunction'],
                        directory, max(0.001, timeout - (time.monotonic() - check_started)))
                    result.update(timed_out=expired, output_limited=capped)
                    if inspection == 0 and not expired and not capped:
                        if re.search(rb'\bpublic static [^;\r\n]+ recovered\([^;\r\n]*\)', declarations):
                            result['status'] = 'COMPILED'
                        else:
                            result['status'] = 'REJECTED'
                            result['diagnostics'].append('Compiled outer class has no public static recovered method')
                    else:
                        result['diagnostics'].append('Callable entry inspection failed; result is unknown')
            elif code == 0:
                result['diagnostics'].append('Compiler produced no expected class file')
            else:
                result['status'] = 'COMPILE_FAILED'
    except OSError:
        result['diagnostics'].append('Java compiler could not run')
    return result


def translate_function(report_path, output, function_id, target_language, config, *,
                       source_kind='baseline', source_job_id=None, progress=None):
    """Create a separate report and export only a compiled translation unit.

    Source evidence is never truncated. A conservative full-wire byte preflight
    reserves model output and overhead; unknown model limits remain explicit.
    """
    started = time.monotonic()
    if target_language not in LANGUAGES or source_kind not in ('baseline', 'candidate'):
        raise ValueError('Invalid translation target or source')
    if not config.llm_endpoint or not config.llm_model:
        raise ValueError('Translation requires an LLM provider')
    output = Path(output)
    if output.is_symlink() or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        raise ValueError('Translation output must be a new or empty directory')
    path = Path(report_path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('Source report must be a regular file')
    with path.open('rb') as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError('Source report exceeds the size limit')
    original = json.loads(raw)
    if original.get('translation'):
        raise ValueError('Select the original analysis before translating again')
    matches = [f for f in original.get('functions', []) if f.get('id') == function_id]
    if len(matches) != 1:
        raise ValueError('Source function identity is missing or ambiguous')
    function = matches[0]
    selected = function
    if source_kind == 'candidate':
        selected = function.get('candidate')
        if not candidate_is_usable(selected):
            raise ValueError('Source candidate is rejected or not compiled')
    if selected.get('semantic_status') == 'DISPROVED':
        raise ValueError('Source has disproved behavior; select a different recovered source')
    source = selected.get('source')
    if not isinstance(source, str) or not source.strip() or '\x00' in source:
        raise ValueError('Source function has no usable recovered source')
    if len(source.encode()) > MAX_SOURCE_BYTES:
        raise ValueError('Source function exceeds 128 KiB; it cannot be truncated safely')
    source_hash = _hash(source.encode())
    evidence_id = 'source:' + source_hash
    context = {'function_id': function_id, 'original_name': function.get('name'),
               'source_semantic_status': selected.get('semantic_status', 'UNKNOWN'),
               'source_kind': source_kind, 'evidence': [{'id': evidence_id, 'kind': 'recovered_source',
               'sha256': source_hash}], 'scope': 'Language conversion; source semantics may be unresolved. '
               'Compilation never establishes equivalence or binary ABI compatibility.'}
    client = LLMClient(config.llm_endpoint, config.llm_model, config.llm_api_key,
        timeout=config.timeout, api_format=config.llm_api_format, json_mode=config.llm_json_mode,
        temperature=config.llm_temperature, max_output_tokens=config.llm_max_output_tokens,
        reasoning_effort=config.llm_reasoning_effort)
    limits = client.model_limits(timeout=max(0.001, config.timeout - (time.monotonic() - started)))
    if 'max_output_tokens' in limits:
        client.max_output_tokens = min(client.max_output_tokens or 16384, limits['max_output_tokens'])
    budget = config.llm_context_bytes
    if 'context_window' in limits:
        budget = min(budget, limits['context_window'] - (client.max_output_tokens or 8192) - 2048)
    attempts, feedback, translated, assumptions = [], [], '', []
    compilation = {'status': 'UNKNOWN', 'diagnostics': ['No translation was accepted']}
    deadline = started + config.timeout

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise LLMError('Translation deadline exceeded', code='deadline_exceeded')
        return value

    def redact(value):
        if isinstance(value, str):
            return value.replace(config.llm_api_key, '[REDACTED]') if config.llm_api_key else value
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        return value

    for number in range(config.llm_attempts):
        attempt = {'number': number + 1, 'inference_invoked': False}
        attempts.append(attempt)
        try:
            remaining()
            size = client.translation_request_size(source, context, target_language, feedback)
            attempt.update(serialized_request_bytes=size, conservative_budget_bytes=budget)
            if size > budget:
                attempt.update(status='CONTEXT_LIMIT', diagnostics=[
                    'Complete source and feedback cannot fit the conservative context budget; no source was truncated'])
                break
            if progress:
                progress('Translating function to ' + LANGUAGES[target_language])
            attempt['inference_invoked'] = True
            response = redact(client.translate(source, context, target_language, feedback, timeout=remaining()))
            attempt['usage'] = response.get('usage', {})
            proposed = response['source']
            issues = translation_issues(proposed, target_language, response['evidence_ids'], evidence_id)
            assumptions = response.get('assumptions', [])
            if issues:
                check = {'status': 'REJECTED', 'diagnostics': issues}
            else:
                if progress:
                    progress('Compiling ' + LANGUAGES[target_language] + ' translation')
                check = (compile_java(proposed, timeout=remaining()) if target_language == 'java' else
                         compile_source(proposed, timeout=remaining(), language='c++', strict=True))
            compilation = redact(check)
            translated = proposed
            attempt.update(status=compilation['status'], diagnostics=compilation['diagnostics'],
                           output_sha256=_hash(proposed.encode()), assumptions=assumptions)
            if compilation['status'] in ('COMPILED', 'UNKNOWN'):
                break
            # Bind compiler diagnostics to the preceding output, while always
            # keeping the complete original source as the translation seed.
            feedback = ['Previous translation SHA-256: ' + attempt['output_sha256'],
                        'Previous translation (bounded excerpt): ' + proposed.encode()[:2048].decode('utf-8', 'ignore'),
                        'Correct the translation using these compiler/structural diagnostics: ' +
                        '\n'.join(compilation['diagnostics']).encode()[:4096].decode('utf-8', 'ignore')]
        except LLMError as error:
            attempt.update(status=error.code or 'LLM_ERROR', diagnostics=[redact(str(error))],
                           usage=getattr(error, 'usage', {}))
            if error.code in ('request_size_exceeded', 'deadline_exceeded', 'context_length_exceeded',
                              'invalid_api_key', 'insufficient_quota', 'provider_refusal'):
                break
            # Preserve compiler constraints through transient/schema failures.
            feedback = feedback[:3] + ['Provider response failed: ' + redact(str(error))[:1024]]

    translation = {'source_job_id': source_job_id, 'source_function_id': function_id,
        'source_kind': source_kind, 'target_language': target_language,
        'source_sha256': source_hash, 'source_report_sha256': _hash(raw),
        'source_semantic_status': selected.get('semantic_status', 'UNKNOWN'),
        'output_sha256': _hash(translated.encode()) if translated else None,
        'semantic_status': 'UNKNOWN', 'provider_limits': limits, 'attempts': attempts,
        'assumptions': assumptions}
    if not translated and attempts:
        compilation['diagnostics'] = attempts[-1].get('diagnostics', compilation['diagnostics'])
    recovered = bool(translated)
    compiled = compilation['status'] == 'COMPILED'
    result = {'schema_version': 1, 'program_version': __version__, 'input': original.get('input', {}),
        'backend': 'llm-translation', 'snapshot_id': _hash((source_hash + target_language + translated).encode()),
        'cache_hit': False, 'engine': {'mode': 'LLM_TRANSLATION', 'model': client.model,
                                    'api_format': client.api_format},
        'summary': {'total': 1, 'recovered': int(recovered), 'compiled': int(compiled),
                    'proved': 0, 'ai_candidates': 0, 'types': 0, 'gnn_predictions': 0},
        'functions': [{'id': function_id, 'name': 'recovered', 'address': function.get('address'),
            'source': translated or None, 'instructions': [], 'calls': [], 'candidate': None,
            'context': context, 'ai_attempts': attempts,
            'metadata': {'language': LANGUAGES[target_language], 'translation': {
                key: value for key, value in translation.items() if key not in ('attempts', 'assumptions')}},
            'compilation': compilation,
            'semantic_status': 'UNKNOWN', 'diagnostics': compilation['diagnostics']}],
        'translation': translation, 'timings': {'total_seconds': time.monotonic() - started},
        'limitations': ['Language conversion is not a recovered original project or native ABI equivalent.',
            'Semantic equivalence is UNKNOWN even when the source passed finite tests.',
            'Compiled means accepted by a trusted local compiler; generated code was never executed.',
            'Model context uses a conservative byte estimate, not exact provider tokenization. '
            'Undisclosed provider limits cannot be guaranteed.'], 'diagnostics': []}
    result = redact(result)
    output.mkdir(parents=True, exist_ok=True)
    if compiled:
        name = 'RecoveredFunction.' + ('cpp' if target_language == 'cpp' else 'java')
        (output / name).write_text(translated, encoding='utf-8')
    write_report(output, result)
    return result
