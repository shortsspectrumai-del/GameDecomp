"""Parallel recovery pipeline. AI candidates never silently replace evidence."""
import asyncio
import fnmatch
import hashlib
import json
import math
import os
import shutil
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from gamedecomp import __version__
from gamedecomp.evidence import KnowledgeBase, candidate_issues, function_context
from gamedecomp.ingest import inspect_binary
from gamedecomp.llm import LLMClient, LLMError
from gamedecomp.models import Analysis
from gamedecomp.report import write_report
from gamedecomp.scheduler import Job, run_jobs, strongly_connected_components
from gamedecomp.semantic import candidate_is_usable, validate_candidate, semantic_feedback
from gamedecomp.store import ArtifactStore, cache_key
from gamedecomp.validation import compile_source


@dataclass
class AnalysisConfig:
    backend: str = 'auto'
    console_profile: str | None = None
    workers: int = 4
    timeout: float = 300
    phase_timeout: float = 30
    cache_path: Path = Path('.gamedecomp-cache/artifacts.sqlite')
    check_compile: bool = True
    compiler: str | None = None
    function_pattern: str | None = None
    max_functions: int = 2000
    llm_endpoint: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = field(default=None, repr=False)
    llm_api_format: str = 'openai'
    llm_json_mode: str = 'object'
    llm_temperature: float | None = None
    llm_workers: int = 2
    llm_attempts: int = 2
    max_llm_functions: int = 100
    llm_context_bytes: int = 196608
    llm_max_output_tokens: int | None = None
    llm_reasoning_effort: str | None = None
    knowledge_path: Path | None = None
    ghidra_home: Path | None = None
    recover_types: bool = True
    max_types: int = 20000
    gnn_model: Path | None = None

    def __post_init__(self):
        from gamedecomp.console_support import CONSOLE_PROFILES
        if self.console_profile is not None and self.console_profile not in CONSOLE_PROFILES:
            raise ValueError('Invalid console loader profile')
        if self.backend not in ('auto', 'native', 'wasm', 'ghidra', 'ilspy'):
            raise ValueError('Backend non valido')
        for name in ('workers', 'llm_workers', 'llm_attempts', 'max_functions', 'max_llm_functions', 'max_types'):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f'{name} deve essere un intero positivo')
        for name in ('timeout', 'phase_timeout'):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f'{name} deve essere finito e positivo')
        if bool(self.llm_endpoint) != bool(self.llm_model):
            raise ValueError('Specificare insieme endpoint e modello LLM')
        if isinstance(self.llm_api_key, str) and self.llm_api_key and (
                self.llm_api_key in (self.llm_endpoint or '') or self.llm_api_key in (self.llm_model or '')):
            raise ValueError('API credentials cannot appear in the endpoint or model name')
        if type(self.llm_context_bytes) is not int or not 16384 <= self.llm_context_bytes <= 1048576:
            raise ValueError('llm_context_bytes deve essere tra 16384 e 1048576')
        if self.llm_max_output_tokens is not None and (type(self.llm_max_output_tokens) is not int or not 256 <= self.llm_max_output_tokens <= 65536):
            raise ValueError('llm_max_output_tokens deve essere tra 256 e 65536 o None')
        if self.llm_reasoning_effort not in (None,'none','low','medium','high','max'):
            raise ValueError('llm_reasoning_effort non valido')
        if self.llm_api_format not in ('openai', 'anthropic'):
            raise ValueError('Invalid LLM API format')
        if self.llm_api_format == 'anthropic' and self.llm_reasoning_effort not in (None, 'none'):
            raise ValueError('Anthropic reasoning effort is not supported; omit the option')
        if not isinstance(self.recover_types, bool):
            raise ValueError('recover_types deve essere booleano')
        if self.llm_json_mode not in ('object', 'prompt'):
            raise ValueError('llm_json_mode deve essere object o prompt')
        if self.llm_api_format == 'anthropic':
            self.llm_json_mode = 'prompt'
        if self.llm_temperature is not None and (isinstance(self.llm_temperature, bool) or
                not isinstance(self.llm_temperature, (int, float)) or not math.isfinite(self.llm_temperature)
                or not 0 <= self.llm_temperature <= 2):
            raise ValueError('llm_temperature deve essere tra 0 e 2 oppure None')
        if self.llm_api_format == 'anthropic' and self.llm_temperature is not None and self.llm_temperature > 1:
            raise ValueError('Anthropic temperature must be between 0 and 1')


async def _blocking(function, *args, **kwargs):
    """Join bounded blocking work even when the awaiting worker is cancelled."""
    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if task.done() and not task.cancelled():
            task.exception()  # Retrieve failures during cancellation cleanup.
        raise


def _backend_name(info: dict, config: AnalysisConfig) -> str:
    if config.backend != 'auto':
        return config.backend
    if info['format'] == 'WASM':
        return 'wasm'
    from gamedecomp.console_support import FORMAT_PROFILES
    if info['format'] in FORMAT_PROFILES:
        return 'ghidra'
    if config.ghidra_home:
        return 'ghidra'
    configured_home = os.environ.get('GHIDRA_HOME')
    if configured_home:
        executable = Path(configured_home) / 'support' / ('analyzeHeadless.bat' if os.name == 'nt' else 'analyzeHeadless')
        if executable.is_file():
            return 'ghidra'
    return 'native'


def _analyze(path: Path, backend: str, config: AnalysisConfig, timeout: float) -> Analysis:
    if backend == 'native':
        from gamedecomp.backends.native import analyze
    elif backend == 'wasm':
        from gamedecomp.backends.wasm import analyze
    elif backend == 'ghidra':
        if config.console_profile:
            from gamedecomp.backends.console import analyze
            return analyze(path, profile=config.console_profile, ghidra_home=config.ghidra_home, timeout=timeout)
        from gamedecomp.backends.ghidra import analyze
        return analyze(path, ghidra_home=config.ghidra_home, timeout=timeout)
    else:
        from gamedecomp.backends.ilspy import analyze
    return analyze(path, timeout=timeout)


def _fingerprint(backend: str, config: AnalysisConfig) -> dict:
    folder = Path(__file__).parent
    files = [folder / 'models.py', folder / 'backends' / f'{backend}.py']
    if backend == 'ghidra':
        files.append(folder / 'ghidra_scripts' / 'ExportGameDecomp.java')
        files += [folder / name for name in ('console_formats.py', 'retro_formats.py', 'nes_format.py', 'megadrive_format.py', 'console_support.py')]
        files += [folder / 'backends' / 'console.py', folder / 'ghidra_scripts' / 'PrepareConsoleEntry.java']
    hashes = {str(path.name): hashlib.sha256(path.read_bytes()).hexdigest() for path in files if path.is_file()}
    tools = []
    for name in ('objdump', 'ilspycmd'):
        path = shutil.which(name)
        if path:
            stat = Path(path).stat()
            tools.append([path, stat.st_size, stat.st_mtime_ns])
    configured_home = config.ghidra_home or os.environ.get('GHIDRA_HOME')
    home = Path(configured_home).resolve() if configured_home else None
    installation = {}
    if home:
        for relative in ('support/analyzeHeadless', 'Ghidra/application.properties'):
            candidate = home / relative
            if candidate.is_file():
                installation[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
    return {'version': __version__, 'backend_code': hashes, 'tools': tools,
            'console_profile': config.console_profile,
            'ghidra_home': str(home) if home else None, 'ghidra_installation': installation}


def _unknown(message: str) -> dict:
    return {'status': 'UNKNOWN', 'diagnostics': [message]}


def _compilation_source(source: str, metadata: dict, backend: str) -> tuple[str, dict | None]:
    """Keep Ghidra's observed declarations separate from its unchanged body."""
    if backend != 'ghidra' or ('compile_preamble' not in metadata and 'compile_preamble_status' not in metadata):
        return source, None
    preamble = metadata.get('compile_preamble')
    if (metadata.get('compile_preamble_status', 'AVAILABLE') != 'AVAILABLE'
            or not isinstance(preamble, str) or '\x00' in preamble
            or len(preamble.encode('utf-8')) > 256 * 1024):
        raise ValueError('Contesto di compilazione Ghidra non disponibile, invalido o oltre il limite')
    unit = preamble + '\n\n' + source
    if len(unit.encode('utf-8')) > 1_000_000:
        raise ValueError('Unità di compilazione Ghidra oltre il limite di 1 MB')
    return unit, {'source': 'ghidra_observed_declarations',
                  'sha256': hashlib.sha256(preamble.encode('utf-8')).hexdigest(),
                  'bytes': len(preamble.encode('utf-8')),
                  'scope': 'Contesto di tipi e dichiarazioni; non verifica l\'ABI o il comportamento'}


def _attach_structural_context(analysis: Analysis, recovered: dict, neural: dict) -> None:
    """Attach bounded evidence summaries without changing recovered source or ABI."""
    by_id = {record['id']: record for record in recovered['types']}
    signatures = recovered.get('functions', {})
    predictions = neural.get('predictions', {})
    for function in analysis.functions:
        signature = signatures.get(function.id)
        if signature:
            references = set()
            pending = [signature]
            while pending and len(references) < 32:
                value = pending.pop()
                if isinstance(value, dict):
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)
                elif isinstance(value, str) and value in by_id and value not in references:
                    references.add(value)
                    pending.extend(by_id[value].values())
            summaries = []
            for identity in sorted(references):
                record = by_id[identity]
                summary = {key: record[key] for key in
                           ('id', 'kind', 'name', 'qualified_name', 'byte_size', 'status',
                            'evidence', 'bases', 'target_type') if key in record}
                for key in ('members', 'methods', 'enumerators', 'dimensions'):
                    if key in record:
                        summary[key] = record[key][:16]
                summaries.append(summary)
            function.metadata['type_recovery'] = {'signature': signature, 'types': summaries}
        if function.id in predictions:
            function.metadata['gnn_prediction'] = dict(predictions[function.id], model_hash=neural['model_hash'])


async def _process(analysis: Analysis, config: AnalysisConfig, knowledge: KnowledgeBase,
                   revision: str, deadline: float, target: dict, candidate_validator=None, progress=None) -> list[dict]:
    contexts, generations, compilations, ai_contexts = {}, {}, {}, {}
    compatibility = {}
    summaries = {f.id: {'name': f.name, 'signature': f.metadata} for f in analysis.functions}
    llm_semaphore = asyncio.Semaphore(config.llm_workers)
    compile_semaphore = asyncio.Semaphore(config.workers)
    client = LLMClient(config.llm_endpoint, config.llm_model, config.llm_api_key,
                       timeout=config.phase_timeout, json_mode=config.llm_json_mode,
                       temperature=config.llm_temperature, max_output_tokens=config.llm_max_output_tokens,
                       reasoning_effort=config.llm_reasoning_effort,
                       api_format=config.llm_api_format) if config.llm_endpoint else None
    model_limits = await _blocking(client.model_limits, timeout=max(0.001,min(config.phase_timeout,deadline-time.monotonic()))) if client else {'status':'DISABLED'}
    if client and 'max_output_tokens' in model_limits:
        client.max_output_tokens = min(client.max_output_tokens or 16384, model_limits['max_output_tokens'])
    jobs = []
    selected_for_ai = {f.id for f in analysis.functions[:config.max_llm_functions]}
    for function in analysis.functions:
        jobs.append(Job('context/' + function.id, frozenset(), ('context', function)))
        jobs.append(Job('compile/' + function.id, frozenset({'context/' + function.id}), ('compile', function)))
        if client and function.id in selected_for_ai:
            jobs.append(Job('ai/' + function.id, frozenset({'compile/' + function.id}), ('ai', function)))

    def remaining():
        value = min(config.phase_timeout, deadline - time.monotonic())
        if value <= 0:
            raise TimeoutError('Budget totale esaurito')
        return value

    async def compile_function(source, function, language, *, support='', verify_abi=False):
        from gamedecomp.console_support import FORMAT_PROFILES
        if analysis.format in FORMAT_PROFILES:
            return _unknown('Console target ABI compiler unavailable; host compilation is not accepted as target ABI validation')
        try:
            unit, context = _compilation_source(source, function.metadata, analysis.backend)
            unit = support + '\n' + unit if support else unit
            assertion = None
            if verify_abi:
                from gamedecomp.ai_engine import abi_assertion, observed_scalar_source, abi_check_kind
                contract = function.source or observed_scalar_source(function.metadata)
                symbol = function.metadata.get('export_name') or function.name
                assertion = abi_assertion(contract, symbol, language, candidate=source)
                if not assertion:
                    return dict(_unknown('Controllo ABI non disponibile: candidata esclusa dalla compilazione e dal progetto AI'),
                                abi_check='UNAVAILABLE')
                unit += assertion
            if len(unit.encode()) > 1_000_000:
                raise ValueError('Unità AI oltre 1 MB')
        except ValueError as error:
            return _unknown(str(error))
        async with compile_semaphore:
            result = await _blocking(compile_source, unit, compiler=config.compiler,
                                     timeout=remaining(), language=language, strict=verify_abi)
        if context is not None:
            result['context'] = context
        if verify_abi:
            result['abi_check'] = abi_check_kind(contract, symbol, language, candidate=source) if assertion else 'UNAVAILABLE'
            result['unit_sha256'] = hashlib.sha256(unit.encode()).hexdigest()
        return result

    async def process_job(job: Job):
        role, function = job.payload
        if role == 'context':
            context = function_context(function, analysis.binary_hash, summaries)
            context['snapshot_id'] = revision
            context['retrieval'] = knowledge.search(context)
            contexts[function.id] = context
            return {'snapshot_id': revision, 'evidence_count': len(context['evidence'])}
        language = function.metadata.get('language', 'c')
        if role == 'compile':
            if not function.source:
                result = _unknown('Nessuna sorgente conservativa recuperata')
            elif not config.check_compile:
                result = _unknown('Controllo di compilazione disabilitato')
            elif language not in ('c', 'c++'):
                result = _unknown('Compilazione del linguaggio non disponibile in questo worker')
            else:
                result = await compile_function(function.source, function, language)
            compilations[function.id] = result
            if (result['status'] == 'COMPILE_FAILED' and analysis.backend == 'ghidra'
                    and language == 'c' and function.source):
                from gamedecomp.ghidra_compat import lower_ghidra_source
                lowered = lower_ghidra_source(function.source, bits=target.get('bits'),
                                             endianness=target.get('endianness'))
                compatibility[function.id] = lowered
                if lowered['status'] == 'AVAILABLE':
                    try:
                        unit, _ = _compilation_source(lowered['source'], function.metadata, 'ghidra')
                        unit = lowered['preamble'] + '\n' + unit
                        if len(unit.encode()) > 1_000_000:
                            raise ValueError('Unità di compatibilità oltre 1 MB')
                    except ValueError as error:
                        lowered['compilation'] = _unknown(str(error))
                    else:
                        lowered['unit_sha256'] = hashlib.sha256(unit.encode()).hexdigest()
                        async with compile_semaphore:
                            lowered['compilation'] = await _blocking(compile_source, unit,
                                compiler=config.compiler, timeout=remaining(), language='c')
            return result
        async with llm_semaphore:
            from gamedecomp.ai_engine import recovery_context, recovery_issues, validator_contract, abi_repair_feedback, bounded_feedback
            lowered = compatibility.get(function.id) or {}
            baseline = function.source or '/* Source not recovered: use only the supplied evidence. */'
            support = ''
            if lowered.get('compilation', {}).get('status') == 'COMPILED':
                baseline, support = lowered['source'], lowered['preamble']
            immutable_contract = validator_contract(function.source, function.metadata, function.name, language)
            context_budget = config.llm_context_bytes
            if 'context_window' in model_limits:
                available = model_limits['context_window']-(client.max_output_tokens or 8192)-2*len(baseline.encode())-8192
                if available < 16384:
                    ai_contexts[function.id] = {'status':'UNAVAILABLE','provider_limits':model_limits,
                        'budget_bytes':context_budget,'reason':'Insufficient model window after output and seed reservation'}
                    generations[function.id] = {'candidate':None,'attempts':[{'status':'UNKNOWN',
                        'diagnostics':['Finestra del modello insufficiente per il contesto minimo e la riserva output']} ]}
                    return {'status':'UNKNOWN'}
                context_budget = min(context_budget, available)
            try:
                context, context_summary = recovery_context(contexts[function.id], compilations[function.id],
                    lowered, budget=context_budget, support=support, contract=immutable_contract)
            except ValueError as error:
                generations[function.id] = {'candidate':None,'attempts':[{'status':'UNKNOWN','diagnostics':[str(error)]}]}
                ai_contexts[function.id] = {'status':'UNAVAILABLE','budget_bytes':context_budget}
                return {'status':'UNKNOWN'}
            context_summary['provider_limits'] = model_limits
            ai_contexts[function.id] = context_summary
            feedback = compilations[function.id].get('diagnostics', [])[:32]
            semantic_constraints = []
            attempts, candidate, rejected_candidates = [], None, []
            if support:
                context_summary['seed'] = 'explicit_compatibility_lowering'
            else:
                context_summary['seed'] = 'static_frontend' if function.source else 'binary_evidence_only'
            for _ in range(config.llm_attempts):
                remaining()
                if progress:
                    progress.start(function, 'RECONSTRUCTION')
                inference_invoked = False
                try:
                    request_feedback = bounded_feedback(list(dict.fromkeys(semantic_constraints + feedback)))
                    if 'context_window' in model_limits:
                        # Full wire bytes include system/seed/feedback and JSON escaping.
                        # One byte per token is a conservative estimate, not a tokenizer proof.
                        prompt_limit = model_limits['context_window'] - (client.max_output_tokens or 8192) - 2048
                        while True:
                            remaining()
                            transport_oversize = False
                            try:
                                size = await _blocking(client.request_size, baseline, context, request_feedback)
                            except LLMError as size_error:
                                if size_error.code != 'request_size_exceeded':
                                    raise
                                size, transport_oversize = None, True
                            preflight = {'status': 'WITHIN_CONSERVATIVE_BUDGET',
                                'serialized_request_bytes': size, 'conservative_budget_bytes': prompt_limit,
                                'transport_limit_exceeded': transport_oversize,
                                'method': 'Serialized UTF-8 bytes with output/overhead reservation; not exact tokenization.'}
                            context_summary['prompt_preflight'] = preflight
                            if size is not None and size <= prompt_limit:
                                break
                            if context_budget <= 16384:
                                preflight['status'] = 'UNAVAILABLE'
                                raise LLMError('Complete prompt cannot fit the conservative model budget without dropping required feedback or ABI', code='prompt_unavailable')
                            context_budget = max(16384, context_budget//2)
                            context, reduced = recovery_context(contexts[function.id], compilations[function.id],
                                lowered, budget=context_budget, support=support, contract=immutable_contract)
                            context_summary.update(reduced, request_reduced_context=True)
                            if transport_oversize:
                                context_summary['transport_reduced_context'] = True
                    inference_invoked = True
                    response = await _blocking(client.refine, baseline, context, request_feedback, timeout=remaining())
                except (LLMError, ValueError, TypeError) as error:
                    attempts.append({'status': 'UNKNOWN', 'diagnostics': [str(error)],
                                     'usage': getattr(error, 'usage', {}), 'inference_invoked': inference_invoked})
                    if getattr(error,'code',None)=='context_length_exceeded' and context_budget>16384:
                        context_budget=max(16384,context_budget//2)
                        try:
                            context, reduced=recovery_context(contexts[function.id],compilations[function.id],
                                lowered,budget=context_budget,support=support,contract=immutable_contract)
                        except ValueError as budget_error:
                            attempts.append({'status':'UNKNOWN','diagnostics':[str(budget_error)]})
                            break
                        context_summary.update(reduced,provider_rejected_larger_context=True)
                        continue
                    if getattr(error,'code',None)=='output_truncated':
                        feedback=feedback+['Previous output was truncated. Return a compact, complete JSON object and source within the output budget.']
                        continue
                    if getattr(error,'code',None)=='invalid_structured_response':
                        feedback=feedback+['Return only a complete JSON object with source, evidence_ids and assumptions. No Markdown fences, no prose outside JSON.']
                        continue
                    break
                issues = candidate_issues(response['source'], context, response['evidence_ids'])
                issues += recovery_issues(response.get('recovery'), context)
                if issues:
                    feedback = issues
                    attempts.append({'status': 'REJECTED', 'diagnostics': issues,
                                     'usage': response.get('usage', {})})
                    continue
                if config.check_compile and language in ('c', 'c++'):
                    result = await compile_function(response['source'], function, language, support=support, verify_abi=True)
                else:
                    result = _unknown('Compilazione candidata non eseguita')
                current = dict(response, compilation=result, semantic_status='UNKNOWN', snapshot_id=revision,
                               compile_support=support, origin='llm_reconstruction_engine',
                               baseline_sha256=hashlib.sha256((function.source or '').encode()).hexdigest(),
                               source_sha256=hashlib.sha256(response['source'].encode()).hexdigest())
                current['selection_eligible'] = result['status'] == 'COMPILED' and candidate_validator is None
                attempt = {'status': result['status'], 'diagnostics': result['diagnostics'],
                           'usage': response.get('usage', {})}
                if result['status'] == 'COMPILED' and candidate_validator is not None:
                    if progress:
                        progress.start(function, 'VALIDATION')
                    validation = await _blocking(validate_candidate, candidate_validator, asdict(function), current, timeout=remaining())
                    current['semantic_validation'] = validation
                    current['semantic_status'] = validation['status']
                    current['selection_eligible'] = validation['status'] == 'TESTED'
                    attempt['semantic_validation'] = validation
                if candidate is None or result['status'] == 'COMPILED':
                    candidate = current
                attempts.append(attempt)
                if result['status'] == 'UNKNOWN' and analysis.format in FORMAT_PROFILES:
                    break
                if result['status'] == 'COMPILED':
                    if candidate_validator is None or current['semantic_status'] == 'TESTED':
                        break
                    rejected_candidates.append(current)
                    if current['semantic_status'] == 'UNKNOWN':
                        break
                    semantic_constraints = semantic_feedback(validation)
                    feedback = abi_repair_feedback(immutable_contract, response['source']) + semantic_constraints
                else:
                    feedback = abi_repair_feedback(immutable_contract, response['source']) + result['diagnostics']
                baseline = response['source']
            generations[function.id] = {'candidate': candidate, 'attempts': attempts,
                                        'rejected_candidates': rejected_candidates}
            return {'status': 'CANDIDATE' if candidate else 'UNKNOWN', 'attempts': len(attempts)}

    async def worker(job):
        role, function = job.payload
        if progress:
            progress.start(function, {'context': 'CONTEXT', 'compile': 'COMPILATION', 'ai': 'RECONSTRUCTION'}[role])
        try:
            return await process_job(job)
        finally:
            if progress:
                done = role == 'ai' or role == 'compile' and (client is None or function.id not in selected_for_ai)
                progress.observe(function, compilations.get(function.id, {}),
                                 generations.get(function.id, {}).get('candidate'), done=done)

    await run_jobs(jobs, worker, workers=config.workers, timeout=max(0.001, deadline - time.monotonic()))
    records = []
    for function in analysis.functions:
        generation = generations.get(function.id, {})
        records.append({
            'id': function.id, 'name': function.name, 'address': function.address,
            'source': function.source, 'metadata': function.metadata,
            'diagnostics': function.diagnostics, 'calls': function.calls,
            'context': contexts[function.id], 'compilation': compilations[function.id],
            'semantic_status': 'UNKNOWN', 'selected_source': 'conservative_baseline' if function.source else None,
            'candidate': generation.get('candidate'), 'ai_attempts': generation.get('attempts', []),
            'rejected_candidates': generation.get('rejected_candidates', []),
            'compatibility': compatibility.get(function.id),
            'ai_context': ai_contexts.get(function.id),
            'reconstruction_source': 'llm_candidate' if generation.get('candidate') else None,
            'instructions': [vars(item) for item in function.instructions],
        })
    return records


def run_analysis(path: Path, output: Path, config: AnalysisConfig | None = None, *, candidate_validator=None,
                 progress_callback=None) -> dict:
    from gamedecomp.progress import ProgressTracker
    progress = ProgressTracker(progress_callback)
    progress.emit('INGEST', 'Inspecting binary input')
    if candidate_validator is not None and not callable(candidate_validator):
        raise TypeError('candidate_validator must be a trusted Python callable or None')
    config = config or AnalysisConfig()
    config.__post_init__()
    started = time.monotonic()
    deadline = started + config.timeout
    info = inspect_binary(path, console_profile=config.console_profile)
    progress.emit('ANALYSIS', 'Running static analysis')
    path, output = Path(info['path']), Path(output).resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError('La directory di output deve essere nuova o vuota')
    if output == path or output in path.parents:
        raise ValueError('La directory di output non deve contenere il binario originale')
    cache = Path(config.cache_path).resolve()
    # SQLite may truncate/delete its sidecars even when they predate the DB.
    # Include configured and resolved names, plus hardlink/symlink aliases.
    cache_names = {cache, Path(config.cache_path).absolute()}
    for cache_name in cache_names:
        for suffix in ('', '-wal', '-shm', '-journal'):
            artifact = Path(str(cache_name) + suffix)
            if artifact.resolve() == path or (artifact.exists() and os.path.samefile(artifact, path)):
                raise ValueError('Cache SQLite e file ausiliari non possono coincidere con il binario originale')
    if cache == output or output in cache.parents:
        raise ValueError('La cache deve essere esterna alla directory del rapporto')
    backend = _backend_name(info, config)
    from gamedecomp.console_support import FORMAT_PROFILES
    required_profile = FORMAT_PROFILES.get(info['format'])
    if required_profile and config.console_profile != required_profile:
        raise ValueError('Select the explicit console loader profile: ' + required_profile)
    if required_profile and backend != 'ghidra':
        raise ValueError('Console module analysis requires the Ghidra backend')
    if config.console_profile and not required_profile:
        raise ValueError('Console loader profile does not match this input; select generic executable analysis')
    if backend == 'wasm' and info['format'] != 'WASM':
        raise ValueError('Il backend WASM richiede un modulo WebAssembly')
    knowledge = KnowledgeBase(config.knowledge_path)
    key = cache_key({'binary': info['sha256'], 'backend': backend,
                     'fingerprint': _fingerprint(backend, config), 'phase_timeout': config.phase_timeout})
    cache_hit = False
    with ArtifactStore(config.cache_path) as store:
        cached = store.get(key)
        if cached is not None:
            analysis = Analysis.from_dict(cached)
            cache_hit = True
        else:
            analysis = _analyze(path, backend, config, min(config.phase_timeout, deadline - time.monotonic()))
            # Unknown or empty analysis may reflect a transient missing frontend.
            if analysis.functions and not analysis.diagnostics:
                store.put(key, analysis.to_dict())
        if analysis.binary_hash != info['sha256']:
            raise RuntimeError('Il backend ha analizzato un contenuto diverso dal binario richiesto')
        # Frontends use their own display names (e.g. Ghidra's "Executable
        # and Linking Format (ELF)" and language IDs). Downstream type/graph
        # stages require the canonical container and architecture from ingest.
        if analysis.format != info['format']:
            analysis.metadata['frontend_format'] = analysis.format
            analysis.format = info['format']
        if analysis.architecture != info['architecture']:
            analysis.metadata['frontend_architecture'] = analysis.architecture
            analysis.architecture = info['architecture']
        analysis_seconds = time.monotonic() - started
        if config.function_pattern:
            analysis.functions = [f for f in analysis.functions if fnmatch.fnmatchcase(f.name, config.function_pattern) or fnmatch.fnmatchcase(f.id, config.function_pattern)]
        if len(analysis.functions) > config.max_functions:
            raise ValueError(f'{len(analysis.functions)} funzioni oltre il limite {config.max_functions}; usare --function o --max-functions')
        progress.configure(analysis.functions)
        structural_started = time.monotonic()
        recovered_types = {'schema_version': 1, 'types': [], 'functions': {}, 'sources': [], 'diagnostics': []}
        types_header = '// Type recovery disabled or format not supported.\n'
        if config.recover_types and info['format'] == 'ELF':
            from gamedecomp.type_recovery import recover_types, render_types_header
            budget = min(config.phase_timeout, deadline - time.monotonic())
            if budget <= 0:
                raise TimeoutError('Budget totale esaurito prima del recupero tipi')
            recovered_types = recover_types(path, analysis, timeout=budget, max_types=config.max_types)
            types_header = render_types_header(recovered_types)
        neural = {'status': 'DISABLED', 'predictions': {}, 'diagnostics': []}
        if config.gnn_model:
            from gamedecomp.gnn import predict
            budget = min(config.phase_timeout, deadline - time.monotonic())
            if budget <= 0:
                raise TimeoutError('Budget totale esaurito prima del GNN')
            neural = predict(analysis, Path(config.gnn_model), timeout=budget)
        _attach_structural_context(analysis, recovered_types, neural)
        structural_seconds = time.monotonic() - structural_started
        revision = cache_key({'analysis': analysis.to_dict(), 'knowledge': knowledge.version,
                              'types': recovered_types, 'gnn': neural})
        records = asyncio.run(_process(analysis, config, knowledge, revision, deadline, info, candidate_validator, progress))
        progress.emit('EXPORT', 'Preparing sources and project artifacts')
        graph = {f.id: f.calls for f in analysis.functions}
        limitations = [
            'No general equivalence proof was performed.',
            'COMPILED means compilation only; TESTED refers only to the declared finite cases.',
            'Compilers and frontends are local processes with timeouts, not a security sandbox.',
            'DWARF types and ABI structures are evidence; static inference and GNN predictions remain hypotheses without universal recovery guarantees.',
            'Input execution was not requested by the pipeline.' if candidate_validator is None else
            'A caller-supplied trusted validator was enabled; consult each candidate validation scope.',
        ]
        if config.llm_endpoint and len(analysis.functions) > config.max_llm_functions:
            limitations.append(f'AI applied to the first {config.max_llm_functions} selected functions; explicit limit.')
        report = {
            'schema_version': 1, 'program_version': __version__, 'input': info,
            'backend': backend, 'snapshot_id': revision, 'cache_hit': cache_hit,
            'summary': {'total': len(records), 'recovered': sum(bool(f['source']) for f in records),
                        'compiled': sum(f['compilation']['status'] == 'COMPILED' for f in records),
                        'compatibility_compiled': sum((f.get('compatibility') or {}).get('compilation', {}).get('status') == 'COMPILED' for f in records),
                        'ai_candidates': sum(bool(f['candidate']) for f in records), 'proved': 0,
                        'types': len(recovered_types['types']), 'gnn_predictions': len(neural['predictions'])},
            'diagnostics': analysis.diagnostics, 'metadata': analysis.metadata,
            'type_recovery': recovered_types, 'gnn': neural,
            'engine': {'mode': 'LLM' if config.llm_endpoint else 'STATIC_ONLY',
                       'api_format': config.llm_api_format if config.llm_endpoint else None,
                       'model': config.llm_model, 'context_budget_bytes': config.llm_context_bytes,
                       'scope': 'The LLM reconstructs from evidence and feedback; frontends and compilers check observed constraints. No universal equivalence.'},
            'functions': records, 'call_graph_scc': strongly_connected_components(graph),
            'limitations': limitations,
            'execution': {'workers': config.workers, 'llm_workers': config.llm_workers,
                          'deadline_seconds': config.timeout, 'llm_model': config.llm_model},
            'timings': {'analysis_seconds': analysis_seconds, 'structural_seconds': structural_seconds,
                        'total_seconds': time.monotonic() - started},
        }
        store.record(revision, 'PROCESSED', {'summary': report['summary'], 'timings': report['timings']})
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.gamedecomp-', dir=output.parent) as directory:
        staging = Path(directory) / 'results'
        staging.mkdir()
        (staging / 'functions').mkdir()
        (staging / 'types.json').write_text(json.dumps(recovered_types, indent=2, ensure_ascii=False, allow_nan=False), encoding='utf-8')
        (staging / 'types.hpp').write_text(types_header, encoding='utf-8')
        recovered_c = ['#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n']
        for ordinal, function in enumerate(records):
            stem = f'{ordinal:05d}_{function["address"]:x}'
            folder = staging / 'functions'
            (folder / (stem + '.json')).write_text(json.dumps(function, indent=2, ensure_ascii=False), encoding='utf-8')
            disassembly = '\n'.join(f'{i["address"]:x}: {i["mnemonic"]} {i["operands"]}' for i in function['instructions'])
            (folder / (stem + '.asm')).write_text(disassembly, encoding='utf-8')
            if function['source']:
                language = function['metadata'].get('language', 'c')
                extension = {'c': '.c', 'c++': '.cpp', 'csharp': '.cs'}.get(language, '.txt')
                (folder / (stem + extension)).write_text(function['source'], encoding='utf-8')
                if backend == 'ghidra' and language in ('c', 'c++'):
                    try:
                        unit, context = _compilation_source(function['source'], function['metadata'], backend)
                    except ValueError:
                        context = None
                    if context is not None:
                        (folder / (stem + '.unit' + extension)).write_text(unit, encoding='utf-8')
                if language == 'c':
                    recovered_c.append(function['source'])
            for rejected_index, rejected in enumerate(function.get('rejected_candidates', [])):
                (folder / (stem + f'.rejected-{rejected_index:02d}.candidate.c')).write_text(rejected['source'], encoding='utf-8')
            if function['candidate']:
                (folder / (stem + '.candidate.c')).write_text(function['candidate']['source'], encoding='utf-8')
                if backend == 'ghidra':
                    try:
                        unit, context = _compilation_source(function['candidate']['source'], function['metadata'], backend)
                    except ValueError:
                        context = None
                    if context is not None:
                        from gamedecomp.ai_engine import abi_assertion, observed_scalar_source
                        unit = function['candidate'].get('compile_support', '') + '\n' + unit
                        unit += abi_assertion(function['source'] or observed_scalar_source(function['metadata']),
                            function['metadata'].get('export_name') or function['name'], function['metadata'].get('language', 'c'),
                            candidate=function['candidate']['source']) or ''
                        (folder / (stem + '.candidate.unit.c')).write_text(unit, encoding='utf-8')
            lowered = function.get('compatibility')
            if lowered and lowered.get('status') == 'AVAILABLE':
                (folder / (stem + '.compat.c')).write_text(lowered['source'], encoding='utf-8')
                try:
                    unit, _ = _compilation_source(lowered['source'], function['metadata'], backend)
                    unit = lowered['preamble']+'\n'+unit
                    if len(unit.encode()) <= 1_000_000:
                        (folder / (stem + '.compat.unit.c')).write_text(unit, encoding='utf-8')
                except ValueError:
                    pass  # The compilation result already records the invalid budget/context.
        (staging / 'recovered.c').write_text('\n\n'.join(recovered_c), encoding='utf-8')
        from gamedecomp.project_export import export_project
        report['project'] = export_project(report, staging)
        if config.llm_endpoint:
            ai_records = []
            for function in records:
                candidate = function.get('candidate')
                if not candidate_is_usable(candidate):
                    continue
                metadata = dict(function['metadata'])
                metadata['compile_preamble'] = candidate.get('compile_support', '')+'\n'+(
                    metadata.get('compile_preamble', '') if backend=='ghidra' else '')
                metadata['compile_preamble_status'] = 'AVAILABLE'
                ai_records.append(dict(function, source=candidate['source'], metadata=metadata, compilation=candidate['compilation']))
            (staging/'ai').mkdir()
            ai_project = export_project(dict(report, backend='ghidra', functions=ai_records), staging/'ai')
            os.replace(staging/'ai/project', staging/'project-ai')
            (staging/'ai').rmdir()
            ai_project['origin'] = 'LLM hypotheses; compilation and ABI checks do not prove behavior'
            (staging/'project-ai/manifest.json').write_text(json.dumps(ai_project, indent=2, ensure_ascii=False)+'\n')
            readme = staging/'project-ai/README.md'
            readme.write_text(readme.read_text().replace('baseline compilabili', 'ricostruzioni LLM compilabili')+
                '\nLe tipizzazioni sono ipotesi; il controllo ABI non verifica layout puntati o equivalenza semantica.\n')
            report['ai_project'] = ai_project
        report['timings']['total_seconds'] = time.monotonic() - started
        report['timings']['scope'] = 'Ingestione, analisi, job, compilazione ed export sorgenti; esclusa scrittura finale del rapporto'
        write_report(staging, report)
        # Refuse destructive overwrite even if another process won the race.
        if output.exists():
            if any(output.iterdir()):
                raise FileExistsError('Output modificato da un altro processo')
            output.rmdir()
        os.replace(staging, output)
        progress.emit('COMPLETE', 'Analysis and export complete')
    with ArtifactStore(config.cache_path) as store:
        store.record(revision, 'PUBLISHED', {'summary': report['summary'], 'output': str(output), 'timings': report['timings']})
    return report
