"""Command line interface. All executable-input tests require explicit trust."""
import argparse
import getpass
import importlib.util
import json
import os
import shutil
import sqlite3
import statistics
import sys
import warnings
from pathlib import Path

from gamedecomp import __version__
from gamedecomp.console_support import CONSOLE_PROFILES
from gamedecomp.ingest import inspect_binary
from gamedecomp.pipeline import AnalysisConfig, run_analysis

LLM_PROVIDERS = {
    'deepseek': ('https://api.deepseek.com', 'DEEPSEEK_API_KEY'),
    'openai': ('https://api.openai.com/v1', 'OPENAI_API_KEY'),
    'anthropic': ('https://api.anthropic.com/v1', 'ANTHROPIC_API_KEY'),
    'ollama': ('http://127.0.0.1:11434/v1', 'GAMEDECOMP_API_KEY'),
    'lmstudio': ('http://127.0.0.1:1234/v1', 'GAMEDECOMP_API_KEY'),
}


def doctor() -> dict:
    from gamedecomp.console_support import CONSOLE_PROFILES
    tools = {name: shutil.which(name) for name in ('objdump', 'gcc', 'clang', 'g++', 'clang++', 'ilspycmd', 'dotnet')}
    for name in ('javac', 'javap'):
        java_home = os.environ.get('JAVA_HOME')
        tools[name] = (shutil.which(str(Path(java_home) / 'bin' / name)) if java_home else None) or shutil.which(name)
    home = os.environ.get('GHIDRA_HOME')
    ghidra = bool(home and (Path(home) / 'support' / 'analyzeHeadless').is_file())
    return {'version': __version__, 'python': sys.version.split()[0], 'tools': tools,
            'console_loaders': {'profiles': list(CONSOLE_PROFILES), 'requires_ghidra': True,
                'lz4_available': importlib.util.find_spec('lz4') is not None,
                'status': 'EXPERIMENTAL', 'runtime_equivalence_verified': False},
            'backends': {
                'native': {'available': bool(tools['objdump']), 'scope': 'ELF x86-64 SysV straight-line integer leaf subset'},
                'wasm': {'available': True, 'scope': 'MVP integer straight-line subset; not a full WASM validator'},
                'ghidra': {'available': ghidra, 'scope': 'optional external headless adapter; set GHIDRA_HOME'},
                'ilspy': {'available': bool(tools['ilspycmd']), 'scope': 'optional managed .NET compilation units'},
            }, 'function_translation': {'languages': ['cpp', 'java'], 'semantic_status': 'UNKNOWN',
                'cpp_compiler_available': bool(tools['g++'] or tools['clang++']),
                'java_compiler_available': bool(tools['javac'] and tools['javap'])},
            'llm': {'configured': False, 'requirement': 'Explicit provider/endpoint and model; no bundled LLM',
                       'providers': ['custom', *LLM_PROVIDERS]},
            'type_recovery': {'available': importlib.util.find_spec('elftools') is not None,
                              'scope': 'ELF DWARF metadata, Itanium RTTI and partial layout hypotheses'},
            'gnn': {'training_available': importlib.util.find_spec('torch') is not None,
                    'inference_requires_torch': False,
                    'builtin_model_available': (Path(__file__).parent / 'data' / 'gnn_family.json').is_file(),
                    'scope': 'GraphSAGE semantic family hypotheses; not a general decompiler'},
            'semantic_prover': {'available': False, 'scope': 'No general equivalence proof in this release'}}


def _analysis_options(parser):
    from gamedecomp.console_support import CONSOLE_PROFILES
    parser.add_argument('--console-profile', choices=CONSOLE_PROFILES,
                        help='Explicit console CPU and memory-map profile; required for console modules/ROMs')
    parser.add_argument('--backend', choices=['auto', 'native', 'wasm', 'ghidra', 'ilspy'], default='auto')
    parser.add_argument('--workers', type=int, default=4, help='Numero massimo di job concorrenti')
    parser.add_argument('--timeout', type=float, default=300, help='Budget totale in secondi, più eventuale cleanup limitato')
    parser.add_argument('--phase-timeout', type=float, default=30)
    parser.add_argument('--function', dest='function_pattern', help='Filtro glob per nome o ID')
    parser.add_argument('--max-functions', type=int, default=2000)
    parser.add_argument('--no-compile', action='store_true')
    parser.add_argument('--compiler', help='Compilatore locale fidato')
    parser.add_argument('--cache', type=Path, default=Path('.gamedecomp-cache/artifacts.sqlite'))
    parser.add_argument('--ghidra-home', type=Path)
    parser.add_argument('--knowledge', type=Path)
    parser.add_argument('--no-types', action='store_true', help='Disabilita il recupero strutturale di tipi e classi ELF')
    parser.add_argument('--max-types', type=int, default=20000)
    parser.add_argument('--gnn-model', type=Path, help='Modello JSON addestrato; builtin usa il modello incluso quando disponibile')
    parser.add_argument('--llm-url', help='Custom API endpoint; select its protocol with --llm-api-format')
    parser.add_argument('--llm-provider', choices=['custom', *LLM_PROVIDERS], default='custom',
                        help='Preset endpoint; custom usa --llm-url')
    parser.add_argument('--llm-model')
    parser.add_argument('--llm-api-format', choices=['openai', 'anthropic'],
                        help='Custom endpoint wire protocol; provider presets use their native format')
    parser.add_argument('--llm-key-env', help='Nome della variabile con la chiave, mai il valore; default dipendente dal provider')
    parser.add_argument('--llm-key-prompt', action='store_true', help='Legge la chiave senza eco e senza salvarla')
    parser.add_argument('--llm-json-mode', choices=['object', 'prompt'], default='object',
                        help='prompt per server senza response_format; la risposta resta validata come JSON')
    parser.add_argument('--llm-temperature', type=float, help='Opzionale; omesso usa il default del provider')
    parser.add_argument('--llm-workers', type=int, default=2)
    parser.add_argument('--llm-attempts', type=int, default=2)
    parser.add_argument('--max-llm-functions', type=int, default=100)
    parser.add_argument('--llm-context-bytes', type=int, default=196608, help='Budget del contesto LLM in byte; evidenze omesse esplicite')
    parser.add_argument('--llm-max-output-tokens', type=int, help='Limite output del provider compatibile con max_tokens')
    parser.add_argument('--llm-reasoning-effort', choices=['none','low','medium','high','max'], help='Livello di ragionamento se supportato dal provider')


def _config(args) -> AnalysisConfig:
    provider = args.llm_provider
    if provider != 'custom' and args.llm_url:
        raise ValueError('Usare --llm-provider custom per un endpoint --llm-url personale')
    endpoint, key_env = LLM_PROVIDERS.get(provider, (args.llm_url, 'GAMEDECOMP_API_KEY'))
    preset_format = 'anthropic' if provider == 'anthropic' else 'openai'
    if provider != 'custom' and args.llm_api_format not in (None, preset_format):
        raise ValueError('API format cannot override a provider preset; select custom instead')
    api_format = args.llm_api_format or preset_format
    if bool(endpoint) != bool(args.llm_model):
        raise ValueError('Specificare insieme provider/endpoint e modello LLM')
    if args.llm_key_prompt and not endpoint:
        raise ValueError('--llm-key-prompt richiede un provider e un modello LLM')
    key = os.environ.get(args.llm_key_env or key_env) if endpoint else None
    if args.llm_key_prompt:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                key = getpass.getpass('Chiave API (non salvata): ')
        except (getpass.GetPassWarning, EOFError):
            raise ValueError('Terminale senza input riservato; usare --llm-key-env') from None
        if not key.strip():
            raise ValueError('La chiave API inserita è vuota')
    if provider in ('deepseek', 'openai', 'anthropic') and not key:
        raise ValueError(f'Chiave API mancante: impostare {args.llm_key_env or key_env} oppure --llm-key-prompt')
    return AnalysisConfig(
        console_profile=args.console_profile,
        backend=args.backend, workers=args.workers, timeout=args.timeout, phase_timeout=args.phase_timeout,
        cache_path=args.cache, check_compile=not args.no_compile, compiler=args.compiler,
        function_pattern=args.function_pattern, max_functions=args.max_functions,
        llm_endpoint=endpoint, llm_model=args.llm_model,
        llm_api_key=key,
        llm_api_format=api_format,
        llm_json_mode=args.llm_json_mode, llm_temperature=args.llm_temperature,
        llm_workers=args.llm_workers, llm_attempts=args.llm_attempts,
        max_llm_functions=args.max_llm_functions, llm_context_bytes=args.llm_context_bytes, knowledge_path=args.knowledge,
        llm_max_output_tokens=args.llm_max_output_tokens,
        llm_reasoning_effort=args.llm_reasoning_effort,
        ghidra_home=args.ghidra_home or (Path(os.environ['GHIDRA_HOME']) if os.environ.get('GHIDRA_HOME') else None),
        recover_types=not args.no_types, max_types=args.max_types,
        gnn_model=(Path(__file__).parent / 'data' / 'gnn_family.json'
                   if args.gnn_model == Path('builtin') else args.gnn_model),
    )


def _benchmark(args) -> dict:
    values = [int(value) for value in args.worker_counts.split(',')]
    if not values or 1 not in values or any(value < 1 or value > 64 for value in values) or len(set(values)) != len(values):
        raise ValueError('--worker-counts deve contenere 1 e interi distinti tra 1 e 64')
    if not 1 <= args.repeats <= 20:
        raise ValueError('--repeats deve essere tra 1 e 20')
    if args.output.exists() and any(args.output.iterdir()):
        raise FileExistsError('Directory benchmark non vuota')
    args.output.mkdir(parents=True, exist_ok=True)
    measurements, runs = [], []
    for repeat in range(args.repeats):
        # Rotate order to reduce a systematic first-run startup advantage.
        order = values[repeat % len(values):] + values[:repeat % len(values)]
        for workers in order:
            config = _config(args)
            config.workers = workers
            config.cache_path = args.output / f'cache-{repeat}-{workers}.sqlite'
            report = run_analysis(args.binary, args.output / f'run-{repeat}-{workers}', config)
            runs.append({'workers': workers, 'repeat': repeat, 'seconds': report['timings']['total_seconds'],
                         'summary': report['summary'], 'cache_hit': report['cache_hit']})
    reference = statistics.median(row['seconds'] for row in runs if row['workers'] == 1)
    for workers in values:
        selected = [row for row in runs if row['workers'] == workers]
        elapsed = statistics.median(row['seconds'] for row in selected)
        measurements.append({'workers': workers, 'median_seconds': elapsed,
                             'speedup_vs_1': reference / elapsed,
                             'efficiency': reference / elapsed / workers,
                             'summaries': [row['summary'] for row in selected]})
    result = {'runs': runs, 'measurements': measurements,
              'contract': 'Cold application analysis caches; compilation only, no behavioral proof. Same hardware. '
                          'OS caches and tool process startup are not normalized; these are local measurements, not a SOTA benchmark.'}
    (args.output / 'benchmark.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='gamedecomp', description='Decompilazione conservativa, agenti paralleli e AI opzionale')
    parser.add_argument('--version', action='version', version=__version__)
    commands = parser.add_subparsers(dest='command', required=True)
    health = commands.add_parser('doctor', help='Dipendenze e capacità effettive')
    health.add_argument('--json', action='store_true')
    inspect = commands.add_parser('inspect', help='Identifica formato, architettura e hash senza esecuzione')
    inspect.add_argument('binary', type=Path)
    inspect.add_argument('--console-profile', choices=CONSOLE_PROFILES,
                         help='Explicit console mapping; required to recognize DOL')
    analyze = commands.add_parser('analyze', help='Recupera sorgenti, evidenze e rapporti')
    analyze.add_argument('binary', type=Path)
    analyze.add_argument('-o', '--output', type=Path, required=True)
    _analysis_options(analyze)
    analyze.add_argument('--validate-trusted', action='store_true',
                         help='Autorizza esecuzione di originale ELF .so e candidate AI fidati in processi figli')
    analyze.add_argument('--validation-cases', type=int,
                         help='Confronti scalari finiti per candidata (default 128); richiede --validate-trusted')
    demo = commands.add_parser('demo', help='Compila, decompila e confronta una fixture fidata inclusa')
    demo.add_argument('-o', '--output', type=Path, required=True)
    demo.add_argument('--workers', type=int, default=4)
    demo.add_argument('--cases', type=int, default=128)
    verify = commands.add_parser('verify', help='Test differenziali su una libreria esplicitamente fidata')
    verify.add_argument('binary', type=Path)
    verify.add_argument('report', type=Path)
    verify.add_argument('--trusted', action='store_true', help='Autorizza l’esecuzione della libreria in un processo figlio')
    verify.add_argument('--cases', type=int, default=128)
    verify.add_argument('--timeout', type=float, default=30)
    verify.add_argument('--workers', type=int, default=4)
    verify.add_argument('-o', '--output', type=Path, required=True)
    benchmark = commands.add_parser('benchmark', help='Confronta localmente diverse concorrenze sullo stesso input')
    benchmark.add_argument('binary', type=Path)
    benchmark.add_argument('-o', '--output', type=Path, required=True)
    benchmark.add_argument('--worker-counts', default='1,2,4,8')
    benchmark.add_argument('--repeats', type=int, default=2)
    _analysis_options(benchmark)
    train = commands.add_parser('train-gnn', help='Addestra GraphSAGE su un dataset esplicito, con validation/test separati')
    train.add_argument('dataset', type=Path)
    train.add_argument('-o', '--output', type=Path, required=True)
    train.add_argument('--epochs', type=int, default=120)
    train.add_argument('--seed', type=int, default=17)
    neural_demo = commands.add_parser('gnn-demo', help='Crea fixture fidate, addestra il GNN e misura il test holdout')
    neural_demo.add_argument('-o', '--output', type=Path, required=True)
    neural_demo.add_argument('--samples', type=int, default=48)
    neural_demo.add_argument('--epochs', type=int, default=120)
    neural_demo.add_argument('--seed', type=int, default=17)
    gui = commands.add_parser('gui', help='Apre GameDecomp Studio, interfaccia locale responsive anche in 4K')
    gui.add_argument('--host', default='127.0.0.1', help='Indirizzo loopback del server locale')
    gui.add_argument('--port', type=int, default=8765)
    gui.add_argument('--workspace', type=Path, default=Path('.gamedecomp-ui'))
    gui.add_argument('--no-browser', action='store_true')
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == 'doctor':
            result = doctor()
        elif args.command == 'inspect':
            result = inspect_binary(args.binary, console_profile=args.console_profile)
        elif args.command == 'analyze':
            if args.validation_cases is not None and not args.validate_trusted:
                raise ValueError('--validation-cases richiede --validate-trusted; nessuna esecuzione autorizzata')
            config = _config(args)
            if args.validate_trusted:
                from gamedecomp.trusted_validation import make_trusted_scalar_validator
                validator = make_trusted_scalar_validator(args.binary, trusted=True,
                    cases=args.validation_cases if args.validation_cases is not None else 128)
                report = run_analysis(args.binary, args.output, config, candidate_validator=validator)
            else:
                report = run_analysis(args.binary, args.output, config)
            result = {'summary': report['summary'], 'timings': report['timings'],
                      'cache_hit': report['cache_hit'], 'report': str((args.output / 'report.html').resolve())}
        elif args.command == 'demo':
            from gamedecomp.verify import run_demo
            result = run_demo(args.output, workers=args.workers, cases=args.cases)
        elif args.command == 'verify':
            from gamedecomp.verify import verify_report
            if args.output.exists():
                raise FileExistsError('Il file di verifica esiste già')
            result = verify_report(args.binary, args.report, trusted=args.trusted,
                                   cases=args.cases, timeout=args.timeout, workers=args.workers)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open('x', encoding='utf-8') as stream:
                json.dump(result, stream, indent=2, ensure_ascii=False)
        elif args.command == 'train-gnn':
            from gamedecomp.gnn import train_model
            result = train_model(args.dataset, args.output, epochs=args.epochs, seed=args.seed)
        elif args.command == 'gnn-demo':
            from gamedecomp.gnn import train_model
            from gamedecomp.gnn_corpus import build_corpus
            if args.output.exists() and (not args.output.is_dir() or any(args.output.iterdir())):
                raise FileExistsError('Directory demo GNN non vuota')
            args.output.mkdir(parents=True, exist_ok=True)
            dataset = build_corpus(args.output / 'corpus', samples=args.samples, seed=args.seed)
            metrics = train_model(dataset, args.output / 'model', epochs=args.epochs, seed=args.seed)
            result = {'dataset': str(dataset.resolve()), 'model': str((args.output / 'model' / 'model.json').resolve()),
                      'metrics': metrics}
        elif args.command == 'gui':
            from gamedecomp.web import serve_gui
            serve_gui(args.workspace, host=args.host, port=args.port, open_browser=not args.no_browser)
            return 0
        else:
            result = _benchmark(args)
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        if args.command in ('demo', 'verify') and result.get('summary', {}).get('mismatches', 0):
            return 3
        return 0
    except KeyboardInterrupt:
        print('Operazione interrotta; nessun risultato incompleto promosso.', file=sys.stderr)
        return 130
    except (ValueError, OSError, RuntimeError, TimeoutError, json.JSONDecodeError, sqlite3.Error) as error:
        print(f'Errore: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
