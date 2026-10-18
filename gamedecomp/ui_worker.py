"""Studio subprocess. Secrets arrive only on stdin and never become artifacts."""
import json
import sys
from pathlib import Path


def _progress(phase):
    print(json.dumps({'phase': phase}, ensure_ascii=False), flush=True)


def run(payload):
    import gamedecomp.pipeline as pipeline
    from gamedecomp.pipeline import AnalysisConfig, run_analysis
    directory = Path(payload['directory'])
    kind, options = payload['kind'], payload.get('options', {})
    if kind == 'analyze':
        _progress('Analysis, type recovery and validation')
        llm = options.pop('llm', {})
        if llm:
            _progress('LLM reconstruction, ABI checks and automatic compilation')
        secret = llm.get('key')
        if secret:
            # Remove echoed credentials before the pipeline can persist model
            # output. This factory replacement lives only in this child.
            original = pipeline.LLMClient
            def redact(value):
                if isinstance(value, str):
                    return value.replace(secret, '[REDACTED]')
                if isinstance(value, list):
                    return [redact(item) for item in value]
                if isinstance(value, dict):
                    return {name: redact(item) for name, item in value.items()}
                return value
            class PrivateClient(original):
                def refine(self, *args, **kwargs):
                    return redact(super().refine(*args, **kwargs))
            pipeline.LLMClient = PrivateClient
        config = AnalysisConfig(**options, cache_path=directory / 'cache.sqlite',
                                llm_endpoint=llm.get('url'), llm_model=llm.get('model'),
                                llm_api_key=llm.pop('key', None),
                                llm_api_format=llm.get('api_format', 'openai'),
                                llm_json_mode=llm.get('json_mode', 'object'),
                                llm_temperature=llm.get('temperature'),
                                llm_max_output_tokens=llm.get('max_output_tokens'),
                                llm_reasoning_effort=llm.get('reasoning_effort'))
        report = run_analysis(Path(payload['source']), directory / 'results', config,
                              progress_callback=lambda event: print(json.dumps(event, ensure_ascii=True), flush=True))
        result = {'summary': report.get('summary', {}), 'report': True}
    elif kind == 'translate':
        from gamedecomp.translation import translate_function
        llm = options.pop('llm', {})
        config = AnalysisConfig(**options, llm_endpoint=llm.get('url'), llm_model=llm.get('model'),
            llm_api_key=llm.get('key'), llm_api_format=llm.get('api_format', 'openai'),
            llm_json_mode=llm.get('json_mode', 'object'), llm_temperature=llm.get('temperature'),
            llm_max_output_tokens=llm.get('max_output_tokens'),
            llm_reasoning_effort=llm.get('reasoning_effort'))
        report = translate_function(payload['source'], directory / 'results',
            payload['function_id'], payload['target_language'], config,
            source_kind=payload['source_kind'], source_job_id=payload.get('source_job_id'),
            progress=_progress)
        result = {'summary': report['summary'], 'report': True}
    elif kind == 'demo':
        from gamedecomp.verify import run_demo
        _progress('Compiling and testing the trusted demo')
        demo = run_demo(directory / 'results', workers=options.get('workers', 4), cases=128)
        result = {'summary': demo['summary'], 'report': True}
    else:
        from gamedecomp.gnn import train_model
        dataset = Path(payload['source']) if kind == 'train_gnn' else None
        if kind == 'gnn_demo':
            from gamedecomp.gnn_corpus import build_corpus
            _progress('Generating the GNN corpus')
            dataset = build_corpus(directory / 'corpus', samples=payload['samples'],
                                   seed=payload['seed'], timeout=options.get('timeout', 600))
        _progress('Training and evaluating the GNN')
        metrics = train_model(dataset, directory / 'model', epochs=payload['epochs'], seed=payload['seed'])
        result = {'metrics': metrics, 'report': True}
    _progress('Saving results')
    (directory / 'result.json').write_text(json.dumps(result, ensure_ascii=False, allow_nan=False), encoding='utf-8')


def main():
    payload = None
    key = None
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError('Worker configuration exceeds the size limit')
        payload = json.loads(raw)
        key = payload.get('options', {}).get('llm', {}).get('key')
        run(payload)
        return 0
    except Exception as error:
        # Exception text from external tools/providers can contain input: redact
        # the ephemeral credential before emitting anything to the supervisor.
        message = str(error)[:4096]
        if key:
            message = message.replace(key, '[REDACTED]')
        print(json.dumps({'error': message or type(error).__name__}, ensure_ascii=False), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
