"""Isolated browser, translation, compiler feedback and restart persistence check.

Run with ``python3 -m scripts.check_translation_ui --output <new-directory>``.
Requires Playwright/Chromium, a C++ compiler and javac (bundled JAVA_HOME is
selected when present). Uses synthetic WASM and a scripted loopback provider;
no remote API, user workspace or generated application execution is involved.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import zipfile
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gamedecomp.web import create_server
from scripts.check_studio_ui import wasm_addition


@contextmanager
def running_server(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        if thread.is_alive():
            raise RuntimeError('Local verification server did not stop')


def fixture_handler(requests, errors):
    class Provider(BaseHTTPRequestHandler):
        def send(self, value, status=200):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.send({'object': 'list', 'data': [{'id': 'translation-local-fixture',
                'object': 'model', 'context_window': 131072, 'max_output_tokens': 4096}]})

        def do_POST(self):
            try:
                assert self.path == '/v1/chat/completions'
                length = int(self.headers.get('Content-Length', '0'))
                assert 0 < length < 262144
                body = json.loads(self.rfile.read(length))
                assert body['model'] == 'translation-local-fixture'
                data = json.loads(body['messages'][-1]['content'])
                target = data['context']['target_language']
                assert target in ('cpp', 'java') and data['source'].strip()
                evidence = data['context']['evidence'][0]['id']
                assert evidence == 'source:' + hashlib.sha256(data['source'].encode()).hexdigest()
                first_cpp = target == 'cpp' and not any(row['target'] == 'cpp' for row in requests)
                if first_cpp:
                    source = 'int recovered(int a, int b) { return a + ; }'
                elif target == 'cpp':
                    assert data['feedback'], 'Compiler feedback was not forwarded'
                    source = 'int recovered(int a, int b) { return a + b; }'
                else:
                    source = ('public final class RecoveredFunction {\n'
                        '  public static int recovered(int a, int b) { return a + b; }\n}')
                requests.append({'target': target, 'feedback_items': len(data.get('feedback', [])),
                    'source_sha256': hashlib.sha256(data['source'].encode()).hexdigest(),
                    'deliberate_compile_error': first_cpp})
                result = {'source': source, 'evidence_ids': [evidence], 'assumptions': []}
                self.send({'id': 'local-fixture', 'choices': [{'finish_reason': 'stop',
                    'message': {'role': 'assistant', 'content': json.dumps(result)}}],
                    'usage': {'prompt_tokens': 100, 'completion_tokens': 30, 'total_tokens': 130}})
            except Exception as error:
                errors.append(str(error))
                self.send({'error': {'message': 'Local fixture assertion failed'}}, 500)

        def log_message(self, *args):
            pass

    return Provider


def exported_source(page, base, job, target, output, suffix=''):
    response = page.request.get(base + f'/api/jobs/{job}/export')
    assert response.status == 200
    raw = response.body()
    name = 'RecoveredFunction.' + ('cpp' if target == 'cpp' else 'java')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert name in archive.namelist(), archive.namelist()
        source = archive.read(name)
        assert source.strip()
        report = json.loads(archive.read('report.json'))
        assert report['functions'][0]['compilation']['status'] == 'COMPILED'
        assert report['functions'][0]['semantic_status'] == 'UNKNOWN'
        assert report['translation']['target_language'] == target
        assert report['translation']['output_sha256'] == hashlib.sha256(source).hexdigest()
    (output / (target + suffix + '.zip')).write_bytes(raw)
    return hashlib.sha256(source).hexdigest()


def check(output):
    from playwright.sync_api import sync_playwright, expect
    requests, provider_errors, page_errors = [], [], []
    root = Path(__file__).resolve().parents[1]
    old_java = os.environ.get('JAVA_HOME')
    bundled = root / 'tools/jdk-21.0.12.1+1'
    if not old_java and (bundled / 'bin/javac').is_file():
        os.environ['JAVA_HOME'] = str(bundled)
    try:
        with tempfile.TemporaryDirectory(prefix='gamedecomp-translation-ui-') as temporary:
            workspace = Path(temporary) / 'studio'
            provider = ThreadingHTTPServer(('127.0.0.1', 0), fixture_handler(requests, provider_errors))
            with running_server(provider), sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                try:
                    page = browser.new_page(viewport={'width': 3840, 'height': 2160})
                    page.on('pageerror', lambda error: page_errors.append(str(error)))
                    translations, hashes = {}, {}
                    with running_server(create_server(workspace, port=0)) as studio:
                        base = f'http://127.0.0.1:{studio.server_port}'
                        page.goto(base + '/#workspace', wait_until='networkidle')
                        version = page.request.get(base + '/api/bootstrap').json()['version']
                        page.locator('#provider').select_option('off')
                        with page.expect_response(lambda r: '/api/upload?' in r.url and r.request.method == 'POST') as uploaded:
                            page.locator('#binary-file').set_input_files({'name': 'addition.wasm',
                                'mimeType': 'application/wasm', 'buffer': wasm_addition('add')})
                        assert uploaded.value.status == 201
                        with page.expect_response(lambda r: r.url == base + '/api/jobs' and r.request.method == 'POST') as submitted:
                            page.locator('#analyze-button').click()
                        assert submitted.value.status == 202
                        origin = submitted.value.json()['job']['id']
                        expect(page.locator('#report-link')).to_have_attribute('href', f'/api/jobs/{origin}/report.html', timeout=60000)
                        page.locator('[data-code="baseline"]').click()
                        expect(page.locator('#translate-function')).to_be_disabled()
                        expect(page.locator('#translation-status')).to_contain_text('Configure an LLM')
                        page.locator('[data-view="settings"]').click()
                        page.locator('#provider').select_option('custom')
                        page.locator('#llm-api-format').select_option('openai')
                        page.locator('#llm-url').fill(f'http://127.0.0.1:{provider.server_port}/v1')
                        page.locator('#llm-model').fill('translation-local-fixture')
                        page.locator('#refresh-llm-models').click()
                        expect(page.locator('#llm-connection-status')).to_contain_text('Server responded')
                        page.locator('[data-view="results"]').click()
                        for target in ('cpp', 'java'):
                            page.locator('[data-code="baseline"]').click()
                            page.locator('#translation-language').select_option(target)
                            expect(page.locator('#translate-function')).to_be_enabled()
                            with page.expect_response(lambda r: r.url == base + '/api/jobs' and r.request.method == 'POST') as submitted:
                                page.locator('#translate-function').click()
                            assert submitted.value.status == 202
                            job = submitted.value.json()['job']['id']
                            translations[target] = job
                            expect(page.locator('#report-link')).to_have_attribute('href', f'/api/jobs/{job}/report.html', timeout=60000)
                            expect(page.locator('#code-status')).to_have_text('LLM TRANSLATION · COMPILED · SEMANTICS UNKNOWN')
                            expect(page.locator('#translate-function')).to_be_disabled()
                            expect(page.locator('#code-output')).to_contain_text('recovered')
                            expect(page.locator('[data-code="baseline"]')).to_have_text('Translated source')
                            report = page.request.get(base + f'/api/jobs/{job}/report').json()
                            assert report['translation']['source_job_id'] == origin
                            toolchain = report['functions'][0]['compilation']['toolchain']
                            if target == 'java':
                                assert toolchain['executed'] is False and toolchain['annotation_processing'] is False
                            else:
                                assert '-c' in toolchain['flags'] and toolchain['language'] == 'c++'
                            if target == 'cpp':
                                assert [a['status'] for a in report['translation']['attempts']] == ['COMPILE_FAILED', 'COMPILED']
                            hashes[target] = exported_source(page, base, job, target, output)
                            page.screenshot(path=str(output / f'{target}-translation-4k.png'), full_page=True, animations='disabled')
                            if target == 'cpp':
                                page.locator('#translation-origin').click()
                                expect(page.locator('#report-link')).to_have_attribute('href', f'/api/jobs/{origin}/report.html')
                        assert len(requests) == 3 and not provider_errors, provider_errors
                    # A new manager must discover persisted metadata and verified outputs.
                    with running_server(create_server(workspace, port=0)) as studio:
                        base = f'http://127.0.0.1:{studio.server_port}'
                        page.goto(base + '/#results', wait_until='networkidle')
                        expect(page.locator('#jobs-list .job-card')).to_have_count(3)
                        expect(page.locator('.job-restored')).to_have_count(3)
                        jobs = page.request.get(base + '/api/bootstrap').json()['jobs']
                        assert len(jobs) == 3 and all(j['restored'] and j['status'] == 'SUCCEEDED' for j in jobs)
                        expect(page.locator('#history-summary')).to_have_text('Showing 3 of 3 matching jobs · 3 total')
                        page.locator('#history-status').select_option('failed')
                        expect(page.locator('#jobs-list .job-card')).to_have_count(0)
                        expect(page.locator('#history-no-match')).to_be_visible()
                        expect(page.locator('#activity-empty')).to_be_hidden()
                        page.locator('#history-status').select_option('succeeded')
                        page.locator('#history-search').fill('Function translation')
                        expect(page.locator('#jobs-list .job-card')).to_have_count(2)
                        expect(page.locator('#job-count')).to_have_text('3 JOBS')
                        for target, job in translations.items():
                            page.locator('#history-search').fill(job)
                            expect(page.locator('#jobs-list .job-card')).to_have_count(1)
                            page.locator('#jobs-list .job-card').get_by_role('button', name='Open results').click()
                            expect(page.locator('#report-link')).to_have_attribute('href', f'/api/jobs/{job}/report.html')
                            expect(page.locator('#code-status')).to_have_text('LLM TRANSLATION · COMPILED · SEMANTICS UNKNOWN')
                            assert exported_source(page, base, job, target, output, '-restored') == hashes[target]
                        page.locator('#history-search').fill('')
                        page.screenshot(path=str(output / 'restored-history-4k.png'), full_page=True, animations='disabled')
                        page.set_viewport_size({'width': 390, 'height': 844})
                        page.screenshot(path=str(output / 'restored-history-mobile.png'), full_page=True, animations='disabled')
                        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'Mobile overflow'
                        assert page.locator('#sidebar').evaluate('(element) => element.getBoundingClientRect().right <= 1'), 'Closed mobile sidebar covers content'
                    assert not page_errors and not provider_errors, [*page_errors, *provider_errors]
                    assert len(requests) == 3, 'Restoring jobs unexpectedly invoked the provider'
                    return {'status': 'PASS', 'version': version, 'origin_job': origin,
                        'translation_jobs': translations, 'source_hashes': hashes,
                        'provider_requests': requests, 'restored_jobs': 3,
                        'semantic_status': 'UNKNOWN', 'page_errors': page_errors,
                        'scope': 'Browser, local scripted protocol, real C++/Java compilation and restart persistence. '
                                 'No model quality or semantic equivalence measurement; generated programs were not executed.'}
                finally:
                    browser.close()
    finally:
        if old_java is None:
            os.environ.pop('JAVA_HOME', None)
        else:
            os.environ['JAVA_HOME'] = old_java


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    try:
        result = check(output)
    except Exception as error:
        (output / 'verification.json').write_text(json.dumps({'status': 'FAIL', 'error': str(error)}, indent=2) + '\n')
        raise
    (output / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: C++/Java translation, compiler feedback, ZIPs, restored history and browser layout')


if __name__ == '__main__':
    main()
