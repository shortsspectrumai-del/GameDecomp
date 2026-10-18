#!/usr/bin/env python3
"""Browser smoke checks against an already running, local GameDecomp Studio.

Requires Playwright and its Chromium browser in the development environment.
No provider requests are made. All binary fixtures are generated in a temporary
directory; the C++ fixture is compiled but never executed. Output is restricted
to the requested artifact directory (JSON report, screenshots, exported ZIPs).

Example:
  python3 scripts/check_studio_ui.py --url http://127.0.0.1:8765 \
      --output demo-output/studio/browser-check
"""
import argparse
import io
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


def local_url(value):
    parts = urlsplit(value)
    if (parts.scheme not in ('http', 'https') or
            parts.hostname not in ('localhost', '127.0.0.1', '::1') or
            parts.username is not None or parts.password is not None or
            parts.path not in ('', '/') or parts.query or parts.fragment):
        raise argparse.ArgumentTypeError('--url must identify a loopback HTTP server without credentials or paths')
    return value.rstrip('/')


def unsigned_leb(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def wasm_addition(name):
    """Generate a tiny MVP module: (i32, i32) -> i32, two locals + add."""
    def section(number, content):
        return bytes([number]) + unsigned_leb(len(content)) + content
    encoded_name = name.encode('ascii')
    signature = bytes([1, 0x60, 2, 0x7f, 0x7f, 1, 0x7f])
    exports = bytes([1]) + unsigned_leb(len(encoded_name)) + encoded_name + bytes([0, 0])
    body = bytes([0, 0x20, 0, 0x20, 1, 0x6a, 0x0b])
    return (b'\0asm' + (1).to_bytes(4, 'little') + section(1, signature) +
            section(3, bytes([1, 0])) + section(7, exports) +
            section(10, bytes([1]) + unsigned_leb(len(body)) + body))


def cpp_fixture(directory, compiler):
    source = directory / 'classes.cpp'
    output = directory / 'classes.so'
    source.write_text('''struct Position { float x, y, z; };
class Actor { public: int health; virtual ~Actor() {};
    virtual int tick(int delta) { return health + delta; } };
class Player : public Actor { public: Position position;
    int tick(int delta) override { return health + delta + 1; } };
extern "C" Actor* create_player() { return new Player(); }
''', encoding='utf-8')
    subprocess.run([compiler, '-shared', '-fPIC', '-g', '-O0', str(source), '-o', str(output)],
                   check=True, capture_output=True, timeout=30)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--url', type=local_url, default='http://127.0.0.1:8765')
    parser.add_argument('--output', type=Path, default=Path('demo-output/studio/browser-check'))
    parser.add_argument('--skip-training', action='store_true', help='Skip the optional real CPU training check')
    args = parser.parse_args()
    try:
        from playwright.sync_api import sync_playwright, expect
    except ImportError:
        parser.error('Playwright is required in the development environment')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'url': args.url,
              'checks': [], 'screenshots': [], 'console_errors': [], 'page_errors': [],
              'failed_requests': [], 'remote_requests': [], 'success': False}
    started = time.monotonic()

    def record(name, status='PASS', **values):
        report['checks'].append({'name': name, 'status': status, **values})
        print(f'{status}: {name}', flush=True)

    def observe(page):
        page.on('console', lambda message: report['console_errors'].append(message.text)
                if message.type == 'error' else None)
        page.on('pageerror', lambda error: report['page_errors'].append(str(error)))
        page.on('requestfailed', lambda request: report['failed_requests'].append(request.url))
        page.on('request', lambda request: report['remote_requests'].append(request.url)
                if urlsplit(request.url).scheme in ('http', 'https') and
                urlsplit(request.url).hostname not in ('localhost', '127.0.0.1', '::1') else None)

    def capture(page, filename):
        path = output / filename
        # A full-page capture at a scrolled position can paint fixed/sticky
        # controls in the middle of the output, including the offscreen skip
        # link. Capture from the same origin at every viewport.
        page.evaluate("window.scrollTo({top: 0, left: 0, behavior: 'instant'})")
        page.screenshot(path=str(path), full_page=True, animations='disabled')
        report['screenshots'].append(str(path))

    def check_width(page, name):
        dimensions = page.evaluate('({width:innerWidth, scroll:document.documentElement.scrollWidth})')
        if dimensions['scroll'] > dimensions['width']:
            raise AssertionError(f'Horizontal overflow in {name}: {dimensions}')

    def navigate(page, name):
        menu = page.locator('#menu-toggle')
        if menu.is_visible():
            menu.click()
        page.locator(f'[data-view="{name}"]').click()

    def submit(page, selector, kind):
        with page.expect_response(lambda response: response.url == args.url + '/api/jobs'
                                 and response.request.method == 'POST') as pending:
            page.locator(selector).click()
        response = pending.value
        if response.status not in (200, 201, 202):
            raise AssertionError(f'{kind} job rejected: HTTP {response.status}')
        job = response.json()['job']
        if kind in ('gnn_demo', 'train_gnn'):
            expect(page.locator('#training-export')).to_have_attribute(
                'href', f'/api/jobs/{job["id"]}/export', timeout=120000)
        else:
            expect(page.locator('#report-link')).to_have_attribute(
                'href', f'/api/jobs/{job["id"]}/report.html', timeout=60000)
        return job

    def archive(page, job, filename):
        response = page.request.get(args.url + '/api/jobs/' + job['id'] + '/export')
        if response.status != 200:
            raise AssertionError('Export failed: HTTP ' + str(response.status))
        raw = response.body()
        with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
            if bundle.testzip() is not None or not bundle.namelist():
                raise AssertionError('Invalid or empty exported archive')
            names = bundle.namelist()
        (output / filename).write_bytes(raw)
        return raw, names

    try:
        with tempfile.TemporaryDirectory(prefix='gamedecomp-browser-') as temporary, sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                for width, height in [(3840, 2160), (1920, 1080), (390, 844)]:
                    page = browser.new_page(viewport={'width': width, 'height': height}, device_scale_factor=1)
                    observe(page)
                    page.goto(args.url, wait_until='networkidle')
                    expect(page.locator('#connection-label')).to_have_text('Server connected')
                    capture(page, f'workspace-{width}.png')
                    for view in ('workspace', 'results', 'types', 'training', 'settings'):
                        navigate(page, view)
                        check_width(page, f'{view} at {width}px')
                    record(f'All five views without horizontal overflow at {width}×{height}')
                    page.close()

                page = browser.new_page(viewport={'width': 1920, 'height': 1080}, device_scale_factor=1)
                observe(page)
                page.goto(args.url, wait_until='networkidle')
                expect(page.locator('#connection-label')).to_have_text('Server connected')
                bootstrap = page.request.get(args.url + '/api/bootstrap').json()
                doctor = bootstrap.get('doctor', {})
                report['program_version'] = bootstrap.get('version')

                page.select_option('#provider', 'deepseek')
                if page.locator('#llm-key').get_attribute('type') != 'password':
                    raise AssertionError('API key input must be a password field')
                ephemeral = secrets.token_urlsafe(24)
                page.fill('#llm-key', ephemeral)
                page.select_option('#provider', 'custom')
                if page.input_value('#llm-key') != '':
                    raise AssertionError('Provider switch must clear the ephemeral credential')
                page.select_option('#provider', 'off')
                record('Provider form and ephemeral key clearing (no remote provider request)')

                function_name = 'studio_add'
                page.locator('#binary-file').set_input_files({
                    'name': 'studio-add.wasm', 'mimeType': 'application/wasm',
                    'buffer': wasm_addition(function_name)})
                page.wait_for_selector('#selected-file:not([hidden])')
                page.select_option('#gnn-model', 'off')
                wasm_job = submit(page, '#analyze-button', 'analyze')
                expect(page.locator('#function-name')).to_have_text(function_name)
                if 'uint32_t' not in page.locator('#code-output').inner_text():
                    raise AssertionError('WASM baseline missing')
                for tab, expected in [('disassembly', 'local.get'), ('evidence', 'diagnostics'),
                                      ('candidate', 'No AI candidate'), ('compatibility', 'No compatibility translation')]:
                    page.locator('[data-code=' + tab + ']').click()
                    if expected not in page.locator('#code-output').inner_text():
                        raise AssertionError('Unexpected content for ' + tab)
                page.locator('[data-code=baseline]').click()
                page.fill('#function-search', 'no-matching-function')
                if page.locator('#function-list .function-row').count() != 0:
                    raise AssertionError('Function search did not filter the list')
                page.fill('#function-search', function_name)
                expect(page.locator('#function-list .function-row')).to_have_count(1)
                capture(page, 'results-wasm-1920.png')
                _, names = archive(page, wasm_job, 'wasm-results.zip')
                if 'report.json' not in names:
                    raise AssertionError('WASM export missing canonical report')
                navigate(page, 'workspace')
                expect(page.locator('#analysis-progress')).to_be_visible()
                expect(page.locator('#progress-summary')).to_contain_text('1 / 1 functions processed')
                if 'TESTED' not in page.locator('#progress-counts').inner_text().upper():
                    raise AssertionError('Finite-test counter missing')
                expect(page.locator('#dependency-canvas svg')).to_have_count(1)
                record('Actual final telemetry and bounded observed-call diagram; compilation is not correctness')
                record('Real WASM upload, analysis, five code tabs, search, CMake project and ZIP export')

                class ProviderFixture(BaseHTTPRequestHandler):
                    def do_GET(self):
                        raw=json.dumps({'data':[{'id':'fixture-model','context_window':65536,'max_output_tokens':8192}]}).encode()
                        self.send_response(200);self.end_headers();self.wfile.write(raw)
                    def do_POST(self):
                        request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                        context=json.loads(request['messages'][1]['content'])['context']
                        signature=next(x for x in context['evidence'] if x['kind']=='signature')
                        name=signature['metadata']['export_name']
                        result={'source':f'uint32_t {name}(uint32_t left,uint32_t right) {{ return left + right; }} /* fixture-ui-api-key */',
                                'evidence_ids':[signature['id']],'assumptions':[]}
                        raw=json.dumps({'choices':[{'message':{'content':json.dumps(result)}}]}).encode()
                        self.send_response(200);self.end_headers();self.wfile.write(raw)
                    def log_message(self,*args):pass
                provider=ThreadingHTTPServer(('127.0.0.1',0),ProviderFixture)
                provider_thread=threading.Thread(target=provider.serve_forever,daemon=True)
                provider_thread.start()
                try:
                    navigate(page,'workspace')
                    page.select_option('#provider','custom')
                    page.fill('#llm-url',f'http://127.0.0.1:{provider.server_port}/v1')
                    page.fill('#llm-model','fixture-model')
                    page.fill('#llm-key','fixture-ui-api-key')
                    navigate(page, 'settings')
                    expect(page.locator('#provider')).to_be_visible()
                    expect(page.locator('#readiness-list')).to_contain_text('LLM connection')
                    page.locator('#refresh-llm-models').click()
                    expect(page.locator('#llm-connection-status')).to_contain_text('Server responded')
                    page.select_option('#discovered-model-select','fixture-model')
                    expect(page.locator('#llm-model')).to_have_value('fixture-model')
                    record('Shared Settings controls, guided prerequisites and actual local model discovery')
                    navigate(page,'workspace')
                    ai_job=submit(page,'#analyze-button','analyze')
                    expect(page.locator('[data-code=candidate]')).to_have_attribute('aria-selected','true')
                    if 'return left + right' not in page.locator('#code-output').inner_text():
                        raise AssertionError('LLM reconstruction not shown as primary view')
                    raw,names=archive(page,ai_job,'ai-results.zip')
                    if 'project-ai/manifest.json' not in names:
                        raise AssertionError('AI CMake project missing')
                    with zipfile.ZipFile(io.BytesIO(raw)) as package:
                        result=json.loads(package.read('report.json'))
                        if result['engine']['mode']!='LLM' or result['functions'][0]['candidate']['compilation']['status']!='COMPILED':
                            raise AssertionError('Actual LLM pipeline or compilation unavailable')
                        if any(b'fixture-ui-api-key' in package.read(x) for x in names):
                            raise AssertionError('Fixture API key leaked to export')
                    capture(page,'results-ai-1920.png')
                    record('Local HTTP LLM engine, automatic context/ABI/compiler checks, AI-first view, project-ai export and credential redaction')
                finally:
                    provider.shutdown();provider.server_close();provider_thread.join(timeout=2)
                    navigate(page,'workspace');page.select_option('#provider','off')

                if doctor.get('tools', {}).get('gcc') or doctor.get('tools', {}).get('clang'):
                    navigate(page, 'workspace')
                    demo_job = submit(page, '#workspace-demo', 'demo')
                    if not page.locator('#function-name').inner_text().startswith('game_'):
                        raise AssertionError('Trusted demo did not produce game functions')
                    capture(page, 'results-demo-1920.png')
                    archive(page, demo_job, 'demo-results.zip')
                    record('Trusted native demo through the actual UI button')
                else:
                    record('Trusted native demo', 'SKIP', reason='No C compiler available')

                compiler = shutil.which('g++') or shutil.which('clang++')
                if doctor.get('type_recovery', {}).get('available') and compiler:
                    fixture = cpp_fixture(Path(temporary), compiler)
                    navigate(page, 'workspace')
                    page.locator('#binary-file').set_input_files(str(fixture))
                    expect(page.locator('#file-name')).to_have_text(fixture.name)
                    submit(page, '#analyze-button', 'analyze')
                    navigate(page, 'types')
                    page.wait_for_selector('#types-content:not([hidden])')
                    page.fill('#type-search', 'Player')
                    page.locator('#type-list .function-row').first.click()
                    if 'Player' not in page.locator('#type-name').inner_text() or 'Actor' not in page.locator('#type-content').inner_text():
                        raise AssertionError('C++ class/base evidence missing')
                    capture(page, 'types-1920.png')
                    record('Generated trusted C++ fixture: types, fields, and Player → Actor base')
                else:
                    record('C++ class browser', 'SKIP', reason='pyelftools or C++ compiler unavailable')

                if not args.skip_training and doctor.get('gnn', {}).get('training_available'):
                    navigate(page, 'training')
                    page.fill('#training-samples', '6')
                    page.fill('#training-epochs', '2')
                    job = submit(page, '#training-button', 'gnn_demo')
                    if 'accuracy' not in page.locator('#training-metrics').inner_text():
                        raise AssertionError('Training metrics missing')
                    capture(page, 'training-1920.png')
                    raw, names = archive(page, job, 'trained-gnn.zip')
                    if not {'model.json', 'metrics.json'}.issubset(names):
                        raise AssertionError('Training archive missing model or metrics')
                    with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
                        model = bundle.read('model.json')
                    navigate(page, 'workspace')
                    page.select_option('#gnn-model', 'custom')
                    page.locator('#model-file').set_input_files({
                        'name': 'trained-model.json', 'mimeType': 'application/json', 'buffer': model})
                    expect(page.locator('#model-upload-status')).to_contain_text('imported')
                    record('Real CPU GNN training, split metrics, model export and custom model upload')
                else:
                    record('Real CPU GNN training', 'SKIP', reason='Explicitly skipped or PyTorch unavailable')

                for width, height in [(3840, 2160), (1920, 1080), (390, 844)]:
                    page.set_viewport_size({'width': width, 'height': height})
                    for view in ('results', 'types', 'training', 'settings'):
                        navigate(page, view)
                        check_width(page, f'populated {view} at {width}px')
                    record(f'Populated result views without horizontal overflow at {width}px')

                if not page.evaluate('localStorage.length === 0 && sessionStorage.length === 0'):
                    raise AssertionError('Studio wrote to browser storage')
                if any(report[key] for key in ('console_errors', 'page_errors', 'failed_requests', 'remote_requests')):
                    raise AssertionError('Browser errors or unexpected remote requests were observed')
                record('No browser storage, console errors, page errors, failed or remote requests')
                report['success'] = True
            finally:
                browser.close()
    except Exception as error:
        record('Browser check interrupted', 'FAIL', error=f'{type(error).__name__}: {error}')
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        path = output / 'browser-check.json'
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print('Report: ' + str(path), flush=True)
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
