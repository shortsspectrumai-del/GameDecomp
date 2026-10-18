#!/usr/bin/env python3
"""Playwright checks of real 2048.c through local GameDecomp Studio.

Uploads the ELF through the UI, analyzes with auto/Ghidra and checks the baseline
and exported archive. The uploaded binary is not executed. AI and GNN providers
are disabled; browser requests to other origins are blocked. Symbol ground truth
is used only by the evaluator after analysis.

Example:
  python3 scripts/check_real_game_ui.py --url http://127.0.0.1:8767
      --output demo-output/studio/real-game-check"""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import time
from urllib.parse import urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.real_game import FILES, function_names, symbol_addresses
from scripts.check_studio_ui import local_url


def extract_archive(raw, destination):
    """Estrae esclusivamente file regolari e directory entro l'output nuovo."""
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if archive.testzip() is not None or not archive.namelist():
            raise AssertionError('Archivio ZIP vuoto o corrotto')
        for entry in archive.infolist():
            name = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if (name.is_absolute() or '..' in name.parts or '\\' in entry.filename
                    or stat.S_ISLNK(mode)):
                raise AssertionError('Percorso ZIP non regolare: ' + entry.filename)
            target = destination.joinpath(*name.parts)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(entry))
        return archive.namelist()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--url', type=local_url, default='http://127.0.0.1:8767')
    parser.add_argument('--binary', type=Path, default=ROOT / 'demo-output/real-game/builds/gcc-O0/2048-stripped')
    parser.add_argument('--output', type=Path, default=ROOT / 'demo-output/studio/real-game-check')
    parser.add_argument('--backend', choices=('auto', 'ghidra'), default='auto')
    args = parser.parse_args(argv)
    try:
        from playwright.sync_api import sync_playwright, expect
    except ImportError:
        parser.error('Playwright e Chromium richiesti nell’ambiente di sviluppo')
    binary, output = args.binary.resolve(), args.output.resolve()
    if not binary.is_file() or binary.read_bytes()[:4] != b'\x7fELF':
        parser.error('--binary deve indicare il binario ELF del gioco già compilato')
    if output.exists():
        parser.error('--output deve essere una directory nuova')
    source = ROOT / 'demo-output/real-game/source/2048.c'
    if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != FILES['2048.c']:
        parser.error('Sorgente 2048.c fissato e verificato richiesto per il solo valutatore')
    authored = function_names(source.read_text())
    symbols = binary.parent / 'symbols-ground-truth.txt'
    if not symbols.is_file():
        parser.error('Manca symbols-ground-truth.txt accanto al binario')
    addresses = symbol_addresses(symbols.read_text(), set(authored))
    if len(addresses) != 19 or len(authored) != 19:
        parser.error('Ground truth delle 19 funzioni originali incompleto')
    output.mkdir(parents=True)
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'url': args.url,
              'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'requested_backend': args.backend, 'binary_executed': False, 'provider': 'off',
              'checks': [], 'screenshots': [], 'console_errors': [], 'page_errors': [],
              'failed_requests': [], 'blocked_requests': [], 'success': False}
    started = time.monotonic()

    def record(name, **values):
        report['checks'].append({'name': name, 'status': 'PASS', **values})
        print('PASS: ' + name, flush=True)

    def capture(page, filename):
        page.evaluate("window.scrollTo({top: 0, left: 0, behavior: 'instant'})")
        path = output / filename
        page.screenshot(path=str(path), full_page=False, animations='disabled')
        report['screenshots'].append({'path': str(path), 'width': 3840, 'height': 2160})

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context(viewport={'width': 3840, 'height': 2160}, device_scale_factor=1)
                def route_request(route):
                    if urlsplit(route.request.url).scheme in ('http', 'https') and (
                            urlsplit(route.request.url).scheme, urlsplit(route.request.url).netloc) != (
                            urlsplit(args.url).scheme, urlsplit(args.url).netloc):
                        report['blocked_requests'].append(route.request.url)
                        route.abort()
                    else:
                        route.continue_()
                context.route('**/*', route_request)
                page = context.new_page()
                page.on('console', lambda message: report['console_errors'].append(message.text)
                        if message.type == 'error' else None)
                page.on('pageerror', lambda error: report['page_errors'].append(str(error)))
                page.on('requestfailed', lambda request: report['failed_requests'].append(request.url))
                page.goto(args.url, wait_until='networkidle')
                expect(page.locator('#connection-label')).to_have_text('Server connected')
                bootstrap = page.request.get(args.url + '/api/bootstrap', max_redirects=0)
                if bootstrap.status != 200:
                    raise AssertionError('Bootstrap locale non disponibile')
                report['program_version'] = bootstrap.json().get('version')
                page.select_option('#backend', args.backend)
                page.select_option('#provider', 'off')
                page.select_option('#gnn-model', 'off')
                page.locator('details.advanced').filter(has=page.locator('#phase-timeout')).locator('summary').click()
                page.fill('#phase-timeout', '180')
                page.fill('#timeout', '300')
                page.fill('#function-pattern', '')
                page.locator('#recover-types').check()
                page.locator('#binary-file').set_input_files(str(binary))
                expect(page.locator('#file-name')).to_have_text(binary.name)
                capture(page, 'workspace-real-game-4k.png')
                with page.expect_response(lambda response: response.url == args.url + '/api/jobs'
                                          and response.request.method == 'POST') as pending:
                    page.locator('#analyze-button').click()
                response = pending.value
                if response.status not in (200, 201, 202):
                    raise AssertionError('Analisi rifiutata: HTTP ' + str(response.status))
                submitted = response.request.post_data_json
                if submitted.get('options', {}).get('llm', {}).get('provider') != 'off':
                    raise AssertionError('Provider AI attivato inaspettatamente')
                report['submitted_options'] = submitted['options']
                job = response.json()['job']
                report['job_id'] = job['id']
                deadline = time.monotonic() + 360
                while job['status'] not in ('SUCCEEDED', 'FAILED', 'CANCELLED'):
                    if time.monotonic() >= deadline:
                        raise AssertionError('Timeout in attesa del job reale')
                    page.wait_for_timeout(1000)
                    status_response = page.request.get(args.url + '/api/jobs/' + job['id'], max_redirects=0)
                    if status_response.status != 200:
                        raise AssertionError('Stato job non disponibile')
                    job = status_response.json()['job']
                report['job'] = job
                if job['status'] != 'SUCCEEDED':
                    raise AssertionError('Job reale terminato con ' + job['status'] + ': ' + str(job.get('error')))
                expect(page.locator('#report-link')).to_have_attribute('href', f'/api/jobs/{job["id"]}/report.html', timeout=15000)
                record('Upload del gioco reale e analisi UI completata con SUCCEEDED')
                response = page.request.get(args.url + '/api/jobs/' + job['id'] + '/report', max_redirects=0)
                if response.status != 200:
                    raise AssertionError('Rapporto del job non disponibile')
                raw_report = response.body()
                canonical = json.loads(raw_report)
                (output / 'report.json').write_bytes(raw_report)
                if canonical.get('backend') != 'ghidra':
                    raise AssertionError('Backend effettivo inatteso: ' + str(canonical.get('backend')))
                if canonical.get('input', {}).get('sha256') != report['binary_sha256']:
                    raise AssertionError('Il rapporto non corrisponde al file caricato')
                if canonical.get('summary', {}).get('ai_candidates') != 0 or any(
                        function.get('candidate') is not None for function in canonical['functions']):
                    raise AssertionError('Il collaudo locale ha generato candidate AI')
                functions = {function['address']: function for function in canonical['functions']
                             if not function['name'].startswith('.') and '@plt' not in function['name']}
                game_functions = {name: functions.get(address) for name, address in addresses.items()}
                if any(function is None or not function.get('source') for function in game_functions.values()):
                    raise AssertionError('Mancano corpi recuperati alle entry delle 19 funzioni del gioco')
                report['coverage'] = {'authored_functions': 19, 'recovered_game_functions': 19,
                                      'compiled_game_functions': sum(function['compilation']['status'] == 'COMPILED'
                                                                     for function in game_functions.values()),
                                      'all_records': len(canonical['functions'])}
                record('Ghidra effettivo, SHA256 input e 19 baseline originali recuperate', **report['coverage'])
                selected = game_functions['getDigitCount']
                page.fill('#function-search', selected['name'])
                expect(page.locator('#function-list .function-row')).to_have_count(1)
                page.locator('#function-list .function-row').click()
                page.locator('[data-code=baseline]').click()
                expect(page.locator('#function-name')).to_have_text(selected['name'])
                if page.locator('#code-output').inner_text().strip() != selected['source'].strip():
                    raise AssertionError('La baseline mostrata differisce dal report Ghidra')
                capture(page, 'results-real-game-baseline-4k.png')
                record('Baseline reale getDigitCount mostrata integralmente nella UI')
                with page.expect_download() as pending_download:
                    page.locator('#export-link').click()
                download = pending_download.value
                if download.failure():
                    raise AssertionError('Download ZIP fallito: ' + download.failure())
                archive_path = output / 'real-game-results.zip'
                download.save_as(str(archive_path))
                names = extract_archive(archive_path.read_bytes(), output / 'extracted')
                if not {'report.json', 'report.html', 'recovered.c'}.issubset(names):
                    raise AssertionError('File necessari mancanti nello ZIP')
                if json.loads((output / 'extracted/report.json').read_text()) != canonical:
                    raise AssertionError('Rapporto esportato diverso da quello mostrato')
                source_found = any(path.read_text() == selected['source'] for path in
                                   (output / 'extracted/functions').glob('*.c') if '.unit.' not in path.name)
                if not source_found:
                    raise AssertionError('Baseline originale non trovata nello ZIP estratto')
                report['export'] = {'path': str(archive_path), 'sha256': hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                                    'files': len(names), 'extracted_directory': str(output / 'extracted')}
                record('Download tramite pulsante UI, ZIP estratto e baseline verificata', files=len(names))
                dimensions = page.evaluate('({width:innerWidth, scroll:document.documentElement.scrollWidth})')
                if dimensions['scroll'] > dimensions['width']:
                    raise AssertionError('Overflow orizzontale nella UI 4K')
                if not page.evaluate('localStorage.length === 0 && sessionStorage.length === 0'):
                    raise AssertionError('Storage browser non vuoto')
                if any(report[key] for key in ('console_errors', 'page_errors', 'failed_requests', 'blocked_requests')):
                    raise AssertionError('Errori browser o tentativi di rete esterna rilevati')
                record('UI 3840×2160 senza overflow, storage o richieste a provider esterni')
                report['success'] = True
            finally:
                browser.close()
    except Exception as error:
        report['checks'].append({'name': 'Collaudo interrotto', 'status': 'FAIL', 'error': f'{type(error).__name__}: {error}'})
        print('FAIL: ' + str(error), flush=True)
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        target = output / 'browser-check.json'
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print('Evidenze: ' + str(target), flush=True)
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
