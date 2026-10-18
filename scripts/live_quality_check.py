"""One-shot local credential form for the existing trusted DeepSeek benchmark.

Development checkout utility. Keys travel only in POST memory and child stdin,
never in command lines, environment, preferences or benchmark configuration files.
"""
import argparse
import html
import json
from pathlib import Path
import secrets
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]


def _require_psutil():
    try:
        import psutil
    except ImportError as error:
        raise RuntimeError('psutil is required for benchmark process-tree cleanup') from error
    if psutil is None:
        raise RuntimeError('psutil is required for benchmark process-tree cleanup')
    return psutil


def _stop(process):
    if process is None:
        return
    psutil = _require_psutil()
    discovered = {}
    for _ in range(2):
        try:
            parent = psutil.Process(process.pid)
            nodes = [parent, *parent.children(recursive=True)]
        except psutil.NoSuchProcess:
            nodes = []
        for node in nodes:
            discovered[node.pid] = node
            try:
                node.suspend()
            except psutil.Error:
                pass
    for node in discovered.values():
        try:
            node.kill()
        except psutil.NoSuchProcess:
            pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    psutil.wait_procs(list(discovered.values()), timeout=3)
    try:
        process.wait(timeout=3)
    except Exception:
        pass


class Control:
    def __init__(self):
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.state = 'READY'
        self.error_type = None
        self.process = None
        self.closing = False

    def finish(self, state, error_type=None):
        with self.lock:
            self.state, self.error_type = state, error_type

    def status(self):
        with self.lock:
            return {'state': self.state, 'error_type': self.error_type}

    def close(self):
        with self.lock:
            self.closing = True
            process = self.process
        if process is not None:
            _stop(process)


def _launch(config, key, model, output, control):
    process = None
    try:
        _require_psutil()
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--worker',
                   '--plan', config['plan'], '--previous', config['previous'],
                   '--ghidra-home', config['ghidra_home'], '--output', str(output)]
        # Only the fixed local benchmark prints progress; provider response
        # bodies are not logged by this worker. Sanitize before writing its log.
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        with control.lock:
            control.process = process
            closing = control.closing
        if closing:
            _stop(process)
        try:
            raw, _ = process.communicate(json.dumps({'key': key, 'model': model}).encode(), timeout=2700)
        except subprocess.TimeoutExpired:
            _stop(process)
            raw, _ = process.communicate()
            control.finish('FAILED', 'TimeoutError')
        log = raw.replace(key.encode(), b'[REDACTED]')[:1048576]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.with_suffix('.log').write_bytes(log)
        if control.status()['state'] != 'FAILED':
            control.finish('SUCCEEDED' if process.returncode == 0 else 'FAILED',
                           None if process.returncode == 0 else 'BenchmarkError')
    except Exception as error:
        if process is not None:
            _stop(process)
        control.finish('FAILED', type(error).__name__)
    finally:
        with control.lock:
            control.process = None
        if process is not None and process.poll() is None:
            _stop(process)


def create_server(config, plan, output, port=0):
    _require_psutil()
    control = Control()
    targets = ''.join('<li>' + html.escape(row['variant']+' / '+row['function']) + '</li>' for row in plan['targets'])
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GameDecomp — Live quality check</title><style nonce="TOKEN">body{background:#101722;color:#e6eef6;font:17px system-ui;max-width:780px;margin:7vh auto;padding:24px}h1{color:#87dfca}input,button{display:block;box-sizing:border-box;width:100%;padding:14px;margin:10px 0 24px;background:#1c2939;color:inherit;border:1px solid #597387;border-radius:8px}button{background:#87dfca;color:#11202a;font-weight:700;cursor:pointer}p,li{line-height:1.6}pre{white-space:pre-wrap}small{color:#b2c2d3}</style>
<h1>Live DeepSeek quality check</h1><p>Four fixed targets from the pinned 2048.c game. Up to 12 model attempts. Compiler checks and finite behavioral comparisons use a separate trusted oracle. Evidence is sent to DeepSeek; original source stays with the evaluator.</p><ul>TARGETS</ul>
<p>API usage may incur charges. No uploaded games are executed. This check runs only the fixed trusted benchmark.</p>
<form id="form"><label for="model">Model identifier</label><input id="model" value="auto" maxlength="512" autocomplete="off"><small>Auto selects a supported model from your account catalog.</small><p><label for="key">DeepSeek API key — memory only</label><input id="key" type="password" required maxlength="8192" autocomplete="off"></p><button id="run">Start measured benchmark</button></form><pre id="status" aria-live="polite">Ready. The key is never saved.</pre>
<script nonce="TOKEN">const token='TOKEN',form=document.getElementById('form'),status=document.getElementById('status');
form.addEventListener('submit',async event=>{event.preventDefault();document.getElementById('run').disabled=true;let key=document.getElementById('key').value;document.getElementById('key').value='';try{const response=await fetch('/run',{method:'POST',headers:{'Content-Type':'application/json','X-Session-Token':token},body:JSON.stringify({key,model:document.getElementById('model').value})});key='';status.textContent=response.ok?'Running. Results are written locally; this can take several minutes.':'Request rejected. Check the model and key, then reload.';}catch(error){key='';status.textContent='Local connection unavailable.';}});
setInterval(async()=>{try{const response=await fetch('/status');const value=await response.json();if(value.state!=='READY')status.textContent=value.state+(value.error_type?' · '+value.error_type:'');}catch(error){}},2000);</script></html>'''.replace('TARGETS', targets).replace('TOKEN', control.token)

    class Handler(BaseHTTPRequestHandler):
        def send(self, code, raw, content_type='application/json'):
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; connect-src 'self'; script-src 'nonce-"+control.token+"'; style-src 'nonce-"+control.token+"'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
            self.end_headers(); self.wfile.write(raw)

        def allowed_host(self):
            return self.headers.get('Host') == '127.0.0.1:' + str(self.server.server_port)

        def do_GET(self):
            if not self.allowed_host():
                self.send(403, b'{}'); return
            if self.path == '/':
                self.send(200, page.encode(), 'text/html; charset=utf-8')
            elif self.path == '/status':
                self.send(200, json.dumps(control.status()).encode())
            else:
                self.send(404, b'{}')

        def do_POST(self):
            base = 'http://127.0.0.1:' + str(self.server.server_port)
            if (not self.allowed_host() or self.headers.get('Origin') != base
                    or not secrets.compare_digest(self.headers.get('X-Session-Token', ''), control.token)):
                self.send(403, b'{}'); return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if self.path != '/run' or not 0 < length <= 16384:
                    raise ValueError
                data = json.loads(self.rfile.read(length))
                if type(data) is not dict or set(data) != {'key', 'model'}:
                    raise ValueError
                key, model = data['key'], data['model']
                if (not isinstance(key, str) or not 16 <= len(key) <= 8192
                        or any(ord(c) < 33 or ord(c) == 127 for c in key)
                        or not isinstance(model, str) or not model.strip() or len(model) > 512
                        or key in model or any(ord(c) < 32 for c in model)):
                    raise ValueError
                with control.lock:
                    if control.state != 'READY':
                        self.send(409, b'{}'); return
                    control.state = 'RUNNING'
                threading.Thread(target=_launch, args=(config, key, model, output, control), daemon=True).start()
                self.send(202, b'{"state":"RUNNING"}')
            except (ValueError, TypeError, UnicodeError):
                self.send(400, b'{}')

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    server.control = control
    return server


def main():
    _require_psutil()
    sys.path.insert(0, str(ROOT))
    from benchmarks.repair_llm import build_repair_plan, run
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--previous', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ghidra-home', type=Path, required=True)
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Benchmark output must be new')
    if args.worker:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise ValueError('Configuration exceeds the size limit')
        data = json.loads(raw)
        run(args.plan, args.previous, args.output, args.ghidra_home, key=data['key'], model=data['model'])
        return
    plan = build_repair_plan(args.plan, args.previous)
    config = {name: str(getattr(args, name).resolve()) for name in ('plan', 'previous', 'ghidra_home')}
    server = create_server(config, plan, args.output.resolve(), args.port)
    print('Protected benchmark form: http://127.0.0.1:'+str(server.server_port)+'/', flush=True)
    try:
        server.serve_forever(poll_interval=.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.control.close()
        server.server_close()


if __name__ == '__main__':
    main()
