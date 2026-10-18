"""Loopback-only GameDecomp Studio service and bounded subprocess queue.

The local process is not a hostile-code sandbox. Uploaded programs are only
analyzed; execution is restricted to the explicit bundled demo workflow.
"""
import base64
import copy
import hashlib
import hmac
import io
import json
import math
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
import zipfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from gamedecomp import __version__
from gamedecomp.ingest import inspect_binary
from gamedecomp.session_store import SessionStore, WorkspaceLock

_ID = re.compile(r'^[a-f0-9]{32}$')
_LIMITS = {'binary': 256 * 1024**2, 'model': 16 * 1024**2, 'dataset': 64 * 1024**2}
_TERMINAL = {'SUCCEEDED', 'FAILED', 'CANCELLED'}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _integer(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f'{name}: expected integer between {minimum} e {maximum}')
    return value


def _number(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError(f'{name}: valore fuori intervallo')
    return value


def _reject_constant(value):
    raise ValueError('Non-finite JSON')


def _json(raw):
    return json.loads(raw, parse_constant=_reject_constant)


def _owned(root, path, *, regular=False):
    """Reject symlinks in every workspace-relative component before access."""
    path = Path(path).absolute()
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise ValueError('Path outside workspace') from None
    current = root
    for part in relative.parts:
        if part in ('.', '..'):
            raise ValueError('Invalid path')
        current /= part
        if current.is_symlink():
            raise ValueError('Symbolic links are not allowed in the workspace')
    if not path.resolve().is_relative_to(root):
        raise ValueError('Path outside workspace')
    if regular and not path.is_file():
        raise FileNotFoundError('Artifact unavailable')
    return path


def _kill(process):
    if process is None:
        return
    try:
        if os.name == 'posix':
            # Frontends/compilers create independent sessions. Freeze the
            # worker, discover its Linux descendants and stop them before
            # killing all their groups. No uploaded program is involved.
            if sys.platform.startswith('linux') and process.poll() is None:
                os.kill(process.pid, signal.SIGSTOP)
                descendants = set()
                for _ in range(4):
                    parents = {}
                    for item in Path('/proc').iterdir():
                        if not item.name.isdecimal():
                            continue
                        try:
                            fields = (item / 'stat').read_text().rsplit(')', 1)[1].split()
                            parents[int(item.name)] = int(fields[1])
                        except (OSError, ValueError, IndexError):
                            continue
                    discovered = set()
                    pending = [process.pid]
                    while pending:
                        parent = pending.pop()
                        children = {pid for pid, ppid in parents.items()
                                    if ppid == parent and pid not in discovered}
                        discovered.update(children)
                        pending.extend(children)
                    new = discovered - descendants
                    for pid in new:
                        try:
                            os.kill(pid, signal.SIGSTOP)
                        except ProcessLookupError:
                            pass
                    descendants.update(new)
                    if not new:
                        break
                for pid in descendants:
                    try:
                        if os.getpgid(pid) == pid:
                            os.killpg(pid, signal.SIGKILL)
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except ProcessLookupError:
        pass


class _Manager:
    def __init__(self, workspace):
        self.workspace = workspace
        self.token = secrets.token_urlsafe(32)
        self.files, self.jobs, self.internal = {}, {}, {}
        self.lock = threading.RLock()
        self.slots = threading.Semaphore(2)
        self.closed = False
        self.workspace_lock = WorkspaceLock(workspace)
        try:
            for name in ('uploads', 'jobs'):
                path = _owned(workspace, workspace / name)
                path.mkdir(mode=0o700, exist_ok=True)
            self.store = SessionStore(workspace)
            restored, skipped = self.store.restore()
            self.history = {'restored': len(restored), 'skipped': skipped, 'warning': bool(skipped)}
            for job in restored:
                job_id = job['id']
                inventory = job.pop('inventory', None)
                self.jobs[job_id] = job
                self.internal[job_id] = {'directory': self.store.directory(job_id),
                    'cancel': threading.Event(), 'process': None, 'thread': None, 'inventory': inventory}
        except Exception:
            self.workspace_lock.close()
            raise

    def snapshots(self):
        with self.lock:
            return [copy.deepcopy(job) for job in reversed(list(self.jobs.values()))]

    def snapshot(self, job_id):
        with self.lock:
            if job_id not in self.jobs:
                raise FileNotFoundError('Job not found')
            return copy.deepcopy(self.jobs[job_id])

    def update(self, job_id, **values):
        with self.lock:
            if values.get('status') == 'SUCCEEDED':
                self.internal[job_id]['inventory'] = self.store.seal(self.jobs[job_id])
            self.jobs[job_id].update(values, updated_at=_now())
            if 'status' in values:
                self._checkpoint(job_id)

    def _checkpoint(self, job_id):
        """Persist state transitions, never reader messages or request payloads."""
        try:
            self.store.checkpoint(self.jobs[job_id], self.internal[job_id].get('inventory'))
            return True
        except (OSError, ValueError, OverflowError):
            self.jobs[job_id]['history_warning'] = 'History checkpoint unavailable; this job may not survive a restart'
            self.history['warning'] = True
            return False

    def validate(self, value):
        from gamedecomp.cli import LLM_PROVIDERS
        from gamedecomp.llm import LLMClient
        if not isinstance(value, dict):
            raise ValueError('Invalid job request')
        kind = value.get('kind')
        if kind not in ('analyze', 'demo', 'gnn_demo', 'train_gnn', 'translate'):
            raise ValueError('Invalid job type')
        raw = value.get('options', {})
        if not isinstance(raw, dict):
            raise ValueError('Invalid options')
        # Deliberate allowlist: paths, compiler commands and env names cannot
        # enter this API. Uploaded file IDs are resolved by the supervisor.
        options = {'backend': raw.get('backend', 'auto'),
                   'console_profile': raw.get('console_profile'),
                   'workers': _integer(raw.get('workers', 4), 'workers', 1, 64),
                   'timeout': _number(raw.get('timeout', 300 if kind in ('analyze', 'demo') else 600), 'timeout', 1, 86400),
                   'phase_timeout': _number(raw.get('phase_timeout', 30), 'phase_timeout', .1, 3600),
                   'recover_types': raw.get('recover_types', True),
                   'max_types': _integer(raw.get('max_types', 20000), 'max_types', 1, 100000)}
        options['llm_context_bytes'] = _integer(raw.get('llm_context_bytes', 196608), 'llm_context_bytes', 16384, 1048576)
        if options['backend'] not in ('auto', 'native', 'wasm', 'ghidra', 'ilspy'):
            raise ValueError('Invalid backend')
        from gamedecomp.console_support import CONSOLE_PROFILES, FORMAT_PROFILES
        if options['console_profile'] is not None and options['console_profile'] not in CONSOLE_PROFILES:
            raise ValueError('Invalid console loader profile')
        if not isinstance(options['recover_types'], bool):
            raise ValueError('recover_types must be a boolean')
        pattern = raw.get('function_pattern')
        if pattern is not None:
            if not isinstance(pattern, str) or len(pattern) > 256:
                raise ValueError('Invalid function filter')
            options['function_pattern'] = pattern or None
        payload = {'kind': kind, 'options': options}
        if kind in ('analyze', 'train_gnn'):
            record = self.files.get(value.get('file_id', ''))
            if not record or record['kind'] != ('binary' if kind == 'analyze' else 'dataset'):
                raise ValueError('Invalid uploaded file ID for this job')
            payload['source'] = str(_owned(self.workspace, record['path'], regular=True))
            if kind == 'analyze':
                expected_profile = FORMAT_PROFILES.get(record['info'].get('format'))
                if options['console_profile'] != expected_profile:
                    raise ValueError('Choose the matching console profile, or generic executable analysis for ELF/PE/WASM')
                if expected_profile and options['backend'] not in ('auto', 'ghidra'):
                    raise ValueError('Console modules require the automatic or Ghidra backend')
        model_id = raw.get('model_file_id')
        if model_id:
            record = self.files.get(model_id)
            if not record or record['kind'] != 'model':
                raise ValueError('Invalid model ID')
            options['gnn_model'] = str(_owned(self.workspace, record['path'], regular=True))
        elif raw.get('gnn_model') == 'builtin':
            model = Path(__file__).parent / 'data' / 'gnn_family.json'
            if not model.is_file():
                raise ValueError('Bundled GNN model unavailable')
            options['gnn_model'] = str(model)
        elif raw.get('gnn_model') is not None:
            raise ValueError('Invalid GNN model selection')
        llm = raw.get('llm', {})
        if not isinstance(llm, dict):
            raise ValueError('Invalid AI configuration')
        provider = llm.get('provider', 'off')
        if provider != 'off':
            if provider not in (*LLM_PROVIDERS, 'custom'):
                raise ValueError('Invalid AI provider')
            from gamedecomp.model_catalog import resolve_connection, resolve_api_format
            endpoint, key = resolve_connection(llm)
            api_format = resolve_api_format(llm)
            if not isinstance(endpoint, str) or len(endpoint) > 2048:
                raise ValueError('Invalid AI endpoint')
            model = llm.get('model')
            if not isinstance(model, str) or not model.strip() or len(model) > 256:
                raise ValueError('AI model required')
            if key is not None and (not isinstance(key, str) or len(key) > 4096 or '\n' in key or '\r' in key):
                raise ValueError('Invalid AI key')
            if provider in ('deepseek', 'openai', 'anthropic') and not key:
                raise ValueError('API key required for this provider')
            if key and (key in endpoint or key in model):
                raise ValueError('The key cannot appear in the model name or endpoint')
            # The client's constructor validates transport/endpoint locally.
            json_mode, temperature = llm.get('json_mode', 'object'), llm.get('temperature')
            reasoning_effort = llm.get('reasoning_effort')
            max_output_tokens = llm.get('max_output_tokens')
            LLMClient(endpoint, model, api_key=key, timeout=options['phase_timeout'],
                      json_mode=json_mode, temperature=temperature, reasoning_effort=reasoning_effort,
                      max_output_tokens=max_output_tokens, api_format=api_format)
            options['llm'] = {'url': endpoint, 'model': model, 'key': key,
                              'api_format': api_format,
                              'json_mode': json_mode, 'temperature': temperature,
                              'reasoning_effort':reasoning_effort,'max_output_tokens':max_output_tokens}
        if kind in ('gnn_demo', 'train_gnn'):
            payload['epochs'] = _integer(value.get('epochs', 120), 'epochs', 1, 10000)
            payload['seed'] = _integer(value.get('seed', 17), 'seed', 0, 2**31-1)
            if kind == 'gnn_demo':
                payload['samples'] = _integer(value.get('samples', 12), 'samples', 3, 256)
        if kind == 'translate':
            source_job_id = value.get('source_job_id')
            if not isinstance(source_job_id, str) or not _ID.fullmatch(source_job_id):
                raise ValueError('Invalid translation source job')
            source_job = self.snapshot(source_job_id)
            if source_job['status'] != 'SUCCEEDED' or source_job['kind'] not in ('analyze', 'demo'):
                raise ValueError('Translation requires a completed analysis')
            function_id = value.get('function_id')
            if not isinstance(function_id, str) or not function_id.strip() or len(function_id) > 512 or any(ord(char) < 32 for char in function_id):
                raise ValueError('Invalid translation function identity')
            if value.get('target_language') not in ('cpp', 'java') or value.get('source_kind') not in ('baseline', 'candidate'):
                raise ValueError('Invalid translation target or source')
            if not options.get('llm'):
                raise ValueError('Translation requires an LLM provider')
            payload.update(source=str(self.artifact(source_job_id)), source_job_id=source_job_id, function_id=function_id,
                           target_language=value['target_language'], source_kind=value['source_kind'])
        if kind not in ('analyze', 'translate'):
            # AI settings are meaningful only for uploaded binary analysis.
            options.pop('llm', None)
            options.pop('gnn_model', None)
        return payload

    def submit(self, value):
        with self.lock:
            if self.closed:
                raise RuntimeError('Server in chiusura')
            if sum(job['status'] not in _TERMINAL for job in self.jobs.values()) >= 18:
                raise OverflowError('Queue full: wait for a job or cancel one')
            if len(self.jobs) >= 1000:
                raise OverflowError('Session history limit reached')
            payload = self.validate(value)
            job_id = uuid.uuid4().hex
            directory = _owned(self.workspace, self.workspace / 'jobs' / job_id)
            directory.mkdir(mode=0o700)
            payload['directory'] = str(directory)
            job = {'id': job_id, 'kind': payload['kind'], 'status': 'QUEUED', 'phase': 'Queued',
                   'created_at': _now(), 'updated_at': _now(), 'logs': []}
            event = threading.Event()
            self.jobs[job_id] = job
            self.internal[job_id] = {'directory': directory, 'cancel': event, 'process': None, 'thread': None}
            if not self._checkpoint(job_id):
                job.update(status='FAILED', phase='History unavailable', error='Unable to save queued job; no worker was started')
                return copy.deepcopy(job)
            thread = threading.Thread(target=self._execute, args=(job_id, payload), daemon=True)
            self.internal[job_id]['thread'] = thread
            thread.start()
            return copy.deepcopy(job)

    def _execute(self, job_id, payload):
        state = self.internal[job_id]
        event = state['cancel']
        acquired = False
        while not event.is_set():
            acquired = self.slots.acquire(timeout=.1)
            if acquired:
                break
        if event.is_set():
            self.update(job_id, status='CANCELLED', phase='Cancelled')
            if acquired:
                self.slots.release()
            return
        process = None
        completed = None
        secret = payload.get('options', {}).get('llm', {}).get('key')
        def clean(text):
            return text.replace(secret, '[REDACTED]') if secret else text
        try:
            self.update(job_id, status='RUNNING', phase='Starting worker')
            command = [sys.executable, '-B', '-m', 'gamedecomp.ui_worker']
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=os.name == 'posix')
            with self.lock:
                state['process'] = process
            encoded = json.dumps(payload, allow_nan=False).encode()
            process.stdin.write(encoded)
            process.stdin.close()
            deadline = time.monotonic() + payload['options']['timeout'] + 30
            payload.clear()
            def reader():
                for raw in iter(lambda: process.stdout.readline(65537), b''):
                    line = clean(raw.decode('utf-8', 'replace').strip())[:32768]
                    if not line:
                        continue
                    try:
                        update = _json(line)
                    except (ValueError, UnicodeError):
                        update = {}
                    with self.lock:
                        if isinstance(update, dict) and isinstance(update.get('phase'), str):
                            self.jobs[job_id]['phase'] = update['phase'][:256]
                        if isinstance(update, dict) and 'progress' in update:
                            from gamedecomp.progress import normalize_progress
                            progress = normalize_progress(update['progress'])
                            if progress is not None:
                                self.jobs[job_id]['progress'] = progress
                        if isinstance(update, dict) and isinstance(update.get('error'), str):
                            self.jobs[job_id]['error'] = update['error'][:4096]
                        logs = self.jobs[job_id]['logs']
                        logs.append(line[:4096])
                        del logs[:-100]
                        self.jobs[job_id]['updated_at'] = _now()
            reader_thread = threading.Thread(target=reader, daemon=True)
            reader_thread.start()
            timed_out = False
            while process.poll() is None:
                if event.wait(.1) or time.monotonic() > deadline:
                    timed_out = not event.is_set()
                    _kill(process)
                    break
            process.wait(timeout=5)
            # Compilers/frontends should not outlive their owning worker.
            _kill(process)
            reader_thread.join(2)
            if event.is_set():
                self.update(job_id, status='CANCELLED', phase='Cancelled')
            elif timed_out:
                self.update(job_id, status='FAILED', phase='Timed out', error='Job time budget exhausted')
            elif process.returncode != 0:
                self.update(job_id, status='FAILED', phase='Error',
                            error=self.jobs[job_id].get('error', f'Worker exited with code {process.returncode}'))
            else:
                result_path = _owned(self.workspace, state['directory'] / 'result.json', regular=True)
                if result_path.stat().st_size > 16 * 1024**2:
                    raise ValueError('Result too large')
                raw = clean(result_path.read_text(encoding='utf-8'))
                result = _json(raw)
                if secret:
                    result_path.write_text(raw, encoding='utf-8')
                    self._redact_artifacts(state['directory'], secret)
                completed = result
        except Exception as error:
            _kill(process)
            self.update(job_id, status='CANCELLED' if event.is_set() else 'FAILED', phase='Error',
                        error=clean(str(error))[:4096] or type(error).__name__)
        finally:
            if process:
                for stream in (process.stdout, process.stdin):
                    if stream:
                        stream.close()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _kill(process)
            if secret:
                try:
                    self._redact_artifacts(state['directory'], secret)
                except (OSError, ValueError, OverflowError):
                    # These artifacts are not served after a failed job.
                    self.update(job_id, status='FAILED', phase='Error', error='Artifact cleanup failed')
            with self.lock:
                state['process'] = None
            if completed is not None and self.jobs[job_id]['status'] == 'RUNNING':
                try:
                    self.update(job_id, status='SUCCEEDED', phase='Completed', result=completed,
                                report_url=f'/api/jobs/{job_id}/report', export_url=f'/api/jobs/{job_id}/export')
                except (OSError, ValueError, OverflowError):
                    self.update(job_id, status='FAILED', phase='Artifact validation failed',
                                error='Unable to seal completed artifacts')
            self.slots.release()

    def _redact_artifacts(self, directory, secret):
        """Providers may echo a credential in text; never publish that echo."""
        for path in directory.rglob('*'):
            path = _owned(self.workspace, path)
            if not path.is_file() or path.suffix not in ('.json', '.html', '.c', '.cpp', '.java', '.cs', '.hpp', '.asm', '.txt'):
                continue
            if path.stat().st_size > 64 * 1024**2:
                raise OverflowError('Text artifact exceeds the 64 MiB limit')
            raw = path.read_text(encoding='utf-8', errors='strict')
            if secret in raw:
                path.write_text(raw.replace(secret, '[REDACTED]'), encoding='utf-8')

    def cancel(self, job_id):
        with self.lock:
            job = self.snapshot(job_id)
            if job['status'] not in _TERMINAL:
                state = self.internal[job_id]
                state['cancel'].set()
                _kill(state['process'])
                if job['status'] == 'QUEUED':
                    self.update(job_id, status='CANCELLED', phase='Cancelled')
            return self.snapshot(job_id)

    def artifact(self, job_id, html=False):
        job = self.snapshot(job_id)
        if job['status'] != 'SUCCEEDED':
            raise FileNotFoundError('Results not yet available')
        directory = self.internal[job_id]['directory']
        self.store.verify(job, self.internal[job_id].get('inventory'))
        if job['kind'] in ('train_gnn', 'gnn_demo'):
            if html:
                raise FileNotFoundError('HTML report unavailable for training')
            path = directory / 'model' / 'metrics.json'
        else:
            path = directory / 'results'
            if job['kind'] == 'demo':
                path /= 'analysis'
            path /= 'report.html' if html else 'report.json'
        return _owned(self.workspace, path, regular=True)

    def archive(self, job_id):
        job = self.snapshot(job_id)
        if job['status'] != 'SUCCEEDED':
            raise FileNotFoundError('Results not yet available')
        directory = self.internal[job_id]['directory']
        self.store.verify(job, self.internal[job_id].get('inventory'))
        root = directory / ('model' if job['kind'] in ('train_gnn', 'gnn_demo') else 'results')
        root = _owned(self.workspace, root)
        total, count = 0, 0
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(root.rglob('*')):
                path = _owned(self.workspace, path)
                if not path.is_file():
                    continue
                count += 1
                total += path.stat().st_size
                if count > 10000 or total > 128 * 1024**2:
                    raise OverflowError('Export exceeds 128 MiB or 10000 files')
                archive.write(path, str(path.relative_to(root)))
        return output.getvalue()

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            threads = []
            for state in self.internal.values():
                state['cancel'].set()
                _kill(state['process'])
                if state.get('thread') is not None:
                    threads.append(state['thread'])
        for thread in threads:
            thread.join(6)
        if any(thread.is_alive() for thread in threads):
            # Retain the lock until all supervisors have stopped writing.
            def release_when_stopped():
                for thread in threads:
                    thread.join()
                self.workspace_lock.close()
            threading.Thread(target=release_when_stopped, daemon=True).start()
        else:
            self.workspace_lock.close()


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, handler, manager):
        self.manager = manager
        super().__init__(address, handler)

    def server_close(self):
        self.manager.close()
        super().server_close()


class _Handler(BaseHTTPRequestHandler):
    server_version = 'GameDecompStudio'
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        # Request queries and external-provider messages can contain secrets.
        pass

    def _send(self, status, body, content_type='application/json; charset=utf-8'):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False, allow_nan=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        styles = "'self'"
        if content_type.startswith('text/html'):
            for style in re.findall(rb'<style[^>]*>(.*?)</style>', body, re.DOTALL | re.IGNORECASE):
                digest = base64.b64encode(hashlib.sha256(style).digest()).decode('ascii')
                styles += f" 'sha256-{digest}'"
        self.send_header('Content-Security-Policy', f"default-src 'self'; script-src 'self'; style-src {styles}; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def _guard(self, post=False):
        expected = self.server.server_address[1]
        parsed = urlsplit('http://' + self.headers.get('Host', ''))
        try:
            host_valid = parsed.hostname in ('localhost', '127.0.0.1') and parsed.port == expected
        except ValueError:
            host_valid = False
        if not host_valid or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            raise PermissionError('Invalid local host')
        origin = self.headers.get('Origin')
        if origin:
            source = urlsplit(origin)
            try:
                valid = source.scheme == 'http' and source.hostname == parsed.hostname and source.port == expected
            except ValueError:
                valid = False
            if not valid or source.username or source.password or source.path not in ('', '/') or source.query or source.fragment:
                raise PermissionError('Origin not allowed')
        if post:
            token = self.headers.get('X-GameDecomp-Token', '')
            if not hmac.compare_digest(token, self.server.manager.token):
                raise PermissionError('Invalid local token')

    def do_GET(self):
        self._dispatch(False)

    def do_POST(self):
        self._dispatch(True)

    def _dispatch(self, post):
        try:
            self.connection.settimeout(15)
            self._guard(post)
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc:
                raise ValueError('Relative request required')
            path = unquote(parsed.path)
            if post:
                self._post(path, parse_qs(parsed.query))
            else:
                self._get(path)
        except PermissionError as error:
            self._send(403, {'error': str(error)})
        except FileNotFoundError as error:
            self._send(404, {'error': str(error)})
        except OverflowError as error:
            self._send(413, {'error': str(error)})
        except (ValueError, TypeError, UnicodeError, RecursionError) as error:
            # Do not echo JSON/provider configuration into responses.
            self._send(400, {'error': 'Invalid request: ' + (str(error)[:256] if not isinstance(error, json.JSONDecodeError) else 'Invalid JSON')})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._send(500, {'error': 'Local operation failed'})

    def _read(self, maximum):
        if self.headers.get('Transfer-Encoding'):
            raise ValueError('Chunked uploads are not supported')
        value = self.headers.get('Content-Length', '')
        if not value.isdecimal():
            raise ValueError('Content-Length required')
        length = int(value)
        if length > maximum:
            raise OverflowError('Request body exceeds the limit')
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError('Truncated request body')
        return raw

    def _post(self, path, query):
        manager = self.server.manager
        if path == '/api/upload':
            kind = query.get('kind', ['binary'])[0]
            name = query.get('name', ['upload'])[0]
            if kind not in _LIMITS or not name or len(name) > 200 or '/' in name or '\\' in name or '\0' in name or name in ('.', '..'):
                raise ValueError('Invalid upload name or type')
            raw = self._read(_LIMITS[kind])
            file_id = uuid.uuid4().hex
            suffix = Path(name).suffix
            suffix = suffix if re.fullmatch(r'\.[a-zA-Z0-9]{1,12}', suffix) else ''
            destination = _owned(manager.workspace, manager.workspace / 'uploads' / (file_id + suffix))
            try:
                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(raw)
                if kind == 'binary':
                    from gamedecomp.console_support import CONSOLE_PROFILES
                    profile = query.get('profile', [''])[0] or None
                    if profile is not None and profile not in CONSOLE_PROFILES:
                        raise ValueError('Invalid console loader profile')
                    info = inspect_binary(destination, console_profile=profile)
                    info.pop('path', None)
                else:
                    value = _json(raw)
                    from gamedecomp.gnn import _validate_dataset, _validate_model
                    (_validate_model if kind == 'model' else _validate_dataset)(value)
                    info = {'format': 'JSON', 'kind': kind, 'sha256': hashlib.sha256(raw).hexdigest()}
                record = {'file_id': file_id, 'name': name, 'size': len(raw), 'kind': kind,
                          'info': info, 'path': destination}
                with manager.lock:
                    if len(manager.files) >= 1000:
                        raise OverflowError('Session upload limit reached')
                    manager.files[file_id] = record
                self._send(201, {key: record[key] for key in ('file_id', 'name', 'size', 'info')})
            except Exception:
                destination.unlink(missing_ok=True)
                raise
        elif path == '/api/jobs':
            self._send(202, {'job': manager.submit(_json(self._read(65536)))})
        elif path == '/api/llm/models':
            from gamedecomp.model_catalog import fetch_models
            self._send(200, fetch_models(_json(self._read(16384))))
        elif re.fullmatch(r'/api/jobs/[a-f0-9]{32}/cancel', path):
            self._read(65536)
            self._send(200, {'job': manager.cancel(path.split('/')[3])})
        else:
            raise FileNotFoundError('Resource not found')

    def _get(self, path):
        manager = self.server.manager
        if path == '/api/bootstrap':
            from gamedecomp.cli import LLM_PROVIDERS, doctor
            providers = [{'id': 'off', 'label': 'Disabled', 'url': None, 'key_env': None}]
            providers += [{'id': key, 'label': {'deepseek': 'DeepSeek', 'openai': 'OpenAI', 'anthropic': 'Anthropic · Claude', 'ollama': 'Ollama', 'lmstudio': 'LM Studio'}[key],
                           'url': endpoint, 'key_env': env, 'api_format': 'anthropic' if key == 'anthropic' else 'openai'} for key, (endpoint, env) in LLM_PROVIDERS.items()]
            providers.append({'id': 'custom', 'label': 'Custom endpoint', 'url': '', 'key_env': 'GAMEDECOMP_API_KEY'})
            from gamedecomp.readiness import readiness
            environment = doctor()
            self._send(200, {'token': manager.token, 'version': __version__, 'doctor': environment,
                             'readiness': readiness(environment),
                             'providers': providers, 'jobs': manager.snapshots(), 'history': dict(manager.history)})
        elif path == '/api/jobs':
            self._send(200, {'jobs': manager.snapshots()})
        elif re.fullmatch(r'/api/jobs/[a-f0-9]{32}/evidence', path):
            from gamedecomp.evidence_view import evidence_view
            query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if set(query) - {'offset', 'limit'} or any(len(value) != 1 for value in query.values()):
                raise ValueError('Invalid evidence page parameters')
            offset = int(query.get('offset', ['0'])[0])
            limit = int(query.get('limit', ['64'])[0])
            artifact = manager.artifact(path.split('/')[3], False)
            if artifact.stat().st_size > 64 * 1024**2:
                raise OverflowError('Report exceeds the 64 MiB limit')
            self._send(200, evidence_view(_json(artifact.read_text(encoding='utf-8')), offset=offset, limit=limit))
        elif re.fullmatch(r'/api/jobs/[a-f0-9]{32}(?:/(?:report(?:\.html)?|export))?', path):
            pieces = path.split('/')
            job_id = pieces[3]
            if len(pieces) == 4:
                self._send(200, {'job': manager.snapshot(job_id)})
            elif pieces[4] == 'export':
                self._send(200, manager.archive(job_id), 'application/zip')
            else:
                html = pieces[4].endswith('.html')
                artifact = manager.artifact(job_id, html)
                if artifact.stat().st_size > 64 * 1024**2:
                    raise OverflowError('Report exceeds the 64 MiB limit')
                self._send(200, artifact.read_bytes(), 'text/html; charset=utf-8' if html else 'application/json; charset=utf-8')
        elif path in ('/', '/index.html', '/app.js', '/app.css'):
            filename = 'index.html' if path == '/' else path[1:]
            asset = Path(__file__).parent / 'ui' / filename
            content_type = {'index.html': 'text/html', 'app.js': 'text/javascript', 'app.css': 'text/css'}[filename]
            self._send(200, asset.read_bytes(), content_type + '; charset=utf-8')
        elif path == '/favicon.ico':
            self._send(204, b'', 'image/x-icon')
        else:
            raise FileNotFoundError('Resource not found')


def create_server(workspace: Path, host='127.0.0.1', port=8765):
    """Create an unstarted local server; call server_close for job cleanup."""
    if host not in ('127.0.0.1', 'localhost'):
        raise ValueError('Studio accetta soltanto host loopback 127.0.0.1 o localhost')
    _integer(port, 'port', 0, 65535)
    workspace = Path(workspace).absolute()
    if any(path.is_symlink() for path in (workspace, *workspace.parents)):
        raise ValueError('Workspace cannot traverse symbolic links')
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    workspace = workspace.resolve()
    manager = _Manager(workspace)
    try:
        server = _Server((host, port), _Handler, manager)
    except Exception:
        manager.close()
        raise
    return server


def serve_gui(workspace: Path, host='127.0.0.1', port=8765, open_browser=True):
    """Run Studio until Ctrl+C. Binding exposes no remote listening socket."""
    server = create_server(workspace, host, port)
    url = f'http://{host}:{server.server_address[1]}/'
    print(f'GameDecomp Studio: {url}', flush=True)
    print(f'Workspace: {server.manager.workspace}', flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
