"""The local benchmark credential form never exposes submitted credentials."""
import json
import io
from pathlib import Path
import tempfile
import threading
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

import psutil


class LiveQualityFormTests(unittest.TestCase):
    def alive(self, pid):
        try:
            process = psutil.Process(pid)
            return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return False

    def detached_child(self, pid_file, *, fail_communicate=False, timeout=False):
        original = subprocess.Popen
        processes = []
        script = ('import subprocess,sys,time; from pathlib import Path; '
            'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"],'
            'start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); '
            'Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(30)')
        def spawn(command, **options):
            process = original([sys.executable, '-c', script, str(pid_file)], **options)
            processes.append(process)
            deadline = time.monotonic()+3
            while not pid_file.exists() and time.monotonic()<deadline:
                time.sleep(.01)
            self.assertTrue(pid_file.exists(), 'Detached fixture child did not start')
            communicate = process.communicate
            first = True
            def respond(*args, **kwargs):
                nonlocal first
                if fail_communicate:
                    raise RuntimeError('Locally authored fixture communication failure')
                if timeout and first:
                    first = False
                    raise subprocess.TimeoutExpired(command, 1)
                return communicate(*args, **kwargs)
            process.communicate = respond
            return process
        def cleanup():
            if pid_file.exists():
                try:
                    psutil.Process(int(pid_file.read_text())).kill()
                except psutil.NoSuchProcess:
                    pass
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
                for pipe in (process.stdin, process.stdout):
                    if pipe is not None:
                        pipe.close()
        self.addCleanup(cleanup)
        return spawn, processes

    def test_close_stops_a_descendant_in_a_separate_session(self):
        from scripts.live_quality_check import Control, _launch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spawn, processes = self.detached_child(root/'child.pid')
            control = Control()
            control.state = 'RUNNING'
            with patch('scripts.live_quality_check.subprocess.Popen', side_effect=spawn):
                thread = threading.Thread(target=_launch, args=(
                    {'plan':'p', 'previous':'v', 'ghidra_home':'g'}, 'private-fixture-key', 'auto',
                    root/'live', control))
                thread.start()
                deadline = time.monotonic()+3
                while control.process is None and time.monotonic()<deadline:
                    time.sleep(.01)
                self.assertIsNotNone(control.process)
                child_pid = int((root/'child.pid').read_text())
                control.close()
                thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertFalse(self.alive(child_pid), 'Detached descendant survived cancellation')
                self.assertIsNotNone(processes[0].poll())
                control.close()

    def test_timeout_stops_detached_descendants(self):
        from scripts.live_quality_check import Control, _launch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spawn, processes = self.detached_child(root/'child.pid', timeout=True)
            control = Control()
            control.state = 'RUNNING'
            with patch('scripts.live_quality_check.subprocess.Popen', side_effect=spawn):
                _launch({'plan':'p', 'previous':'v', 'ghidra_home':'g'}, 'private-fixture-key',
                        'auto', root/'live', control)
            self.assertFalse(self.alive(int((root/'child.pid').read_text())))
            self.assertIsNotNone(processes[0].poll())
            self.assertEqual(control.status(), {'state':'FAILED', 'error_type':'TimeoutError'})

    def test_communication_failure_cleans_up_worker_and_detached_descendants(self):
        from scripts.live_quality_check import Control, _launch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spawn, processes = self.detached_child(root/'child.pid', fail_communicate=True)
            control = Control()
            control.state = 'RUNNING'
            with patch('scripts.live_quality_check.subprocess.Popen', side_effect=spawn):
                _launch({'plan':'p', 'previous':'v', 'ghidra_home':'g'}, 'private-fixture-key',
                        'auto', root/'live', control)
            self.assertFalse(self.alive(int((root/'child.pid').read_text())))
            self.assertIsNotNone(processes[0].poll())
            self.assertEqual(control.status()['state'], 'FAILED')

    def test_missing_process_dependency_fails_before_form_opens(self):
        from scripts.live_quality_check import create_server
        with patch.dict(sys.modules, {'psutil': None}), \
             patch('scripts.live_quality_check.ThreadingHTTPServer') as server:
            with self.assertRaisesRegex(RuntimeError, 'psutil'):
                create_server({}, {'targets':[]}, Path('unused'))
            server.assert_not_called()

    def test_missing_process_dependency_fails_before_worker_benchmark(self):
        from scripts.live_quality_check import main
        arguments = ['live_quality_check.py', '--worker', '--plan', 'p', '--previous', 'v',
                     '--output', '/tmp/nonexistent-utility-dependency-fixture', '--ghidra-home', 'g']
        stream = io.TextIOWrapper(io.BytesIO(b'{"key":"private-fixture-key","model":"auto"}'))
        with patch.dict(sys.modules, {'psutil': None}), patch.object(sys, 'argv', arguments), \
             patch.object(sys, 'stdin', stream), patch('benchmarks.repair_llm.run') as benchmark:
            with self.assertRaisesRegex(RuntimeError, 'psutil'):
                main()
            benchmark.assert_not_called()

    def test_child_stdin_key_is_redacted_before_the_log_is_written(self):
        from scripts.live_quality_check import Control, _launch
        key = 'private-fixture-key-never-log'
        original = subprocess.Popen
        def child(command, **options):
            self.assertNotIn(key, repr(command))
            return original([sys.executable, '-c',
                'import json,sys; data=json.load(sys.stdin); print(data["key"])'], **options)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'live'
            control = Control()
            control.state = 'RUNNING'
            with patch('scripts.live_quality_check.subprocess.Popen', side_effect=child):
                _launch({'plan':'p', 'previous':'v', 'ghidra_home':'g'}, key, 'auto', output, control)
            self.assertEqual(control.status()['state'], 'SUCCEEDED')
            self.assertNotIn(key, output.with_suffix('.log').read_text())
            self.assertIn('[REDACTED]', output.with_suffix('.log').read_text())

    def test_close_stops_the_owned_child_process(self):
        from scripts.live_quality_check import Control, _launch
        original = subprocess.Popen
        def child(command, **options):
            return original([sys.executable, '-c', 'import time; time.sleep(30)'], **options)
        with tempfile.TemporaryDirectory() as directory:
            control = Control()
            control.state = 'RUNNING'
            with patch('scripts.live_quality_check.subprocess.Popen', side_effect=child):
                thread = threading.Thread(target=_launch, args=(
                    {'plan':'p', 'previous':'v', 'ghidra_home':'g'}, 'private-fixture-key', 'auto',
                    Path(directory)/'live', control))
                thread.start()
                deadline = time.monotonic()+3
                while control.process is None and time.monotonic()<deadline:
                    time.sleep(.01)
                process = control.process
                self.assertIsNotNone(process)
                control.close()
                thread.join(3)
                self.assertFalse(thread.is_alive())
                self.assertIsNotNone(process.poll())

    def test_origin_token_guards_and_key_free_status(self):
        from scripts.live_quality_check import create_server
        with tempfile.TemporaryDirectory() as directory:
            server = create_server({}, {'targets': [{'variant': 'fixture', 'function': 'fn'}]}, Path(directory))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = 'http://127.0.0.1:' + str(server.server_port)
            try:
                with urllib.request.urlopen(base) as response:
                    page = response.read().decode()
                    self.assertIn('type="password"', page)
                    self.assertIn('no-store', response.headers['Cache-Control'])
                key = 'private-fixture-key-never-log'
                body = json.dumps({'key': key, 'model': 'auto'}).encode()
                for headers in ({}, {'Origin': base, 'X-Session-Token': 'wrong'},
                                {'Origin': 'https://untrusted.test', 'X-Session-Token': server.control.token}):
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        urllib.request.urlopen(urllib.request.Request(base+'/run', data=body, headers=headers))
                    self.assertEqual(raised.exception.code, 403)
                def launch(config, secret, model, output, control):
                    control.finish('SUCCEEDED')
                with patch('scripts.live_quality_check._launch', launch):
                    headers = {'Origin': base, 'X-Session-Token': server.control.token, 'Content-Type': 'application/json'}
                    with urllib.request.urlopen(urllib.request.Request(base+'/run', data=body, headers=headers)) as response:
                        self.assertEqual(response.status, 202)
                with urllib.request.urlopen(base+'/status') as response:
                    status = response.read().decode()
                self.assertNotIn(key, status)
                self.assertNotIn(key, page)
            finally:
                server.shutdown(); server.server_close(); thread.join(3)
