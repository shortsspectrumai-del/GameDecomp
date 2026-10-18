"""The checkout launcher exposes local tools and preserves explicit settings."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class StudioLauncherTests(unittest.TestCase):
    def launch(self, overrides=None, *, local_tools=True):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);shutil.copyfile(ROOT/'start-studio.sh',root/'start-studio.sh')
            commands=root/'commands';commands.mkdir()
            python=commands/'python3'
            python.write_text('#!/bin/sh\nexec /usr/bin/python3 -c \'import os,json;print(json.dumps({k:os.environ.get(k) for k in ("PATH","DOTNET_ROOT","GHIDRA_HOME","JAVA_HOME")}))\'\n')
            python.chmod(0o755)
            if local_tools:
                for name in ('ghidra_12.1.4_PUBLIC/support/analyzeHeadless','jdk-21.0.12.1+1/bin/java','dotnet/dotnet','dotnet-tools/ilspycmd'):
                    p=root/'tools'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o755)
            env={k:v for k,v in os.environ.items() if k not in ('GHIDRA_HOME','JAVA_HOME','DOTNET_ROOT')}
            env['PATH']=str(commands)+':/usr/bin:/bin';env.update(overrides or {})
            result=subprocess.run(['bash',str(root/'start-studio.sh'),'--no-browser'],env=env,capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            return json.loads(result.stdout),str(root)

    def test_local_dotnet_and_ilspy_are_visible_to_studio_and_workers(self):
        env,root=self.launch()
        self.assertEqual(env['DOTNET_ROOT'],root+'/tools/dotnet')
        self.assertIn(root+'/tools/dotnet',env['PATH'].split(':'))
        self.assertIn(root+'/tools/dotnet-tools',env['PATH'].split(':'))
        self.assertEqual(env['GHIDRA_HOME'],root+'/tools/ghidra_12.1.4_PUBLIC')
        self.assertEqual(env['JAVA_HOME'],root+'/tools/jdk-21.0.12.1+1')

    def test_explicit_runtime_and_java_settings_are_preserved(self):
        explicit={'DOTNET_ROOT':'/selected/runtime','GHIDRA_HOME':'/selected/ghidra','JAVA_HOME':'/selected/java'}
        env,root=self.launch(explicit)
        for key,value in explicit.items():self.assertEqual(env[key],value)
        self.assertNotIn(root+'/tools/dotnet',env['PATH'].split(':'))

    def test_missing_local_tools_do_not_add_broken_paths(self):
        env,root=self.launch(local_tools=False)
        self.assertIsNone(env['DOTNET_ROOT']);self.assertIsNone(env['GHIDRA_HOME'])
        self.assertNotIn(root+'/tools/dotnet-tools',env['PATH'].split(':'))
