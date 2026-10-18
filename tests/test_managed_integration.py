"""Optional real ILSpy extraction and recompilation of an authored C# fixture."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(os.environ.get('GAMEDECOMP_TEST_DOTNET_HOME') and os.environ.get('GAMEDECOMP_TEST_ILSPY_HOME'),
                     'Optional local .NET SDK and ILSpy paths are required')
class ManagedIntegrationTests(unittest.TestCase):
    def test_compiled_managed_library_extracts_classes_and_recompiles_offline(self):
        from gamedecomp.pipeline import AnalysisConfig, run_analysis
        sdk=Path(os.environ['GAMEDECOMP_TEST_DOTNET_HOME']).resolve()
        ilspy=Path(os.environ['GAMEDECOMP_TEST_ILSPY_HOME']).resolve()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);original=root/'original';original.mkdir()
            configuration=root/'NuGet.Config'
            configuration.write_text('<configuration><packageSources><clear/></packageSources></configuration>')
            project='''<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>
<TargetFramework>net10.0</TargetFramework><GenerateAssemblyInfo>false</GenerateAssemblyInfo>
<GenerateTargetFrameworkAttribute>false</GenerateTargetFrameworkAttribute>
</PropertyGroup></Project>'''
            (original/'Fixture.csproj').write_text(project)
            (original/'Fixture.cs').write_text('''namespace ManagedGame;
public struct Position { public float X, Y, Z; }
public class Actor { public uint Health = 100; public virtual uint Tick(uint delta) => Health + delta; }
public sealed class Player : Actor {
    public Position Location;
    public void ApplyDamage(uint damage) { Health = damage >= Health ? 0 : Health - damage; }
    public override uint Tick(uint delta) => base.Tick(delta) + 1;
}
''')
            env=dict(os.environ, DOTNET_ROOT=str(sdk), DOTNET_CLI_HOME=str(root/'profile'),
                     NUGET_PACKAGES=str(root/'packages'), DOTNET_CLI_TELEMETRY_OPTOUT='1',
                     DOTNET_GENERATE_ASPNET_CERTIFICATE='false', DOTNET_NOLOGO='1',
                     PATH=str(sdk)+os.pathsep+str(ilspy)+os.pathsep+os.environ.get('PATH',''))
            def build(folder):
                for args in (['restore','--configfile',str(configuration)],['build','--no-restore','-c','Release','--nologo']):
                    result=subprocess.run([str(sdk/'dotnet'),*args],cwd=folder,env=env,
                                          capture_output=True,text=True,timeout=90)
                    self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)
            build(original)
            binary=original/'bin/Release/net10.0/Fixture.dll'
            with patch.dict(os.environ,env):
                report=run_analysis(binary,root/'analysis',AnalysisConfig(backend='ilspy',timeout=90,
                    phase_timeout=60,cache_path=root/'cache.sqlite'))
            self.assertEqual(report['backend'],'ilspy')
            self.assertTrue(report['functions'])
            sources='\n'.join(f['source'] or '' for f in report['functions'])
            for required in ('class Actor','class Player','struct Position','ApplyDamage','override'):
                self.assertIn(required,sources)
            self.assertTrue(all(f['metadata']['language']=='csharp' for f in report['functions']))
            self.assertTrue(all(f['semantic_status']=='UNKNOWN' for f in report['functions']))
            self.assertEqual(report['summary']['proved'],0)
            recovered=root/'recompiled';recovered.mkdir()
            (recovered/'Recompiled.csproj').write_text(project)
            for source in (root/'analysis/functions').glob('*.cs'):
                shutil.copyfile(source,recovered/source.name)
            build(recovered)
            self.assertTrue((recovered/'bin/Release/net10.0/Recompiled.dll').is_file())
