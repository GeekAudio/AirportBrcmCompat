"""Exercise compiler discovery through xcrun and command-name fallbacks."""
import importlib.util
import contextlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('brcm_test_runner',ROOT/'tools/run_tests.py')
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ToolchainTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='toolchain-fixture-')
        self.root=Path(self.temp.name)
        self.paths={}
        for tool in ('clang','clang++','nm','xcrun'):
            path=self.root/tool;path.write_text('#!/bin/sh\nexit 0\n');path.chmod(0o755)
            self.paths[tool]=str(path)

    def tearDown(self):self.temp.cleanup()

    def test_xcrun_success_aliases_exact_names_and_restores_environment(self):
        before=os.environ.get('PATH')
        def find(args,**kwargs):
            # Some xcrun installations return the clang driver for clang++.
            tool='clang' if args[-1]=='clang++' else args[-1]
            return subprocess.CompletedProcess(args,0,self.paths[tool]+'\n','')
        with mock.patch.object(runner.shutil,'which',side_effect=self.paths.get),mock.patch.object(runner.subprocess,'run',side_effect=find):
            with runner.ensure_macos_toolchain():
                alias=Path(os.environ['PATH'].split(os.pathsep)[0])
                self.assertIn(self.paths['clang'],(alias/'clang++').read_text())
                self.assertIn('--driver-mode=g++',(alias/'clang++').read_text())
                self.assertIn(self.paths['nm'],(alias/'nm').read_text())
            self.assertFalse(alias.exists())
        self.assertEqual(os.environ.get('PATH'),before)

    def test_forwarding_preserves_the_original_compiler_path(self):
        Path(self.paths['clang++']).write_text('#!/bin/sh\nprintf "%s" "$0"\n')
        with mock.patch.object(runner.shutil,'which',side_effect=lambda name:None if name=='xcrun' else self.paths.get(name)):
            with runner.ensure_macos_toolchain():
                result=subprocess.run(['clang++'],check=True,capture_output=True,text=True)
                self.assertEqual(result.stdout,self.paths['clang++'])

    def test_failed_xcrun_uses_path_and_restores_after_test_failure(self):
        before=os.environ.get('PATH')
        failure=subprocess.CompletedProcess([],1,'','unavailable')
        with mock.patch.object(runner.shutil,'which',side_effect=self.paths.get),mock.patch.object(runner.subprocess,'run',return_value=failure):
            with self.assertRaisesRegex(ValueError,'test failure'):
                with runner.ensure_macos_toolchain() as tools:
                    self.assertEqual(tools['clang++'],self.paths['clang++'])
                    raise ValueError('test failure')
        self.assertEqual(os.environ.get('PATH'),before)

    def test_missing_required_tools_is_an_error(self):
        with mock.patch.object(runner.shutil,'which',return_value=None),mock.patch.object(runner,'_executable',return_value=False):
            with self.assertRaisesRegex(RuntimeError,'Could not locate clang'):
                with runner.ensure_macos_toolchain():pass

    def test_required_mode_rejects_an_otherwise_successful_skipped_suite(self):
        result=types.SimpleNamespace(skipped=[('external','missing fixture')],wasSuccessful=lambda:True)
        with mock.patch.object(runner,'SUITES',{'scan':('fixture',)}),mock.patch.object(
            runner,'ensure_macos_toolchain',return_value=contextlib.nullcontext()),mock.patch.object(
            runner,'load_module',return_value=types.ModuleType('fixture')),mock.patch.object(
            runner.unittest,'TextTestRunner') as text_runner,contextlib.redirect_stderr(io.StringIO()):
            text_runner.return_value.run.return_value=result
            self.assertEqual(runner.main(['--require-all']),1)
            self.assertEqual(runner.main([]),0)

    def test_clang_driver_fallback_compiles_and_links_cpp(self):
        clang=shutil.which('clang');nm=shutil.which('nm')
        if not clang or not nm:self.skipTest('real clang/nm are required')
        executable=runner._executable
        with mock.patch.object(runner.shutil,'which',side_effect={'clang':clang,'nm':nm}.get),mock.patch.object(
            runner,'_executable',side_effect=lambda path:False if path=='/usr/bin/clang++' else executable(path)):
            with runner.ensure_macos_toolchain() as tools:
                self.assertEqual(tools['clang++'],str(Path(clang).absolute()))
                binary=self.root/'cpp'
                subprocess.run(['clang++','-x','c++','-std=c++14','-','-o',str(binary)],
                               input='#include <vector>\nint main(){std::vector<int> v(3);return v.size()!=3;}\n',
                               text=True,check=True,capture_output=True)
                subprocess.run([str(binary)],check=True)


if __name__=='__main__':unittest.main()
