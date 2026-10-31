#!/usr/bin/env python3
"""Offline checks for the minimum Lilu runtime and pinned build API."""

import json
from pathlib import Path
import re
import subprocess
import sys
import unittest


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'tools'))
import build_unified_kernel as builder
import verify_lilu_release_compatibility as lilu_matrix


class LiluCompatibilityTests(unittest.TestCase):
    def test_runtime_minimum_and_reproducible_build_pin_are_separate(self):
        lock = json.loads((PROJECT / 'dependencies.lock.json').read_text())
        lilu = lock['Lilu']

        self.assertEqual(builder.LILU_RUNTIME_MINIMUM, '1.7.1')
        self.assertEqual(builder.LIBRARIES['as.vit9696.Lilu'], '1.7.1')
        self.assertEqual(builder.bundle_info()['OSBundleLibraries']['as.vit9696.Lilu'], '1.7.1')
        self.assertEqual(lilu['version'], '1.7.2')
        self.assertEqual(lilu['commit'], lilu_matrix.RELEASES['1.7.2']['commit'])
        self.assertEqual(lilu['repository'], 'https://github.com/acidanthera/Lilu.git')
        self.assertNotEqual(builder.LILU_RUNTIME_MINIMUM, lilu['version'])

    def test_official_matrix_uses_tahoe_capable_releases_and_small_assets(self):
        self.assertEqual(tuple(lilu_matrix.RELEASES), ('1.7.1', '1.7.2'))
        self.assertEqual(lilu_matrix.RELEASES['1.7.1']['commit'],
                         'dc01cb583295ceded4f42a6310a15e3abac1c025')
        self.assertEqual(lilu_matrix.RELEASES['1.7.2']['commit'],
                         'e4748cc081bf060302c7d3c44a643ce1d11b7e1d')
        self.assertTrue(all(item['asset_size'] < 1_000_000
                            for item in lilu_matrix.RELEASES.values()))
        self.assertEqual(lilu_matrix.RUNTIME_MINIMUM, '1.7.1')
        for symbol in ('routeMultipleLong', 'routeMultipleShort', 'solveSymbol',
                       'getError', 'clearError', 'requestAccess', 'releaseAccess',
                       'shouldLoad', 'onKextLoad', 'onPatcherLoad'):
            self.assertTrue(any(symbol in exported for exported in lilu_matrix.REQUIRED_EXPORTS))
        for token in ('sizeof(KernelPatcher::KextInfo) == 40',
                      'sizeof(PluginConfiguration) == 88',
                      'offsetof(PluginConfiguration, minKernel) == 72',
                      'offsetof(PluginConfiguration, maxKernel) == 76',
                      'offsetof(PluginConfiguration, pluginStart) == 80'):
            self.assertIn(token, lilu_matrix.PLUGIN_ABI_PROBE)

    def test_vendored_public_api_contract_when_dependencies_are_prepared(self):
        headers = PROJECT / 'vendor/LiluResources/Headers'
        if not headers.is_dir():
            self.skipTest('run tools/prepare_dependencies.py to inspect vendored Lilu headers')

        api = (headers / 'kern_api.hpp').read_text()
        patcher = (headers / 'kern_patcher.hpp').read_text()
        startup = (headers / 'plugin_start.hpp').read_text()
        kernel_versions = (headers / 'kern_util.hpp').read_text()

        for symbol in ('requestAccess', 'releaseAccess', 'shouldLoad', 'onKextLoad', 'onPatcherLoad'):
            with self.subTest(symbol=symbol):
                self.assertIn(symbol, api)
        for symbol in ('getError', 'clearError', 'solveSymbol', 'routeMultiple',
                       'routeMultipleLong', 'routeMultipleShort', 'struct KextInfo'):
            with self.subTest(symbol=symbol):
                self.assertIn(symbol, patcher)
        self.assertIn('CompatibilityVersion {parseModuleVersion("1.2.0")}', api)
        self.assertRegex(patcher, r'static_assert\(sizeof\(KextInfo\)\s*==')
        for name, value in (('Sonoma', 23), ('Sequoia', 24), ('Tahoe', 25)):
            self.assertRegex(kernel_versions, rf'\b{name}\s*=\s*{value}\b')

        config = re.search(r'struct PluginConfiguration\s*\{(.*?)\n\};', startup, re.S)
        self.assertIsNotNone(config)
        names = ('product', 'version', 'runmode', 'disableArg', 'disableArgNum',
                 'debugArg', 'debugArgNum', 'betaArg', 'betaArgNum', 'minKernel',
                 'maxKernel', 'pluginStart')
        positions = [config.group(1).index(name) for name in names]
        self.assertEqual(positions, sorted(positions))

    def test_production_kernel_identity_does_not_depend_on_lilu_machinfo_layout(self):
        forbidden = re.compile(
            r'MachInfo::(?:create|deleter|HeaderSize|setKernelWriting)'
            r'|sizeof\s*\(\s*MachInfo\s*\)'
            r'|(?:->|\.)\s*getRunning(?:Addresses|Position)\s*\('
        )
        for path in sorted((PROJECT / 'src').rglob('*')):
            if path.suffix not in ('.c', '.cc', '.cpp', '.h', '.hpp'):
                continue
            with self.subTest(path=path.relative_to(PROJECT)):
                self.assertNotRegex(path.read_text(), forbidden)

    def test_prepared_dependency_checkout_matches_immutable_lock_when_present(self):
        source = PROJECT / 'vendor/Lilu-source'
        if not source.is_dir():
            self.skipTest('Lilu source checkout is optional in public offline tests')
        lock = json.loads((PROJECT / 'dependencies.lock.json').read_text())
        result = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'],
                                check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), lock['Lilu']['commit'])


if __name__ == '__main__':
    unittest.main()
