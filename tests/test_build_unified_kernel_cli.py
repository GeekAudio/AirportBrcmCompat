import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import build_unified_kernel as builder


def make_sdk(root):
    sdk = root / 'MacKernelSDK'
    (sdk / 'Headers').mkdir(parents=True)
    (sdk / 'Library/universal').mkdir(parents=True)
    (sdk / 'Library/universal/libkmod.a').touch()
    (sdk / 'Library/universal/libkmodc++.a').touch()
    return sdk


def make_lilu(root):
    resources = root / 'LiluResources'
    headers = resources / 'Headers'
    headers.mkdir(parents=True)
    for name in ('kern_api.hpp', 'kern_mach.hpp', 'kern_patcher.hpp', 'plugin_start.hpp'):
        (headers / name).touch()
    return resources


class BuildToolchainCLI(unittest.TestCase):
    def parse(self, *options):
        return builder.build_parser().parse_args(['--output', 'out.zip', *options])

    def test_explicit_dependency_options_override_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            explicit_sdk = make_sdk(root / 'explicit')
            explicit_lilu = make_lilu(root / 'explicit')
            env_sdk = make_sdk(root / 'environment')
            env_lilu = make_lilu(root / 'environment')
            args = self.parse('--mackernelsdk', str(explicit_sdk),
                              '--lilu-resources', str(explicit_lilu))

            sdk, lilu = builder.resolve_toolchain_paths(
                args, project=root / 'repo',
                environ={builder.SDK_ENV: str(env_sdk), builder.LILU_ENV: str(env_lilu)})

            self.assertEqual(sdk, explicit_sdk.resolve())
            self.assertEqual(lilu, explicit_lilu.resolve())

    def test_environment_and_repository_vendor_defaults(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env_sdk = make_sdk(root / 'environment')
            env_lilu = make_lilu(root / 'environment')
            args = self.parse()

            self.assertEqual(builder.resolve_toolchain_paths(
                args, project=root / 'repo',
                environ={builder.SDK_ENV: str(env_sdk), builder.LILU_ENV: str(env_lilu)}),
                (env_sdk.resolve(), env_lilu.resolve()))

            vendor_sdk = make_sdk(root / 'repo/vendor')
            vendor_lilu = make_lilu(root / 'repo/vendor')
            self.assertEqual(builder.resolve_toolchain_paths(
                args, project=root / 'repo', environ={}),
                (vendor_sdk.resolve(), vendor_lilu.resolve()))

    def test_incomplete_dependency_paths_fail_with_relative_missing_items(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk = root / 'MacKernelSDK'
            sdk.mkdir()
            lilu = root / 'LiluResources'
            lilu.mkdir(parents=True)
            args = self.parse('--mackernelsdk', str(sdk), '--lilu-resources', str(lilu))

            with self.assertRaisesRegex(ValueError, 'Library/universal/libkmod.a'):
                builder.resolve_toolchain_paths(args, project=root / 'repo', environ={})

    def test_help_exposes_both_external_dependency_options(self):
        help_text = builder.build_parser().format_help()
        self.assertIn('--mackernelsdk', help_text)
        self.assertIn('--lilu-resources', help_text)
        self.assertIn('--dual-profile-test-candidate', help_text)
        self.assertIn('--control-rx-windows', help_text)


if __name__ == '__main__':
    unittest.main()
