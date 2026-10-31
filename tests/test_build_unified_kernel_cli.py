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
    def setUp(self):
        builder.VERSION = '1.1.0'

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
        self.assertIn('--automatic-compatibility', help_text)
        self.assertNotIn('--dual-profile-test-candidate', help_text)
        self.assertNotIn('--baseline-25g332', help_text)
        self.assertNotIn('--hotspot-scan-compat', help_text)
        self.assertNotIn('--sae-compat', help_text)
        self.assertNotIn('--test-candidate', help_text)
        self.assertNotIn('--event-pipe-test-candidate', help_text)
        self.assertNotIn('--release-version', help_text)
        self.assertIn('--baseline-trace', help_text)
        self.assertIn('--control-rx-windows', help_text)

    def test_unqualified_build_defaults_to_automatic_candidate(self):
        args = self.parse()
        mode = builder.configure_build_mode(args)

        self.assertEqual(mode, {'mode': 'automatic-compatibility', 'version': '1.1.0',
                                'ready_for_install': False})
        self.assertTrue(args.automatic_compatibility)
        self.assertTrue(args.event_pipe_routes_review)
        self.assertTrue(args.event_pipe_components_review)
        defines = builder.compatibility_compile_defines(args)
        self.assertIn('-DAIRPORT_BRCM_SCAN_MULTIPLE=1', defines)
        self.assertIn('-DAIRPORT_BRCM_SAE_COMPAT=1', defines)
        self.assertFalse(any('PROFILE' in define or '25G' in define for define in defines))

    def test_automatic_candidate_includes_full_wifi_compatibility_and_optional_debug_features(self):
        args = self.parse('--automatic-compatibility', '--build-flavor', 'DEBUG',
                          '--baseline-trace', '--control-rx-windows')
        mode = builder.configure_build_mode(args)

        self.assertEqual(mode['version'], '1.1.0')
        self.assertFalse(mode['ready_for_install'])
        self.assertEqual(args.build_flavor, 'DEBUG')
        self.assertTrue(args.event_pipe_routes_review)
        self.assertTrue(args.baseline_trace)
        self.assertTrue(args.control_rx_windows)
        self.assertEqual(builder.compatibility_compile_defines(args), [
            '-DAIRPORT_BRCM_SCAN_MULTIPLE=1', '-DAIRPORT_BRCM_SAE_COMPAT=1',
            '-DAIRPORT_BRCM_BASELINE_TRACE=1', '-DAIRPORT_BRCM_BASELINE_WINDOW=1'])

    def test_control_windows_require_baseline_trace(self):
        args = self.parse('--automatic-compatibility', '--control-rx-windows')
        with self.assertRaisesRegex(ValueError, 'require --baseline-trace'):
            builder.configure_build_mode(args)

    def test_diagnostics_require_automatic_candidate(self):
        args = self.parse('--baseline-trace')
        with self.assertRaisesRegex(ValueError, 'require --automatic-compatibility'):
            builder.configure_build_mode(args)

    def test_automatic_candidate_conflicts_with_review_modes(self):
        for options in (('--automatic-compatibility', '--event-pipe-components-review'),
                        ('--automatic-compatibility', '--event-pipe-routes-review')):
            with self.subTest(options=options):
                with self.assertRaisesRegex(ValueError, 'standalone candidate mode'):
                    builder.configure_build_mode(self.parse(*options))

    def test_component_review_modes_keep_current_version_without_install_claims(self):
        components = builder.configure_build_mode(self.parse('--event-pipe-components-review'))
        self.assertEqual(components['mode'], 'component-review')
        self.assertEqual(components['version'], '1.1.0')
        self.assertFalse(components['ready_for_install'])

        routes = builder.configure_build_mode(self.parse('--event-pipe-routes-review'))
        self.assertEqual(routes['mode'], 'component-review')
        self.assertEqual(routes['version'], '1.1.0')
        self.assertFalse(routes['ready_for_install'])

    def test_automatic_metadata_has_probe_policy_strict_schemas_and_no_build_allowlist(self):
        info = builder.bundle_info()
        info.update(builder.automatic_compatibility_info_metadata(True, True))
        manifest = builder.apply_automatic_compatibility_manifest({
            'minimum_darwin_kernel_version': '25.0.0',
            'ready_for_install': True,
            'runtime_validated': False,
            'awdl_backend_active': False,
            'native_control_only': True,
            'native_control_runtime_validated': False,
            'active_behavior': 'Preserved Test011 Wi-Fi/private-MAC bridge. No event-pipe capability advertised.',
            'native_empty_query_policy': 'No event capability advertised.',
            'linked_inactive_cores': ['AWDL bounded event ring'],
            'remaining': 'Historical validation backlog',
            'colocated_scope_policy': 'Historical scope statement',
            'association_policy_survey': 'Historical survey',
            'dhcp_device_type_policy': 'Historical policy',
            'original_driver_dependencies': 'Historical dependency summary',
        }, True, True)
        policy = manifest['compatibility_policy']

        self.assertEqual(info['AirportBrcmAutomaticCompatibility'], 1)
        self.assertIn('ABIContractProbes', info['AirportBrcmKernelIdentityPolicy'])
        self.assertEqual(info['AirportBrcmMinimumDarwinKernelVersion'], '25.0.0')
        self.assertEqual(info['AirportBrcmRequestSchemaPolicy'], 'StrictFailClosed')
        self.assertEqual(info['AirportBrcmStrictRequestSchemas'],
                         ['scan-multiple-set86-v1', 'sae-password-carrier-subset-v1'])
        self.assertEqual(info['CFBundleVersion'], '1.1.0')
        self.assertTrue(info['AirportBrcmBaselineTraceConfigured'])
        self.assertTrue(info['AirportBrcmControlRxWindowsConfigured'])
        self.assertIn('unknown UUID alone never admits', policy['kernel_admission'])
        self.assertIn('strict-fail-closed', policy['request_schema_policy'])
        self.assertEqual(policy['minimum_darwin_kernel_version'], '25.0.0')
        self.assertEqual(manifest['validation_scope'], 'offline')
        self.assertEqual(manifest['minimum_darwin_kernel_version'], '25.0.0')
        self.assertEqual(manifest['scan_multiple_nonzero_min_timestamp'], 'refuse')
        self.assertEqual(manifest['compiled_features'], {
            'automatic_kernel_abi_probe_gate': True,
            'wifi_private_mac_bridge': True,
            'native_control_endpoint': True,
            'scan_multiple_set86_adapter': True,
            'sae_password_carrier_subset': True,
            'awdl_event_pipeline_and_routes': True,
            'baseline_control_rx_trace': True,
            'control_rx_observation_windows': True,
        })
        self.assertTrue(manifest['compiled_features']['awdl_event_pipeline_and_routes'])
        self.assertTrue(manifest['compiled_features']['scan_multiple_set86_adapter'])
        self.assertTrue(manifest['compiled_features']['sae_password_carrier_subset'])
        self.assertTrue(manifest['compiled_features']['baseline_control_rx_trace'])
        self.assertTrue(manifest['compiled_features']['control_rx_observation_windows'])
        self.assertNotIn('awdl_backend_active', manifest)
        self.assertNotIn('native_control_only', manifest)
        self.assertNotIn('native_control_runtime_validated', manifest)
        self.assertNotIn('active_behavior', manifest)
        self.assertNotIn('remaining', manifest)
        self.assertNotIn('colocated_scope_policy', manifest)
        self.assertNotIn('association_policy_survey', manifest)
        self.assertNotIn('dhcp_device_type_policy', manifest)
        self.assertNotIn('original_driver_dependencies', manifest)
        self.assertNotIn('No event capability advertised', manifest['native_empty_query_policy'])
        self.assertEqual(manifest['linked_inactive_cores'],
                         ['Strict message55 recovery codec: no proven observer source'])
        self.assertFalse(manifest['release_ready'])
        self.assertFalse(manifest['runtime_validated'])
        self.assertNotIn('supported_build', manifest)
        self.assertNotIn('supported_builds', manifest)
        self.assertNotIn('kernel_profiles', manifest)
        self.assertNotIn('maximum_darwin_kernel_version', manifest)
        for key in ('AirportBrcmSupportedBuilds','AirportBrcmKernelProfiles',
                    'AirportBrcmMaximumDarwinKernelVersion'):
            self.assertNotIn(key, info)
        serialized = repr((info, manifest))
        for profile in ('25G241', '25G332', '1291D44A', '28267FD5'):
            self.assertNotIn(profile, serialized)
        self.assertTrue(builder.validate_automatic_compatibility_metadata(info, manifest))

        inconsistent = dict(manifest)
        inconsistent['runtime_validated'] = True
        with self.assertRaisesRegex(ValueError, 'cannot claim'):
            builder.validate_automatic_compatibility_metadata(info, inconsistent)


if __name__ == '__main__':
    unittest.main()
