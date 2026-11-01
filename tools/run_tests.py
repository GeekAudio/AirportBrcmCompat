#!/usr/bin/env python3
"""Run the public, offline-only AirportBrcmCompat regression suites."""

import argparse
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
SUITES = {
    "scan": (
        "test_scan_kernel",
        "test_scan_result_profiles",
        "test_primary_interface",
        "test_scan_capabilities",
        "test_scan_lifecycle",
        "test_runtime_build_guard",
        "test_kernel_identity",
        "test_kernel_contracts",
        "test_ifnet_verifier_inputs",
        "test_scan_multiple_compat",
    ),
    "private-mac": (
        "test_ifnet_scope_core",
        "test_ifnet_kpi_contract",
        "test_network_callback_contract",
        "test_bsd_lease",
        "test_route_checked",
        "test_private_mac_admission",
        "test_private_mac_state_gate",
        "test_private_mac_transaction",
        "test_private_mac_native_request",
        "test_private_mac_association_flow",
        "test_association_profiles",
        "test_association_profile_dispatch",
        "test_association_survey",
        "test_association_sae",
    ),
    "awdl": (
        "test_version_method_schema",
        "test_message48_subset_codec",
        "test_awdl_async_notification_owner",
        "test_event_pipe_core",
        "test_event_pipe_router",
        "test_event_pipe_worker",
        "test_event_pipe_session",
        "test_broadcom_baseline_trace",
        "test_control_rx_windows",
    ),
    "build": (
        "test_modern_driver_pins",
        "test_build_unified_kernel_cli",
        "test_namespace_profiles",
        "test_combine_wifi_dependency_profiles",
        "test_prepare_broadcom_injector",
        "test_namespace_vtable_closure",
        "test_lilu_api_compatibility",
        "test_scoped_reset_contract",
        "test_run_tests_toolchain",
        "test_prepare_test_fixtures",
        "test_brcmctl",
        "test_package_release",
    ),
}


def _executable(path):
    return path and Path(path).is_file() and os.access(path, os.X_OK)


@contextmanager
def ensure_macos_toolchain():
    if sys.platform != "darwin":
        raise RuntimeError("These x86_64 kext host tests require macOS and Xcode Command Line Tools.")

    xcrun = shutil.which("xcrun")
    resolved = {}
    for tool in ("clang", "clang++", "nm"):
        candidate = None
        if xcrun:
            result = subprocess.run([xcrun, "--find", tool], capture_output=True, text=True)
            if result.returncode == 0 and _executable(result.stdout.strip()):
                candidate = result.stdout.strip()
        if not candidate:
            candidate = next((path for path in (shutil.which(tool), "/usr/bin/"+tool)
                              if _executable(path)), None)
        if not candidate and tool == "clang++":
            # A forwarding entry supplies clang++ even if only clang exists.
            candidate = resolved.get("clang")
        if not candidate:
            raise RuntimeError(f"Could not locate {tool} through xcrun, PATH or /usr/bin; install Xcode Command Line Tools.")
        resolved[tool] = str(Path(candidate).absolute())

    old_path = os.environ.get("PATH")
    old_sdk = os.environ.get('SDKROOT')
    sdk = old_sdk if old_sdk and Path(old_sdk).is_dir() else None
    if not sdk and xcrun:
        selected = subprocess.run([xcrun,'--sdk','macosx','--show-sdk-path'],
                                  capture_output=True,text=True)
        if selected.returncode==0 and Path(selected.stdout.strip()).is_dir() and selected.stdout.strip():
            sdk=selected.stdout.strip()
    with tempfile.TemporaryDirectory(prefix="brcm-test-tools-") as aliases:
        for name, executable in resolved.items():
            # Execute the real pathname so Clang finds its installed C++
            # headers beside the toolchain, rather than beside this temporary
            # entry. Symlinks work on some CLT installs but break Xcode runners.
            mode=' --driver-mode=g++' if name=='clang++' else ''
            if name in ('clang','clang++') and sdk:
                mode+=' -isysroot '+shlex.quote(sdk)
            wrapper=Path(aliases)/name
            wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(executable)+mode+' "$@"\n')
            wrapper.chmod(0o755)
        os.environ["PATH"] = aliases + (os.pathsep+old_path if old_path else "")
        if sdk:os.environ['SDKROOT']=sdk
        try:
            yield resolved
        finally:
            if old_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = old_path
            if old_sdk is None:os.environ.pop('SDKROOT',None)
            else:os.environ['SDKROOT']=old_sdk


def load_module(name):
    tests_path = str(TESTS)
    if tests_path not in sys.path:
        sys.path.insert(0, tests_path)
    path = TESTS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"airport_public_tests.{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load test module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite",
        action="append",
        choices=tuple(SUITES),
        help="suite to run; repeat to select several (default: all)",
    )
    parser.add_argument('--require-all',action='store_true',
                        help='Fail if any test is skipped; CI requires prepared external fixtures')
    args = parser.parse_args(argv)
    selected = tuple(dict.fromkeys(args.suite or SUITES))

    try:
        with ensure_macos_toolchain():
            suite = unittest.TestSuite()
            loader = unittest.TestLoader()
            for suite_name in selected:
                for module_name in SUITES[suite_name]:
                    suite.addTests(loader.loadTestsFromModule(load_module(module_name)))
            result = unittest.TextTestRunner(verbosity=2).run(suite)
    except (OSError, RuntimeError) as error:
        print(f"run_tests: {error}", file=sys.stderr)
        return 2
    if args.require_all and result.skipped:
        print(f'run_tests: partial validation refused: {len(result.skipped)} tests skipped',file=sys.stderr)
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
