#!/usr/bin/env python3
"""Run the public, offline-only AirportBrcmCompat regression suites."""

import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
SUITES = {
    "scan": (
        "test_scan_kernel",
        "test_scan_capabilities",
        "test_scan_lifecycle",
        "test_runtime_build_guard",
        "test_kernel_identity",
        "test_kernel_contracts",
        "test_scan_multiple_compat",
    ),
    "private-mac": (
        "test_private_mac_admission",
        "test_private_mac_state_gate",
        "test_private_mac_transaction",
        "test_private_mac_native_request",
        "test_private_mac_association_flow",
        "test_association_survey",
        "test_association_sae",
    ),
    "awdl": (
        "test_message48_subset_codec",
        "test_message55_recovery_codec",
        "test_awdl_async_notification_owner",
        "test_event_pipe_core",
        "test_event_pipe_router",
        "test_event_pipe_worker",
        "test_event_pipe_session",
        "test_broadcom_baseline_trace",
        "test_control_rx_windows",
    ),
    "build": (
        "test_build_unified_kernel_cli",
        "test_lilu_api_compatibility",
        "test_scoped_reset_contract",
    ),
}


def ensure_macos_toolchain():
    if sys.platform != "darwin":
        raise RuntimeError("These x86_64 kext host tests require macOS and Xcode Command Line Tools.")

    xcrun = shutil.which("xcrun")
    if not xcrun:
        raise RuntimeError("xcrun was not found; install Xcode Command Line Tools first.")

    tool_dirs = []
    for tool in ("clang", "clang++", "nm"):
        result = subprocess.run([xcrun, "--find", tool], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"xcrun could not locate {tool}: {result.stderr.strip()}")
        tool_dirs.append(str(Path(result.stdout.strip()).resolve().parent))

    path_parts = list(dict.fromkeys(tool_dirs + os.environ.get("PATH", "").split(os.pathsep)))
    os.environ["PATH"] = os.pathsep.join(part for part in path_parts if part)


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
    args = parser.parse_args(argv)
    selected = tuple(dict.fromkeys(args.suite or SUITES))

    try:
        ensure_macos_toolchain()
        suite = unittest.TestSuite()
        loader = unittest.TestLoader()
        for suite_name in selected:
            for module_name in SUITES[suite_name]:
                suite.addTests(loader.loadTestsFromModule(load_module(module_name)))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    except (OSError, RuntimeError) as error:
        print(f"run_tests: {error}", file=sys.stderr)
        return 2
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
