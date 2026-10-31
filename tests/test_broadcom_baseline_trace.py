from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]


class BroadcomBaselineTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="brcm-awdl-baseline-", dir="/private/tmp")
        cls.folder = Path(cls.temporary.name)
        source = PROJECT / "tests/baseline_trace_host.cpp"
        production = PROJECT / "src/awdl_kernel/baseline_trace.cpp"
        include = PROJECT / "src/awdl_kernel"
        cls.asan_binary = cls.folder / "baseline-asan-ubsan"
        cls.tsan_binary = cls.folder / "baseline-tsan"
        cls.compile([
            "xcrun", "clang++", "-std=c++14", "-pthread", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-I", str(include),
            str(source), str(production), "-o", str(cls.asan_binary),
        ])
        cls.compile([
            "xcrun", "clang++", "-std=c++14", "-pthread", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=thread", "-fno-omit-frame-pointer", "-I", str(include),
            str(source), str(production), "-o", str(cls.tsan_binary),
        ])

    @staticmethod
    def compile(command):
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_mode(self, binary, mode):
        result = subprocess.run([str(binary), str(mode)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_message48_metadata_and_psf_mif_numeric_fields(self): self.run_mode(self.asan_binary, 1)
    def test_short_unknown_and_truncated_tlvs_are_observed_only(self): self.run_mode(self.asan_binary, 2)
    def test_tlv_iteration_and_input_are_strictly_bounded(self): self.run_mode(self.asan_binary, 3)
    def test_zero_length_opaque_tlv_and_empty_path_flags_are_preserved(self): self.run_mode(self.asan_binary, 4)
    def test_concurrent_sessions_publish_complete_bounded_rows(self): self.run_mode(self.tsan_binary, 5)
    def test_psf_flood_does_not_consume_mif_pool_and_last_rows_are_independent(self): self.run_mode(self.asan_binary, 6)
    def test_mif_flood_does_not_consume_psf_pool(self): self.run_mode(self.asan_binary, 7)
    def test_known_suffix_flags_and_prefix_only_address_comparison(self): self.run_mode(self.asan_binary, 8)
    def test_concurrent_snapshot_aggregation_reads_only_published_rows(self): self.run_mode(self.tsan_binary, 9)
    def test_other_subtype_flood_cannot_consume_psf_mif_pools(self): self.run_mode(self.asan_binary, 10)

    def test_production_hook_is_after_owned_take_and_before_unchanged_codec(self):
        source = (PROJECT / "src/awdl_kernel/event_pipe_session.cpp").read_text()
        taken = source.index("LegacyPostObserver::take(observer_,source_,delivery)")
        observed = source.index("BaselineTrace::observeOwnedMessage48(source_.body,source_.length)")
        translated = source.index("awcm48_translate_diagnosed(&format,source_.message")
        self.assertLess(taken, observed)
        self.assertLess(observed, translated)
        self.assertIn("source_.message==AWCM48_ACTION_FRAME_RX)", source[observed - 220:observed])
        self.assertIn("#if defined(AIRPORT_BRCM_BASELINE_TRACE)", source[:observed])
        self.assertIn("ScanKernelIdentity::currentProfile()==ScanKernelIdentity::Profile::Build25G332",
                      source[observed - 200:observed])

    def test_lifecycle_exposes_only_numeric_baseline_fields(self):
        source = (PROJECT / "src/scan_kernel/lifecycle.cpp").read_text()
        self.assertIn("#if defined(AIRPORT_BRCM_BASELINE_TRACE)", source)
        self.assertIn("ScanKernelIdentity::currentProfile()==ScanKernelIdentity::Profile::Build25G332", source)
        self.assertIn('all->setObject("BroadcomAwdlBaseline25G332",baseline)', source)
        self.assertIn('Baseline" key,values.member', source)
        self.assertIn('BASELINE_NUMBER(controlRxOnly,"ControlRxOnly")', source)
        self.assertIn('BASELINE_NUMBER(psfSamples,"PsfSamples")', source)
        self.assertIn('BASELINE_NUMBER(lastTlv12AwdlAddressPrefixMatchesMetadataSource,"LastTlv12AwdlAddressPrefixMatchesMetadataSource")', source)
        self.assertIn('BASELINE_NUMBER(lastTlv12AwdlAddressPrefixComparable,"LastTlv12AwdlAddressPrefixComparable")', source)
        self.assertIn('addSubtypeSummary("Psf",values.psf)', source)
        self.assertIn('addSubtypeSummary("Mif",values.mif)', source)
        self.assertIn('BASELINE_NUMBER(otherPoolCapacity,"OtherPoolCapacity")', source)
        self.assertIn('BASELINE_NUMBER(schema,"Schema")', source)
        self.assertNotIn("SYSLOG", (PROJECT / "src/awdl_kernel/baseline_trace.cpp").read_text())


if __name__ == "__main__":
    unittest.main()
