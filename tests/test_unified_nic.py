import importlib.util
import sys
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "airport_public_tests.verify_unified_nic",
    PROJECT / "tools" / "verify_unified_nic.py")
unified_tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = unified_tool
SPEC.loader.exec_module(unified_tool)

SONOMA = PROJECT / "build/compatibility-profiles/sonoma14-dependencies.zip"
TAHOE = PROJECT / "build/compatibility-profiles/tahoe26-dependencies.zip"


class RelativeBranchTests(unittest.TestCase):
    def test_decodes_x86_relative_branch_target(self):
        code = bytearray(64)
        site, target = 7, 43
        code[site] = 0xE9
        code[site + 1:site + 5] = (target - site - 5).to_bytes(
            4, "little", signed=True)
        self.assertEqual(unified_tool.decode_rel32_target(bytes(code), site, 0xE9),
                         target)

    def test_rejects_unexpected_branch_opcode(self):
        with self.assertRaisesRegex(unified_tool.VerificationError,
                                    "Expected relative branch opcode"):
            unified_tool.decode_rel32_target(bytes(16), 2, 0xE8)


class DeltaScopeTests(unittest.TestCase):
    def test_accepts_only_declared_code_and_signature_differences(self):
        base = b"abcdef"
        candidate = bytearray(base)
        candidate[1] ^= 1
        candidate[4] ^= 1
        report = unified_tool._check_delta(
            base, bytes(candidate), (4, 2), code_ranges=(("shim", 1, 2),))
        self.assertEqual(report["code_region_changed_bytes"], {"shim": 1})
        self.assertEqual(report["signature_changed_byte_count"], 1)
        self.assertEqual(report["unlisted_changes"], 0)

    def test_rejects_difference_outside_declared_ranges(self):
        with self.assertRaisesRegex(unified_tool.VerificationError,
                                    "Unexpected NIC binary difference"):
            unified_tool._check_delta(
                b"abc", b"axc", (2, 1), code_ranges=())


@unittest.skipUnless(SONOMA.is_file() and TAHOE.is_file(),
                     "requires the hash-pinned Sonoma and Tahoe dependency ZIPs")
class PinnedUnifiedNICTests(unittest.TestCase):
    def test_tahoe_image_is_an_offline_single_bundle_candidate(self):
        report = unified_tool.verify(SONOMA, TAHOE)
        self.assertEqual(report["candidate"]["binary_sha256"],
                         unified_tool.EXPECTED_BINARY_SHA256["tahoe"])
        self.assertEqual(report["static_evidence"]["macho_uuid"],
                         unified_tool.EXPECTED_UUID)
        evidence = report["static_evidence"]
        self.assertTrue(evidence["load_commands_identical"])
        self.assertTrue(evidence["native_undefined_symbols_identical"])
        self.assertTrue(evidence["cxx_vtable_symbols_identical"])
        self.assertTrue(evidence["matching_info_plist_identical"])
        self.assertTrue(evidence["chipmatch_table_identical"])
        self.assertEqual(evidence["binary_delta"]["changed_byte_count"], 1412)
        self.assertEqual(evidence["binary_delta"]["signature_changed_byte_count"], 190)
        self.assertEqual(evidence["native_undefined_symbol_count"], 1107)
        self.assertEqual(evidence["cxx_vtable_symbol_count"], 16)
        self.assertFalse(report["runtime_tested"])
        self.assertFalse(report["kernel_kext_loaded"])
        self.assertFalse(report["driver_functions_invoked"])
        self.assertIn("DMA allocation lifetime, concurrent teardown, or failure-path correctness",
                      report["not_established"])

    def test_hook_and_helper_calls_land_at_audited_targets(self):
        report = unified_tool.verify(SONOMA, TAHOE)
        evidence = report["static_evidence"]
        hooks = {entry["name"]: entry for entry in evidence["hook_and_rejoin_targets"]}
        self.assertEqual(hooks["dma_detach_hook"]["target"], "0x1b47c")
        self.assertEqual(hooks["tx_dma_hook"]["target"], "0x1b17f")
        self.assertEqual(hooks["rx_dma_hook"]["target"], "0x1b2b7")
        self.assertEqual(hooks["rx_complete_hook"]["target"], "0x1b2ea")
        self.assertTrue(all(entry["target_in_text"] for entry in hooks.values()))

        calls = {(entry["site"], entry["symbol"]): entry["target"]
                 for entry in evidence["shim_call_targets"]}
        self.assertEqual(calls[("0x1b12d", "_osl_dma_alloc_consistent")], "0x1f8cd")
        self.assertEqual(calls[("0x1b3fc", "_osl_dma_free_consistent")], "0x1fbd0")
        self.assertEqual(calls[("0x1b423", "_osl_mfree")], "0x1f756")
        self.assertEqual(calls[("0x2c260d", "_osl_dma_map")], "0x21674")
        self.assertEqual(calls[("0x2c3d73", "_osl_dma_map")], "0x21674")


if __name__ == "__main__":
    unittest.main()
