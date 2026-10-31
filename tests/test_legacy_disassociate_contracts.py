"""Offline selected-route contracts for the retained El Cap child binaries."""
from pathlib import Path
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
import verify_legacy_disassociate_contracts as verifier  # noqa: E402


BCM4331 = PROJECT / "build/research/oclp-legacy/elcap-analysis-inputs/AirPortBrcm4331.bin"
BCM43224 = PROJECT / "build/research/oclp-legacy/elcap-analysis-inputs/AppleAirPortBrcm43224.bin"


class LegacyDisassociateChildContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for sample in (BCM4331, BCM43224):
            if not sample.is_file():
                raise AssertionError(f"retained child binary is missing: {sample}")
        cls.result = verifier.verify(BCM4331, BCM43224)

    def test_pins_both_real_child_images_and_selected_function_boundaries(self):
        self.assertEqual([item["label"] for item in self.result["raw_binaries"]],
                         ["AirPortBrcm4331", "AppleAirPortBrcm43224"])
        self.assertEqual(len(self.result["raw_binaries"][0]["selected_functions"]), 27)
        self.assertEqual(len(self.result["raw_binaries"][1]["selected_functions"]), 19)
        first_symbols = {item["symbol"] for item in self.result["raw_binaries"][0]["selected_functions"]}
        second_symbols = {item["symbol"] for item in self.result["raw_binaries"][1]["selected_functions"]}
        self.assertTrue({"_wlc_bss_clear_bssid", "_wlc_bsscfg_mfree", "_wlc_bsscfg_free",
                         "_wlc_detach", "__ZN16AirPort_Brcm43317wlcStopEv"}.issubset(first_symbols))
        self.assertTrue({"_wlc_down", "_wlc_detach",
                         "__ZN17AirPort_Brcm432247wlcStopEv"}.issubset(second_symbols))
        self.assertIn("_osl_pktfree", first_symbols)
        self.assertIn("_osl_pktfree", second_symbols)
        self.assertIn("_wlc_recv_parse_bcn_prb", first_symbols)
        self.assertIn("_wlc_recvctl", first_symbols)
        self.assertIn("_wlc_join_complete", first_symbols)
        self.assertIn("_wlc_join_complete", second_symbols)
        self.assertTrue({"_wlc_assoc_change_state", "_wlc_bsscfg_down", "_wlc_assoc_timeout",
                         "_wlc_auth_complete", "_wlc_bss_mac_event",
                         "_wlc_bss_mac_rxframe_event", "_wlc_eventq_enq"}.issubset(first_symbols))
        self.assertTrue({"_wlc_assoc_change_state", "_wlc_bsscfg_down", "_wlc_assoc_timeout",
                         "_wlc_bss_mac_event", "_wlc_eventq_enq"}.issubset(second_symbols))
        self.assertNotIn("_wlc_auth_complete", second_symbols)
        self.assertNotIn("_wlc_bss_mac_rxframe_event", second_symbols)
        self.assertEqual(len(self.result["raw_binaries"][0]["selected_code_ranges"]), 4)
        self.assertEqual(len(self.result["raw_binaries"][1]["selected_code_ranges"]), 3)
        self.assertEqual(self.result["raw_binaries"][0]["relative_table_entries"][0]["target"],
                         "0x332b9")
        self.assertEqual(self.result["raw_binaries"][1]["relative_table_entries"][0]["target"],
                         "0x6883e")
        self.assertEqual(self.result["raw_binaries"][0]["selected_local_relocations"], 0)
        self.assertEqual(self.result["raw_binaries"][0]["selected_section_relocations"], 0)
        self.assertEqual(self.result["raw_binaries"][1]["selected_local_relocations"], 0)
        self.assertEqual(self.result["raw_binaries"][1]["selected_section_relocations"], 0)
        self.assertIn("_mbuf_freem", self.result["raw_binaries"][0]["imports"])
        self.assertIn("_mbuf_free", self.result["raw_binaries"][1]["imports"])
        sync_symbol = next(item for item in self.result["raw_binaries"][0]["route_symbols"]
                           if item["symbol"] == "_wl_event_sync")
        self.assertEqual(sync_symbol, {"symbol": "_wl_event_sync", "address": "0x16c10",
                                       "external": True})
        for audit in self.result["raw_binaries"]:
            tail_jumps = [item for item in audit["external_calls"]
                          if item["opcode"] == "0xe9"]
            self.assertEqual(len(tail_jumps), 2)
            self.assertEqual({item["target_symbol"] for item in tail_jumps},
                             {"_IOLog", "_mbuf_freem"})

    def test_production_guard_rejects_body_relocation_and_address_mutations(self):
        first, second = self.result["runtime_harness"]
        self.assertEqual(first["rejected_body_bytes"], 32033)
        self.assertEqual(second["rejected_body_bytes"], 14374)
        self.assertEqual(first["rejected_code_range_bytes"], 617)
        self.assertEqual(second["rejected_code_range_bytes"], 653)
        self.assertEqual(first["rejected_table_entry_bytes"], 4)
        self.assertEqual(second["rejected_table_entry_bytes"], 4)
        self.assertEqual(first["rejected_relative_jumps"], 1)
        self.assertEqual(second["rejected_relative_jumps"], 0)
        self.assertEqual(first["rejected_conditional_branches"], 1)
        self.assertEqual(second["rejected_conditional_branches"], 0)
        self.assertEqual(first["rejected_internal_branches"], 135)
        self.assertEqual(second["rejected_internal_branches"], 79)
        self.assertEqual(first["rejected_tail_jump_opcodes"], 2)
        self.assertEqual(second["rejected_tail_jump_opcodes"], 2)
        self.assertEqual(first["rejected_tail_jump_targets"], 2)
        self.assertEqual(second["rejected_tail_jump_targets"], 2)
        self.assertEqual(first["rejected_import_targets"], 15)
        self.assertEqual(second["rejected_import_targets"], 14)
        self.assertEqual(first["rejected_symbol_addresses"], 27)
        self.assertEqual(second["rejected_symbol_addresses"], 19)
        self.assertEqual(first["rejected_route_symbols"], 2)
        self.assertEqual(second["rejected_route_symbols"], 1)
        for result in (first, second):
            self.assertTrue(result["rejected_uuid_mutation"])
            self.assertTrue(result["rejected_unresolved_import"])
            self.assertTrue(result["rejected_short_image"])
            self.assertTrue(result["rejected_base_overflow"])
            self.assertEqual(result["rejected_bad_return_pc_contexts"], 4)

    def test_current_bss_metadata_and_scope_limit_are_explicit(self):
        self.assertEqual(self.result["current_bss_layout"]["4331"]["record_size"], "0xa0")
        self.assertEqual(self.result["current_bss_layout"]["43224"]["record_size"], "0x98")
        self.assertIn("pointer validity", self.result["current_bss_layout"]["scope_note"])
        self.assertEqual(self.result["current_bss_layout"]["4331"]["cfg_allocation_size"], "0x600")
        self.assertEqual(self.result["current_bss_layout"]["4331"]["current_bss_allocation_size"], "0xa0")
        self.assertEqual(self.result["current_bss_layout"]["43224"]["wlc_allocation_size"], "0x3b98")
        self.assertIn("full _wlc_ioctl dispatcher", " ".join(self.result["not_guarded"]))
        self.assertIn("static guards do not authorize", self.result["current_bss_layout"]["scope_note"])
        self.assertIn("before original SET22", self.result["capture_preconditions"])
        self.assertFalse(self.result["runtime_support_claimed"])
        self.assertFalse(self.result["nonzero_set22_runtime_support_proven"])

    def test_writer_guard_abis_and_child_specific_slots_are_explicit(self):
        first = {item["symbol"]: item for item in self.result["raw_binaries"][0]["selected_functions"]}
        second = {item["symbol"]: item for item in self.result["raw_binaries"][1]["selected_functions"]}
        self.assertEqual(first["_wlc_bss_clear_bssid"]["entry_abi"], "RDI=cfg")
        self.assertIn("opaque RAX", first["_wlc_bss_clear_bssid"]["return_abi"])
        self.assertEqual(first["_wlc_bsscfg_mfree"]["entry_abi"], "RDI=osh, RSI=cfg")
        self.assertIn("void-style", first["_wlc_bsscfg_mfree"]["return_abi"])
        self.assertEqual(first["_wlc_bsscfg_free"]["entry_abi"], "RDI=wlc, RSI=cfg")
        self.assertIn("before clearing wlc+0x2e0+index*8", first["_wlc_bsscfg_free"]["return_abi"])
        self.assertEqual(first["__ZN16AirPort_Brcm43317wlcStopEv"]["range"],
                         ["0x49e8", "0x4a9a"])
        self.assertIn("after _wlc_detach returns",
                      first["__ZN16AirPort_Brcm43317wlcStopEv"]["return_abi"])
        self.assertEqual(second["__ZN17AirPort_Brcm432247wlcStopEv"]["range"],
                         ["0x38aa", "0x395b"])
        self.assertEqual(second["__ZN17AirPort_Brcm432247wlcStopEv"]["next_offset"], "0x395c")
        self.assertIn("int32", first["_wlc_detach"]["return_abi"])
        self.assertIn("int32", second["_wlc_down"]["return_abi"])
        self.assertIn("int32", second["_wlc_detach"]["return_abi"])

    def test_pktfree_body_abi_and_e9_import_targets_are_pinned(self):
        first = {item["symbol"]: item for item in self.result["raw_binaries"][0]["selected_functions"]}
        second = {item["symbol"]: item for item in self.result["raw_binaries"][1]["selected_functions"]}
        self.assertEqual(first["_osl_pktfree"]["range"], ["0x1680", "0x17ad"])
        self.assertEqual(second["_osl_pktfree"]["range"], ["0x1504", "0x1631"])
        self.assertEqual(first["_osl_pktfree"]["raw_sha256"],
                         "5a57c1c211d92c5bbeb578eb46727c613ba308db86ef12dad422b48b135d45a4")
        self.assertEqual(second["_osl_pktfree"]["raw_sha256"],
                         "73b7d183579ea6051345b4299370380026b9e89c1446ddd10a601955b1832830")
        for function in (first["_osl_pktfree"], second["_osl_pktfree"]):
            self.assertEqual(function["entry_abi"], "RDI=osh, RSI=mbuf, EDX=freeFlag")
            self.assertEqual(function["return_abi"],
                             "void; exact adapter ABI is (osh, unqueued packet, 1)")
        for audit in self.result["raw_binaries"]:
            self.assertTrue({"_mbuf_type", "_mbuf_next", "_mbuf_setnext",
                             "_mbuf_free", "_mbuf_freem"}.issubset(audit["imports"]))
            branches = {item["instruction"]: item
                        for item in audit["external_calls"]}
            if audit["label"] == "AirPortBrcm4331":
                self.assertEqual(branches["0x1796"]["target_symbol"], "_IOLog")
                self.assertEqual(branches["0x17a8"]["target_symbol"], "_mbuf_freem")
            else:
                self.assertEqual(branches["0x161a"]["target_symbol"], "_IOLog")
                self.assertEqual(branches["0x162c"]["target_symbol"], "_mbuf_freem")
            self.assertEqual(branches["0x1796"]["opcode"] if audit["label"] == "AirPortBrcm4331"
                             else branches["0x161a"]["opcode"], "0xe9")

    def test_receive_refresh_parser_and_commit_are_relocation_normalized(self):
        audit = self.result["raw_binaries"][0]
        selected = {item["symbol"]: item for item in audit["selected_functions"]}
        parser = selected["_wlc_recv_parse_bcn_prb"]
        recvctl = selected["_wlc_recvctl"]
        self.assertEqual(parser["range"], ["0x473c9", "0x47c46"])
        self.assertEqual(recvctl["range"], ["0x434e1", "0x47389"])
        self.assertEqual(parser["raw_sha256"], parser["normalized_sha256"])
        self.assertEqual(recvctl["raw_sha256"], recvctl["normalized_sha256"])
        branches = {item["instruction"]: item for item in audit["external_calls"]}
        for callsite, symbol in (("0x46c7b", "_wlc_recv_parse_bcn_prb"),
                                 ("0x46cdb", "_wlc_BSSinit")):
            branch = next(item for item in audit["internal_calls"]
                          if item["instruction"] == callsite)
            self.assertEqual(branch["symbol"], symbol)
            self.assertEqual(branch["return_pc"], hex(int(callsite, 16) + 5))
        self.assertIn("_bcmp", audit["imports"])
        self.assertIn("_mbuf_len", audit["imports"])
        self.assertIn("___stack_chk_fail", audit["imports"])
        self.assertIn("0x43b6b", branches)
        self.assertEqual(branches["0x43b6b"]["target_symbol"], "_bcmp")

    def test_join_complete_guards_pin_full_body_call_graph_and_abi(self):
        first, second = self.result["raw_binaries"]
        first_functions = {item["symbol"]: item for item in first["selected_functions"]}
        second_functions = {item["symbol"]: item for item in second["selected_functions"]}
        join4331 = first_functions["_wlc_join_complete"]
        join43224 = second_functions["_wlc_join_complete"]
        self.assertEqual(join4331["range"], ["0xaf453", "0xafad7"])
        self.assertEqual(join4331["raw_sha256"],
                         "dd58903500bb521f52871aaf7faa41e97745494cad0983effc231e50a627c052")
        self.assertEqual(join4331["normalized_sha256"], join4331["raw_sha256"])
        self.assertIn("R8D=body length; R9 unused", join4331["entry_abi"])
        self.assertIn("void-style", join4331["return_abi"])
        self.assertEqual(join43224["range"], ["0x81fe3", "0x8269e"])
        self.assertEqual(join43224["raw_sha256"],
                         "95423d7bd299fc5f86c033b8a0b5ff0faa24a45485e71a209f20a11924886e28")
        self.assertEqual(join43224["normalized_sha256"], join43224["raw_sha256"])
        self.assertIn("EDX=body length", join43224["entry_abi"])
        self.assertIn("retq at 0x8266e", join43224["return_abi"])
        self.assertTrue({"_memset", "_strncpy"}.issubset(second["imports"]))
        callers = {item["instruction"]: item for item in first["internal_calls"]
                   if item["symbol"] == "_wlc_join_complete"}
        self.assertEqual(set(callers), {"0x45bbe", "0x46e3f"})
        callers = {item["instruction"]: item for item in second["internal_calls"]
                   if item["symbol"] == "_wlc_join_complete"}
        self.assertEqual(set(callers), {"0x776a1", "0x78658"})
        for audit, start, end, external_count, internal_count in (
                (first, 0xAF453, 0xAFAD7, 6, 34),
                (second, 0x81FE3, 0x8269E, 9, 29)):
            self.assertEqual(sum(1 for item in audit["external_calls"]
                                 if start <= int(item["instruction"], 16) < end),
                             external_count)
            self.assertEqual(sum(1 for item in audit["internal_calls"]
                                 if start <= int(item["instruction"], 16) < end),
                             internal_count)

    def test_idle_timeout_guards_pin_state_layout_and_event3_handoff(self):
        first, second = self.result["raw_binaries"]
        first_functions = {item["symbol"]: item for item in first["selected_functions"]}
        second_functions = {item["symbol"]: item for item in second["selected_functions"]}
        self.assertEqual(first_functions["_wlc_assoc_change_state"]["range"],
                         ["0xad25f", "0xad420"])
        self.assertEqual(first_functions["_wlc_bsscfg_down"]["range"],
                         ["0x5de67", "0x5e0aa"])
        self.assertEqual(first_functions["_wlc_assoc_timeout"]["range"],
                         ["0xade7e", "0xae0a8"])
        self.assertEqual(first_functions["_wlc_auth_complete"]["range"],
                         ["0xae0a8", "0xae54c"])
        self.assertEqual(second_functions["_wlc_assoc_change_state"]["range"],
                         ["0x57347", "0x573bb"])
        self.assertEqual(second_functions["_wlc_bsscfg_down"]["range"],
                         ["0x8ffa6", "0x900d5"])
        self.assertEqual(second_functions["_wlc_assoc_timeout"]["range"],
                         ["0x5eb02", "0x5ec84"])
        event_call = next(item for item in first["internal_calls"]
                          if item["instruction"] == "0x4efd4")
        self.assertEqual(event_call["symbol"], "_wl_event_sync")
        self.assertEqual(event_call["target"], "0x16c10")
        branches = first["relative_conditional_branches"]
        self.assertEqual(branches, [{"instruction": "0x16c1a",
                                     "opcode": "0x75", "target": "0x16c3c"}])
        entry = next(item for item in first["selected_code_ranges"]
                     if item["range"] == ["0x16c10", "0x16c1c"])
        epilogue = next(item for item in first["selected_code_ranges"]
                        if item["range"] == ["0x16c3c", "0x16c43"])
        self.assertEqual(entry["size"], 12)
        self.assertEqual(epilogue["size"], 7)
        self.assertIn("event code 3", entry["purpose"])
        self.assertIn("0x20 willRoam path is excluded", epilogue["purpose"])
        self.assertIn("0x20 willRoam branch and any higher-level event consumer are outside this check",
                      self.result["idle_timeout_event_scope"]["4331"]["boundary"])
        self.assertIn("do not independently validate the runtime idle no-op",
                      self.result["idle_timeout_event_scope"]["claim_boundary"])
        self.assertNotIn("_wl_event_sync", first_functions)
        self.assertNotIn("__ZN16IO80211Interface8willRoamEP10ether_addrj", first["imports"])

    def test_43224_setibss_is_a_full_guard_with_all_local_call_targets(self):
        audit = self.result["raw_binaries"][1]
        selected = {item["symbol"]: item for item in audit["selected_functions"]}
        setter = selected["__ZN17AirPort_Brcm432247setIBSSEb"]
        self.assertEqual(setter["range"], ["0x4d3a", "0x4e42"])
        self.assertEqual(setter["next_symbol"], "__ZN17AirPort_Brcm4322411powerChangeEj")
        self.assertEqual(setter["raw_sha256"],
                         "f2dcc22c06603d337d68408c04291f87bb4feb1a7135f3c3a8296957655bb481")
        self.assertEqual(setter["normalized_sha256"], setter["raw_sha256"])
        self.assertEqual(setter["entry_abi"], "RDI=controller this, SIL=IBSS boolean")
        self.assertIn("int32 status in EAX", setter["return_abi"])
        calls = {item["instruction"]: item for item in audit["internal_calls"]
                 if 0x4d3a <= int(item["instruction"], 16) < 0x4e42}
        self.assertEqual(set(calls), {"0x4d90", "0x4d9a", "0x4db6", "0x4de3",
                                      "0x4dfb", "0x4e1d", "0x4e2c"})
        self.assertEqual(calls["0x4d90"]["symbol"], "_wlc_down")
        self.assertEqual(calls["0x4d9a"]["symbol"], "__ZN17AirPort_Brcm432245setAPEb")
        self.assertEqual(calls["0x4dfb"]["symbol"], "_wlc_get")
        self.assertEqual(calls["0x4e2c"]["symbol"], "_wl_up")

    def test_rejects_mutated_source_artifact_before_harness(self):
        original = BCM4331.read_bytes()
        changed = bytearray(original)
        changed[0x4D777] ^= 1
        with tempfile.TemporaryDirectory(prefix="legacy-child-mutated-") as directory:
            path = Path(directory) / "AirPortBrcm4331.bin"
            path.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "source SHA-256 mismatch"):
                verifier._verify_raw_child(path, "4331")


if __name__ == "__main__":
    unittest.main()
