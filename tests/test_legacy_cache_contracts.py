"""Offline verifier tests for the pinned cache-provider lifetime contract."""
from pathlib import Path
import sys
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
import verify_legacy_cache_contracts as verifier  # noqa: E402


class LegacyCacheContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = verifier.DEFAULT_PROVIDER
        if not cls.provider.is_file():
            raise AssertionError(f"retained provider sample is missing: {cls.provider}")
        cls.raw = cls.provider.read_bytes()
        cls.result = verifier.verify_bytes(cls.raw)

    def test_pins_cache_layout_and_true_function_boundaries(self):
        self.assertEqual(self.result["provider_sha256"], verifier.PROVIDER_SHA256)
        self.assertEqual(self.result["provider_uuid"], verifier.PROVIDER_UUID.hex())
        layout = self.result["cache_layout"]
        self.assertEqual(layout["manager_cache_head_offset"], 0x18)
        self.assertEqual(layout["pending_request_head_offset"], 0x10)
        self.assertEqual(layout["cache_node_size"], 0xC0)
        self.assertEqual(layout["cache_node_previous_link_offset"], 0x08)
        self.assertEqual(layout["cache_node_reference_count_offset"], 0x10)
        self.assertEqual(len(self.result["functions"]), 13)
        self.assertEqual(sum(item["size"] for item in self.result["functions"]), 4485)
        self.assertEqual(self.result["functions"][2]["end_exclusive"], "0x5fd45")
        self.assertEqual(self.result["functions"][2]["next_symbol_offset"], "0x5fd46")
        self.assertEqual(self.result["functions"][6]["end_exclusive"], "0x6203b")
        self.assertEqual(self.result["functions"][6]["next_symbol_offset"], "0x6203c")
        detach = self.result["functions"][10]
        self.assertEqual(detach["symbol"], "__ZN16IO80211Interface23detachFromDataLinkLayerEjPv")
        self.assertEqual(detach["start"], "0x58126")
        self.assertEqual(detach["end_exclusive"], "0x5819e")
        self.assertEqual(detach["next_symbol_offset"], "0x5819e")
        self.assertEqual(detach["terminal"], "0x58198")
        self.assertEqual(detach["terminal_dispatch_slot"], "0x9b8")
        finish_attach = self.result["functions"][11]
        self.assertEqual(finish_attach["symbol"], "__ZN16IO80211Interface27finishAttachToDataLinkLayerEv")
        self.assertEqual(finish_attach["start"], "0x578ba")
        self.assertEqual(finish_attach["end_exclusive"], "0x57b63")
        self.assertEqual(finish_attach["next_symbol_offset"], "0x57b64")
        self.assertEqual(finish_attach["terminal"], "0x57b5e")
        dispatcher = self.result["functions"][12]
        self.assertEqual(dispatcher["symbol"],
                         "__ZN17IO80211Controller20apple80211_ioctl_setEP16IO80211InterfaceP23IO80211VirtualInterfaceP7__ifnetPv")
        self.assertEqual(dispatcher["start"], "0x55460")
        self.assertEqual(dispatcher["end_exclusive"], "0x55519")
        self.assertEqual(dispatcher["next_symbol_offset"], "0x5551a")
        self.assertEqual(dispatcher["terminal"], "0x55518")
        self.assertEqual(self.result["finish_attach_manager_init_callsite"], {
            "function": "__ZN16IO80211Interface27finishAttachToDataLinkLayerEv",
            "function_start": "0x578ba",
            "call_instruction": "0x57a41",
            "return_pc": "0x57a46",
            "target_function": "__ZN18IO80211ScanManager30initWithControllerAndInterfaceEP17IO80211ControllerP16IO80211Interface",
            "target_instruction": "0x5f70a",
            "test_mutations_rejected": 4,
            "scope": "Exact pinned provider callsite and rel32 target; caller must already have accepted the complete provider contract",
        })

    def test_checks_external_and_internal_relocation_contracts(self):
        relocation = self.result["external_relocations"]
        self.assertEqual(relocation["count"], 59)
        self.assertEqual(len(relocation["unique_imports"]), 23)
        self.assertEqual(self.result["internal_branches"], 18)
        self.assertEqual(self.result["selected_function_relocations"], {"external": 59, "local": 0})
        self.assertEqual(self.result["external_pointer_relocations"]["records"], [
            {"address": 0x98090, "symbol": "__ZTV19IOEthernetInterface",
             "pcrel": 0, "length": 3, "type": 0}
        ])
        self.assertEqual(self.result["indirect_calls"], [
            {"instruction": "0x58170", "vtable_slot": "0x28", "target": "OSObject::release"}
        ])
        dispatch = self.result["set_dispatcher"]
        self.assertEqual(dispatch["start"], "0x55460")
        self.assertEqual(dispatch["end_exclusive"], "0x55519")
        self.assertEqual(dispatch["next_symbol_offset"], "0x5551a")
        self.assertEqual(dispatch["handler_table_address"], "0xa30e0")
        self.assertEqual(dispatch["handler_count_address"], "0xa3840")
        self.assertEqual(dispatch["handler_count_value"], 236)
        self.assertEqual(dispatch["indirect_call"], "0x554e4: ff d0")
        self.assertEqual(dispatch["disassociate_handler_return_pc"], "0x554e6")
        self.assertFalse(dispatch["type22_slot_checked"])
        self.assertEqual([item["symbol"] for item in self.result["external_relocations"]["records"][-3:]],
                         ["_proc_self", "_proc_is64bit", "_proc_rele"])

    def test_actual_guard_acceptance_and_mutation_rejections_are_sanitized(self):
        self.assertTrue(self.result["accepted_after_synthetic_import_relocations"])
        self.assertEqual(self.result["sanitizers"], ["address", "undefined"])
        self.assertTrue(self.result["accepted_finish_attach_init_return"])
        self.assertEqual(self.result["rejected_finish_attach_init_return_mutations"], 4)
        self.assertTrue(self.result["accepted_disassociate_dispatch_callsite"])
        self.assertEqual(self.result["rejected_disassociate_dispatch_mutations"], 5)
        self.assertTrue(self.result["rejected_set_handler_table_count_mutation"])
        self.assertEqual(self.result["rejected_body_byte_mutations"], 4485)
        self.assertEqual(self.result["rejected_padding_mutations"], 5)
        self.assertEqual(self.result["rejected_symbol_address_mutations"], 13)
        self.assertEqual(self.result["rejected_import_address_mutations"], 24)
        self.assertEqual(self.result["rejected_external_pointer_mutations"], 1)
        self.assertTrue(self.result["rejected_manager_size_mutation"])
        self.assertTrue(self.result["rejected_uuid_mutation"])
        self.assertFalse(self.result["provider_code_executed"])
        self.assertFalse(self.result["driver_loaded"])
        self.assertFalse(self.result["hardware_validated"])

    def test_rejects_any_change_to_pinned_source_binary(self):
        changed = bytearray(self.raw)
        changed[0x6265A] ^= 1
        with self.assertRaisesRegex(ValueError, "pinned provider SHA-256"):
            verifier.verify_bytes(bytes(changed))


if __name__ == "__main__":
    unittest.main()
