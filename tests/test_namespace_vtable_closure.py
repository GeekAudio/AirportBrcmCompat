import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "airport_public_tests.build_namespace_vtable", ROOT / "src" / "build_namespace.py")
namespace_builder = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = namespace_builder
SPEC.loader.exec_module(namespace_builder)


def add_symbol(image, name, value, defined=True):
    image["symbols"].setdefault(name, []).append({
        "defined": defined, "external": True, "section_index": 1 if defined else 0,
        "description": 0 if defined else 0xFE00, "value": value if defined else 0,
    })


def add_relocation(image, address, symbol):
    image["external_relocations"].append({
        "address": address, "symbol": symbol, "pcrel": 0, "length": 3, "type": 0,
    })


def data_image(section_address, section_size, file_offset, file_size):
    return {"sections": [{"segment": "__DATA", "name": "__const",
                          "address": section_address, "size": section_size,
                          "file_offset": file_offset}],
            "symbols": {}, "external_relocations": []}, bytearray(file_size)


def put_rip_reference(data, file_offset, instruction_address, target, opcode):
    displacement = target - (instruction_address + 7)
    data[file_offset:file_offset + 7] = opcode + displacement.to_bytes(4, "little", signed=True)


def valid_linkage_fixture():
    methods = namespace_builder.INHERITED_VTABLE_METHODS
    provider, provider_bytes = data_image(0x1000, 0x3000, 0x100, 0x3200)
    legacy, legacy_bytes = data_image(0x2000, 0x3000, 0x100, 0x4200)
    brcm, brcm_bytes = data_image(0x7000, 0x2000, 0x100, 0x4200)
    legacy["sections"].append({"segment": "__TEXT", "name": "__text", "address": 0x5000,
                               "size": 0x100, "file_offset": 0x4000})
    brcm["sections"].append({"segment": "__TEXT", "name": "__text", "address": 0x9000,
                             "size": 0x100, "file_offset": 0x4000})

    provider_class = "IOLegacyWEthernetInterface"
    skywalk_class = "IO80211SkywalkInterface"
    infra_class = "IO80211InfraInterface"
    brcm_class = "AirPort_Brcm43xxLLSkywalkInterface"
    provider_vtable = "__ZTV26IOLegacyWEthernetInterface"
    skywalk_vtable = "__ZTV23IO80211SkywalkInterface"
    infra_vtable = "__ZTV21IO80211InfraInterface"
    brcm_vtable = "__ZTV34AirPort_Brcm43xxLLSkywalkInterface"

    add_symbol(provider, provider_vtable, 0x1200)
    add_symbol(provider, f"__ZN26{provider_class}10gMetaClassE", 0x1800)
    for index, method in enumerate(methods):
        implementation = method["parent_implementation_symbol"]
        address = 0x5100 + index * 0x10
        add_symbol(provider, implementation, address)
        slot_address = 0x1200 + 16 + method["slot"] * 8
        file_offset = 0x100 + slot_address - 0x1000
        provider_bytes[file_offset:file_offset + 8] = address.to_bytes(8, "little")

    add_symbol(legacy, skywalk_vtable, 0x2100)
    add_symbol(legacy, infra_vtable, 0x3000)
    skywalk_meta = f"__ZN{len(skywalk_class)}{skywalk_class}10gMetaClassE"
    infra_meta = f"__ZN{len(infra_class)}{infra_class}10gMetaClassE"
    provider_meta = f"__ZN{len(provider_class)}{provider_class}10gMetaClassE"
    add_symbol(legacy, skywalk_meta, 0x4000)
    add_symbol(legacy, infra_meta, 0x4010)
    add_symbol(legacy, f"__ZN{len(skywalk_class)}{skywalk_class}9MetaClassC2Ev", 0x5000)
    add_symbol(legacy, f"__ZN{len(infra_class)}{infra_class}9MetaClassC2Ev", 0x5020)
    for method in methods:
        parent_implementation = method["parent_implementation_symbol"]
        slot_address = 0x2100 + 16 + method["slot"] * 8
        add_relocation(legacy, slot_address, parent_implementation)
        slot_address = 0x3000 + 16 + method["slot"] * 8
        add_relocation(legacy, slot_address, parent_implementation)
    put_rip_reference(legacy_bytes, 0x4000, 0x5000, 0x4800, b"\x48\x8b\x15")
    add_relocation(legacy, 0x4800, provider_meta)
    put_rip_reference(legacy_bytes, 0x4020, 0x5020, 0x4000, b"\x48\x8d\x15")

    add_symbol(brcm, brcm_vtable, 0x7100)
    add_symbol(brcm, f"__ZN{len(brcm_class)}{brcm_class}9MetaClassC2Ev", 0x9000)
    add_symbol(brcm, infra_meta, 0, defined=False)
    for method in methods:
        slot_address = 0x7100 + 16 + method["slot"] * 8
        add_relocation(brcm, slot_address, method["undefined_symbol"])
    put_rip_reference(brcm_bytes, 0x4000, 0x9000, 0x8800, b"\x48\x8b\x15")
    add_relocation(brcm, 0x8800, infra_meta)
    return (provider_bytes, provider, legacy_bytes, legacy, brcm_bytes, brcm)


class NamespaceVtableClosureTests(unittest.TestCase):
    def test_three_pinned_inherited_vtable_slots_are_verified(self):
        provider_bytes, provider, legacy_bytes, legacy, brcm_bytes, brcm = valid_linkage_fixture()
        evidence = namespace_builder._verify_inherited_vtable_layout(
            provider_bytes, provider, legacy_bytes, legacy, brcm_bytes, brcm,
            "AirPortBrcmNIC-Sonoma-Sequoia.kext")
        self.assertEqual([item["slot"] for item in evidence], [334, 336, 338])
        self.assertEqual(
            [item["parent_implementation_symbol"] for item in evidence],
            [item["parent_implementation_symbol"]
             for item in namespace_builder.INHERITED_VTABLE_METHODS])
        self.assertTrue(all(item["resolution"] == "kxld-inherited-vtable-slot"
                            for item in evidence))

    def test_wrong_child_slot_is_refused(self):
        provider_bytes, provider, legacy_bytes, legacy, brcm_bytes, brcm = valid_linkage_fixture()
        expected_address = 0x7100 + 16 + 338 * 8
        brcm["external_relocations"] = [
            relocation for relocation in brcm["external_relocations"]
            if relocation["address"] != expected_address]
        brcm["external_relocations"].append({
            "address": 0x7100 + 16 + 337 * 8,
            "symbol": namespace_builder.INHERITED_VTABLE_METHODS[-1]["undefined_symbol"],
            "pcrel": 0, "length": 3, "type": 0,
        })
        with self.assertRaisesRegex(namespace_builder.BuildError, "vtable relocation"):
            namespace_builder._verify_inherited_vtable_layout(
                provider_bytes, provider, legacy_bytes, legacy, brcm_bytes, brcm,
                "AirPortBrcmNIC-Sonoma-Sequoia.kext")

    def test_wrong_parent_metaclass_relocation_is_refused(self):
        provider_bytes, provider, legacy_bytes, legacy, brcm_bytes, brcm = valid_linkage_fixture()
        brcm["external_relocations"][-1]["symbol"] = "__ZN16IO80211Interface10gMetaClassE"
        with self.assertRaisesRegex(namespace_builder.BuildError, "superclass"):
            namespace_builder._verify_inherited_vtable_layout(
                provider_bytes, provider, legacy_bytes, legacy, brcm_bytes, brcm,
                "AirPortBrcmNIC-Sonoma-Sequoia.kext")

    def test_unknown_private_import_is_refused(self):
        exception_imports = {
            item["undefined_symbol"] for item in namespace_builder.INHERITED_VTABLE_METHODS
        }
        inherited = [{"consumer_bundle": "AirPortBrcmNIC-Sonoma-Sequoia.kext",
                      "undefined_symbol": symbol} for symbol in exception_imports]
        definitions = {"IOLegacyWFamily.kext": {"__ZN26IOLegacyWEthernetInterfaceDirectEv"},
                       "IO80211FamilyLegacy.kext": set(),
                       "AirPortBrcmNIC-Sonoma-Sequoia.kext": set()}
        imports = {"IOLegacyWFamily.kext": set(), "IO80211FamilyLegacy.kext": set(),
                   "AirPortBrcmNIC-Sonoma-Sequoia.kext": exception_imports | {
                       "__ZN26IOLegacyWEthernetInterfaceUnreviewedEv"}}
        with self.assertRaisesRegex(namespace_builder.BuildError, "closure mismatch"):
            namespace_builder.private_import_resolution(definitions, imports, inherited)

    def test_vtable_exception_rejects_an_unpinned_provider(self):
        with self.assertRaisesRegex(namespace_builder.BuildError, "exact source hashes"):
            namespace_builder.verify_inherited_vtable_exceptions(
                b"", b"", b"", {"provider": "wrong"}, "expected", "Brcm.kext")


if __name__ == "__main__":
    unittest.main()
