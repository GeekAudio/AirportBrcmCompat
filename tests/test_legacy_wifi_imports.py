import pathlib
import sys
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
import verify_legacy_wifi_imports as audit


class LegacyWiFiImportAuditTests(unittest.TestCase):
    def test_parse_nm_fileset_modules_imports_and_weak_imports(self):
        # Apple's `nm -m` fileset output has a trailing space after headers.
        sample = """Symbols for com.apple.iokit.IO80211Family:\x20
ffffff8000100000 (__TEXT,__text) external _defined
                 (undefined) external _required
                 (undefined) weak external _optional
Symbols for com.apple.kernel:\x20
ffffff8000200000 (__TEXT,__text) external _kernel
"""
        images, strong, weak = audit.parse_nm_mach(sample)
        self.assertEqual(images["com.apple.iokit.IO80211Family"], {"_defined"})
        self.assertEqual(images["com.apple.kernel"], {"_kernel"})
        self.assertEqual(strong, {"_required"})
        self.assertEqual(weak, {"_optional"})

    def test_parse_nm_defined_addresses_with_trailing_header_space(self):
        sample = """Symbols for com.apple.iokit.IONetworkingFamily:\x20
ffffff8000100000 (__TEXT,__text) external __ZN20IOEthernetController7attachEv
                 (undefined) external __ZN20IOEthernetController6missingEv
"""
        result = audit.parse_nm_defined_addresses(sample)
        self.assertEqual(result["com.apple.iokit.IONetworkingFamily"], {
            0xFFFFFF8000100000: {"__ZN20IOEthernetController7attachEv"}
        })

    def test_class_meta_filter_and_closure(self):
        metas = audit.class_meta_symbols({
            "__ZN17IO80211Controller10gMetaClassE",
            "__ZN17IO80211Controller6attachEP9IOService",
            "__ZN17IO80211Controller9MetaClassC1Ev",
        })
        self.assertEqual(metas, {"__ZN17IO80211Controller10gMetaClassE"})
        result = audit.closure({"strong_imports": {"_present", "_missing"},
                                "weak_imports": {"_weak"}}, {"_present"}, {"_missing"})
        self.assertEqual(result["raw_nm_unresolved_strong"], ["_missing"])
        self.assertEqual(result["kxld_inherited_vtable_resolved"], ["_missing"])
        self.assertEqual(result["unresolved_strong"], [])
        self.assertEqual(result["unresolved_weak"], ["_weak"])

    def test_class_name_from_meta_symbol_and_overlap_report(self):
        symbol = "__ZN17IO80211Controller10gMetaClassE"
        self.assertEqual(audit.class_name_from_meta_symbol(symbol), "IO80211Controller")
        report = audit._class_overlap_report(
            {"IO80211Controller": "IO80211Controller"},
            {"IO80211Controller": "IO80211Controller"})
        self.assertEqual(report["potential_co_load_class_name_overlap_count"], 1)
        self.assertFalse(report["runtime_load_claim"])
        with self.assertRaises(ValueError):
            audit._class_overlap_report(
                {"IO80211Controller": "IO80211Controller"},
                {"IO80211Controller": "OtherName"})

    def test_label_path_argument(self):
        label, path = audit.parse_assignment("Sequoia=/tmp/BootKC.kc")
        self.assertEqual(label, "Sequoia")
        self.assertEqual(path, pathlib.Path("/tmp/BootKC.kc"))


if __name__ == "__main__":
    unittest.main()
