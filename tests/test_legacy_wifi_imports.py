import pathlib
import struct
import sys
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
import verify_legacy_wifi_imports as audit


def synthetic_kernel_collection(mode="container-absolute", ambiguous=False,
                               malformed=False, duplicate_entry=False,
                               empty_entry=False, no_valid_symbols=False,
                               invalid_section=False, end_marker=False,
                               zero_sized_section=False,
                               kernel_symbolsets_marker=False):
    """Build a bounded one-member MH_FILESET with nlists in a __LINKEDIT span."""
    member_offset = 0x100
    member_id = b"\0" if empty_entry else b"com.apple.test\0"
    entry_size = (32 + len(member_id) + 7) & ~7
    entry_count = 2 if duplicate_entry else 1
    outer_sizeofcmds = entry_size * entry_count
    raw = bytearray(0xA00 if ambiguous else 0x900)
    struct.pack_into("<IiiIIIII", raw, 0, 0xFEEDFACF, 0x01000007, 3, 0xC,
                     entry_count, outer_sizeofcmds, 0, 0)
    cursor = 32
    for _ in range(entry_count):
        struct.pack_into("<IIQQII", raw, cursor, 0x80000035, entry_size,
                         0x1000, member_offset, 32, 0)
        raw[cursor + 32:cursor + 32 + len(member_id)] = member_id
        cursor += entry_size

    nlist_count = 6 if kernel_symbolsets_marker else 5
    strings = (b"\0__defined\0_required\0_prebound\0_abs\0_alias\0__defined\0" +
               (b"_last_kernel_symbol\0" if kernel_symbolsets_marker else b""))
    string_index = {
        "__defined": 1,
        "_required": strings.index(b"_required"),
        "_prebound": strings.index(b"_prebound"),
        "_abs": strings.index(b"_abs"),
        "_alias": strings.index(b"_alias"),
        "__defined_alias": strings.rindex(b"__defined"),
    }
    if kernel_symbolsets_marker:
        string_index["_last_kernel_symbol"] = strings.index(b"_last_kernel_symbol")
    symoff, stroff = (0x700, 0x760)
    if mode == "member-relative":
        symoff, stroff = symoff - member_offset, stroff - member_offset
    if mode not in ("container-absolute", "member-relative"):
        raise ValueError(mode)

    def write_nlists(base):
        entries = [
            (string_index["__defined"], 0x0F, 2 if invalid_section else 1, 0,
             0x1100 if end_marker else 0x1000 if zero_sized_section else 0x1004),
            (string_index["_required"], 0x01, 0, 0, 0),       # N_UNDF | N_EXT
            (string_index["_prebound"], 0x0D, 0, 0, 0),      # N_PBUD | N_EXT
            (string_index["_abs"], 0x03, 0, 0, 0x55),         # N_ABS | N_EXT
            (string_index["_alias"], 0x0B, 0, 0,
             string_index["__defined_alias"]),               # N_INDR | N_EXT
        ]
        if kernel_symbolsets_marker:
            entries.append((string_index["_last_kernel_symbol"], 0x0F, 2, 0, 0x4000))
        if malformed:
            entries[1] = (0xFFFF, 0x01, 0, 0, 0)
        if no_valid_symbols:
            entries = [(string_index["__defined"], 0x0E, 1, 0, 0x1004)] * nlist_count
        for index, item in enumerate(entries):
            struct.pack_into("<IBBHQ", raw, base + index * 16, *item)
        raw[base + 0x60:base + 0x60 + len(strings)] = strings

    if ambiguous:
        write_nlists(0x700)
        write_nlists(0x800)
        linkedit_fileoff, linkedit_size = 0x700, 0x200
    else:
        # Both LC_SYMTAB offset conventions resolve to this one physical table.
        write_nlists(0x700)
        linkedit_fileoff, linkedit_size = 0x700, 0x100

    text_command_size = 152
    marker_command_size = 152 if kernel_symbolsets_marker else 0
    linkedit_command_size = 72
    symtab_command_size = 24
    commands_size = text_command_size + 2 * marker_command_size + linkedit_command_size + symtab_command_size
    ncmds = 5 if kernel_symbolsets_marker else 3
    struct.pack_into("<IiiIIIII", raw, member_offset, 0xFEEDFACF, 0x01000007,
                     3, 11, ncmds, commands_size, 0, 0)
    cmd = member_offset + 32
    struct.pack_into("<II", raw, cmd, 0x19, text_command_size)
    raw[cmd + 8:cmd + 16] = b"__TEXT\0\0"
    struct.pack_into("<QQQQ", raw, cmd + 24, 0x1000, 0x100, 0x400, 0x100)
    struct.pack_into("<iiII", raw, cmd + 56, 7, 5, 1, 0)
    section = cmd + 72
    raw[section:section + 7] = b"__text\0"
    raw[section + 16:section + 23] = b"__TEXT\0"
    text_size = 0 if zero_sized_section else 0x100
    struct.pack_into("<QQII", raw, section + 32, 0x1000, text_size, 0x400, 4)
    struct.pack_into("<I", raw, section + 64, 0x80000400)
    cmd += text_command_size
    if kernel_symbolsets_marker:
        struct.pack_into("<II", raw, cmd, 0x19, marker_command_size)
        raw[cmd + 8:cmd + 16] = b"__LAST\0\0"
        struct.pack_into("<QQQQ", raw, cmd + 24, 0x3000, 0, 0x500, 0)
        struct.pack_into("<iiII", raw, cmd + 56, 1, 1, 1, 0)
        section = cmd + 72
        raw[section:section + 7] = b"__last\0"
        raw[section + 16:section + 24] = b"__LAST\0\0"
        struct.pack_into("<QQII", raw, section + 32, 0x3000, 0, 0x500, 0)
        cmd += marker_command_size
        struct.pack_into("<II", raw, cmd, 0x19, marker_command_size)
        raw[cmd + 8:cmd + 19] = b"__LINKINFO\0"
        struct.pack_into("<QQQQ", raw, cmd + 24, 0x4000, 0x100, 0x500, 0x100)
        struct.pack_into("<iiII", raw, cmd + 56, 1, 1, 1, 0)
        section = cmd + 72
        raw[section:section + 13] = b"__symbolsets\0"
        raw[section + 16:section + 27] = b"__LINKINFO\0"
        struct.pack_into("<QQII", raw, section + 32, 0x4000, 0x100, 0x500, 0)
        cmd += marker_command_size
    struct.pack_into("<II", raw, cmd, 0x19, linkedit_command_size)
    raw[cmd + 8:cmd + 19] = b"__LINKEDIT\0"
    struct.pack_into("<QQQQ", raw, cmd + 24, 0x2000, linkedit_size,
                     linkedit_fileoff, linkedit_size)
    struct.pack_into("<iiII", raw, cmd + 56, 1, 1, 0, 0)
    cmd += linkedit_command_size
    struct.pack_into("<IIIIII", raw, cmd, 0x2, 24, symoff, nlist_count,
                     stroff, len(strings))
    return bytes(raw)


class LegacyWiFiImportAuditTests(unittest.TestCase):
    def test_parse_kernel_collection_container_absolute_symbol_table(self):
        import tempfile
        with tempfile.NamedTemporaryFile() as sample:
            sample.write(synthetic_kernel_collection())
            sample.flush()
            definitions, strong, weak = audit.parse_kernel_collection_symbols(
                pathlib.Path(sample.name))
        self.assertEqual(definitions["com.apple.test"]["__defined"], {0x1004})
        self.assertEqual(definitions["com.apple.test"]["_abs"], {0x55})
        self.assertNotIn("_prebound", definitions["com.apple.test"])
        self.assertNotIn("_alias", definitions["com.apple.test"])
        self.assertEqual(strong["com.apple.test"], {"_required", "_prebound"})
        self.assertEqual(weak["com.apple.test"], set())

    def test_parse_kernel_collection_member_relative_symbol_table(self):
        import tempfile
        with tempfile.NamedTemporaryFile() as sample:
            sample.write(synthetic_kernel_collection(mode="member-relative"))
            sample.flush()
            definitions, strong, _weak = audit.parse_kernel_collection_symbols(
                pathlib.Path(sample.name))
        self.assertIn("__defined", definitions["com.apple.test"])
        self.assertEqual(strong["com.apple.test"], {"_required", "_prebound"})

    def test_reject_ambiguous_symbol_table_offsets_and_bad_strings(self):
        import tempfile
        for fixture, message in ((synthetic_kernel_collection(ambiguous=True), "ambiguous LC_SYMTAB"),
                                 (synthetic_kernel_collection(malformed=True), "invalid string index")):
            with self.subTest(message=message), tempfile.NamedTemporaryFile() as sample:
                sample.write(fixture)
                sample.flush()
                with self.assertRaisesRegex(ValueError, message):
                    audit.parse_kernel_collection_symbols(pathlib.Path(sample.name))

    def test_reject_duplicate_fileset_identifiers(self):
        import tempfile
        with tempfile.NamedTemporaryFile() as sample:
            sample.write(synthetic_kernel_collection(duplicate_entry=True))
            sample.flush()
            with self.assertRaisesRegex(ValueError, "duplicate fileset IDs"):
                audit.parse_kernel_collection_symbols(pathlib.Path(sample.name))

    def test_reject_empty_fileset_identifier_and_zero_symbol_candidates(self):
        import tempfile
        for fixture, message in ((synthetic_kernel_collection(empty_entry=True), "empty fileset ID"),
                                 (synthetic_kernel_collection(no_valid_symbols=True), "no valid external symbols")):
            with self.subTest(message=message), tempfile.NamedTemporaryFile() as sample:
                sample.write(fixture)
                sample.flush()
                with self.assertRaisesRegex(ValueError, message):
                    audit.parse_kernel_collection_symbols(pathlib.Path(sample.name))

    def test_section_symbols_allow_only_bounded_addresses(self):
        import tempfile
        for fixture in (synthetic_kernel_collection(end_marker=True),
                        synthetic_kernel_collection(zero_sized_section=True)):
            with tempfile.NamedTemporaryFile() as sample:
                sample.write(fixture)
                sample.flush()
                definitions, _strong, _weak = audit.parse_kernel_collection_symbols(
                    pathlib.Path(sample.name))
            self.assertIn("__defined", definitions["com.apple.test"])

        with tempfile.NamedTemporaryFile() as sample:
            sample.write(synthetic_kernel_collection(invalid_section=True))
            sample.flush()
            with self.assertRaisesRegex(ValueError, "invalid section"):
                audit.parse_kernel_collection_symbols(pathlib.Path(sample.name))

    def test_kernel_symbolsets_boundary_uses_exact_linkinfo_anchor(self):
        import tempfile
        with tempfile.NamedTemporaryFile() as sample:
            sample.write(synthetic_kernel_collection(kernel_symbolsets_marker=True))
            sample.flush()
            definitions, _strong, _weak = audit.parse_kernel_collection_symbols(
                pathlib.Path(sample.name))
        self.assertEqual(definitions["com.apple.test"]["_last_kernel_symbol"], {0x4000})

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
