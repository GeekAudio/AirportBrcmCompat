import hashlib
import importlib.util
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "airport_public_tests.build_namespace", ROOT / "src" / "build_namespace.py")
namespace_builder = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = namespace_builder
SPEC.loader.exec_module(namespace_builder)


def minimal_x86_64_kext():
    header = struct.pack("<8I", 0xFEEDFACF, 0x1000007, 3, 11, 1, 24, 0, 0)
    symtab = struct.pack("<6I", 2, 24, 56, 0, 56, 1)
    return header + symtab + b"\0"


def minimal_fileset(entry_id="com.apple.iokit.IOSkywalkFamily"):
    name = entry_id.encode() + b"\0"
    entry_size = (32 + len(name) + 7) & ~7
    child_offset = 32 + entry_size
    child_commands_size = 72 + 24 + 24
    symbol_offset = child_offset + 32 + child_commands_size
    strings = b"\0_defined\0_undefined\0_prebound\0"
    string_offset = symbol_offset + 3 * 16
    linkedit_size = 3 * 16 + len(strings)
    segment = struct.pack(
        "<II16sQQQQIIII", 0x19, 72, b"__LINKEDIT", 0, linkedit_size,
        symbol_offset, linkedit_size, 7, 7, 0, 0)
    symtab = struct.pack("<6I", 2, 24, symbol_offset, 3, string_offset, len(strings))
    uuid = bytes.fromhex("00112233445566778899aabbccddeeff")
    uuid_command = struct.pack("<II16s", 0x1B, 24, uuid)
    child_commands = segment + symtab + uuid_command
    child_header = struct.pack(
        "<8I", 0xFEEDFACF, 0x1000007, 3, 11, 3,
        len(child_commands), 0x80000085, 0)
    symbol_table = (struct.pack("<IBBHQ", 1, 0x0F, 1, 0, 0x1000) +
                    struct.pack("<IBBHQ", 10, 0x01, 0, 0, 0) +
                    struct.pack("<IBBHQ", 21, 0x0D, 0, 0, 0))
    child = child_header + child_commands + symbol_table + strings
    entry_command = struct.pack(
        "<IIQQII", 0x80000035, entry_size, 0xFFFFFF8000000000,
        child_offset, 32, 0) + name
    entry_command += b"\0" * (entry_size - len(entry_command))
    outer_header = struct.pack(
        "<8I", 0xFEEDFACF, 0x1000007, 3, 0xC, 1,
        len(entry_command), 0, 0)
    return outer_header + entry_command + child


def make_bundle(root, name, info, binary):
    bundle = root / name
    executable_name = info["CFBundleExecutable"]
    executable = bundle / "Contents" / "MacOS" / executable_name
    executable.parent.mkdir(parents=True)
    (bundle / "Contents" / "Info.plist").write_bytes(
        plistlib.dumps(info, sort_keys=False))
    executable.write_bytes(binary)
    return bundle


class NamespaceDependencyProfileTests(unittest.TestCase):
    def test_tahoe_remains_the_default_profile(self):
        self.assertEqual(namespace_builder.DEFAULT_PROFILE, "tahoe")
        self.assertEqual(namespace_builder.dependency_profile()["min_kernel"], "25.0.0")
        self.assertEqual(namespace_builder.dependency_profile()["max_kernel"], "")

    def test_os_profiles_pin_separate_binary_and_kernel_ranges(self):
        sonoma = namespace_builder.dependency_profile("sonoma-sequoia")
        tahoe = namespace_builder.dependency_profile("tahoe")
        self.assertEqual((sonoma["min_kernel"], sonoma["max_kernel"]),
                         ("23.0.0", "24.99.99"))
        self.assertEqual((tahoe["min_kernel"], tahoe["max_kernel"]), ("25.0.0", ""))
        self.assertNotEqual(sonoma["brcm_binary_sha256"], tahoe["brcm_binary_sha256"])
        self.assertEqual(sonoma["brcm_info_sha256"], tahoe["brcm_info_sha256"])
        self.assertNotEqual(sonoma["brcm_bundle"], tahoe["brcm_bundle"])
        self.assertEqual(namespace_builder.resolve_profile_brcm_source(
            Path("/inputs"), "sonoma-sequoia"),
            Path("/inputs/IO80211FamilyLegacy.kext/Contents/PlugIns/AirPortBrcmNIC.kext"))
        self.assertEqual(namespace_builder.resolve_profile_brcm_source(
            Path("/inputs"), "tahoe"), Path("/inputs/AirPortBrcmNIC-Tahoe.kext"))

    def test_unknown_profile_is_refused(self):
        with self.assertRaisesRegex(namespace_builder.BuildError, "Unknown dependency profile"):
            namespace_builder.dependency_profile("unknown")

    def test_pinned_bundle_verifies_binary_metadata_and_identity(self):
        raw = minimal_x86_64_kext()
        info = {"CFBundleIdentifier": "com.example.test", "CFBundleVersion": "1.0",
                "CFBundleExecutable": "Example"}
        info_raw = plistlib.dumps(info, sort_keys=False)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_bundle(root, "Example.kext", info, raw)
            original = namespace_builder.pinned_bundle(
                root, ("Example.kext",), "Example.kext", hashlib.sha256(raw).hexdigest(),
                hashlib.sha256(info_raw).hexdigest(), "synthetic profile fixture",
                "com.example.test", "1.0")
            self.assertEqual(original.raw, raw)
            self.assertEqual(original.destination, "Example.kext")
            with self.assertRaisesRegex(namespace_builder.BuildError, "binary hash mismatch"):
                namespace_builder.pinned_bundle(
                    root, ("Example.kext",), "Example.kext", "0" * 64,
                    hashlib.sha256(info_raw).hexdigest(), "wrong binary fixture")
            with self.assertRaisesRegex(namespace_builder.BuildError, "metadata hash mismatch"):
                namespace_builder.pinned_bundle(
                    root, ("Example.kext",), "Example.kext", hashlib.sha256(raw).hexdigest(),
                    "0" * 64, "wrong Info fixture")

    def test_native_skywalk_is_an_explicit_sample_and_metadata_is_recorded(self):
        raw = minimal_x86_64_kext()
        info = {"CFBundleIdentifier": namespace_builder.OLD_ID,
                "CFBundleVersion": "sample-version", "DTSDKName": "sample-sdk",
                "CFBundleExecutable": "IOSkywalkFamily"}
        with tempfile.TemporaryDirectory() as temporary:
            bundle = make_bundle(Path(temporary), "IOSkywalkFamily.kext", info, raw)
            _, _, copied_bytes, metadata = namespace_builder.native_sample(bundle, "fixture")
        self.assertEqual(copied_bytes, raw)
        self.assertEqual(metadata["label"], "fixture")
        self.assertEqual(metadata["bundle_id"], namespace_builder.OLD_ID)
        self.assertEqual(metadata["bundle_version"], "sample-version")
        self.assertEqual(metadata["sdk_name"], "sample-sdk")
        self.assertEqual(metadata["executable_sha256"], hashlib.sha256(raw).hexdigest())

    def test_kernel_collection_fileset_reader_returns_only_child_exports(self):
        raw = minimal_fileset()
        with tempfile.TemporaryDirectory() as temporary:
            collection = Path(temporary) / "sample.kc"
            collection.write_bytes(raw)
            exports, metadata = namespace_builder.kernel_collection_symbols(
                collection, namespace_builder.OLD_ID, "synthetic KC child")
        self.assertEqual(exports, {"_defined"})
        self.assertEqual(metadata["sample_kind"], "kernel-collection-fileset-entry")
        self.assertEqual(metadata["label"], "synthetic KC child")
        self.assertEqual(metadata["container_sha256"], hashlib.sha256(raw).hexdigest())
        expected_entry_size = (32 + len(namespace_builder.OLD_ID.encode()) + 1 + 7) & ~7
        self.assertEqual(metadata["fileset_entry_file_offset"], 32 + expected_entry_size)
        self.assertEqual(metadata["macho_uuid"], "00112233-4455-6677-8899-AABBCCDDEEFF")

    def test_kernel_collection_fileset_reader_requires_exact_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            collection = Path(temporary) / "sample.kc"
            collection.write_bytes(minimal_fileset())
            with self.assertRaisesRegex(namespace_builder.BuildError, "not found"):
                namespace_builder.kernel_collection_symbols(collection, "other.entry")


if __name__ == "__main__":
    unittest.main()
