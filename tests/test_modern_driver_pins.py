import importlib.util
import shutil
import struct
import sys
import tempfile
import unittest
import warnings
from dataclasses import replace
import zipfile
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "airport_public_tests.verify_modern_driver_pins",
    PROJECT / "tools" / "verify_modern_driver_pins.py")
pins_tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pins_tool
SPEC.loader.exec_module(pins_tool)

SONOMA = PROJECT / "build/compatibility-profiles/sonoma14-dependencies.zip"
TAHOE = PROJECT / "build/compatibility-profiles/tahoe26-dependencies.zip"


def _padded_name(value):
    raw = value.encode("ascii")
    return raw + b"\0" * (16 - len(raw))


def _synthetic_macho(*, section_fileoff=0x990, vmaddr=0x1000,
                     vmsize=0x1000, fileoff=0, filesize=0x1000):
    section = struct.pack(
        "<16s16sQQIIIIIIII", _padded_name("__text"), _padded_name("__TEXT"),
        vmaddr + 0x990, 16, section_fileoff, 4, 0, 0,
        pins_tool.S_ATTR_PURE_INSTRUCTIONS, 0, 0, 0)
    segment = struct.pack(
        "<II16sQQQQiiII", pins_tool.LC_SEGMENT_64, 152, _padded_name("__TEXT"),
        vmaddr, vmsize, fileoff, filesize, 7, 5, 1, 0) + section
    uuid_bytes = bytes(range(16))
    uuid_command = struct.pack("<II16s", pins_tool.LC_UUID, 24, uuid_bytes)
    commands = segment + uuid_command
    header = struct.pack(
        "<IiiIIIII", pins_tool.MH_MAGIC_64, pins_tool.CPU_TYPE_X86_64,
        pins_tool.CPU_SUBTYPE_X86_64_ALL, pins_tool.MH_KEXT_BUNDLE, 2,
        len(commands), 0, 0)
    data = bytearray(0x1000)
    data[:len(header)] = header
    data[len(header):len(header) + len(commands)] = commands
    data[0x990:0x9A0] = bytes(range(0xA0, 0xB0))
    return bytes(data)


class MachOMapTests(unittest.TestCase):
    def test_maps_segments_by_vm_address_and_preserves_uuid(self):
        source = _synthetic_macho()
        mapped = pins_tool.map_thin_x86_64_macho(source)
        self.assertEqual(mapped.image_vmaddr, 0x1000)
        self.assertEqual(mapped.text_vmaddr, 0x1000)
        self.assertEqual(mapped.text_fileoff, 0)
        self.assertEqual(mapped.text_file_size, 0x1000)
        self.assertEqual(mapped.text_size, 16)
        self.assertEqual(mapped.data[:len(source)], source)
        self.assertEqual(mapped.data[0x990:0x9A0], bytes(range(0xA0, 0xB0)))
        self.assertEqual(mapped.macho_uuid,
                         "00010203-0405-0607-0809-0A0B0C0D0E0F")

    def test_rejects_non_x86_64_or_truncated_macho(self):
        with self.assertRaisesRegex(pins_tool.VerificationError, "truncated"):
            pins_tool.map_thin_x86_64_macho(b"short")
        invalid = bytearray(_synthetic_macho())
        struct.pack_into("<I", invalid, 0, 0xCAFEBABE)
        with self.assertRaisesRegex(pins_tool.VerificationError, "thin x86_64"):
            pins_tool.map_thin_x86_64_macho(bytes(invalid))

    def test_rejects_inconsistent_text_vm_file_mapping(self):
        source = _synthetic_macho(section_fileoff=0x991)
        with self.assertRaisesRegex(pins_tool.VerificationError,
                                    "file/VM mapping"):
            pins_tool.map_thin_x86_64_macho(source)

    def test_rejects_mapped_image_over_limit(self):
        source = _synthetic_macho(vmsize=pins_tool.MAX_MAPPED_IMAGE_SIZE + 1)
        with self.assertRaisesRegex(pins_tool.VerificationError,
                                    "Mapped Mach-O image exceeds"):
            pins_tool.map_thin_x86_64_macho(source)


class DependencyZipPreflightTests(unittest.TestCase):
    def test_rejects_duplicate_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("safe/member", b"one")
                    archive.writestr("safe/member", b"two")
            with self.assertRaisesRegex(pins_tool.VerificationError,
                                        "Duplicate ZIP member"):
                pins_tool._read_zip_members(path)

    def test_rejects_unsafe_member_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "unsafe.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../outside", b"bad")
            with self.assertRaisesRegex(pins_tool.VerificationError,
                                        "Unsafe ZIP member path"):
                pins_tool._read_zip_members(path)

    def test_rejects_oversized_zip_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("safe/member", b"1234")
            with mock.patch.object(pins_tool, "MAX_MEMBER_SIZE", 3):
                with self.assertRaisesRegex(pins_tool.VerificationError,
                                            "Oversized ZIP member"):
                    pins_tool._read_zip_members(path)

    def test_rejects_oversized_zip_file_before_reading_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "large.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("safe/member", b"ok")
            with mock.patch.object(pins_tool, "MAX_ARCHIVE_FILE_SIZE", 8):
                with self.assertRaisesRegex(pins_tool.VerificationError,
                                            "compressed-size limit"):
                    pins_tool._read_zip_members(path)


@unittest.skipUnless(SONOMA.is_file() and TAHOE.is_file() and
                     shutil.which("clang++"),
                     "requires the two pinned dependency ZIPs and clang++")
class ActualDriverPinTests(unittest.TestCase):
    def test_both_real_nic_variants_pass_actual_pin_initializer(self):
        report = pins_tool.verify_dependencies([SONOMA, TAHOE])
        self.assertEqual(report["required_variants_present"], ["sonoma-sequoia", "tahoe"])
        self.assertTrue(report["checks"]["all_pin_initializers_passed"])
        self.assertFalse(report["checks"]["driver_function_pointers_invoked"])
        self.assertEqual([variant["initialize_driver_pins_status"]
                          for variant in report["variants"]], [0, 0])
        self.assertEqual([variant["nonnull_pin_count"] for variant in report["variants"]],
                         [8, 8])
        expected={'14e4:43ba','14e4:43a3','14e4:43a0','14e4:4357','14e4:43b1','14e4:43b2'}
        for variant in report['variants']:
            self.assertEqual(set(variant['chipmatch']['accepted_pci_ids']),expected)
            self.assertFalse(variant['chipmatch']['driver_function_invoked'])
        self.assertEqual(report["variants"][0]["binary_sha256"],
                         "c43b8c5443c14d029c86459ea60502ede731bb94acb8de201fc210c99080f0d0")
        self.assertEqual(report["variants"][1]["binary_sha256"],
                         "999c1a5b6a0d18baba2050520c1d429b49edfd99bfc8d71299b639334f263982")

    def test_chipmatch_rejects_changed_lookup_path_target_and_missing_device_ids(self):
        with zipfile.ZipFile(TAHOE) as archive:
            name='Kexts/AirPortBrcmNIC-Tahoe.kext/Contents/MacOS/AirPortBrcmNIC'
            source=archive.read(name)
        mapped=pins_tool.map_thin_x86_64_macho(source)
        start=0x12f25a
        for offset in list(range(0x17))+list(range(0x1b,0x31))+list(range(0xb6,0xc7)):
            mutated=bytearray(mapped.data);mutated[start+offset]^=1
            with self.subTest(offset=hex(offset)):
                with self.assertRaisesRegex(pins_tool.VerificationError,'success path'):
                    pins_tool.verify_chipmatch(source,replace(mapped,data=bytes(mutated)))
        mutated=bytearray(mapped.data);mutated[start+0x17]^=1
        with self.assertRaisesRegex(pins_tool.VerificationError,'resolved device table'):
            pins_tool.verify_chipmatch(source,replace(mapped,data=bytes(mutated)))
        table=start+0x1b+struct.unpack_from('<i',mapped.data,start+0x17)[0]
        for device in (0x43ba,0x43a3,0x43a0,0x4357,0x43b1,0x43b2):
            mutated=bytearray(mapped.data)
            for offset in range(table,table+0xd4,2):
                if struct.unpack_from('<H',mutated,offset)[0]==device:
                    struct.pack_into('<H',mutated,offset,0xffff)
            with self.subTest(device=hex(device)):
                with self.assertRaisesRegex(pins_tool.VerificationError,'absent'):
                    pins_tool.verify_chipmatch(source,replace(mapped,data=bytes(mutated)))


if __name__ == "__main__":
    unittest.main()
