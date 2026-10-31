import io
import plistlib
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
import legacy_wifi_dependency_builder as builder


OCLP_RESEARCH = PROJECT / "build/research/oclp-legacy"
IO80211_ARCHIVE = OCLP_RESEARCH / "IO80211ElCap-v2.0.1.zip"
CORECAPTURE_ARCHIVE = OCLP_RESEARCH / "corecaptureElCap-v1.0.2.zip"
KERNEL_COLLECTIONS = [
    ("Darwin25", Path("/System/Library/KernelCollections/BootKernelExtensions.kc")),
]


def synthetic_macho(class_name="CCPipe"):
    """Build one x86_64 Mach-O constructor fixture with one bounded C string."""
    image = bytearray(0x400)
    command_size = 72 + 2 * 80
    commands_size = command_size + 24
    struct.pack_into("<IiiIIIII", image, 0, builder.MH_MAGIC_64,
                     builder.CPU_TYPE_X86_64, 3, 2, 2, commands_size, 0, 0)

    base = 0x100000000
    struct.pack_into("<II", image, 32, builder.LC_SEGMENT_64, command_size)
    image[40:48] = b"__TEXT\0\0"
    struct.pack_into("<QQQQ", image, 56, base, 0x300, 0, 0x300)
    struct.pack_into("<iiII", image, 88, 7, 5, 2, 0)

    text_section = 104
    image[text_section:text_section + 7] = b"__text\0"
    image[text_section + 16:text_section + 23] = b"__TEXT\0"
    struct.pack_into("<QQI", image, text_section + 32, base + 0x200, 16, 0x200)
    struct.pack_into("<I", image, text_section + 64, 0)

    string_section = text_section + 80
    image[string_section:string_section + 9] = b"__cstring\0"
    image[string_section + 16:string_section + 23] = b"__TEXT\0"
    struct.pack_into("<QQI", image, string_section + 32, base + 0x240, 0x80, 0x240)
    struct.pack_into("<I", image, string_section + 64, builder.S_CSTRING_LITERALS)

    symtab_command = 32 + command_size
    struct.pack_into("<IIIIII", image, symtab_command, builder.LC_SYMTAB,
                     24, 0x300, 1, 0x310, 0x100)
    class_bytes = class_name.encode("ascii")
    symbol = f"__ZN{len(class_name)}{class_name}9MetaClassC2Ev".encode("ascii")
    displacement = 0x240 - (0x200 + 7)
    image[0x200:0x207] = b"\x48\x8d\x35" + struct.pack("<i", displacement)
    image[0x207] = 0xC3
    image[0x240:0x240 + len(class_bytes) + 1] = class_bytes + b"\0"
    image[0x260:0x260 + len(class_bytes) + 9] = class_bytes + b"Extended\0"
    image[0x300:0x310] = struct.pack("<IBBHQ", 1, 0x0F, 1, 0, base + 0x200)
    strings = b"\0" + symbol + b"\0"
    image[0x310:0x310 + len(strings)] = strings
    # LC_SYMTAB strsize is deliberately bounded to the actual string table.
    struct.pack_into("<I", image, symtab_command + 20, len(strings))
    return bytes(image)


class LegacyWiFiDependencyBuilderTests(unittest.TestCase):
    def test_legacy_profile_minimum_is_monterey(self):
        self.assertEqual(builder.PROFILES, {"legacy-darwin21plus": ("21.0.0", "")})
        self.assertEqual(builder.TARGET_KERNEL_LABELS,
                         {"Darwin21", "Darwin22", "Darwin23", "Darwin24", "Darwin25"})

    def test_single_target_sample_validation_accepts_monterey_and_ventura(self):
        with tempfile.TemporaryDirectory(prefix="legacy-wifi-target-samples-") as directory:
            root = Path(directory)
            samples = []
            for label in ("Darwin21", "Darwin22"):
                path = root / f"{label}.kc"
                path.write_bytes(b"mock BootKC")
                samples.append((label, path))
            for sample in samples:
                self.assertEqual(builder._validate_kernel_collection_samples([sample]),
                                 [sample])

            with self.assertRaisesRegex(ValueError, "at least one user-selected target"):
                builder._validate_kernel_collection_samples([])
            with self.assertRaisesRegex(ValueError, "duplicate target BootKC label"):
                builder._validate_kernel_collection_samples([samples[0], samples[0]])
            with self.assertRaisesRegex(ValueError, "Darwin21 through Darwin25"):
                builder._validate_kernel_collection_samples([("Darwin20", samples[0][1])])

    def test_missing_target_sample_does_not_emit_a_package(self):
        with tempfile.TemporaryDirectory(prefix="legacy-wifi-missing-target-") as directory:
            output = Path(directory) / "out.zip"
            with self.assertRaisesRegex(ValueError, "at least one user-selected target"):
                builder.prepare(Path("missing-io80211.zip"), Path("missing-corecapture.zip"),
                                output, [])
            self.assertFalse(output.exists())

    def test_generated_plist_has_literal_core_and_corecapture_executable_paths(self):
        with tempfile.TemporaryDirectory(prefix="legacy-wifi-config-fragment-") as directory:
            stage = Path(directory)
            config = builder._write_config_fragment(stage, "legacy-darwin21plus")
            actual = plistlib.loads((stage / "config-legacy-wifi.fragment.plist").read_bytes())
            self.assertEqual(actual, config)
            add = actual["Kernel"]["Add"]
            self.assertEqual(add[0]["ExecutablePath"], "Contents/MacOS/AirportBrcmCompat")
            self.assertEqual(add[1]["ExecutablePath"], "Contents/MacOS/corecaptureElCap")
            self.assertEqual(add[0]["MinKernel"], "21.0.0")
            self.assertEqual(add[0]["MaxKernel"], "")

    def test_mock_package_records_only_the_one_supplied_target_sample(self):
        with tempfile.TemporaryDirectory(prefix="legacy-wifi-single-target-package-") as directory:
            root = Path(directory)
            io_archive = root / "io80211.zip"
            core_archive = root / "corecapture.zip"
            target_kc = root / "darwin21.kc"
            output = root / "LegacyWiFiDependencies.zip"
            io_archive.write_bytes(b"mock archive path")
            core_archive.write_bytes(b"mock archive path")
            target_kc.write_bytes(b"mock official target BootKC")

            def extract_fixture(_archive_bytes, stage, relative, _excluded=()):
                if relative == builder.CORECAPTURE:
                    executable_paths = (builder.CORECAPTURE_BINARY,)
                else:
                    executable_paths = (builder.PROVIDER_EXECUTABLE,
                                        builder.DRIVER_4331_EXECUTABLE,
                                        builder.DRIVER_43224_EXECUTABLE)
                for executable in executable_paths:
                    path = stage / executable
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"mock executable")
                    path.chmod(0o755)

            def source_tree(stage):
                return {
                    builder.CORECAPTURE: stage / builder.CORECAPTURE_BINARY,
                    builder.PROVIDER: stage / builder.PROVIDER_EXECUTABLE,
                    builder.DRIVER_4331: stage / builder.DRIVER_4331_EXECUTABLE,
                    builder.DRIVER_43224: stage / builder.DRIVER_43224_EXECUTABLE,
                }

            namespace = {"mapping": {name: "Q" + name[1:]
                                      for name in builder.EXPECTED_CLASS_NAMES}}
            with mock.patch.object(builder, "_read_pinned_archive",
                                   side_effect=[b"mock io80211 source", b"mock corecapture source"]), \
                 mock.patch.object(builder.shutil, "which", return_value="codesign"), \
                 mock.patch.object(builder, "kernel_collection_classes",
                                   return_value=set(builder.EXPECTED_CLASS_NAMES)), \
                 mock.patch.object(builder, "_extract_selected_archive", side_effect=extract_fixture), \
                 mock.patch.object(builder, "_validated_source_tree", side_effect=source_tree), \
                 mock.patch.object(builder, "_patch_corecapture_namespace", return_value=namespace), \
                 mock.patch.object(builder, "_restrict_personality"), \
                 mock.patch.object(builder, "_sign_and_verify"), \
                 mock.patch.object(builder, "_verify_package_tree"):
                manifest = builder.prepare(io_archive, core_archive, output,
                                          [("Darwin21", target_kc)])

            self.assertEqual([sample["label"]
                              for sample in manifest["kernel_collection_collision_samples"]],
                             ["Darwin21"])
            with zipfile.ZipFile(output) as package:
                actual = plistlib.loads(package.read("config-legacy-wifi.fragment.plist"))
            add = actual["Kernel"]["Add"]
            self.assertEqual(add[0]["ExecutablePath"], "Contents/MacOS/AirportBrcmCompat")
            self.assertEqual(add[1]["ExecutablePath"], "Contents/MacOS/corecaptureElCap")
            self.assertTrue(all(entry["MinKernel"] == "21.0.0" for entry in add))

    def test_parser_follows_constructor_rip_literal_and_exact_terminator(self):
        raw = synthetic_macho()
        image = builder.parse_macho64(raw, "synthetic")
        value, offset = builder.constructor_class_name(raw, image, "CCPipe", "synthetic")
        self.assertEqual((value, offset), ("CCPipe", 0x240))
        self.assertEqual(builder.cstring_offsets(raw, image, b"CCPipe", "synthetic"), [0x240])
        self.assertEqual(builder.macho_meta_class_names(raw, image), set())
        self.assertIn("__ZN6CCPipe9MetaClassC2Ev", builder.macho_symbol_names(raw, image))

    def test_namespace_uses_same_length_name_and_skips_colliding_prefix(self):
        prefix, mapping = builder.namespace_class_names({"XCCapture"})
        self.assertEqual(prefix, "Q")
        self.assertEqual(mapping["CCCapture"], "QCCapture")
        self.assertTrue(all(len(old) == len(new) for old, new in mapping.items()))
        self.assertEqual(len(mapping), len(builder.EXPECTED_CLASS_NAMES))
        self.assertNotIn("XCCapture", mapping.values())
        with self.assertRaisesRegex(ValueError, "collision-free"):
            builder.namespace_class_names(set(), prefix_order="C")

    def test_archive_hash_failure_creates_no_output(self):
        with tempfile.TemporaryDirectory(prefix="legacy-wifi-hash-") as directory:
            root = Path(directory)
            first, second, output = root / "io.zip", root / "core.zip", root / "out.zip"
            target_kc = root / "darwin21.kc"
            first.write_bytes(b"not the pinned OCLP archive")
            second.write_bytes(b"other")
            target_kc.write_bytes(b"mock BootKC")
            samples = [("Darwin21", target_kc)]
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                builder.prepare(first, second, output, samples, profile="legacy-darwin21plus")
            self.assertFalse(output.exists())

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix="legacy-wifi-existing-") as directory:
            output = Path(directory) / "output.zip"
            output.mkdir()
            marker = output / "keep.txt"
            marker.write_text("keep")
            with self.assertRaisesRegex(ValueError, "already exists"):
                builder.prepare(Path("missing"), Path("missing"), output, [])
            self.assertEqual(marker.read_text(), "keep")

    def test_upstream_archive_path_traversal_is_rejected(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("IO80211ElCap.kext/../../outside", b"bad")
        with zipfile.ZipFile(io.BytesIO(payload.getvalue())) as archive:
            with self.assertRaisesRegex(ValueError, "unsafe path"):
                builder._safe_archive_members(archive, builder.PROVIDER)

    def test_personality_filter_is_narrow_and_explicit(self):
        with tempfile.TemporaryDirectory(prefix="legacy-wifi-personality-") as directory:
            bundle = Path(directory) / "Driver.kext"
            (bundle / "Contents/MacOS").mkdir(parents=True)
            (bundle / "Contents/MacOS/Driver").write_bytes(b"fixture")
            info = {"CFBundleExecutable": "Driver",
                    "IOKitPersonalities": {"Broadcom 802.11 PCI": {
                        "IOClass": "AirPort_Brcm4331",
                        "IOProviderClass": "IOPCIDevice",
                        "IONameMatch": ["pci14e4,4331", "pci14e4,432b"]}}}
            (bundle / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
            builder._restrict_personality(bundle, ("pci14e4,432b",))
            restricted = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
            self.assertEqual(restricted["IOKitPersonalities"]["Broadcom 802.11 PCI"]["IONameMatch"],
                             ["pci14e4,432b"])

    def test_personality_filter_keeps_only_the_selected_oclp_broadcom_set(self):
        with tempfile.TemporaryDirectory(prefix="legacy-wifi-personality-set-") as directory:
            bundle = Path(directory) / "Driver.kext"
            (bundle / "Contents/MacOS").mkdir(parents=True)
            (bundle / "Contents/MacOS/Driver").write_bytes(b"fixture")
            info = {"CFBundleExecutable": "Driver",
                    "IOKitPersonalities": {"Broadcom 802.11 PCI": {
                        "IOClass": "AirPort_Brcm43224",
                        "IOProviderClass": "IOPCIDevice",
                        "IONameMatch": ["pci106b,4e", "pci14e4,4328"]}}}
            (bundle / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
            selected = builder.TARGET_PCI_IDS["AppleAirPortBrcm43224.kext"]
            self.assertIn("pci106b,4e", selected)
            builder._restrict_personality(bundle, selected)
            restricted = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
            self.assertEqual(restricted["IOKitPersonalities"]["Broadcom 802.11 PCI"]["IONameMatch"],
                             list(selected))
            with self.assertRaisesRegex(ValueError, "pinned Apple alias"):
                builder._restrict_personality(bundle, ("pci106b,9999",))


@unittest.skipUnless(IO80211_ARCHIVE.is_file() and CORECAPTURE_ARCHIVE.is_file() and
                     all(path.is_file() for _label, path in KERNEL_COLLECTIONS) and
                     shutil.which("codesign") and shutil.which("nm"),
                     "requires pinned OCLP inputs, a target BootKC sample, codesign and nm")
class LegacyWiFiDependencyReleaseTests(unittest.TestCase):
    def test_real_dependencies_are_patched_signed_and_packaged(self):
        with tempfile.TemporaryDirectory(prefix="legacy-wifi-release-") as directory:
            output = Path(directory) / "LegacyWiFiDependencies.zip"
            manifest = builder.prepare(IO80211_ARCHIVE, CORECAPTURE_ARCHIVE,
                                       output, KERNEL_COLLECTIONS)
            self.assertEqual(manifest["status"],
                             "EFI_LEGACY_WIFI_DEPENDENCY_OFFLINE_CHECKED")
            self.assertEqual(manifest["input_sources"]["IO80211ElCap"]["sha256"],
                             builder.IO80211_SHA256)
            self.assertEqual(manifest["input_sources"]["corecaptureElCap"]["sha256"],
                             builder.CORECAPTURE_SHA256)
            self.assertEqual(manifest["corecapture_class_namespace"]["patched_binaries"][
                builder.CORECAPTURE]["literal_replacements"], len(builder.EXPECTED_CLASS_NAMES))
            self.assertEqual(manifest["corecapture_cpp_imports_preserved"],
                             list(builder.CORECAPTURE_REQUIRED_IMPORTS))
            self.assertEqual(manifest["dependency_profile"], "legacy-darwin21plus")
            self.assertEqual(manifest["minimum_kernel"], "21.0.0")

            with zipfile.ZipFile(output) as package:
                members = set(package.namelist())
                self.assertFalse(any("AirPortAtheros40" in name for name in members))
                self.assertEqual(len([name for name in members if name.endswith(".kext/Contents/Info.plist")]),
                                 4)
                config = plistlib.loads(package.read("config-legacy-wifi.fragment.plist"))
                add = config["Kernel"]["Add"]
                self.assertEqual([entry["BundlePath"] for entry in add],
                                 [builder.CORE_BUNDLE, builder.CORECAPTURE, builder.PROVIDER,
                                  builder.DRIVER_4331, builder.DRIVER_43224])
                self.assertEqual(add[0]["ExecutablePath"],
                                 "Contents/MacOS/AirportBrcmCompat")
                self.assertEqual(add[1]["ExecutablePath"],
                                 "Contents/MacOS/corecaptureElCap")
                self.assertTrue(all(entry["MinKernel"] == "21.0.0" and
                                    entry["Enabled"] for entry in add))
                self.assertTrue(all(entry["MinKernel"] == "21.0.0" and
                                    entry["Enabled"] for entry in config["Kernel"]["Block"]))
                self.assertFalse(any("IO80211FamilyLegacy" in entry["BundlePath"] or
                                     "AirPortBrcmNIC" in entry["BundlePath"] for entry in add))
                block_ids = {entry["Identifier"] for entry in config["Kernel"]["Block"]}
                self.assertEqual(block_ids, set(manifest["profile_blocks"]))
                self.assertEqual(manifest["personality_pci_ids"], {
                    "AirPortBrcm4331.kext": ["pci14e4,432b"],
                    "AppleAirPortBrcm43224.kext": list(builder.TARGET_PCI_IDS[
                        "AppleAirPortBrcm43224.kext"]),
                })
                self.assertFalse(manifest["hardware_validation"])
                self.assertIn("not hardware validation",
                              manifest["personality_pci_id_basis"])
                self.assertIn("not covered by this repository's BSD-3-Clause license",
                              package.read("NOTICE-legacy-wifi.txt").decode())

                executable_paths = {
                    builder.CORECAPTURE: builder.CORECAPTURE_BINARY,
                    builder.PROVIDER: builder.PROVIDER_EXECUTABLE,
                    builder.DRIVER_4331: builder.DRIVER_4331_EXECUTABLE,
                    builder.DRIVER_43224: builder.DRIVER_43224_EXECUTABLE,
                }
                source_execs = {
                    builder.CORECAPTURE: (CORECAPTURE_ARCHIVE, "corecaptureElCap.kext/Contents/MacOS/corecaptureElCap"),
                    builder.PROVIDER: (IO80211_ARCHIVE, "IO80211ElCap.kext/Contents/MacOS/IO80211ElCap"),
                    builder.DRIVER_4331: (IO80211_ARCHIVE, "IO80211ElCap.kext/Contents/PlugIns/AirPortBrcm4331.kext/Contents/MacOS/AirPortBrcm4331"),
                    builder.DRIVER_43224: (IO80211_ARCHIVE, "IO80211ElCap.kext/Contents/PlugIns/AppleAirPortBrcm43224.kext/Contents/MacOS/AppleAirPortBrcm43224"),
                }
                for bundle, executable_path in executable_paths.items():
                    signed_binary = package.read(executable_path)
                    image = builder.parse_macho64(signed_binary, executable_path)
                    self.assertEqual(
                        builder.file_backed_section_hashes(signed_binary, image),
                        manifest["corecapture_class_namespace"]["section_hashes_before_signing"][bundle])
                    source_archive, source_path = source_execs[bundle]
                    with zipfile.ZipFile(source_archive) as upstream:
                        source_binary = upstream.read(source_path)
                    source_image = builder.parse_macho64(source_binary, source_path)
                    self.assertEqual(builder.macho_symbol_names(signed_binary, image),
                                     builder.macho_symbol_names(source_binary, source_image))
                    for old_name, new_name in manifest["corecapture_class_namespace"]["mapping"].items():
                        self.assertEqual(builder.cstring_offsets(signed_binary, image,
                                                                 old_name.encode(), executable_path), [])
                    if bundle == builder.CORECAPTURE:
                        for old_name, new_name in manifest["corecapture_class_namespace"]["mapping"].items():
                            actual, _offset = builder.constructor_class_name(
                                signed_binary, image, old_name, executable_path)
                            self.assertEqual(actual, new_name)
                for executable in executable_paths.values():
                    self.assertNotEqual(package.getinfo(executable).external_attr >> 16 & 0o111, 0)

            extraction = Path(directory) / "extract"
            extraction.mkdir()
            builder._extract_package(output.read_bytes(), extraction)
            builder._verify_package_tree(extraction, config,
                                         manifest["corecapture_class_namespace"])


if __name__ == "__main__":
    unittest.main()
