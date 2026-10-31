import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile
import unittest
import warnings
import zipfile


PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "airport_public_tests.combine_wifi_dependency_profiles",
    PROJECT / "tools" / "combine_wifi_dependency_profiles.py")
combine_tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = combine_tool
SPEC.loader.exec_module(combine_tool)

SONOMA = PROJECT / "build/compatibility-profiles/sonoma14-dependencies.zip"
TAHOE = PROJECT / "build/compatibility-profiles/tahoe26-dependencies.zip"


class CombineWifiDependencyProfileTests(unittest.TestCase):
    def _read_zip(self, path):
        with zipfile.ZipFile(path) as archive:
            return {info.filename: archive.read(info) for info in archive.infolist()}

    def test_combined_fragment_has_only_wifi_routing_and_required_core_quirk(self):
        config = combine_tool._combined_config()
        self.assertEqual(set(config), {"Kernel"})
        kernel = config["Kernel"]
        self.assertEqual(set(kernel), {"Add", "Block", "Quirks"})
        entries = kernel["Add"]
        self.assertEqual([entry["BundlePath"] for entry in entries], [
            "AirportBrcmCompat.kext",
            "IOLegacyWFamily.kext",
            "IO80211FamilyLegacy.kext",
            "AirPortBrcmNIC-Sonoma-Sequoia.kext",
            "AirPortBrcmNIC-Tahoe.kext",
        ])
        self.assertEqual((entries[0]["MinKernel"], entries[0]["MaxKernel"]),
                         ("23.0.0", ""))
        self.assertEqual((entries[1]["MinKernel"], entries[1]["MaxKernel"]),
                         ("23.0.0", ""))
        self.assertEqual((entries[2]["MinKernel"], entries[2]["MaxKernel"]),
                         ("23.0.0", ""))
        self.assertEqual((entries[3]["MinKernel"], entries[3]["MaxKernel"]),
                         ("23.0.0", "24.99.99"))
        self.assertEqual((entries[4]["MinKernel"], entries[4]["MaxKernel"]),
                         ("25.0.0", ""))
        self.assertEqual(kernel["Block"][0]["Identifier"],
                         "com.apple.iokit.IO80211Family")
        self.assertEqual((kernel["Block"][0]["MinKernel"],
                          kernel["Block"][0]["MaxKernel"]), ("23.0.0", ""))
        self.assertEqual(kernel["Quirks"], {"DisableLinkeditJettison": True})

    def test_common_dependency_payload_comparison_is_byte_exact(self):
        left = {}
        for bundle, paths in combine_tool.COMMON_RELATIVE_FILES.items():
            for relative in paths:
                left[f"Kexts/{bundle}/{relative}"] = b"same bytes"
        right = dict(left)
        hashes = combine_tool._compare_common_payloads(left, right)
        self.assertEqual(set(hashes), set(left))
        right[next(iter(right))] = b"different bytes"
        with self.assertRaisesRegex(combine_tool.CombineError,
                                    "differs byte-for-byte"):
            combine_tool._compare_common_payloads(left, right)

    def test_preflight_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "traversal.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../outside", b"bad")
            with zipfile.ZipFile(path) as archive:
                with self.assertRaisesRegex(combine_tool.CombineError, "Unsafe ZIP member path"):
                    combine_tool._preflight_zip(
                        archive, combine_tool.PROFILES["sonoma-sequoia"])

    def test_preflight_rejects_duplicate_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("manifest.json", b"first")
                    archive.writestr("manifest.json", b"second")
            with zipfile.ZipFile(path) as archive:
                with self.assertRaisesRegex(combine_tool.CombineError, "Duplicate ZIP member"):
                    combine_tool._preflight_zip(
                        archive, combine_tool.PROFILES["sonoma-sequoia"])

    def test_preflight_rejects_symlink_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "symlink.zip"
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(info, b"../outside")
            with zipfile.ZipFile(path) as archive:
                with self.assertRaisesRegex(combine_tool.CombineError,
                                            "Symlink ZIP member is not accepted"):
                    combine_tool._preflight_zip(
                        archive, combine_tool.PROFILES["sonoma-sequoia"])


@unittest.skipUnless(SONOMA.is_file() and TAHOE.is_file() and shutil.which("/usr/bin/codesign"),
                     "requires the two pinned profile ZIPs and macOS codesign")
class CombineWifiDependencyProfileReleaseTests(unittest.TestCase):
    def _read_zip(self, path):
        with zipfile.ZipFile(path) as archive:
            return {info.filename: archive.read(info) for info in archive.infolist()}

    def _rewrite_profile(self, source_path, destination, transform):
        with zipfile.ZipFile(source_path) as source:
            members = [(info, source.read(info)) for info in source.infolist()]
        files = {info.filename: data for info, data in members}
        manifest = json.loads(files["manifest.json"])
        transform(files, manifest)
        files["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as target:
            for info, _ in members:
                target.writestr(info, files[info.filename])
        return manifest

    def test_pinned_profiles_combine_with_signatures_and_common_bytes_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "cross-version-wifi.zip"
            manifest = combine_tool.combine(SONOMA, TAHOE, output)
            sonoma_files = self._read_zip(SONOMA)
            tahoe_files = self._read_zip(TAHOE)
            output_files = self._read_zip(output)

            expected_bundles = {
                "IOLegacyWFamily.kext", "IO80211FamilyLegacy.kext",
                "AirPortBrcmNIC-Sonoma-Sequoia.kext", "AirPortBrcmNIC-Tahoe.kext",
            }
            output_bundles = {name.split("/", 2)[1] for name in output_files
                              if name.startswith("Kexts/")}
            self.assertEqual(output_bundles, expected_bundles)
            self.assertFalse(any(word in bundle.lower() for bundle in output_bundles
                                 for word in ("bluetooth", "bluetool", "amfi", "btf", "lilu")))
            for bundle, relative_paths in combine_tool.COMMON_RELATIVE_FILES.items():
                for relative in relative_paths:
                    name = f"Kexts/{bundle}/{relative}"
                    self.assertEqual(sonoma_files[name], tahoe_files[name])
                    self.assertEqual(output_files[name], sonoma_files[name])
            for profile, source_files in (("sonoma-sequoia", sonoma_files), ("tahoe", tahoe_files)):
                bundle = combine_tool.PROFILES[profile]["bundle"]
                prefix = f"Kexts/{bundle}/"
                for name, data in source_files.items():
                    if name.startswith(prefix):
                        self.assertEqual(output_files[name], data)

            config = plistlib.loads(output_files["config.fragment.plist"])
            entries = config["Kernel"]["Add"]
            self.assertEqual(entries[0]["BundlePath"], "AirportBrcmCompat.kext")
            self.assertEqual(entries[0]["MinKernel"], "23.0.0")
            self.assertEqual(entries[0]["MaxKernel"], "")
            self.assertEqual(entries[3]["MaxKernel"], "24.99.99")
            self.assertEqual(entries[4]["MinKernel"], "25.0.0")
            self.assertEqual(entries[4]["MaxKernel"], "")
            self.assertEqual(config["Kernel"]["Quirks"],
                             {"DisableLinkeditJettison": True})
            self.assertTrue(manifest["checks"]["strict_codesign_verified"])
            self.assertEqual(manifest["profiles"][0]["name"], "sonoma-sequoia")
            self.assertEqual(manifest["profiles"][1]["name"], "tahoe")

            with tempfile.TemporaryDirectory() as extracted:
                root = Path(extracted)
                for name, data in output_files.items():
                    if name.startswith("Kexts/"):
                        target = root.joinpath(*name.split("/"))
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(data)
                for bundle in expected_bundles:
                    combine_tool._verify_codesign(root / "Kexts" / bundle)

    def test_native_target_sample_metadata_may_change_with_same_kext_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            changed = root / "different-native-sample.zip"
            output = root / "combined.zip"

            def alter_native_sample(_files, manifest):
                sample = manifest["native_skywalk_sample"]
                sample["label"] = "Sonoma14.8.x alternate native KC"
                sample["macho_uuid"] = "11223344-5566-7788-99AA-BBCCDDEEFF00"
                sample["macho_load_commands_sha256"] = "a" * 64

            changed_manifest = self._rewrite_profile(SONOMA, changed, alter_native_sample)
            output_manifest = combine_tool.combine(changed, TAHOE, output)
            output_sample = output_manifest["profiles"][0]["native_skywalk_sample"]
            self.assertEqual(output_sample, changed_manifest["native_skywalk_sample"])
            self.assertTrue(output.is_file())

    def test_changed_kext_and_forged_manifest_hash_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tampered = root / "tampered-sonoma.zip"
            output = root / "should-not-exist.zip"
            bundle = combine_tool.PROFILES["sonoma-sequoia"]["bundle"]
            executable = f"Kexts/{bundle}/Contents/MacOS/AirPortBrcmNIC"

            def alter_kext_and_forge_hash(files, manifest):
                changed = bytearray(files[executable])
                changed[-1] ^= 0x01
                files[executable] = bytes(changed)
                record = next(item for item in manifest["binaries"]
                              if item["bundle"] == bundle)
                record["output_sha256"] = combine_tool.sha256(files[executable])

            self._rewrite_profile(SONOMA, tampered, alter_kext_and_forge_hash)
            with self.assertRaisesRegex(combine_tool.CombineError,
                                        "Pinned manifest binary record differs"):
                combine_tool.combine(tampered, TAHOE, output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
