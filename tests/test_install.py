import hashlib
import plistlib
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import install as tool


LILU = "as.vit9696.Lilu"
BUNDLES = {
    "AirportBrcmCompat.kext": ("org.geekaudio.AirportBrcmCompat", {
        LILU: "1.7.1"
    }, "AirportBrcmCompat"),
    "IOLegacyWFamily.kext": ("org.geekaudio.IOLegacyWFamilyKC", {LILU: "1.7.1"}, "IOLegacyWFamily"),
    "IO80211FamilyLegacy.kext": ("com.apple.iokit.IO80211FamilyLegacy", {
        "com.apple.iokit.IONetworkingFamily": "3.4", LILU: "1.7.1"
    }, "IO80211FamilyLegacy"),
    "AirPortBrcmNIC.kext": ("com.apple.driver.AirPort.BrcmNIC", {
        "org.geekaudio.IOLegacyWFamilyKC": "1.0",
        "com.apple.iokit.IO80211FamilyLegacy": "600.0"
    }, "AirPortBrcmNIC"),
    "AirportBrcmFixup.kext": ("as.lvs1974.AirportBrcmFixup", {LILU: "1.7.1"}, "AirportBrcmFixup"),
    "AirPortBrcmNIC_Injector.kext": ("as.lvs1974.AirportBrcmNICInjector",
                                      {"as.lvs1974.AirportBrcmFixup": "2.2.1"}, ""),
    "Lilu.kext": (LILU, {}, "Lilu"),
}


def info(bundle, identifier, libraries, executable):
    data = {
        "CFBundleIdentifier": identifier,
        "CFBundleVersion": ("1.7.2" if bundle == "Lilu.kext" else
                            "2.2.1" if bundle == "AirportBrcmFixup.kext" else "1.0.0"),
        "CFBundlePackageType": "KEXT",
        "OSBundleLibraries": libraries,
    }
    if executable:
        data["CFBundleExecutable"] = executable
    return plistlib.dumps(data)


def make_archive(path, *, split_nic=False, max_kernel=False, include_lilu=True):
    members = {}
    package_names = [name for name in BUNDLES if include_lilu or name != "Lilu.kext"]
    for bundle in package_names:
        identifier, libraries, executable = BUNDLES[bundle]
        members[f"Kexts/{bundle}/Contents/Info.plist"] = info(
            bundle, identifier, libraries, executable)
        if executable:
            members[f"Kexts/{bundle}/Contents/MacOS/{executable}"] = b"synthetic executable"
    entries = []
    order = ["Lilu.kext", "AirportBrcmCompat.kext", "AirportBrcmFixup.kext",
             "IOLegacyWFamily.kext", "IO80211FamilyLegacy.kext", "AirPortBrcmNIC.kext",
             "AirPortBrcmNIC_Injector.kext"]
    for bundle in order:
        if bundle not in package_names:
            continue
        entry = {
            "BundlePath": bundle,
            "Arch": "x86_64",
            "Enabled": True,
            "ExecutablePath": "Contents/MacOS/" + BUNDLES[bundle][2]
            if BUNDLES[bundle][2] else "",
            "PlistPath": "Contents/Info.plist",
            "MinKernel": "23.0.0",
            "MaxKernel": "24.99.99" if max_kernel and bundle == "AirPortBrcmNIC.kext" else "",
        }
        if bundle == "AirPortBrcmNIC.kext" and split_nic:
            entry["BundlePath"] = "AirPortBrcmNIC-Tahoe.kext"
        entries.append(entry)
    fragment = {
        "Kernel": {
            "Add": entries,
            "Block": [{
                "Arch": "x86_64",
                "Identifier": "com.apple.iokit.IO80211Family",
                "Strategy": "Exclude",
                "Enabled": True,
                "MinKernel": "23.0.0",
                "MaxKernel": "",
            }],
            "Quirks": {"DisableLinkeditJettison": True},
        }
    }
    members["config.plist"] = plistlib.dumps(fragment)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_oc(root, *, external_lilu=True, version="1.7.3"):
    oc = root / "EFI" / "OC"
    kexts = oc / "Kexts"
    kexts.mkdir(parents=True)
    if external_lilu:
        lib = kexts / "Lilu.kext"
        (lib / "Contents" / "MacOS").mkdir(parents=True)
        (lib / "Contents" / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": LILU, "CFBundleVersion": version,
            "CFBundleExecutable": "Lilu", "OSBundleLibraries": {},
        }))
        (lib / "Contents" / "MacOS" / "Lilu").write_bytes(b"existing Lilu")
    smc = kexts / "VirtualSMC.kext"
    (smc / "Contents" / "MacOS").mkdir(parents=True)
    (smc / "Contents" / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "as.vit9696.VirtualSMC",
        "CFBundleVersion": "1.0.0", "CFBundleExecutable": "VirtualSMC",
        "OSBundleLibraries": {"com.apple.kpi.iokit": "8.0.0"},
    }))
    (smc / "Contents" / "MacOS" / "VirtualSMC").write_bytes(b"existing VirtualSMC")
    config = {
        "Kernel": {
            "Add": ([{
                "BundlePath": "Lilu.kext", "Enabled": True, "Arch": "x86_64",
                "ExecutablePath": "Contents/MacOS/Lilu",
                "PlistPath": "Contents/Info.plist", "MinKernel": "23.0.0", "MaxKernel": "",
            }, {
                "BundlePath": "VirtualSMC.kext", "Enabled": True, "Arch": "x86_64",
                "ExecutablePath": "Contents/MacOS/VirtualSMC",
                "PlistPath": "Contents/Info.plist", "MinKernel": "23.0.0", "MaxKernel": "",
            }] if external_lilu else [{
                "BundlePath": "VirtualSMC.kext", "Enabled": True, "Arch": "x86_64",
                "ExecutablePath": "Contents/MacOS/VirtualSMC",
                "PlistPath": "Contents/Info.plist", "MinKernel": "23.0.0", "MaxKernel": "",
            }]),
            "Block": [{
                "Identifier": "com.apple.iokit.IO80211Family",
                "Strategy": "Exclude", "Enabled": True,
                "MinKernel": "23.0.0", "MaxKernel": "",
            }],
            "Quirks": {"DisableLinkeditJettison": True},
        },
        "NVRAM": {"Add": {"7C436110-AB2A-4BBB-A880-FE41995C9F82": {
            "csr-active-config": b"\x00\x00\x00\x00",
            "boot-args": "-v",
        }}},
        "PlatformInfo": {"Generic": {"ROM": b"\x00\x11\x22\x33\x44\x55",
                                       "MLB": "SERIAL-BOARD-ID"}},
    }
    (oc / "config.plist").write_bytes(plistlib.dumps(config))
    return oc


class UnifiedInstallerTests(unittest.TestCase):
    def test_dry_run_checks_hash_and_does_not_write_opencore_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "release.zip"
            checksum = make_archive(archive)
            oc = make_oc(base)
            before = (oc / "config.plist").read_bytes()

            result = tool.plan(archive, checksum, oc, "25.6.0")

            self.assertTrue(result["preflight"]["passed"])
            self.assertIn("staged AirportBrcmCompat kext group", result["preflight"]["scope"])
            self.assertTrue(result["external_lilu_used"])
            self.assertEqual((oc / "config.plist").read_bytes(), before)
            self.assertEqual({path.name for path in (oc / "Kexts").iterdir()},
                             {"Lilu.kext", "VirtualSMC.kext"})
            with self.assertRaisesRegex(tool.InstallError, "SHA-256"):
                tool.plan(archive, "0" * 64, oc, "25.6.0")

    def test_shared_package_rejects_system_split_and_kernel_ceiling(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "release.zip"
            checksum = make_archive(archive, split_nic=True)
            files = tool.read_archive(archive, checksum)
            infos = tool.validate_bundles(files)
            with self.assertRaisesRegex(tool.InstallError, "separate"):
                tool.validate_fragment(files["config.plist"], infos)

            checksum = make_archive(archive, max_kernel=True)
            files = tool.read_archive(archive, checksum)
            infos = tool.validate_bundles(files)
            with self.assertRaisesRegex(tool.InstallError, "maximum"):
                tool.validate_fragment(files["config.plist"], infos)

    def test_external_lilu_is_kept_without_reinstalling_package_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "release.zip"
            checksum = make_archive(archive)
            oc = make_oc(base, version="1.7.3")

            result = tool.plan(archive, checksum, oc, "23.0.0")

            self.assertTrue(result["external_lilu_used"])
            self.assertNotIn("Lilu.kext/Contents/Info.plist", result["bundles"])
            self.assertEqual((oc / "Kexts/Lilu.kext/Contents/MacOS/Lilu").read_bytes(),
                             b"existing Lilu")
            self.assertEqual([entry["BundlePath"] for entry in result["config"]["Kernel"]["Add"]
                              if entry.get("BundlePath") == "Lilu.kext"], ["Lilu.kext"])

    def test_unconfigured_lilu_at_package_path_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "release.zip"
            checksum = make_archive(archive)
            oc = make_oc(base, external_lilu=False)
            lilu = oc / "Kexts/Lilu.kext"
            (lilu / "Contents" / "MacOS").mkdir(parents=True)
            (lilu / "Contents/Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": LILU, "CFBundleVersion": "1.7.3",
            }))
            executable = lilu / "Contents/MacOS/Lilu"
            executable.write_bytes(b"unconfigured user copy")

            with self.assertRaisesRegex(tool.InstallError, "unconfigured Lilu"):
                tool.plan(archive, checksum, oc, "25.6.0")

            self.assertEqual(executable.read_bytes(), b"unconfigured user copy")

    def test_incompatible_external_lilu_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "release.zip"
            checksum = make_archive(archive)
            oc = make_oc(base, version="1.6.9")
            library = oc / "Kexts/Lilu.kext/Contents/MacOS/Lilu"
            before = library.read_bytes()

            with self.assertRaisesRegex(tool.InstallError, "older"):
                tool.plan(archive, checksum, oc, "24.0.0")

            self.assertEqual(library.read_bytes(), before)

    def test_apply_retires_only_known_old_bundles_and_keeps_other_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "release.zip"
            checksum = make_archive(archive)
            oc = make_oc(base)
            old = oc / "Kexts/AirPortBrcmNIC-Tahoe.kext"
            (old / "Contents").mkdir(parents=True)
            (old / "Contents/Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.apple.driver.AirPort.BrcmNIC",
                "CFBundleVersion": "old",
            }))
            config = plistlib.loads((oc / "config.plist").read_bytes())
            config["Kernel"]["Add"].append({
                "BundlePath": old.name, "Enabled": True, "Arch": "x86_64",
                "PlistPath": "Contents/Info.plist", "ExecutablePath": "",
                "MinKernel": "25.0.0", "MaxKernel": "",
            })
            unrelated = next(e for e in config["Kernel"]["Add"] if e["BundlePath"] == "VirtualSMC.kext")
            (oc / "config.plist").write_bytes(plistlib.dumps(config))
            result = tool.plan(archive, checksum, oc, "25.6.0")
            backup = base / "backup"

            applied = tool.apply(result, backup)

            self.assertTrue(applied["preflight"]["passed"])
            self.assertTrue((backup / "config.plist").is_file())
            self.assertFalse(old.exists())
            self.assertTrue((oc / "Kexts/AirPortBrcmNIC.kext/Contents/Info.plist").is_file())
            installed = plistlib.loads((oc / "config.plist").read_bytes())
            self.assertEqual(installed["NVRAM"]["Add"][
                "7C436110-AB2A-4BBB-A880-FE41995C9F82"]["csr-active-config"],
                b"\x00\x00\x00\x00")
            self.assertEqual(installed["PlatformInfo"]["Generic"]["ROM"],
                             b"\x00\x11\x22\x33\x44\x55")
            executable = oc / "Kexts/AirportBrcmCompat.kext/Contents/MacOS/AirportBrcmCompat"
            info = oc / "Kexts/AirportBrcmCompat.kext/Contents/Info.plist"
            self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(info.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(executable.parent.stat().st_mode), 0o755)
            self.assertIn(unrelated, installed["Kernel"]["Add"])
            self.assertTrue((oc / "Kexts/VirtualSMC.kext/Contents/MacOS/VirtualSMC").is_file())
            self.assertNotIn(old.name, [entry["BundlePath"] for entry in installed["Kernel"]["Add"]])

    def test_failed_post_install_preflight_restores_the_previous_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "release.zip"
            checksum = make_archive(archive)
            oc = make_oc(base)
            old = oc / "Kexts/AirPortBrcmNIC-Tahoe.kext"
            (old / "Contents").mkdir(parents=True)
            (old / "Contents/Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.apple.driver.AirPort.BrcmNIC",
                "CFBundleVersion": "old",
            }))
            config = plistlib.loads((oc / "config.plist").read_bytes())
            config["Kernel"]["Add"].append({
                "BundlePath": old.name, "Enabled": True, "Arch": "x86_64",
                "PlistPath": "Contents/Info.plist", "ExecutablePath": "",
                "MinKernel": "25.0.0", "MaxKernel": "",
            })
            original_config = plistlib.dumps(config)
            (oc / "config.plist").write_bytes(original_config)
            original_old = (old / "Contents/Info.plist").read_bytes()
            result = tool.plan(archive, checksum, oc, "25.6.0")

            with mock.patch.object(tool, "check_staged", return_value={"passed": False,
                                                                        "errors": ["injected"]}):
                with self.assertRaisesRegex(tool.InstallError, "failed preflight"):
                    tool.apply(result, base / "backup")

            self.assertEqual((oc / "config.plist").read_bytes(), original_config)
            self.assertEqual((old / "Contents/Info.plist").read_bytes(), original_old)
            self.assertFalse((oc / "Kexts/AirPortBrcmNIC.kext").exists())

    def test_apply_requires_new_backup_outside_oc(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "release.zip"
            checksum = make_archive(archive)
            oc = make_oc(base)
            result = tool.plan(archive, checksum, oc, "24.0.0")

            with self.assertRaisesRegex(tool.InstallError, "outside"):
                tool.apply(result, oc / "backup")

    def test_backup_must_be_outside_efi_not_only_outside_oc(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "release.zip"
            checksum = make_archive(archive)
            oc = make_oc(base)
            result = tool.plan(archive, checksum, oc, "24.0.0")

            with self.assertRaisesRegex(tool.InstallError, "outside EFI"):
                tool.apply(result, oc.parent / "backup")

    def test_change_during_staging_is_preserved_without_install_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "release.zip"
            checksum = make_archive(archive)
            oc = make_oc(base)
            result = tool.plan(archive, checksum, oc, "25.6.0")
            config_path = oc / "config.plist"
            original_config = config_path.read_bytes()
            backup = base / "backup"
            original_stage = tool.write_staged_payload

            def stage_then_edit_config(files, destination):
                original_stage(files, destination)
                concurrent = plistlib.loads(config_path.read_bytes())
                concurrent["ConcurrentEditor"] = "preserve me"
                config_path.write_bytes(plistlib.dumps(concurrent))

            with mock.patch.object(tool, "write_staged_payload", side_effect=stage_then_edit_config):
                with self.assertRaisesRegex(tool.InstallError, "while the install payload"):
                    tool.apply(result, backup)

            current = plistlib.loads(config_path.read_bytes())
            self.assertEqual(current["ConcurrentEditor"], "preserve me")
            self.assertEqual((backup / "config.plist").read_bytes(), original_config)
            self.assertFalse((oc / "Kexts/AirportBrcmCompat.kext").exists())
            self.assertEqual(list((oc / "Kexts").glob(".airportbrcmcompat-stage-*")), [])

    def test_changed_target_after_preflight_aborts_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "release.zip"
            checksum = make_archive(archive)
            oc = make_oc(base)
            result = tool.plan(archive, checksum, oc, "25.6.0")
            old = oc / "Kexts/AirPortBrcmNIC-Tahoe.kext"
            (old / "Contents").mkdir(parents=True)
            (old / "Contents/Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": tool.NIC, "CFBundleVersion": "old",
            }))
            before = (oc / "config.plist").read_bytes()
            with self.assertRaisesRegex(tool.InstallError, "changed after preflight"):
                tool.apply(result, base / "backup")
            self.assertEqual((oc / "config.plist").read_bytes(), before)
            self.assertFalse((oc / "Kexts/AirPortBrcmNIC.kext").exists())
            self.assertFalse((base / "backup").exists())

    def test_duplicate_active_bundle_identifier_aborts_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "release.zip"
            checksum = make_archive(archive)
            oc = make_oc(base)
            extra = oc / "Kexts/ExtraNIC.kext"
            (extra / "Contents" / "MacOS").mkdir(parents=True)
            (extra / "Contents/Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": tool.NIC, "CFBundleVersion": "1.0",
                "CFBundleExecutable": "ExtraNIC", "OSBundleLibraries": {},
            }))
            (extra / "Contents/MacOS/ExtraNIC").write_bytes(b"unknown active NIC")
            config = plistlib.loads((oc / "config.plist").read_bytes())
            config["Kernel"]["Add"].append({
                "BundlePath": "ExtraNIC.kext", "Enabled": True, "Arch": "x86_64",
                "ExecutablePath": "Contents/MacOS/ExtraNIC", "PlistPath": "Contents/Info.plist",
                "MinKernel": "23.0.0", "MaxKernel": "",
            })
            (oc / "config.plist").write_bytes(plistlib.dumps(config))
            before = (oc / "config.plist").read_bytes()
            with self.assertRaisesRegex(tool.InstallError, "Duplicate component identifiers"):
                tool.plan(archive, checksum, oc, "25.6.0")
            self.assertEqual((oc / "config.plist").read_bytes(), before)

    def test_symlinked_old_bundle_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "release.zip"
            checksum = make_archive(archive)
            oc = make_oc(base)
            outside = base / "outside.kext"
            outside.mkdir()
            (outside / "Contents").mkdir()
            (outside / "Contents/Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": tool.NIC, "CFBundleVersion": "old",
            }))
            (oc / "Kexts/AirPortBrcmNIC-Tahoe.kext").symlink_to(outside, target_is_directory=True)
            config = plistlib.loads((oc / "config.plist").read_bytes())
            config["Kernel"]["Add"].append({
                "BundlePath": "AirPortBrcmNIC-Tahoe.kext", "Enabled": True, "Arch": "x86_64",
                "ExecutablePath": "", "PlistPath": "Contents/Info.plist",
                "MinKernel": "25.0.0", "MaxKernel": "",
            })
            (oc / "config.plist").write_bytes(plistlib.dumps(config))
            with self.assertRaises(tool.InstallError):
                tool.plan(archive, checksum, oc, "25.6.0")
            self.assertTrue((outside / "Contents/Info.plist").is_file())


if __name__ == "__main__":
    unittest.main()
