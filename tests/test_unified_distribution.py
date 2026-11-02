"""Integration checks for the two flat, complete Wi-Fi delivery ZIPs."""

from pathlib import Path
import json
import plistlib
import shutil
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import package_release as package
import install as installer
import unify_wifi_dependencies as unify
import verify_unified_nic as nic_verifier
import prepare_broadcom_injector as injector_builder
from brcmctl import applies, preflight, version


SONOMA = ROOT / "build/compatibility-profiles/sonoma14-dependencies.zip"
SEQUOIA = ROOT / "build/compatibility-profiles/sequoia15-dependencies.zip"
TAHOE = ROOT / "build/compatibility-profiles/tahoe26-dependencies.zip"
FIXUP = ROOT / "build/research/AirportBrcmFixup-2.2.1-RELEASE.zip"
RUNTIME = ROOT / "build/research/Lilu-1.7.2-RELEASE.zip"


class UnifiedDistributionTests(unittest.TestCase):
    def test_actual_packages_install_into_temporary_oc_copies(self):
        for flavor,path in self.output_archives.items():
            for darwin in ('23.0.0','24.0.0','25.0.0'):
                with self.subTest(flavor=flavor,darwin=darwin),tempfile.TemporaryDirectory() as temporary:
                    root=Path(temporary);oc=root/'EFI/OC';(oc/'Kexts').mkdir(parents=True)
                    config={'Kernel':{'Add':[],'Block':[],'Quirks':{}},
                            'NVRAM':{'Add':{'proof':{'existing-data':b'\x01\x02'}}}}
                    (oc/'config.plist').write_bytes(plistlib.dumps(config))
                    plan=installer.plan(path,package.sha(path.read_bytes()),oc,darwin)
                    self.assertEqual(list((oc/'Kexts').iterdir()),[])
                    result=installer.apply(plan,root/'backup')
                    self.assertTrue(result['preflight']['passed'])
                    actual=plistlib.loads((oc/'config.plist').read_bytes())
                    self.assertEqual(actual['NVRAM'],config['NVRAM'])
                    installed={p.relative_to(oc).as_posix():p.read_bytes()
                               for p in (oc/'Kexts').rglob('*') if p.is_file()}
                    package.verify_signatures(installed)

    @classmethod
    def setUpClass(cls):
        for path in (SONOMA, SEQUOIA, TAHOE, FIXUP, RUNTIME):
            if not path.is_file():
                raise FileNotFoundError(f"Required pinned offline input is missing: {path}")
        cls.temporary = tempfile.TemporaryDirectory(prefix="brcm-unified-delivery-tests-")
        cls.root = Path(cls.temporary.name)
        cls.dependency_zip = cls.root / "dependencies.zip"
        cls.dependency_manifest = unify.unify(SONOMA, SEQUOIA, TAHOE, cls.dependency_zip)
        cls.additional_zip = cls.root / "additional.zip"
        injector_builder.prepare(FIXUP, cls.additional_zip, "automatic")

        raw_dependencies = package.read_files(cls.dependency_zip)
        dependencies = package.installation_files(
            raw_dependencies,
            tuple("Kexts/" + name + ".kext" for name in (
                "IOLegacyWFamily", "IO80211FamilyLegacy", "AirPortBrcmNIC")))
        additional_raw = package.read_files(cls.additional_zip)
        optional_manifest = json.loads(additional_raw["manifest.json"])
        additional = package.installation_files(
            additional_raw, ("AirportBrcmFixup.kext",), ("config.additional-cards.plist",))
        cls.flat_optional = package.flat_additional_cards(additional)
        cls.runtime = package.runtime_files(RUNTIME)

        cls.payloads = {}
        for flavor, source in (
            ("RELEASE", ROOT / "AirportBrcmCompat.kext"),
            ("DEBUG", ROOT / "Variants/DEBUG/AirportBrcmCompat.kext"),
        ):
            core = {"Kexts/" + name: data for name, data in
                    package.installation_files(package.read_files(cls._bundle_zip(source)),
                                               ("AirportBrcmCompat.kext",)).items()}
            payload = {**dependencies, **cls.flat_optional, **cls.runtime, **core}
            payload["config.plist"] = plistlib.dumps(
                package.install_configuration(payload, flavor), sort_keys=False)
            package.validate_installation(payload)
            example = plistlib.loads(
                (ROOT / f"Examples/config-WiFi-{flavor}.example.plist").read_bytes())
            self_config = plistlib.loads(payload["config.plist"])
            if example != self_config:
                raise AssertionError(f"{flavor} example configuration differs from packaged config")
            cls.payloads[flavor] = payload

        # The same production packager helper selects the only two custom ZIP
        # names; metadata files stay outside those installation archives.
        cls.zip_names = package.release_filenames("1.1.0")
        cls.output_dir = cls.root / "distribution"
        cls.output_dir.mkdir()
        cls.output_archives = {}
        for flavor in ("RELEASE", "DEBUG"):
            name = cls.zip_names[flavor]
            path = cls.output_dir / name
            package.write_zip(path, cls.payloads[flavor])
            cls.output_archives[flavor] = path

    @classmethod
    def _bundle_zip(cls, bundle):
        """Read a tracked bundle into an in-memory ZIP for the packager filter."""
        data = cls.root / (bundle.name + ".zip")
        with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in bundle.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(bundle.parent).as_posix())
        return data

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_nic_evidence_accepts_the_one_pinned_binary_for_shared_installation(self):
        report = self.dependency_manifest["unified_nic"]
        self.assertIn("does not establish runtime compatibility", report["scope"])
        self.assertFalse(report["runtime_tested"])
        self.assertEqual(report["candidate"]["binary_sha256"],
                         nic_verifier.EXPECTED_BINARY_SHA256["tahoe"])
        roles = {item["role"]: item for item in report["inputs"]}
        self.assertEqual(roles["sonoma"]["binary_sha256"],
                         nic_verifier.EXPECTED_BINARY_SHA256["sonoma"])
        self.assertEqual(roles["tahoe"]["binary_sha256"],
                         nic_verifier.EXPECTED_BINARY_SHA256["tahoe"])

    def test_unified_dependency_archive_has_one_flat_nic_and_shared_config(self):
        with zipfile.ZipFile(self.dependency_zip) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        manifest = json.loads(files["manifest.json"])
        bundles = [name for name in files if name.endswith("/Contents/Info.plist")]
        self.assertEqual(manifest["nic_variants"], 1)
        self.assertIn("Kexts/AirPortBrcmNIC.kext/Contents/Info.plist", bundles)
        self.assertFalse(any("AirPortBrcmNIC-" in name for name in bundles))
        self.assertFalse(any("/PlugIns/" in name for name in files))

        fragment = plistlib.loads(files["config.fragment.plist"])
        nic_entries = [entry for entry in fragment["Kernel"]["Add"]
                       if entry["BundlePath"] == "AirPortBrcmNIC.kext"]
        self.assertEqual(len(nic_entries), 1)
        self.assertEqual(nic_entries[0]["MinKernel"], "23.0.0")
        self.assertEqual(nic_entries[0]["MaxKernel"], "")
        for target in ("23.0.0", "24.0.0", "25.0.0", "26.0.0", "99.0.0"):
            active = [entry["BundlePath"] for entry in fragment["Kernel"]["Add"]
                      if applies(entry, version(target))]
            self.assertEqual(active.count("AirPortBrcmNIC.kext"), 1)
            self.assertFalse(any("AirPortBrcmNIC-" in name for name in active))

    def test_both_installers_are_complete_flat_and_differ_only_in_core_flavor(self):
        expected_bundles = {
            "AirportBrcmCompat.kext", "IOLegacyWFamily.kext", "IO80211FamilyLegacy.kext",
            "AirPortBrcmNIC.kext", "AirportBrcmFixup.kext",
            "AirPortBrcmNIC_Injector.kext", "Lilu.kext",
        }
        for flavor, path in self.output_archives.items():
            with zipfile.ZipFile(path) as archive:
                names = set(archive.namelist())
                self.assertEqual(archive.testzip(), None)
                self.assertIn("config.plist", names)
                self.assertTrue(all(name.startswith("Kexts/") or name == "config.plist"
                                    for name in names))
                self.assertFalse(any("/PlugIns/" in name for name in names))
                self.assertFalse(any("AirPortBrcmNIC-" in name for name in names))
                actual_bundles = {
                    name.split("/", 2)[1] for name in names if name.startswith("Kexts/")
                }
                self.assertEqual(actual_bundles, expected_bundles)
                fragment = plistlib.loads(archive.read("config.plist"))
                entries = fragment["Kernel"]["Add"]
                self.assertEqual(len(entries), 7)
                self.assertTrue(all(entry["MinKernel"] == "23.0.0" and
                                    entry["MaxKernel"] == "" for entry in entries))
                for target in ("23.0.0", "24.0.0", "25.0.0", "26.0.0", "99.0.0"):
                    report = preflight(self._stage(payload=archive), target)
                    self.assertTrue(report["passed"], report["errors"])

        release = package.read_files(self.output_archives["RELEASE"])
        debug = package.read_files(self.output_archives["DEBUG"])
        for name in release.keys() & debug.keys():
            if name.startswith("Kexts/AirportBrcmCompat.kext/"):
                continue
            self.assertEqual(release[name], debug[name], name)
        self.assertNotEqual(release["Kexts/AirportBrcmCompat.kext/Contents/MacOS/AirportBrcmCompat"],
                            debug["Kexts/AirportBrcmCompat.kext/Contents/MacOS/AirportBrcmCompat"])

    def test_release_assets_are_exactly_two_sorted_installer_zips(self):
        names = self.zip_names
        self.assertEqual(names["RELEASE"], "01-AirportBrcmCompat-1.1.0-RELEASE.zip")
        self.assertEqual(names["DEBUG"], "02-AirportBrcmCompat-1.1.0-DEBUG.zip")
        self.assertEqual([name for name in names.values() if name.endswith(".zip")],
                         [names["RELEASE"], names["DEBUG"]])
        self.assertEqual({path.name for path in self.output_dir.glob("*.zip")},
                         {names["RELEASE"], names["DEBUG"]})

    def test_runtime_and_fixup_inputs_are_pinned_and_flattened_code_stays_intact(self):
        from verify_lilu_release_compatibility import RELEASES
        self.assertEqual(package.sha(RUNTIME.read_bytes()), RELEASES["1.7.2"]["asset_sha256"])
        self.assertIn("Kexts/Lilu.kext/Contents/MacOS/Lilu", self.runtime)
        with self.assertRaisesRegex(ValueError, "pinned release"):
            corrupted = self.root / "corrupt-runtime.zip"
            shutil.copyfile(RUNTIME, corrupted)
            corrupted.write_bytes(corrupted.read_bytes() + b"bad")
            package.runtime_files(corrupted)

        with zipfile.ZipFile(self.additional_zip) as archive:
            optional = {name: archive.read(name) for name in archive.namelist()}
        original = optional["AirportBrcmFixup.kext/Contents/MacOS/AirportBrcmFixup"]
        flattened = self.flat_optional["Kexts/AirportBrcmFixup.kext/Contents/MacOS/AirportBrcmFixup"]
        from prepare_broadcom_injector import _check_executable_sections
        _check_executable_sections(original, flattened)
        self.assertIn("Kexts/AirPortBrcmNIC_Injector.kext/Contents/Info.plist", self.flat_optional)
        self.assertFalse(any("/PlugIns/" in name for name in self.flat_optional))

    def _stage(self, payload):
        root = Path(self.temporary.name) / "preflight"
        if root.exists():
            shutil.rmtree(root)
        root.mkdir()
        for name in payload.namelist():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload.read(name))
        return root


if __name__ == "__main__":
    unittest.main()
