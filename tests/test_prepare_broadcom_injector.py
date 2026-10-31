import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import zipfile
import plistlib


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'tools'))
import prepare_broadcom_injector as prepare_tool


OFFICIAL_ARCHIVE = PROJECT / 'build/research/AirportBrcmFixup-2.2.1-RELEASE.zip'


class PrepareBroadcomInjectorPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='prepare-brcm-preflight-')
        self.root = Path(self.temporary.name)
        self.archive = self.root / 'not-the-release.zip'
        self.archive.write_bytes(b'not the pinned upstream archive')
        self.output = self.root / 'candidate.zip'

    def tearDown(self):
        self.temporary.cleanup()

    def test_archive_hash_failure_creates_no_output(self):
        with self.assertRaisesRegex(ValueError, 'official AirportBrcmFixup'):
            prepare_tool.prepare(self.archive, self.output, 'sonoma-sequoia')
        self.assertFalse(self.output.exists())

    def test_existing_directory_output_is_not_overwritten(self):
        self.output.mkdir()
        marker = self.output / 'keep.txt'
        marker.write_text('existing output')
        with self.assertRaisesRegex(ValueError, 'Output already exists'):
            prepare_tool.prepare(self.archive, self.output, 'sonoma-sequoia')
        self.assertEqual(marker.read_text(), 'existing output')

    def test_unknown_profile_creates_no_output(self):
        with self.assertRaisesRegex(ValueError, 'Unknown dependency profile'):
            prepare_tool.prepare(self.archive, self.output, 'darwin-99')
        self.assertFalse(self.output.exists())

    def test_id_policy_is_exactly_three_base_and_five_additional_ids(self):
        prepare_tool._check_id_policy()
        self.assertEqual(len(prepare_tool.MATCH_IDS), 8)
        self.assertEqual(len(prepare_tool.ADDITIONAL_IDS), 5)
        self.assertEqual(set(prepare_tool.BASE_IDS) | set(prepare_tool.ADDITIONAL_IDS),
                         set(prepare_tool.MATCH_IDS))


@unittest.skipUnless(OFFICIAL_ARCHIVE.is_file() and shutil.which('codesign'),
                     'requires the ignored official release ZIP and macOS codesign')
class PrepareBroadcomInjectorReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='prepare-brcm-release-', dir='/private/tmp')
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_real_release_profiles_and_signatures(self):
        expected_profiles = {
            'sonoma-sequoia': ('23.0.0', '24.99.99'),
            'tahoe': ('25.0.0', ''),
            'automatic': ('23.0.0', ''),
        }
        with zipfile.ZipFile(OFFICIAL_ARCHIVE) as upstream:
            upstream_executable = upstream.read(prepare_tool.EXECUTABLE)

        for profile, expected_kernel_range in expected_profiles.items():
            with self.subTest(profile=profile):
                output = self.root / f'{profile}.zip'
                manifest = prepare_tool.prepare(OFFICIAL_ARCHIVE, output, profile)
                with zipfile.ZipFile(output) as package:
                    names = package.namelist()
                    self.assertFalse(any('AirPortBrcm4360_Injector.kext' in name for name in names))
                    self.assertIn(prepare_tool.CORE + '/Contents/Info.plist', names)
                    self.assertIn(prepare_tool.INJECTOR + '/Contents/Info.plist', names)
                    self.assertEqual(package.read('LICENSE-AirportBrcmFixup.txt'),
                                     (PROJECT / 'LICENSES/AirportBrcmFixup-LICENSE.txt').read_bytes())
                    config = plistlib.loads(package.read('config.additional-cards.plist'))
                    entries = config['Kernel']['Add']
                    self.assertEqual([entry['BundlePath'] for entry in entries],
                                     [prepare_tool.CORE, prepare_tool.INJECTOR])
                    self.assertEqual(len(entries), 2)
                    self.assertTrue(all((entry['MinKernel'], entry['MaxKernel']) == expected_kernel_range
                                        for entry in entries))
                    self.assertEqual(manifest['minimum_kernel'], expected_kernel_range[0])
                    self.assertEqual(manifest['maximum_kernel'], expected_kernel_range[1])
                    self.assertEqual(manifest['status'], 'ADDITIONAL_CARD_MATCHING_CANDIDATE')
                    self.assertTrue(manifest['requires_matching_wifi_dependency_profile'])
                    self.assertEqual(manifest['injector_match_pci_ids'],
                                     ['14e4:' + item for item in prepare_tool.MATCH_IDS])
                    self.assertEqual(manifest['additional_pci_ids'],
                                     ['14e4:' + item for item in prepare_tool.ADDITIONAL_IDS])
                    self.assertEqual(set(plistlib.loads(package.read(
                        prepare_tool.INJECTOR + '/Contents/Info.plist'))[
                            'IOKitPersonalities']['Airport_BrcmNIC']['IONameMatch']),
                                     {'pci14e4,' + item for item in prepare_tool.MATCH_IDS})

                    packaged_executable = package.read(prepare_tool.EXECUTABLE)
                    self.assertEqual(prepare_tool._check_executable_sections(
                        upstream_executable, packaged_executable),
                        manifest['binary_integrity']['file_backed_section_sha256'])
                    self.assertNotEqual(hashlib.sha256(upstream_executable).hexdigest(),
                                        hashlib.sha256(packaged_executable).hexdigest())
                    self.assertTrue(package.getinfo(prepare_tool.EXECUTABLE).external_attr >> 16 & 0o111)

                # Independent fresh extraction: strict verification must hold
                # for the bytes delivered in the ZIP, including nested seals.
                extracted = self.root / f'{profile}-extracted'
                extracted.mkdir()
                prepare_tool._extract_package(output.read_bytes(), extracted)
                prepare_tool._verify_tree(extracted)
                self.assertTrue((extracted / prepare_tool.EXECUTABLE).stat().st_mode & 0o111)


if __name__ == '__main__':
    unittest.main()
