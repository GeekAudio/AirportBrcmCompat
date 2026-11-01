import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import release_inventory as tool


class ReleaseInventoryTests(unittest.TestCase):
    def binary(self):return struct.pack('<IiiIIIII',0xfeedfacf,0x1000007,3,11,1,24,0,0)+struct.pack('<II',0x1b,24)+b'x'*16

    def stage(self,root):
        binary=self.binary();info={'CFBundleIdentifier':'org.geekaudio.AirportBrcmCompat','CFBundleVersion':'1.1.0',
                                  'CFBundleExecutable':'AirportBrcmCompat','AirportBrcmBuildFlavor':'RELEASE'}
        files={'AirportBrcmCompat.kext/Contents/Info.plist':plistlib.dumps(info),
               'AirportBrcmCompat.kext/Contents/MacOS/AirportBrcmCompat':binary}
        archive=root/'core.zip'
        with zipfile.ZipFile(archive,'w') as z:
            for name,data in files.items():z.writestr(name,data)
        record={'sha256':tool.sha(archive.read_bytes()),'bytes':archive.stat().st_size,**tool.inventory(files)}
        manifest={'artifacts':{'core.zip':record,'optional.zip':{}},'lineage':{'release':{'tag':'v1.1.0','tag_commit':None},
            'repackaging':{'source_commit':'fixture'},'core_builds':{'RELEASE':{'binary_sha256':tool.sha(binary),'macho_uuid':tool.macho_uuid(binary)}}}}
        self.manifest(root,manifest);return manifest

    def manifest(self,root,manifest):
        data=json.dumps(manifest).encode();(root/'06-VALIDATION.json').write_bytes(data)
        (root/'05-SHA256SUMS.txt').write_text(tool.sha(data)+'  06-VALIDATION.json\n'+tool.sha((root/'core.zip').read_bytes())+'  core.zip\n')

    def test_selected_downloads_are_not_reported_as_complete_distribution(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.stage(root);report=tool.verify(root)
            self.assertTrue(report['passed']);self.assertFalse(report['complete_distribution'])
            self.assertEqual(report['not_checked'],['optional.zip'])
            self.assertEqual(report['verified'][0]['bundles'][0]['bundle_path'],'AirportBrcmCompat.kext')

    def test_manifest_and_member_tampering_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);manifest=self.stage(root)
            (root/'06-VALIDATION.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'manifest checksum'):tool.verify(root)
            manifest['artifacts']['core.zip']['members']['AirportBrcmCompat.kext/Contents/Info.plist']['sha256']='0'*64
            self.manifest(root,manifest)
            with self.assertRaisesRegex(ValueError,'member mismatch'):tool.verify(root)

    def test_wrong_core_lineage_and_unknown_selection_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);manifest=self.stage(root)
            with self.assertRaisesRegex(ValueError,'Unknown'):tool.verify(root,assets=['other.zip'])
            manifest['lineage']['core_builds']['RELEASE']['macho_uuid']='wrong';self.manifest(root,manifest)
            with self.assertRaisesRegex(ValueError,'lineage'):tool.verify(root)

    def test_uuid_and_inventory_path_boundaries(self):
        self.assertEqual(tool.macho_uuid(self.binary()),'78787878-7878-7878-7878-787878787878')
        for binary in (b'bad',self.binary()[:40]):
            with self.assertRaises(ValueError):tool.macho_uuid(binary)
        with self.assertRaises(ValueError):tool.inventory({'../outside':b'bad'})

    def test_tag_source_match_is_distinct_from_build_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            def git(*args):return subprocess.check_output(['git',*args],cwd=root,stderr=subprocess.DEVNULL).decode().strip()
            git('init');(root/'source.c').write_bytes(b'original');git('add','source.c')
            git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-m','fixture')
            git('tag','v1.1.0');commit=git('rev-parse','HEAD')
            source={'manifest':{'sources':{'source.c':tool.sha(b'original')}},'binary':self.binary(),
                    'archive_sha256':'a'*64,'manifest_sha256':'b'*64}
            report=tool.lineage(root,'v1.1.0',{'RELEASE':source},'packaging-fixture')
            self.assertEqual(report['release']['tag_commit'],commit)
            self.assertIsNone(report['core_builds']['RELEASE']['builder_recorded_source_commit'])
            self.assertTrue(report['core_builds']['RELEASE']['source_files_match_tag'])
            source['manifest']['sources']['source.c']='0'*64
            self.assertFalse(tool.lineage(root,'v1.1.0',{'RELEASE':source},'fixture')['core_builds']['RELEASE']['source_files_match_tag'])
            report=tool.lineage(root,'missing-tag',{'RELEASE':source},'fixture')
            self.assertIsNone(report['release']['tag_commit'])
            self.assertIsNone(report['core_builds']['RELEASE']['source_files_match_tag'])
