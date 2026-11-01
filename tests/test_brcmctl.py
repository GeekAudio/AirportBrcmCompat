import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('brcmctl',ROOT/'tools/brcmctl.py')
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)


class DeliveryToolsTests(unittest.TestCase):
    def stage(self,root):
        ids=[tool.CORE,tool.PROVIDER,tool.LEGACY,tool.NIC,tool.NIC]
        names=['AirportBrcmCompat','IOLegacyWFamily','IO80211FamilyLegacy','NIC23','NIC25']
        entries=[]
        for index,(name,identifier) in enumerate(zip(names,ids)):
            bundle=root/'Kexts'/(name+'.kext');(bundle/'Contents/MacOS').mkdir(parents=True)
            info={'CFBundleIdentifier':identifier,'CFBundleVersion':'1.1.0','CFBundleExecutable':name,
                  'OSBundleLibraries':({tool.PROVIDER:'1.0'} if index==2 else {})}
            (bundle/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
            (bundle/'Contents/MacOS'/name).write_bytes(b'fictional offline executable')
            entries.append({'BundlePath':name+'.kext','PlistPath':'Contents/Info.plist',
                            'ExecutablePath':'Contents/MacOS/'+name,'Enabled':True,'Arch':'x86_64',
                            'MinKernel':'25.0.0' if index==4 else '23.0.0',
                            'MaxKernel':'24.99.99' if index==3 else ''})
        config={'Kernel':{'Add':entries,'Block':[{'Identifier':'com.apple.iokit.IO80211Family',
                'Strategy':'Exclude','Enabled':True,'MinKernel':'23.0.0'}],
                'Quirks':{'DisableLinkeditJettison':True}},
                'PlatformInfo':{'SystemSerialNumber':'private-serial'},
                'NVRAM':{'private-address':'00:11:22:33:44:55'}}
        (root/'config.plist').write_bytes(plistlib.dumps(config));return config

    def test_profile_selection_and_filtered_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.stage(root)
            for target in ('23.0.0','24.6.0','25.6.0','26.0.0'):
                report=tool.preflight(root,target)
                self.assertTrue(report['passed'],report['errors'])
                self.assertEqual(sum(c['identifier']==tool.NIC for c in report['components']),1)
                text=json.dumps(report)
                self.assertNotIn('private-serial',text);self.assertNotIn('00:11:22:33:44:55',text)

    def test_duplicate_nic_and_missing_file_are_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config=self.stage(root)
            config['Kernel']['Add'][-1]['MinKernel']='23.0.0'
            (root/'config.plist').write_bytes(plistlib.dumps(config))
            self.assertFalse(tool.preflight(root,'23.0.0')['passed'])
            (root/'Kexts/NIC23.kext/Contents/MacOS/NIC23').unlink()
            self.assertTrue(any('Executable is missing' in error for error in tool.preflight(root,'23')['errors']))

    def test_missing_runtime_dependency_and_wrong_order_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config=self.stage(root)
            entries=config['Kernel']['Add'];entries[1],entries[2]=entries[2],entries[1]
            (root/'config.plist').write_bytes(plistlib.dumps(config))
            self.assertTrue(any('must load first' in error for error in tool.preflight(root,'23')['errors']))
            path=root/'Kexts/AirportBrcmCompat.kext/Contents/Info.plist';info=plistlib.loads(path.read_bytes())
            info['OSBundleLibraries']={'third.party.runtime':'1.0'};path.write_bytes(plistlib.dumps(info))
            self.assertTrue(any('Missing EFI dependency' in error for error in tool.preflight(root,'23')['errors']))

    def test_configure_preserves_source_identity_and_order(self):
        source={'PlatformInfo':{'serial':'private'},'NVRAM':{'original':b'\x01'},
                'Kernel':{'Add':[{'BundlePath':'Runtime.kext'},{'BundlePath':'Core.kext'}]}}
        before=copy.deepcopy(source)
        fragment={'Kernel':{'Add':[{'BundlePath':'Core.kext','Enabled':True},
                                 {'BundlePath':'Dependency.kext','Enabled':True}],
                            'Quirks':{'DisableLinkeditJettison':True}}}
        result=tool.configure(source,fragment)
        self.assertEqual(source,before);self.assertEqual(result['PlatformInfo'],source['PlatformInfo'])
        self.assertEqual(result['NVRAM'],source['NVRAM'])
        self.assertEqual([e['BundlePath'] for e in result['Kernel']['Add']],
                         ['Runtime.kext','Core.kext','Dependency.kext'])
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.plist';tool.write_new(path,plistlib.dumps(result))
            with self.assertRaises(FileExistsError):tool.write_new(path,b'overwrite')
        with self.assertRaises(ValueError):tool.configure({'Kernel':{'Add':[{'BundlePath':'x'},{'BundlePath':'x'}]}},fragment)

    def test_paths_and_native_stack_block_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config=self.stage(root)
            config['Kernel']['Add'][0]['BundlePath']='../outside.kext'
            config['Kernel']['Block'].append({'Identifier':'com.apple.iokit.IOSkywalkFamily','Enabled':True})
            (root/'config.plist').write_bytes(plistlib.dumps(config))
            report=tool.preflight(root,'25')
            self.assertFalse(report['passed'])
            self.assertTrue(any('Unsafe' in error for error in report['errors']))
            self.assertIn('Native IOSkywalkFamily is blocked',report['errors'])

    def test_probe_checks_expected_hash_and_member_integrity(self):
        with tempfile.TemporaryDirectory() as directory:
            archive=Path(directory)/'core.zip';payload=b'core bytes'
            manifest={'files':{'core':hashlib.sha256(payload).hexdigest()},'version':'1.1.0','build_flavor':'RELEASE'}
            with zipfile.ZipFile(archive,'w') as z:
                z.writestr('core',payload);z.writestr('build-manifest.json',json.dumps(manifest))
            self.assertTrue(tool.probe(archive,tool.sha(archive.read_bytes()))['passed'])
            with self.assertRaises(ValueError):tool.probe(archive,'0'*64)
            with zipfile.ZipFile(archive,'w') as z:
                z.writestr('core',b'changed');z.writestr('build-manifest.json',json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'Manifest hash'):tool.probe(archive)


if __name__=='__main__':unittest.main()
