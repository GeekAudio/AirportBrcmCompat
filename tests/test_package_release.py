import importlib.util
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
import warnings
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
spec=importlib.util.spec_from_file_location('release_packager',ROOT/'tools/package_release.py')
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)


class ReleasePackagingTests(unittest.TestCase):
    def test_validation_log_requires_complete_success(self):
        self.assertEqual(tool.test_result('Ran 12 tests in 1.25s\n\nOK\n')['passed'],12)
        for text in ('Ran 12 tests in 1.25s\n\nOK (skipped=1)\n',
                     'Ran 12 tests in 1.25s\n\nFAILED (errors=1)\n',
                     'Ran 0 tests in 0s\n\nOK\n'):
            with self.assertRaises(ValueError):tool.test_result(text)

    def test_unsafe_and_duplicate_archive_members_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'bad.zip'
            for names in (['../outside'],['same','same']):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    with zipfile.ZipFile(path,'w') as archive:
                        for name in names:archive.writestr(name,b'data')
                with self.assertRaises(ValueError):tool.read_files(path)

    def test_distribution_zip_is_deterministic_and_preserves_executable_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);original={'LICENSE':b'license','README.txt':b'notes',
                 'manifest.json':b'{}','tools/helper.py':b'code',
                 'Core.kext/Contents/Info.plist':b'plist',
                 'Core.kext/Contents/MacOS/Core':b'fictional executable',
                 'config.plist':b'configuration'}
            files=tool.installation_files(original,('Core.kext',),('config.plist',))
            self.assertEqual(set(files),{'Core.kext/Contents/Info.plist',
                                        'Core.kext/Contents/MacOS/Core','config.plist'})
            with self.assertRaises(ValueError):tool.installation_files(original,('Missing.kext',))
            with self.assertRaises(ValueError):tool.installation_files(original,('Core.kext',),('missing.plist',))
            tool.write_zip(root/'one.zip',files);tool.write_zip(root/'two.zip',files)
            self.assertEqual(hashlib.sha256((root/'one.zip').read_bytes()).digest(),
                             hashlib.sha256((root/'two.zip').read_bytes()).digest())
            self.assertEqual(tool.read_files(root/'one.zip'),files)
            with zipfile.ZipFile(root/'one.zip') as archive:
                self.assertTrue(archive.getinfo('Core.kext/Contents/MacOS/Core').external_attr>>16&0o111)
            with self.assertRaises(FileExistsError):tool.write_zip(root/'one.zip',files)


if __name__=='__main__':unittest.main()
