import hashlib
import importlib.util
import io
import tempfile
from pathlib import Path
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixture_loader',ROOT/'tools/prepare_test_fixtures.py')
loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(loader)


class FixturePreparationTests(unittest.TestCase):
    def fixture(self,root):
        members={'build/one.zip':b'one','build/two.zip':b'two'};data=io.BytesIO()
        with zipfile.ZipFile(data,'w') as archive:
            for name,payload in members.items():archive.writestr(name,payload)
        path=root/'fixture.zip';path.write_bytes(data.getvalue())
        lock={'max_download_bytes':10000,'sha256':hashlib.sha256(data.getvalue()).hexdigest(),
              'files':{name:hashlib.sha256(payload).hexdigest() for name,payload in members.items()}}
        return path,lock

    def test_offline_preparation_is_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive,lock=self.fixture(root)
            self.assertEqual(loader.prepare(archive,root=root,lock=lock),2)
            self.assertEqual(loader.prepare(archive,root=root,lock=lock),2)
            self.assertEqual((root/'build/one.zip').read_bytes(),b'one')

    def test_hash_and_missing_member_fail_without_partial_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive,lock=self.fixture(root)
            lock['files']['build/two.zip']='0'*64
            with self.assertRaisesRegex(ValueError,'member hash'):loader.prepare(archive,root=root,lock=lock)
            self.assertFalse((root/'build').exists())
            archive.write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError,'archive hash'):loader.prepare(archive,root=root,lock=lock)

    def test_existing_different_input_and_symlink_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive,lock=self.fixture(root)
            (root/'build').mkdir();(root/'build/one.zip').write_bytes(b'different')
            with self.assertRaisesRegex(ValueError,'Existing'):loader.prepare(archive,root=root,lock=lock)
            (root/'build/one.zip').unlink();(root/'build').rmdir()
            (root/'target').mkdir();(root/'build').symlink_to(root/'target')
            with self.assertRaisesRegex(ValueError,'symlink'):loader.prepare(archive,root=root,lock=lock)


if __name__=='__main__':unittest.main()
