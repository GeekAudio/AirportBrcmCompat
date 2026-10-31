"""Check structural readiness gating without reading kern.osversion."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

PROJECT=pathlib.Path(__file__).resolve().parents[1]
HARNESS=r'''
#include <stdio.h>
#include "runtime_build_guard.hpp"
#define CHECK(x) do { if(!(x))return __LINE__; } while(0)
int main(void) {
    using Profile=ScanKernelIdentity::Profile;
    CHECK(ScanCompat::runtimeBuildState(Profile::Pending)==1);
    CHECK(ScanCompat::runtimeBuildState(Profile::Unsupported)==3);
    CHECK(ScanCompat::runtimeBuildState(Profile::Structural)==0);
    CHECK(ScanCompat::runtimeBuildState(static_cast<Profile>(99))==3);
    puts("structural admission states passed");return 0;
}
'''


@unittest.skipUnless(shutil.which('clang++'),'C++ compiler required')
class RuntimeBuildGateTests(unittest.TestCase):
    def test_pending_and_unsupported_states_refuse_admission(self):
        with tempfile.TemporaryDirectory(prefix='scan-runtime-build-') as tmp:
            target=pathlib.Path(tmp)/'gate'
            result=subprocess.run(['clang++','-std=c++14','-Wall','-Wextra','-Werror',
                                   '-I',str(PROJECT/'src/scan_kernel'),'-x','c++','-','-o',str(target)],
                                  input=HARNESS,capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([str(target)],capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('structural admission states passed',result.stdout)


if __name__=='__main__': unittest.main()
