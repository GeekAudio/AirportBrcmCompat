"""Execute the exact late build gate, including mutable and non-sticky states."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest
PROJECT=pathlib.Path(__file__).resolve().parents[1]
HARNESS=r'''
#include <stdio.h>
#include <string.h>
#include "runtime_build_guard.hpp"
#define CHECK(x) do { if(!(x))return __LINE__; } while(0)
int main(void) {
    using Profile=ScanKernelIdentity::Profile;
    char value[7]={0};
    CHECK(ScanCompat::runtimeBuildState(nullptr,Profile::Build25G241)==3);
    CHECK(ScanCompat::runtimeBuildState(value,Profile::Build25G241)==1);
    CHECK(ScanCompat::runtimeBuildState(value,Profile::Build25G332)==1);
    CHECK(ScanCompat::runtimeBuildState(value,Profile::Unsupported)==3);
    memcpy(value,"25G241",7);
    CHECK(ScanCompat::runtimeBuildState(value,Profile::Build25G241)==0);
    CHECK(ScanCompat::runtimeBuildState(value,Profile::Build25G332)==2);
    for(unsigned i=0;i<6;i++){char old=value[i];value[i]='?';CHECK(ScanCompat::runtimeBuildState(value,Profile::Build25G241)==2);value[i]=old;}
    value[6]='X';CHECK(ScanCompat::runtimeBuildState(value,Profile::Build25G241)==2);
    memcpy(value,"25G332",7);
    CHECK(ScanCompat::runtimeBuildState(value,Profile::Build25G332)==0);
    CHECK(ScanCompat::runtimeBuildState(value,Profile::Build25G241)==2);
    value[6]='X';CHECK(ScanCompat::runtimeBuildState(value,Profile::Build25G332)==2);
    puts("exact build/profile pairs passed");return 0;
}
'''
@unittest.skipUnless(shutil.which('clang++'),'C++ compiler required')
class RuntimeBuildGateTests(unittest.TestCase):
    def test_exact_nul_match_and_live_mutable_state(self):
        with tempfile.TemporaryDirectory(prefix='scan-runtime-build-') as tmp:
            target=pathlib.Path(tmp)/'gate'
            r=subprocess.run(['clang++','-std=c++14','-Wall','-Wextra','-Werror','-I',str(PROJECT/'src/scan_kernel'),'-x','c++','-','-o',str(target)],input=HARNESS,capture_output=True,text=True,timeout=30)
            self.assertEqual(r.returncode,0,r.stderr)
            r=subprocess.run([str(target)],capture_output=True,text=True,timeout=5)
            self.assertEqual(r.returncode,0,r.stderr)
if __name__=='__main__':unittest.main()
