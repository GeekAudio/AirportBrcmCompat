"""Host contracts for the scoped PID identity used by ElCap scan nodes."""
import pathlib
import subprocess
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/scan_owner_core.hpp"
#include <assert.h>
#include <stdint.h>

namespace C=LegacyWiFi::ScanOwner::Core;
static bool held=false;
static void lock(void *p){auto *v=(bool*)p;assert(!*v);*v=true;}
static void unlock(void *p){auto *v=(bool*)p;assert(*v);*v=false;}

int main(){
 uintptr_t target=0;int32_t displacement=0;
 const uintptr_t kernelBase=static_cast<uintptr_t>(0xffffff8000100000ULL);
 assert(C::addRelative32(kernelBase+5,0x1234,&target));
 assert(target==kernelBase+5+0x1234);
 assert(C::addRelative32(kernelBase+5,-0x2345,&target));
 assert(target==kernelBase+5-0x2345);
 assert(!C::addRelative32(UINTPTR_MAX-1,5,&target));
 assert(!C::addRelative32(0x10,-0x20,&target));
 assert(C::relative32(kernelBase+5,kernelBase+5+INT32_MAX,&displacement));
 assert(displacement==INT32_MAX);
 assert(C::relative32(kernelBase+5,kernelBase+5-(static_cast<uintptr_t>(INT32_MAX)+1),&displacement));
 assert(displacement==INT32_MIN);
 assert(!C::relative32(kernelBase,kernelBase+static_cast<uintptr_t>(INT32_MAX)+1,&displacement));
 assert(!C::relative32(kernelBase,kernelBase-(static_cast<uintptr_t>(INT32_MAX)+2),&displacement));

 C::Registry registry;assert(!registry.ready());
 C::Lock api{&held,lock,unlock};assert(registry.prepare(api));
 assert(!registry.prepare(api));assert(registry.ready());
 C::Scope outer,inner;
 assert(!registry.enter(outer,0x100,nullptr,41));
 assert(!registry.enter(outer,0x100,(void*)1,0));
 assert(registry.enter(outer,0x100,(void*)1,41));
 assert(registry.pidForThread(0x100,7)==41);
 assert(registry.pidForThread(0x200,7)==7);
 assert(registry.enter(inner,0x100,(void*)2,52));
 assert(registry.pidForThread(0x100,7)==52); // nested scope wins
 assert(registry.leave(inner));
 assert(registry.pidForThread(0x100,7)==41);
 assert(!registry.leave(inner));
 assert(registry.leave(outer));
 assert(registry.pidForThread(0x100,7)==7);
 assert(registry.count()==0&&!held);

 C::Scope scopes[C::MaximumScopes+1];
 for(size_t i=0;i<C::MaximumScopes;i++)
  assert(registry.enter(scopes[i],i+1,(void*)(i+1),static_cast<int>(i+100)));
 assert(!registry.enter(scopes[C::MaximumScopes],99,(void*)99,199));
 for(size_t i=C::MaximumScopes;i>0;i--)assert(registry.leave(scopes[i-1]));
 assert(registry.count()==0&&!held);
}
'''


class ScanOwnerCoreTests(unittest.TestCase):
    def test_nested_thread_scopes_and_bounded_registry(self):
        with tempfile.TemporaryDirectory(prefix="scan-owner-core-", dir="/private/tmp") as tmp:
            source = pathlib.Path(tmp) / "owner.cpp"
            binary = pathlib.Path(tmp) / "owner"
            source.write_text(HARNESS)
            build = subprocess.run(
                ["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-I",
                 str(PROJECT / "src"), str(source), "-o", str(binary)],
                capture_output=True, text=True, check=False)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
