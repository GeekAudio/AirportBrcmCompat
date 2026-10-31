"""Fault-inject the production route result gate using a host backend."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
HARNESS=r'''
#include "src/private_mac_compat/route_checked.hpp"
#include <cassert>
using Function=int (*)(int);
int native(int result){return result;}
struct Request{Function *original;};
struct Patcher{
 enum class Error{NoError,MemoryIssue,MemoryProtection};
 Error error=Error::NoError,result=Error::NoError;
 bool success=true,provide=true;unsigned calls=0,clears=0;
 Error getError(){return error;}
 void clearError(){error=Error::NoError;++clears;}
 bool routeMultiple(size_t index,Request*r,size_t count,uintptr_t address,size_t size){
  assert(index==7 && count==1 && address==0x1000 && size==0x2000);
  assert(error==Error::NoError);++calls;
  if(provide)*r->original=native;
  error=result;return success;
 }
};
int main(){
 for(unsigned kind=0;kind<5;++kind){
  Patcher patcher;Function original=nullptr;Request request{&original};
  patcher.error=Patcher::Error::MemoryIssue; // stale errors must not leak in.
  if(kind==1)patcher.result=Patcher::Error::MemoryIssue;
  if(kind==2)patcher.result=Patcher::Error::MemoryProtection;
  if(kind==3)patcher.success=false;
  if(kind==4)patcher.provide=false;
  const bool ready=PrivateMAC::routeChecked(patcher,7,request,original,0x1000,0x2000);
  assert(ready==(kind==0));assert(patcher.calls==1 && patcher.clears==2);
  assert(patcher.getError()==Patcher::Error::NoError);
  // A partially installed wrapper retains the original trampoline and its
  // exact native error; failure must not replace it with an error-code pointer.
  if(original)assert(original(-81)==-81);
 }
}
'''


class CheckedRouteTests(unittest.TestCase):
    def test_false_success_and_partial_route_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/"route.cpp";output=Path(directory)/"route"
            source.write_text(HARNESS)
            subprocess.run(["xcrun","clang++","-std=c++14","-Wall","-Wextra","-Werror",
                            "-fsanitize=address,undefined","-I",str(ROOT),str(source),
                            "-o",str(output)],check=True,capture_output=True)
            subprocess.run([str(output)],check=True,capture_output=True)


if __name__=="__main__":unittest.main()
