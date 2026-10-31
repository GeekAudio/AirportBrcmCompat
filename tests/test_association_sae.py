"""Fictional buffers only; no password, OS network API or SAE handshake test."""
import pathlib
import subprocess
import tempfile
import unittest

import test_private_mac_association_flow as flow

PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "association_compat.hpp"
#include <assert.h>
#include <string.h>
using namespace AssociationCompat;
static void put(uint8_t *p,uint32_t x){memcpy(p,&x,4);}
static void init(uint8_t *p,bool privateMac=false){
 memset(p,0,NativeSize);put(p,1);ScanCompat::write16(p+4,2);put(p+8,1);put(p+12,4096);
 put(p+16,3);memcpy(p+20,"abc",3);put(p+64,16);put(p+68,10);
 memset(p+76,0x5c,16);put(p+472,32);memset(p+476,0xa6,32);put(p+508,0x40000004U);p[899]=2;
 if(privateMac){p[468]=8;const uint8_t address[]={6,1,2,3,4,5};memcpy(p+512,address,6);}
}
int main(){
 for(uint32_t upper=0;upper<65536;upper++){
  const bool expected=upper==0||upper==8
#ifdef AIRPORT_BRCM_SAE_COMPAT
   ||upper==4096
#endif
   ;assert(PrivateMAC::supportedStationAuthUpper(upper)==expected);
 }
 uint8_t native[NativeSize],before[NativeSize],old[LegacySize],oldBefore[LegacySize];init(native);
#ifndef AIRPORT_BRCM_SAE_COMPAT
 auto denied=convert(native,NativeSize,old,LegacySize);assert(denied.error==EOPNOTSUPP&&denied.field==12);return 0;
#else
 for(uint32_t mask:{0U,4U,0x40000004U})for(unsigned length=8;length<=63;length++){
  init(native);put(native+508,mask);put(native+64,length);memset(native+76,0x6b,length);
  memcpy(before,native,NativeSize);assert(!convert(native,NativeSize,old,LegacySize).error);
  assert(ScanCompat::read16(old+8)==4096);assert(!memcmp(old+12,native+16,496));
  assert(ScanCompat::read32(old+504)==mask&&!memcmp(native,before,NativeSize));
 }
 // Every refused shape leaves caller's buffers unchanged. Never substitute
 // WPA2, discard a policy bit, or treat a raw PMK/PSK as an SAE password.
 const uint32_t invalid[][2]={{12,4097},{68,6},{64,0},{64,7},{64,64},{472,0},{472,31},{472,33},
                            {508,0x100},{508,0x40000100},{508,8},{508,0xffffffffU},{899,0}};
 for(auto &entry:invalid){init(native);put(native+entry[0],entry[1]);memcpy(before,native,NativeSize);
  memset(old,0x7d,LegacySize);memcpy(oldBefore,old,LegacySize);auto result=convert(native,NativeSize,old,LegacySize);
  assert(result.error&&!memcmp(native,before,NativeSize)&&!memcmp(old,oldBefore,LegacySize));}
 init(native,true);PrivateMAC::NativeRequest plan;assert(!convert(native,NativeSize,old,LegacySize,&plan).error&&plan.requested);
 Scope scope;scope.thread=1;scope.caller=2;scope.controller=(void*)3;scope.interface=(void*)4;scope.source=5;
 scope.legacy=old;scope.consumed=true;scope.privatePlan=plan;scope.authUpper=4096;
 {DriverValidationLease lease(scope);assert(lease.acquired());assert(infrastructureIntent(scope,1,(void*)3,(void*)4));
  ScanCompat::write16(old+8,8);assert(!infrastructureIntent(scope,1,(void*)3,(void*)4));}
 assert(!scope.driverValidated);
#endif
}
'''


class AssociationSaeTests(unittest.TestCase):
    def compile_run(self, source, enabled):
        with tempfile.TemporaryDirectory(prefix="sae-subset-", dir="/private/tmp") as tmp:
            cpp = pathlib.Path(tmp) / "test.cpp"
            binary = pathlib.Path(tmp) / "test"
            cpp.write_text(source)
            subprocess.run(["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-variable", "-fsanitize=address,undefined", "-g",
                            *(["-DAIRPORT_BRCM_SAE_COMPAT=1"] if enabled else []),
                            "-include", "initializer_list", "-I", str(PROJECT / "src/scan_kernel"),
                            "-I", str(PROJECT / "src/private_mac_compat"), str(cpp), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_default_build_still_rejects_sae(self):
        self.compile_run(HARNESS, False)

    def test_candidate_preserves_selected_auth_carriers_policy_and_owned_intent(self):
        self.compile_run(HARNESS, True)

    def test_candidate_private_address_scope_and_error_paths(self):
        source = flow.HARNESS.replace("int main(", "int legacy_flow_main(", 1).replace('puts("ok");}', 'puts("ok");return 0;}')
        source += r'''
static void sae(Fixture &p){put32(p.payload+12,4096);put32(p.payload+64,16);put32(p.payload+68,10);
 put32(p.payload+472,32);put32(p.payload+508,0x40000004U);}
int main(){
 {Fixture p;sae(p);assert(!p.run()&&p.planApplied&&p.planCompleted&&p.copied);p.allPrivate();
  assert(p.observedSurvey.cipher68.low16==10&&p.observedSurvey.keyLength64.low16==16&&p.observedSurvey.pmkLength472.low16==32);}
 for(int error:{EINVAL,EIO,ETIMEDOUT}){Fixture p;sae(p);p.driverError=error;
  assert(p.run()==error&&p.planApplied&&p.planCompleted);p.allPrivate();}
 for(unsigned key:{0,7,64}){Fixture p;sae(p);put32(p.payload+64,key);assert(p.run()==EOPNOTSUPP&&!p.setters&&!p.drivers);}
}
'''
        self.compile_run(source, True)


if __name__ == "__main__":
    unittest.main()
