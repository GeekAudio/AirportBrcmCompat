"""Compile the production-portable policy with fake callbacks only; no OS calls."""
import pathlib
import subprocess
import tempfile
import unittest

PROJECT=pathlib.Path(__file__).resolve().parents[1]
HARNESS=r'''
#include "transaction.hpp"
#include <assert.h>
#include <stdlib.h>
using namespace PrivateMAC;
struct Context {
 State *state; API *api;
 bool root=true,unlocked=true,gate=true,idle=true,source=true,privateFlag=true;
 int fail=0,callbackMode=0;unsigned calls=0,writes=0,authChecks=0;
 unsigned poisonGuard=0,poisonOccurrence=0,guardCounts[5]{};
 unsigned sequence[32]{};
 uint8_t firmware[6]{2,1,1,1,1,1},bsd[6]{2,1,1,1,1,1},property[6]{2,1,1,1,1,1};
};
static const uint8_t desired[6]={6,2,2,2,2,2}; // Fictional fixture, never printed.
static void guardCallback(Context &c,unsigned guard){
 c.guardCounts[guard-1]++;
 if(c.poisonGuard==guard&&c.guardCounts[guard-1]==c.poisonOccurrence)scopeCopyFailed(*c.state);
}
static int authorization(void *p){auto &c=*(Context*)p;c.authChecks++;guardCallback(c,1);return c.root?0:EACCES;}
static int unlocked(void *p){auto &c=*(Context*)p;guardCallback(c,2);return c.unlocked?0:EDEADLK;}
static int gate(void *p){auto &c=*(Context*)p;guardCallback(c,3);return c.gate?0:EDEADLK;}
static int idle(void *p){auto &c=*(Context*)p;guardCallback(c,4);return c.idle?0:EBUSY;}
static int source(void *p,const uint8_t *a){assert(a);auto &c=*(Context*)p;guardCallback(c,5);return c.source?0:EOPNOTSUPP;}
static int operation(void *p,const uint8_t *address,unsigned step){
 auto &c=*(Context*)p;
 assert(c.root&&c.unlocked&&c.gate);assert(c.privateFlag);
 assert(blocked(*c.state)); // Every association entry must reject during apply/finish.
 assert(!memcmp(address,desired,6));assert(c.calls<32);c.sequence[c.calls++]=step;
 if(c.fail==(int)step)return EIO;
 if(step==1){memcpy(c.firmware,address,6);c.writes++;}
 if(step==2&&memcmp(c.firmware,address,6))return EIO;
 if(step==3){memcpy(c.bsd,address,6);c.writes++;}
 if(step==4&&memcmp(c.bsd,address,6))return EIO;
 if(step==5){memcpy(c.property,address,6);c.writes++;}
 if(step==6&&memcmp(c.property,address,6))return EIO;
 if(step==1&&c.callbackMode==1){auto nested=apply(*c.api,*c.state,address,true);assert(nested.error==EBUSY);}
 if((step==1&&c.callbackMode==2)||(step==6&&c.callbackMode==5))scopeCopyFailed(*c.state);
 if(step==1&&c.callbackMode==3)c.gate=false;
 if(step==1&&c.callbackMode==4)c.root=false;
 return 0;
}
static int s1(void *p,const uint8_t*a){return operation(p,a,1);}
static int s2(void *p,const uint8_t*a){return operation(p,a,2);}
static int s3(void *p,const uint8_t*a){return operation(p,a,3);}
static int s4(void *p,const uint8_t*a){return operation(p,a,4);}
static int s5(void *p,const uint8_t*a){return operation(p,a,5);}
static int s6(void *p,const uint8_t*a){return operation(p,a,6);}
static void setup(Context &c,State &s,API &a){
 c.state=&s;c.api=&a;a.context=&c;a.authorization=authorization;a.registryUnlocked=unlocked;
 a.controllerGate=gate;a.unassociated=idle;a.policySource=source;a.setFirmware=s1;
 a.verifyDriverCache=s2;a.setPrimaryBSD=s3;a.verifyPrimaryBSD=s4;a.publishCurrentIOMAC=s5;a.verifyCurrentIOMAC=s6;
}
static void success(){State s;API a;Context c;setup(c,s,a);
 uint8_t payload[14];memset(payload,0x5a,sizeof(payload));memcpy(payload+4,desired,6);uint8_t before[14];memcpy(before,payload,14);
 auto r=apply(a,s,payload+4,true);assert(!r.error&&r.consistentPrivate&&!r.quarantined&&s.ready&&!s.running);
 assert(s.awaitingHandler&&blockError(s)==EBUSY);
 unsigned beforeRetry=c.calls;assert(apply(a,s,payload+4,true).error==EBUSY&&c.calls==beforeRetry);
 assert(!memcmp(before,payload,14));assert(c.privateFlag);assert(c.calls==6&&c.writes==3);
 for(unsigned i=0;i<6;i++)assert(c.sequence[i]==i+1);
 c.idle=false;auto done=associationReturned(a,s,0,true);assert(!done.error&&done.consistentPrivate&&!blocked(s));
 assert(c.writes==3&&c.calls==9); // Final checks are read-only and do not require idle after JOIN.
 assert(!s.awaitingHandler&&blockError(s)==0);
}
static void preconditions(){
 for(unsigned mode=0;mode<8;mode++){State s;API a;Context c;setup(c,s,a);
 bool flag=true;uint8_t address[6];memcpy(address,desired,6);
 if(mode==0)c.root=false;if(mode==1)c.unlocked=false;if(mode==2)c.gate=false;if(mode==3)c.idle=false;
 if(mode==4)c.source=false;if(mode==5)flag=false;if(mode==6)address[0]=0;if(mode==7)a.setFirmware=nullptr;
 auto r=apply(a,s,address,flag);assert(r.error&&!r.quarantined&&!s.running&&!s.ready&&c.calls==0&&c.writes==0);
 }
}
static void every_partial_failure(){
 for(int step=1;step<=6;step++){State s;API a;Context c;setup(c,s,a);c.fail=step;
 auto r=apply(a,s,desired,true);assert(r.error&&r.quarantined&&blocked(s)&&!s.ready&&!s.running);
 assert(c.calls==(unsigned)step);auto first=s.firstFailure;unsigned count=c.calls;
 auto again=apply(a,s,desired,true);assert(again.error&&again.quarantined&&c.calls==count&&s.firstFailure==first);
 // There is no restore callback/API: every attempted address write received desired, never the old fixture.
 }
}
static void original_failure_keeps_private(){State s;API a;Context c;setup(c,s,a);assert(!apply(a,s,desired,true).error);
 auto r=associationReturned(a,s,EACCES,true);assert(r.error==EACCES&&r.consistentPrivate&&!r.quarantined);
 assert(s.ready&&!s.running&&!memcmp(c.firmware,desired,6)&&!memcmp(c.bsd,desired,6)&&!memcmp(c.property,desired,6));
 assert(c.writes==3&&c.privateFlag); // No address/PMK/connection rollback.
}
static void copy_failure(){State s;API a;Context c;setup(c,s,a);assert(!apply(a,s,desired,true).error);
 auto r=scopeCopyFailed(s);assert(r.quarantined&&s.firstFailure==Stage::ScopeCopy);
 unsigned n=c.calls;assert(associationReturned(a,s,0,false).quarantined&&c.calls==n);
}
static void post_failures(){const int steps[]={2,4,6};for(int step: steps){State s;API a;Context c;setup(c,s,a);
 assert(!apply(a,s,desired,true).error);c.fail=step;auto r=associationReturned(a,s,0,true);
 assert(r.error&&r.quarantined&&!s.ready&&c.writes==3);}}
static void callback_conditions(){
 for(int mode=1;mode<=5;mode++){State s;API a;Context c;setup(c,s,a);c.callbackMode=mode;
 auto r=apply(a,s,desired,true);
 if(mode==1){assert(!r.error&&s.ready&&c.writes==3);}else{
 assert(r.error&&r.quarantined&&blocked(s)&&!s.ready&&!s.running);
 if(mode!=5)assert(c.calls==1&&c.writes==1);
 }
 }
}
static void no_copy_or_reentry(){State s;API a;Context c;setup(c,s,a);
 assert(!apply(a,s,desired,true).error);assert(associationReturned(a,s,0,false).quarantined);
 State other;API b;Context d;setup(d,other,b);other.running=true;
 assert(apply(b,other,desired,true).error==EBUSY&&d.calls==0&&!other.quarantined);
}
static void guard_poison(){
 // Poison from any check at preflight, immediately before FW, or after FW.
 // Each callback deliberately returns zero: poison must still stop the engine.
 for(unsigned guard=1;guard<=4;guard++)for(unsigned occurrence=1;occurrence<=3;occurrence++){
  State s;API a;Context c;setup(c,s,a);c.poisonGuard=guard;c.poisonOccurrence=occurrence;
  auto r=apply(a,s,desired,true);assert(r.error==EIO&&r.quarantined&&!s.running&&!s.ready);
  assert(c.calls==(occurrence==3?1U:0U)&&c.writes==(occurrence==3?1U:0U));
  assert(s.firstFailure==Stage::ScopeCopy);
  // No later check in this guard group may run after poisoning.
  for(unsigned later=guard;later<4;later++)assert(c.guardCounts[later]==occurrence-1);
 }
 // Policy provenance is a callback too, before any mutating step.
 {State s;API a;Context c;setup(c,s,a);c.poisonGuard=5;c.poisonOccurrence=1;
  assert(apply(a,s,desired,true).quarantined&&c.calls==0&&c.writes==0);}
 // Final read-only consistency checks must not start after a poisoned guard.
 for(unsigned guard=1;guard<=3;guard++){
  State s;API a;Context c;setup(c,s,a);assert(!apply(a,s,desired,true).error);
  c.poisonGuard=guard;c.poisonOccurrence=c.guardCounts[guard-1]+1;
  auto r=associationReturned(a,s,0,true);assert(r.error==EIO&&r.quarantined&&c.calls==6&&c.writes==3);
 }
}
int main(int argc,char**argv){assert(argc==2);switch(atoi(argv[1])){
 case 0:success();break;case 1:preconditions();break;case 2:every_partial_failure();break;
 case 3:original_failure_keeps_private();break;case 4:copy_failure();break;case 5:post_failures();break;
 case 6:callback_conditions();break;case 7:no_copy_or_reentry();break;case 8:guard_poison();break;default:abort();}}
'''

class PrivateMACTransactionTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory(prefix='private-mac-policy-',dir='/private/tmp')
  cls.binary=pathlib.Path(cls.tmp.name)/'test'
  r=subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
      '-fno-omit-frame-pointer','-I',str(PROJECT/'src/private_mac_compat'),'-x','c++','-','-o',str(cls.binary)],
      input=HARNESS,text=True,capture_output=True,timeout=60)
  if r.returncode:raise AssertionError(r.stderr)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def scenario(self,n):
  r=subprocess.run([str(self.binary),str(n)],capture_output=True,text=True,timeout=10)
  self.assertEqual(r.returncode,0,r.stderr)
 def test_six_ordered_steps_preserve_native_input_and_private_policy(self):self.scenario(0)
 def test_authorization_gate_idle_source_shape_and_api_fail_before_mutation(self):self.scenario(1)
 def test_every_partial_failure_quarantines_and_blocks_retry_without_fallback(self):self.scenario(2)
 def test_original_assoc_failure_retains_consistent_new_private_address(self):self.scenario(3)
 def test_scope_copy_failure_persistently_quarantines(self):self.scenario(4)
 def test_post_assoc_consistency_failure_quarantines_without_address_rollback(self):self.scenario(5)
 def test_reentry_revocation_gate_loss_and_callback_quarantine_cannot_be_overridden(self):self.scenario(6)
 def test_missing_copy_and_reentrant_engine_are_not_success(self):self.scenario(7)
 def test_every_guard_callback_poison_stops_before_next_operation(self):self.scenario(8)

if __name__=='__main__':unittest.main()
