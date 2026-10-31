"""Real portable association/registry/admission/transaction coupling.

The old handler and driver/backend are deliberately fake synchronous consumers.
This proves portable policy composition, not credentials, native hook ABI, BSD
drainage, WorkLoop ownership, firmware behavior or an actual private MAC apply.
No IOKit, network, Keychain, kernel load or real driver function is used.
"""
import pathlib
import subprocess
import tempfile
import unittest

PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "association_compat.hpp"
#include "../private_mac_compat/transaction.hpp"
#include "../private_mac_compat/admission.hpp"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <initializer_list>
#include <vector>
namespace AC=AssociationCompat;
namespace PM=PrivateMAC;
constexpr size_t N=AC::NativeSize,O=AC::LegacySize;
// Fictional fixture values; never printed or sent to an OS interface.
static const uint8_t requested[6]={6,0x24,0x31,0x42,0x53,0x64};
static const uint8_t prior[6]={2,0x74,0x21,0x32,0x43,0x54};
static void put32(uint8_t*p,uint32_t x){memcpy(p,&x,4);}
enum class Mode {Normal,NoCopy,OnlyCopy,Unapplied,FakeCompleted,Uncompleted,
                 WrongConsumer,DuplicateCopy,DuplicateAuth,WrongAuth};
enum Event {Admitted,Entry,Allocated,CopiedNative,Consumer,Handler,CopiedOld,
            Driver,Auth,Policy,SetFW,ReadFW,SetBSD,ReadBSD,SetProperty,
            ReadProperty,OriginalAuth,OriginalDriver,Post,Freed,Finished};
struct Fixture;
static Fixture *current=nullptr;
struct Fixture {
    unsigned controllerToken=1,interfaceToken=2,otherToken=3;
    void *controller=&controllerToken,*interface=&interfaceToken;
    uintptr_t owner=0x1100,copyCaller=0x2200;
    PM::Binding binding{(uintptr_t)controller,(uintptr_t)interface,1};
    PM::Admission admission{binding};PM::AdmissionLease lease;
    PM::State state;
    bool contextLive=false,locked=false,consumer=true,failAlloc=false,postPhase=false;
    bool copied=false,sawPlan=false,planApplied=false,planCompleted=false;
    bool joining=false,guardFixtureAllowed=true;
    unsigned allocs=0,frees=0,nativeCopies=0,originals=0,oldCopies=0;
    unsigned drivers=0,auths=0,originalAuths=0,posts=0,setters=0,availableCalls=0;
    unsigned admissionCalls=0,entryCalls=0,transactionChecks=0;
    unsigned observedCalls=0,surveyCalls=0;uint32_t observedFlags=0;uint8_t observed469=0;
    AssociationSurvey::Snapshot observedSurvey;
    int entryError=0,copyError=0,driverError=0,authError=0,failStep=-1;
    int failPost=-1,badConsume=-1,badLookup=-1,badDriverByte=-1;
    int lastCopy=-2,lastAuth=0;Mode mode=Mode::Normal;
    uint8_t payload[N],firmware[6],bsd[6],property[6];
    struct Envelope {ScanCompat::Request request;uint8_t untouchedMetadata[8];} envelope{};
    uint8_t *allocation=nullptr;
    AC::Registry registry{};AC::API api{};
    std::vector<Event> events;std::vector<int> operations;
    Fixture(bool privateRequested=true){
        current=this;memset(payload,0,sizeof(payload));put32(payload,1);
        ScanCompat::write16(payload+4,2);put32(payload+8,1);put32(payload+12,8);
        put32(payload+16,3);memcpy(payload+20,"abc",3);put32(payload+60,1);
        put32(payload+64,32);put32(payload+68,6);memset(payload+76,0x3c,32);
        put32(payload+508,4);payload[899]=2;
        if(privateRequested){payload[468]=8;memcpy(payload+512,requested,6);}
        memcpy(firmware,prior,6);memcpy(bsd,prior,6);memcpy(property,prior,6);
        auto&r=envelope.request;memcpy(r.interfaceName,"en1",3);r.type=20;r.length=N;
        r.userData=(uintptr_t)payload;memset(envelope.untouchedMetadata,0x71,8);
        registry.lock={this,enterLock,leaveLock};
        api.original=original;api.copyIn=copyNative;api.allocate=allocate;
        api.deallocate=deallocate;api.currentThread=thread;api.registry=&registry;
        api.caller=copyCaller;api.entryAllowed=entryAllowed;api.privateAvailable=available;
        api.primaryInterface=primary;
        api.observeFlags=observe;api.observeSurvey=survey;
    }
    ~Fixture(){assert(!locked&&!allocation&&!registry.head&&!admission.isBusy());}
    static Fixture&f(){assert(current);return *current;}
    static void enterLock(void*v){auto&p=*(Fixture*)v;assert(!p.locked);p.locked=true;}
    static void leaveLock(void*v){auto&p=*(Fixture*)v;assert(p.locked);p.locked=false;}
    static uintptr_t thread(){return f().owner;}
    static bool primary(void*c,void*i,const char name[16]){auto&p=f();
        return c==p.controller&&i==p.interface&&PrimaryInterface::sameRequestAndProperty(name,"en1",3);}
    static void *allocate(size_t n){auto&p=f();assert(n==AC::StorageSize&&!p.locked);
        p.events.push_back(Allocated);if(p.failAlloc)return nullptr;
        assert(!p.allocation);p.allocation=(uint8_t*)malloc(n+32);assert(p.allocation);
        memset(p.allocation,0x5a,n+32);p.allocs++;return p.allocation+16;
    }
    static void deallocate(void*v,size_t n){auto&p=f();assert(!p.locked&&n==AC::StorageSize);
        assert(v==p.allocation+16);for(size_t j=0;j<n;j++)assert(!((uint8_t*)v)[j]);
        for(size_t j=0;j<16;j++)assert(p.allocation[j]==0x5a&&p.allocation[16+n+j]==0x5a);
        p.frees++;p.events.push_back(Freed);free(p.allocation);p.allocation=nullptr;
    }
    static int copyNative(void*c,uint64_t src,void*out,size_t n){auto&p=f();
        assert(!p.locked&&c==p.controller&&src==(uintptr_t)p.payload&&n==p.envelope.request.length);
        p.nativeCopies++;p.events.push_back(CopiedNative);if(p.copyError)return p.copyError;
        memcpy(out,p.payload,n);return 0;
    }
    static int entryAllowed(void*c,void*i){auto&p=f();assert(c==p.controller&&i==p.interface);
        p.entryCalls++;p.events.push_back(Entry);if(p.entryError)return p.entryError;
        if(p.admission.isQuarantined())return EIO;
        return p.contextLive?0:EOPNOTSUPP;
    }
    static bool available(void*c,void*i){auto&p=f();assert(c==p.controller&&i==p.interface);
        assert(!p.locked);p.availableCalls++;p.events.push_back(Consumer);
        return p.consumer&&p.contextLive&&!p.admission.isQuarantined();
    }
    static void observe(uint32_t flags,uint8_t byte469){auto&p=f();
        assert(!p.locked&&p.nativeCopies&&p.allocation);
        p.observedCalls++;p.observedFlags=flags;p.observed469=byte469;
        assert(flags==(ScanCompat::read32(p.payload+467)&0xffffffU)&&byte469==p.payload[469]);
    }
    static void survey(const AssociationSurvey::Snapshot&s){auto&p=f();
        assert(!p.locked&&p.nativeCopies&&p.allocation);
        AssociationSurvey::Snapshot expected;
        uint8_t normalized[N];const uint8_t *input=p.payload;
        if(p.envelope.request.length==AssociationProfiles::Sequoia15Size){
            assert(!AssociationProfiles::normalizeSequoia15(p.payload,AssociationProfiles::Sequoia15Size,normalized,N).error);
            input=normalized;
        }
        assert(AssociationSurvey::inspect(input,N,expected)==AssociationSurvey::Status::Ok);
        assert(!memcmp(&s,&expected,sizeof(s)));p.surveyCalls++;p.observedSurvey=s;
    }
    static int check(void*v){auto&p=*(Fixture*)v;assert(!p.locked);
        p.transactionChecks++;return p.guardFixtureAllowed?0:EACCES;
    }
    static int unlocked(void*v){auto&p=*(Fixture*)v;return p.locked?EDEADLK:0;}
    static int idle(void*v){auto&p=*(Fixture*)v;assert(!p.locked);
        return p.joining?EBUSY:0;
    }
    static int policy(void*v,const uint8_t*address){auto&p=*(Fixture*)v;
        assert(!p.locked&&p.state.running&&!memcmp(address,p.payload+512,6));
        p.events.push_back(Policy);return 0;
    }
    static int operation(void*v,const uint8_t*address,int step){auto&p=*(Fixture*)v;
        assert(!p.locked&&p.state.running&&!memcmp(address,p.payload+512,6));
        p.operations.push_back(step+(p.postPhase?10:0));
        const Event order[]={SetFW,ReadFW,SetBSD,ReadBSD,SetProperty,ReadProperty};
        p.events.push_back(order[step]);uint8_t*target=step<2?p.firmware:step<4?p.bsd:p.property;
        if(!(step&1)){assert(!p.postPhase);memcpy(target,address,6);p.setters++;}
        if((p.postPhase?p.failPost:p.failStep)==step)return EIO;
        if(step&1)assert(!memcmp(target,address,6));return 0;
    }
    static int op0(void*v,const uint8_t*a){return operation(v,a,0);}
    static int op1(void*v,const uint8_t*a){return operation(v,a,1);}
    static int op2(void*v,const uint8_t*a){return operation(v,a,2);}
    static int op3(void*v,const uint8_t*a){return operation(v,a,3);}
    static int op4(void*v,const uint8_t*a){return operation(v,a,4);}
    static int op5(void*v,const uint8_t*a){return operation(v,a,5);}
    PM::API backend(){PM::API a;a.context=this;a.authorization=check;a.registryUnlocked=unlocked;
        a.controllerGate=check;a.unassociated=idle;a.policySource=policy;a.setFirmware=op0;
        a.verifyDriverCache=op1;a.setPrimaryBSD=op2;a.verifyPrimaryBSD=op3;
        a.publishCurrentIOMAC=op4;a.verifyCurrentIOMAC=op5;return a;
    }
    void poison(){if(state.quarantined){assert(contextLive);
        assert(!admission.poison(lease,owner,(uint32_t)state.firstFailure));}}
    struct Frame {AC::Scope*scope;bool attempted=false,applied=false;};
    int auth(Frame&frame){
        auto*scope=registry.find(owner,controller,interface);auths++;events.push_back(Auth);
        if(scope!=frame.scope||!scope||!scope->consumed||scope->privateFrame!=&frame||
           frame.attempted)return EOPNOTSUPP;
        frame.attempted=true;
        // Fictional trusted consumer input. This is NOT real kauth/session proof.
        if(mode==Mode::WrongAuth)return EINVAL;
        assert(scope->authUpper==ScanCompat::read32(payload+12));
        auto a=backend();auto result=PM::apply(a,state,scope->privatePlan.address,true);
        frame.applied=!result.error&&result.consistentPrivate;
        scope->privateApplied=frame.applied;scope->privateError=result.error;poison();
        if(result.error)return result.error;
        originalAuths++;events.push_back(OriginalAuth);return authError;
    }
    int driver(AC::Scope*scope,uint8_t*old){drivers++;events.push_back(Driver);
        if(!scope||!scope->consumed||scope->privateFrame||memcmp(old,scope->legacy,O))return EINVAL;
        assert(scope->privatePlan.deviceTypeInDhcpAllowed==bool(payload[469]&0x40));
        assert(!(old[464]&8)&&!(old[465]&0x40));
        if(mode==Mode::Unapplied){scope->privateError=0;return 0;}
        if(mode==Mode::FakeCompleted){scope->privateCompleted=true;scope->privateError=0;return 0;}
        Frame frame{scope};scope->privateFrame=&frame;
        int error=auth(frame);lastAuth=error;
        if(mode==Mode::DuplicateAuth&&!error){
            // A second actual transaction is also prohibited while awaiting
            // completion; the consumer's once-only frame rejects it first.
            auto a=backend();auto repeated=PM::apply(a,state,scope->privatePlan.address,true);
            assert(repeated.error==EBUSY);
            error=auth(frame);assert(error==EOPNOTSUPP);scope->privateError=error;
        }
        if(!error){events.push_back(OriginalDriver);error=driverError;}
        if(frame.applied&&mode!=Mode::Uncompleted){
            joining=true;postPhase=true;posts++;events.push_back(Post);auto a=backend();
            auto result=PM::associationReturned(a,state,error,scope->consumed);
            error=result.error;scope->privateCompleted=result.consistentPrivate&&!result.quarantined;
            poison();
        } else if(!frame.applied&&!error) error=scope->privateError?scope->privateError:EIO;
        scope->privateError=error;scope->privateFrame=nullptr;return error;
    }
    static int original(void*c,void*i,void*v,void*infra,ScanCompat::Request*r,bool user64){auto&p=f();
        assert(!p.locked&&c==p.controller&&i==p.interface);p.originals++;p.events.push_back(Handler);
        if(!AC::eligible(r,c,i,v,infra,user64))return p.driverError;
        auto*scope=p.registry.find(p.owner,c,i);assert(scope);
        assert(scope->thread==p.owner&&scope->caller==p.copyCaller&&scope->interface==p.interface);
        assert(scope->controller==p.controller&&scope->source==(uintptr_t)p.payload);
        assert(scope->authUpper==ScanCompat::read32(p.payload+12));
        assert(scope->legacy==p.allocation+16+N);
        assert(scope->privatePlan.requested==bool(p.payload[468]&8));
        if(scope->privatePlan.requested)assert(!memcmp(scope->privatePlan.address,p.payload+512,6));
        p.sawPlan=scope->privatePlan.requested;
        if(p.mode==Mode::NoCopy)return 0;
        uint8_t old[O];memset(old,0xa6,O);
        uintptr_t thread=p.owner,caller=p.copyCaller;void*controller=c;uint64_t source=r->userData;
        size_t length=O;
        switch(p.badConsume){case 0:thread++;break;case 1:caller++;break;
          case 2:controller=&p.otherToken;break;case 3:source++;break;case 4:length--;break;}
        p.lastCopy=p.registry.consume(thread,caller,controller,source,old,length);
        if(p.lastCopy)return EINVAL;
        p.oldCopies++;p.events.push_back(CopiedOld);assert(!memcmp(old,scope->legacy,O));
        if(p.mode==Mode::DuplicateCopy){assert(p.registry.consume(thread,caller,controller,source,old,O)==EINVAL);return EINVAL;}
        if(!scope->privatePlan.requested)return p.driverError;
        if(p.mode==Mode::OnlyCopy)return 0;
        if(p.mode==Mode::WrongConsumer){
            auto*wrong=p.registry.find(p.badLookup==0?p.owner+1:p.owner,
                p.badLookup==1?(void*)&p.otherToken:c,p.badLookup==2?(void*)&p.otherToken:i);
            assert(!wrong);return 0; // Even a fake consumer swallowing this cannot pass handle().
        }
        if(p.badDriverByte>=0)old[p.badDriverByte]^=1;
        const int error=p.driver(scope,old);
        p.planApplied=scope->privateApplied;p.planCompleted=scope->privateCompleted;
        memset(old,0,O);return error;
    }
    int handle(bool user64=true){
        const auto saved=envelope;uint8_t before[N];memcpy(before,payload,N);
        AC::Result validation{};bool used=false;
        const int error=AC::handle(api,controller,interface,nullptr,nullptr,&envelope.request,user64,&validation,&used);
        copied=used;
        assert(!memcmp(before,payload,N)&&!memcmp(&saved,&envelope,sizeof(saved)));
        assert(!registry.head&&!allocation&&allocs==frees&&!locked);return error;
    }
    int run(bool user64=true){
        assert(!contextLive);admissionCalls++;
        const int admitted=admission.enter(binding,owner,lease);if(admitted)return admitted;
        contextLive=true;events.push_back(Admitted);const int error=handle(user64);
        poison();const int finish=admission.finish(lease,owner);assert(!finish);
        contextLive=false;events.push_back(Finished);return error?error:finish;
    }
    void resetLease(){lease=PM::AdmissionLease{};}
    void allPrivate(){assert(!memcmp(firmware,requested,6)&&!memcmp(bsd,requested,6)&&!memcmp(property,requested,6));}
};
static void good(){Fixture p;assert(!p.run());assert(p.sawPlan&&p.copied&&p.planApplied&&p.planCompleted);
    assert(p.nativeCopies==1&&p.oldCopies==1&&p.originals==1&&p.drivers==1&&p.auths==1&&p.posts==1);
    assert(p.setters==3&&p.originalAuths==1&&!p.state.quarantined&&!p.state.awaitingHandler);p.allPrivate();
    const std::vector<int> sequence={0,1,2,3,4,5,11,13,15};assert(p.operations==sequence);
    const Event expected[]={Admitted,Entry,Allocated,CopiedNative,Consumer,Handler,CopiedOld,
        Driver,Auth,Policy,SetFW,ReadFW,SetBSD,ReadBSD,SetProperty,ReadProperty,OriginalAuth,
        OriginalDriver,Post,ReadFW,ReadBSD,ReadProperty,Freed,Finished};
    assert(p.events==std::vector<Event>(expected,expected+sizeof(expected)/sizeof(expected[0])));
}
static void entryBlocks(){for(uint32_t length:{uint32_t(0),uint32_t(32),uint32_t(O),uint32_t(N),uint32_t(N+1)})
    for(bool user64:{false,true})for(bool privateFlag:{false,true}){
        Fixture p(privateFlag);p.envelope.request.length=length;p.entryError=EPERM;
        assert(p.run(user64)==EPERM);assert(p.entryCalls==1&&!p.nativeCopies&&!p.originals&&!p.allocs&&!p.availableCalls);
    }
}
static void consumerRequired(){
    {Fixture p;p.consumer=false;assert(p.run()==EOPNOTSUPP);assert(!p.sawPlan&&!p.originals&&!p.oldCopies&&!p.setters);
      assert(p.nativeCopies==1&&p.allocs==1&&p.frees==1);}
    {Fixture p(false);p.consumer=false;assert(!p.run());assert(!p.sawPlan&&p.copied&&!p.drivers&&!p.setters);}
    {Fixture p;p.api.privateAvailable=nullptr;assert(p.run()==EOPNOTSUPP);assert(!p.originals&&!p.setters);}
}
static void exactScope(){Fixture p;assert(!p.run());assert(p.sawPlan&&p.copied);
    // An old-size request is admitted but is never a native conversion scope.
    Fixture old;old.envelope.request.length=O;assert(!old.run());
    assert(old.originals==1&&!old.nativeCopies&&!old.availableCalls&&!old.allocs&&!old.sawPlan);
}
static void missingWork(){for(auto mode:{Mode::NoCopy,Mode::OnlyCopy,Mode::Unapplied,Mode::FakeCompleted,Mode::Uncompleted}){
    Fixture p;p.mode=mode;assert(p.run()!=0);
    assert(!p.planCompleted||mode==Mode::FakeCompleted);
    if(mode==Mode::NoCopy)assert(!p.copied&&!p.drivers&&!p.setters);
    if(mode==Mode::Uncompleted)assert(p.planApplied&&!p.planCompleted&&p.posts==0&&p.state.awaitingHandler);
    else assert(!p.setters);
}}
static void wrongConsumer(){for(int kind=0;kind<3;kind++){Fixture p;p.mode=Mode::WrongConsumer;p.badLookup=kind;
    assert(p.run()!=0&&p.copied&&!p.drivers&&!p.setters&&!p.planApplied&&!p.planCompleted);}}
static void copyMismatches(){for(int kind=0;kind<5;kind++){Fixture p;p.badConsume=kind;
    assert(p.run()==EINVAL&&!p.copied&&!p.oldCopies&&!p.drivers&&!p.setters);
    assert(p.lastCopy==(kind<2?-1:EINVAL));}}
static void allOldBytes(){for(size_t j=0;j<O;j++){Fixture p;p.badDriverByte=(int)j;
    assert(p.run()==EINVAL&&p.copied&&p.drivers==1&&!p.auths&&!p.setters&&!p.planApplied);}}
static void duplicateCopy(){Fixture p;p.mode=Mode::DuplicateCopy;assert(p.run()==EINVAL);
    assert(p.copied&&p.oldCopies==1&&!p.drivers&&!p.setters);}
static void duplicateAuth(){Fixture p;p.mode=Mode::DuplicateAuth;assert(p.run()==EOPNOTSUPP);
    assert(p.auths==2&&p.originalAuths==1&&p.setters==3&&p.posts==1&&p.planCompleted);p.allPrivate();}
static void wrongAuth(){Fixture p;p.mode=Mode::WrongAuth;assert(p.run()==EINVAL);
    assert(p.copied&&p.auths==1&&!p.originalAuths&&!p.setters&&!p.planApplied);}
static void errorsPreserved(){for(int error:{EINVAL,EACCES,EIO,ETIMEDOUT}){
    Fixture p;p.driverError=error;assert(p.run()==error&&p.planApplied&&p.planCompleted);
    assert(!p.state.quarantined&&!p.state.awaitingHandler);p.allPrivate();
    Fixture q;q.authError=error;assert(q.run()==error&&q.planApplied&&q.planCompleted);q.allPrivate();
}}
static void partialQuarantine(){for(int step=0;step<6;step++){
    Fixture p;p.failStep=step;assert(p.run()==EIO&&p.state.quarantined&&p.admission.isQuarantined());
    assert(p.state.firstFailure!=PM::Stage::None&&!p.planCompleted&&!p.originalAuths);
    const auto writes=p.setters,originals=p.originals,copies=p.nativeCopies,allocs=p.allocs;
    for(uint32_t length:{uint32_t(0),uint32_t(32),uint32_t(O),uint32_t(N),uint32_t(N+1)})
      for(bool privateFlag:{false,true}){
        p.resetLease();p.envelope.request.length=length;p.payload[468]=privateFlag?8:0;
        if(!privateFlag)memset(p.payload+512,0,6);else memcpy(p.payload+512,requested,6);
        assert(p.run()==EIO);assert(p.setters==writes&&p.originals==originals&&p.nativeCopies==copies&&p.allocs==allocs);
        // Also execute handle's own admission callback without an outer lease.
        assert(p.handle()==EIO);assert(p.originals==originals&&p.nativeCopies==copies&&p.allocs==allocs);
      }
    assert(!memcmp(p.firmware,requested,6)); // Failed firmware attempt can mutate; never restore factory/prior.
}}
static void postQuarantine(){for(int step:{1,3,5}){Fixture p;p.failPost=step;
    assert(p.run()==EIO&&p.planApplied&&!p.planCompleted&&p.posts==1&&p.admission.isQuarantined());p.allPrivate();
    p.resetLease();assert(p.run()==EIO);assert(p.setters==3&&p.originals==1);
}}
static void beforeMutation(){Fixture p;p.guardFixtureAllowed=false;
    assert(p.run()==EACCES&&!p.setters&&!p.state.quarantined&&!p.admission.isQuarantined());
    assert(!memcmp(p.firmware,prior,6)&&!memcmp(p.bsd,prior,6)&&!memcmp(p.property,prior,6));}
static void earlyCleanup(){
    {Fixture p;p.copyError=EFAULT;assert(p.run()==EFAULT&&!p.originals&&p.allocs==p.frees&&!p.observedCalls&&!p.surveyCalls);}
    {Fixture p;p.failAlloc=true;assert(p.run()==ENOMEM&&!p.nativeCopies&&!p.originals&&!p.allocs&&!p.frees);}
    {Fixture p;p.payload[469]=0x80;assert(p.run()==EOPNOTSUPP&&!p.originals&&p.allocs==p.frees);
      assert(p.observedCalls==1&&p.observed469==0x80);}
    {Fixture p;p.payload[518]=1;assert(p.run()==EOPNOTSUPP&&!p.originals&&p.allocs==p.frees);}
}
static void dhcpPolicy(){Fixture p;p.payload[469]=0x40;assert(!p.run());
    assert(p.planApplied&&p.planCompleted&&p.copied&&p.originalAuths==1);
    assert(p.observedCalls==1&&p.observed469==0x40&&p.observedFlags==0x400800);
    assert(p.surveyCalls==1&&p.observedSurvey.allowedAuth508.low16==4&&p.observedSurvey.allowedAuth508.high16==0);
    p.allPrivate();
}
static void noContext(){Fixture p;assert(p.handle()==EOPNOTSUPP);
    assert(!p.nativeCopies&&!p.originals&&!p.allocs&&!p.availableCalls);}
static void sequoiaProfile(){
    {Fixture p;p.envelope.request.length=900;p.payload[899]=0;
     assert(!p.run()&&p.copied&&p.planApplied&&p.planCompleted);p.allPrivate();
     assert(p.nativeCopies==1&&p.oldCopies==1&&p.surveyCalls==1&&p.payload[899]==0);}
    {Fixture p(false);p.consumer=false;p.envelope.request.length=900;p.payload[899]=0;
     assert(!p.run()&&p.copied&&!p.drivers&&!p.setters);}
    for(size_t bad:{size_t(700),size_t(899)}){
     Fixture p;p.envelope.request.length=900;p.payload[899]=0;p.payload[bad]=1;
     assert(p.run()==EOPNOTSUPP&&!p.originals&&!p.setters&&p.allocs==p.frees);}
}
int main(int argc,char**argv){assert(argc==2);switch(atoi(argv[1])){
 case 0:good();break;case 1:entryBlocks();break;case 2:consumerRequired();break;
 case 3:exactScope();break;case 4:missingWork();break;case 5:wrongConsumer();break;
 case 6:copyMismatches();break;case 7:allOldBytes();break;case 8:duplicateCopy();break;
 case 9:duplicateAuth();break;case 10:wrongAuth();break;case 11:errorsPreserved();break;
 case 12:partialQuarantine();break;case 13:postQuarantine();break;case 14:beforeMutation();break;
 case 15:earlyCleanup();break;case 16:noContext();break;case 17:dhcpPolicy();break;
 case 18:sequoiaProfile();break;default:abort();}puts("ok");}
'''


class PrivateMACAssociationFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="private-mac-flow-", dir="/private/tmp")
        cls.binary = pathlib.Path(cls.tmp.name) / "test"
        result = subprocess.run(
            ["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             "-I", str(PROJECT / "src/scan_kernel"), "-x", "c++", "-", "-o", str(cls.binary)],
            input=HARNESS, text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def scenario(self, number):
        result = subprocess.run([str(self.binary), str(number)], text=True,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ok\n")
        self.assertEqual(result.stderr, "")

    def test_full_copy_driver_auth_apply_post_order_and_scope_values(self): self.scenario(0)
    def test_entry_allowed_blocks_every_primary_length_bitness_and_policy_before_copy(self): self.scenario(1)
    def test_private_extension_requires_registered_consumer_and_nonprivate_still_works(self): self.scenario(2)
    def test_native_scope_preserves_exact_address_upper_interface_and_old_passthrough(self): self.scenario(3)
    def test_missing_copy_apply_or_completion_cannot_report_success(self): self.scenario(4)
    def test_wrong_thread_controller_or_interface_consumer_cannot_complete(self): self.scenario(5)
    def test_copy_consumer_exact_thread_caller_controller_source_length(self): self.scenario(6)
    def test_driver_entry_compares_all_548_bytes_before_auth(self): self.scenario(7)
    def test_scope_copy_is_consumable_only_once(self): self.scenario(8)
    def test_duplicate_auth_cannot_reapply_or_report_success(self): self.scenario(9)
    def test_auth_consumer_rejection_never_calls_backend(self): self.scenario(10)
    def test_original_driver_and_auth_errors_survive_successful_consistency_post(self): self.scenario(11)
    def test_each_partial_failure_quarantines_all_later_primary_set20_shapes(self): self.scenario(12)
    def test_each_post_failure_quarantines_and_never_restores_an_address(self): self.scenario(13)
    def test_pre_mutation_denial_does_not_mutate_or_claim_quarantine(self): self.scenario(14)
    def test_allocation_copy_extension_failures_remove_scope_and_scrub_heap(self): self.scenario(15)
    def test_absent_admission_context_refuses_before_copy_or_original(self): self.scenario(16)
    def test_known_dhcp_permission_is_scoped_and_flags_are_observed_after_copy(self): self.scenario(17)
    def test_sequoia_exact_copy_and_normalization_share_scoped_private_transaction(self): self.scenario(18)


if __name__ == "__main__":
    unittest.main()
