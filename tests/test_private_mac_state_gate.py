"""Run the actual portable state gate against allocated fake object maps only.

No IOKit calls, kernel loads, ioctl, MAC setters or hardware reads are made.
Addresses below are opaque fixture keys; the reader never dereferences them.
"""
import pathlib
import subprocess
import tempfile
import unittest

PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "state_gate.hpp"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
using namespace PrivateMAC::StateGate;
constexpr Address C=0x10000,I=0x20000,W=0x30000,P=0x40000,T=0x50000;
constexpr Address B=0x60000,M=0x70000,A=0x80000,S=0x90000,D=0xa0000;
struct Block {Object kind;Address base;std::vector<uint8_t> bytes;};
struct Read {Object kind;size_t offset;};
struct Fixture {
    std::vector<Block> blocks;
    std::vector<Read> history;
    bool pinned=true,authorized=true,lease=true,gate=true,identity=true,unlocked=true;
    bool getterOK=true,assocOK=true,stateOK=true,busy=false;
    bool joinAllowed=false,joinRevoke=false;unsigned joinCalls=0;
    Address getterMain=B;uint32_t version=1,state=0;
    unsigned reads=0,mainCalls=0,assocCalls=0,stateCalls=0,denyAt=0,revokeAt=0;
    unsigned revokeMode=0,getterRevoke=0;
    bool forbiddenRead=false;
    Fixture() {
        blocks={{Object::Controller,C,std::vector<uint8_t>(controllerSize)},
         {Object::Wlc,W,std::vector<uint8_t>(wlcSize)},
         {Object::Pub,P,std::vector<uint8_t>(pubSize)},
         {Object::BssTable,T,std::vector<uint8_t>(tableSize)},
         {Object::BssModule,M,std::vector<uint8_t>(modulePrefix)},
         {Object::MainCfg,B,std::vector<uint8_t>(mainPrefix)},
         {Object::Assoc,A,std::vector<uint8_t>(assocSize)},
         {Object::ScanPub,S,std::vector<uint8_t>(scanPubSize)},
         {Object::ScanPrivate,D,std::vector<uint8_t>(scanPrivateSize)}};
        put<Address>(C,0xa10,W);put<Address>(C,0xa18,P);put<uint64_t>(C,0x1a90,2);
        put<Address>(W,0,P);put<Address>(P,0,W);put<Address>(W,0x338,T);
        put<Address>(W,0x340,B);put<Address>(T,0,B);put<Address>(W,0x160,M);
        put<Address>(M,0,W);put<uint32_t>(M,8,0x448);put<Address>(W,0x1e0,S);
        put<uint8_t>(W,0x31,1);put<uint8_t>(P,0x20,1);put<uint8_t>(P,0x30,1);
        put<Address>(B,0,W);put<uint8_t>(B,9,1);put<uint8_t>(B,0x18,1);
        put<Address>(B,0x128,A);put<Address>(S,0,D);put<Address>(D,0,S);
        put<Address>(D,0x10,W);
    }
    Block &block(Address address) {for(auto &b:blocks)if(b.base==address)return b;abort();}
    template<class V>void put(Address address,size_t offset,V value) {
        auto &b=block(address);assert(offset<=b.bytes.size()&&sizeof(V)<=b.bytes.size()-offset);
        memcpy(b.bytes.data()+offset,&value,sizeof(value));
    }
};
static bool pins(void*p){return ((Fixture*)p)->pinned;}
static bool root(void*p){return ((Fixture*)p)->authorized;}
static bool lease(void*p,Address c,Address i){assert(c==C&&i==I);return ((Fixture*)p)->lease;}
static bool gate(void*p,Address c){assert(c==C);return ((Fixture*)p)->gate;}
static bool identity(void*p,Address c,Address i){assert(c==C&&i==I);return ((Fixture*)p)->identity;}
static bool unlocked(void*p){return ((Fixture*)p)->unlocked;}
static void revoke(Fixture &f){switch(f.revokeMode){case 0:f.gate=false;break;
    case 1:f.authorized=false;break;case 2:f.lease=false;break;case 3:f.pinned=false;break;
    case 4:f.identity=false;break;case 5:f.unlocked=false;break;default:abort();}}
static bool reader(void*p,Object kind,Address address,size_t extent,size_t offset,void*out,size_t n){
    auto &f=*(Fixture*)p;
    if(!f.lease||!f.gate||!f.authorized||!f.pinned){f.forbiddenRead=true;return false;}
    f.reads++;
    f.history.push_back({kind,offset});
    if(f.denyAt==f.reads)return false;
    for(auto &b:f.blocks)if(b.base==address&&b.kind==kind){
        if(extent>b.bytes.size()||offset>extent||n>extent-offset)return false;
        memcpy(out,b.bytes.data()+offset,n);
        if(f.revokeAt==f.reads)revoke(f);
        return true;
    }
    return false;
}
static bool mainGetter(void*p,Address c,Address*out){auto &f=*(Fixture*)p;assert(c==C);
    assert(f.lease&&f.gate);f.mainCalls++;*out=f.getterMain;
    if(f.getterRevoke==1)revoke(f);return f.getterOK;}
static bool assocHelper(void*p,Address w,bool*out){auto &f=*(Fixture*)p;assert(w==W);
    assert(f.lease&&f.gate);f.assocCalls++;*out=f.busy;
    if(f.getterRevoke==2)revoke(f);return f.assocOK;}
static bool stateGetter(void*p,Address c,Address i,uint32_t*out){auto &f=*(Fixture*)p;
    assert(c==C&&i==I&&f.lease&&f.gate);f.stateCalls++;out[0]=f.version;out[1]=f.state;
    if(f.getterRevoke==3)revoke(f);return f.stateOK;}
// A portable fixture callback only. The real adapter must validate its actual
// current scope/caller/request; this boolean is never an external API input.
static bool infrastructure(void*p,Address c,Address i){auto &f=*(Fixture*)p;
    assert(c==C&&i==I&&f.pinned&&f.authorized&&f.lease&&f.gate&&f.identity&&f.unlocked);
    f.joinCalls++;if(f.joinRevoke)revoke(f);return f.joinAllowed;}
static Access access(Fixture &f){Access a;a.context=&f;a.pins=pins;a.root=root;a.liveLease=lease;
    a.gateHeld=gate;a.identity=identity;a.registryUnlocked=unlocked;a.read=reader;
    a.mainGetter=mainGetter;a.assocInProgress=assocHelper;a.getState=stateGetter;return a;}
static Result run(Fixture &f){return check(access(f),C,I);}
static void expect(const Result &r,Reason reason,Field field){
    // Only stable numeric status is emitted if a fixture expectation fails.
    if(r.reason!=reason||r.field!=field){
        fprintf(stderr,"reason=%u field=%u\n",(unsigned)r.reason,(unsigned)r.field);abort();
    }
}
static void success(){Fixture f;auto before=f.blocks;auto r=run(f);assert(r.ok());
    assert(r.field==Field::None&&f.mainCalls==1&&f.assocCalls==1&&f.stateCalls==1);
    assert(f.reads>=30&&!f.forbiddenRead);
    for(size_t i=0;i<before.size();i++)assert(before[i].bytes==f.blocks[i].bytes);
    assert(run(f).ok()&&f.mainCalls==2&&f.assocCalls==2); // Getters are not cached.
}
static void scalarFields(){
    struct Test{Address base;size_t offset;uint64_t value;unsigned width;Field field;};
    const Test cases[]={
      {C,0x1aa0,1,1,Field::ControllerPowerSleep},{C,0x249a,1,1,Field::ControllerPowerCycle},
      {C,0x1a90,1,8,Field::ControllerPowerState},{C,0x1a90,0x100000002ULL,8,Field::ControllerPowerState},
      {M,8,0x447,4,Field::BssModuleSize},{W,0x5e8,8,8,Field::WlcAssocQueue},
      {W,0x28e,1,1,Field::WlcGoingDown},{W,0x31,0,1,Field::WlcClock},
      {P,0x20,0,1,Field::PubUp},{P,0x21,1,1,Field::PubHardwareOff},
      {P,0x30,0,1,Field::PubHardwareUp},{B,8,1,1,Field::MainUp},
      {B,9,255,1,Field::MainEnable},{B,0xa,1,1,Field::MainAP},
      {B,0xc,1,1,Field::MainAssociated},{B,0x18,0,1,Field::MainInfra},
      {B,0x60,1,1,Field::MainIndex},{B,0x60,255,1,Field::MainIndex},
      {A,0xc,1,4,Field::AssocState},{A,0xc,8,4,Field::AssocState},
      {S,0xa,1,1,Field::ScanInProgress}};
    for(auto &t:cases)for(uint8_t enable:{uint8_t(0),uint8_t(1)}){Fixture f;
      f.put<uint8_t>(B,9,enable);
      if(t.width==1)f.put<uint8_t>(t.base,t.offset,(uint8_t)t.value);
      if(t.width==4)f.put<uint32_t>(t.base,t.offset,(uint32_t)t.value);
      if(t.width==8)f.put<uint64_t>(t.base,t.offset,t.value);
      expect(run(f),Reason::ValueMismatch,t.field);assert(!f.forbiddenRead);
    }
    // Unknown non-boolean values remain rejected, including enable==2.
    const Test boolean[]={{W,0x31,2,1,Field::WlcClock},{P,0x20,2,1,Field::PubUp},
      {P,0x30,2,1,Field::PubHardwareUp},{B,9,2,1,Field::MainEnable},{B,0x18,2,1,Field::MainInfra}};
    for(auto&t:boolean){Fixture f;f.put<uint8_t>(t.base,t.offset,2);expect(run(f),Reason::ValueMismatch,t.field);}
}
static void pointerShapes(){struct Test{Address base;size_t offset;Field field;};
    const Test cases[]={{C,0xa10,Field::ControllerWlc},{C,0xa18,Field::ControllerPub},
      {W,0x338,Field::WlcTable},{W,0x340,Field::WlcMain},{W,0x160,Field::WlcBssModule},
      {W,0x1e0,Field::WlcScan},{B,0x128,Field::MainAssoc},{S,0,Field::ScanPrivate}};
    const Address bad[]={0,1,UINTPTR_MAX-7};
    for(auto&t:cases)for(auto v:bad){Fixture f;f.put<Address>(t.base,t.offset,v);
      expect(run(f),Reason::InvalidPointer,t.field);assert(!f.forbiddenRead);}
}
static void backlinks(){struct Test{Address base;size_t offset;Field field;};
    const Test cases[]={{W,0,Field::WlcPub},{P,0,Field::PubOwner},{T,0,Field::TableMain},
       {M,0,Field::BssModuleOwner},{B,0,Field::MainOwner},{D,0,Field::ScanPubBacklink},
       {D,0x10,Field::ScanOwner}};
    for(auto&t:cases){Fixture f;f.put<Address>(t.base,t.offset,0);expect(run(f),Reason::ValueMismatch,t.field);}
    {Fixture f;f.getterMain=B+8;expect(run(f),Reason::ValueMismatch,Field::MainGetter);}
}
static void allocationBounds(){
    for(Address base:{C,W,P,T,M,B,A,S,D}){Fixture f;auto &b=f.block(base);b.bytes.resize(b.bytes.size()-1);
      auto r=run(f);assert(r.reason==Reason::ReadDenied&&!r.ok()&&!f.forbiddenRead);}
    {Fixture f;f.put<Address>(C,0xa10,0xb0000);auto r=run(f);
      expect(r,Reason::ReadDenied,Field::WlcPub);assert(!f.forbiddenRead);}
    // Even an aligned pointer to a real allocation of a different kind fails.
    {Fixture f;f.put<Address>(C,0xa10,P);expect(run(f),Reason::ReadDenied,Field::WlcPub);}
    // Larger legitimate cubby size does not authorize any expanded BSS read.
    {Fixture f;f.put<uint32_t>(M,8,0x900);assert(run(f).ok());}
    {Fixture f;f.put<uint32_t>(M,8,UINT32_MAX);assert(run(f).ok());}
}
static void missingBindings(){for(unsigned k=0;k<11;k++){Fixture f;auto a=access(f);
    switch(k){case 0:a.context=nullptr;break;case 1:a.pins=nullptr;break;case 2:a.root=nullptr;break;
    case 3:a.liveLease=nullptr;break;case 4:a.gateHeld=nullptr;break;case 5:a.identity=nullptr;break;
    case 6:a.registryUnlocked=nullptr;break;case 7:a.read=nullptr;break;case 8:a.mainGetter=nullptr;break;
    case 9:a.assocInProgress=nullptr;break;case 10:a.getState=nullptr;break;}
    assert(check(a,C,I).reason==Reason::MissingBinding&&f.reads==0&&f.stateCalls==0);
}}
static void preconditions(){for(unsigned k=0;k<6;k++){Fixture f;
    const Field fields[]={Field::Pins,Field::Authorization,Field::LiveLease,Field::Gate,Field::Identity,Field::RegistryUnlocked};
    switch(k){case 0:f.pinned=false;break;case 1:f.authorized=false;break;case 2:f.lease=false;break;
    case 3:f.gate=false;break;case 4:f.identity=false;break;case 5:f.unlocked=false;break;}
    expect(run(f),Reason::Prerequisite,fields[k]);assert(f.reads==0&&f.stateCalls==0&&!f.forbiddenRead);
}}
static void readRevocation(){Fixture baseline;assert(run(baseline).ok());unsigned count=baseline.reads;
    const Field revoked[]={Field::Gate,Field::Authorization,Field::LiveLease,Field::Pins,Field::Identity,Field::RegistryUnlocked};
    for(unsigned n=1;n<=count;n++){
      for(unsigned k=0;k<6;k++){
        Fixture f;f.revokeAt=n;f.revokeMode=k;Observation o;
        expect(check(access(f),C,I,&o),Reason::Prerequisite,revoked[k]);
        assert(f.reads==n&&!f.forbiddenRead);
        uint16_t expected=0;
        // The final read revoked authority: its value must not become present.
        for(unsigned j=0;j+1<n;j++){
          const auto &read=f.history[j];
          if(read.kind==Object::MainCfg){switch(read.offset){
            case 8:expected|=MainUpObserved;break;case 9:expected|=MainEnableObserved;break;
            case 0xa:expected|=MainAPObserved;break;case 0xc:expected|=MainAssociatedObserved;break;
            case 0x18:expected|=MainInfraObserved;break;case 0x60:expected|=MainIndexObserved;break;}}
          if(read.kind==Object::Assoc&&read.offset==0xc)expected|=AssocStateObserved;
          if(read.kind==Object::ScanPub&&read.offset==0xa)expected|=ScanInProgressObserved;
        }
        assert(o.reached==expected);
        if(!(o.reached&MainEnableObserved))assert(o.mainEnable==0);
        if(!(o.reached&MainInfraObserved))assert(o.mainInfra==0);
      }
      Fixture d;d.denyAt=n;auto r=run(d);assert(r.reason==Reason::ReadDenied&&d.reads==n);
    }
}
static void getters(){
    {Fixture f;f.getterOK=false;expect(run(f),Reason::GetterFailed,Field::MainGetter);}
    {Fixture f;f.assocOK=false;expect(run(f),Reason::GetterFailed,Field::AssocHelper);}
    {Fixture f;f.stateOK=false;expect(run(f),Reason::GetterFailed,Field::StateGetter);assert(f.reads==0);}
    {Fixture f;f.busy=true;expect(run(f),Reason::ValueMismatch,Field::AssocHelper);}
    {Fixture f;f.version=0;expect(run(f),Reason::ValueMismatch,Field::StateVersion);assert(f.reads==0);}
    {Fixture f;f.state=4;expect(run(f),Reason::ValueMismatch,Field::StateValue);assert(f.reads==0);}
    const Field revoked[]={Field::Gate,Field::Authorization,Field::LiveLease,Field::Pins,Field::Identity,Field::RegistryUnlocked};
    for(unsigned which=1;which<=3;which++)for(unsigned k=0;k<6;k++){
       Fixture f;f.getterRevoke=which;f.revokeMode=k;
       expect(run(f),Reason::Prerequisite,revoked[k]);assert(!f.forbiddenRead);
       if(which==3)assert(f.reads==0);
    }
}
static void malformedInputs(){Fixture f;auto a=access(f);
    for(Address bad:{(Address)0,(Address)1,UINTPTR_MAX-7}){
       expect(check(a,bad,I),Reason::InvalidPointer,Field::Controller);
       expect(check(a,C,bad),Reason::InvalidPointer,Field::Primary);
    }
    assert(f.reads==0&&f.stateCalls==0);
    uint64_t value=0;
    expect(readValue(a,C,I,Object::Controller,C,4,0,value,Field::Reader),Reason::ReadDenied,Field::Reader);
    expect(readValue(a,C,I,Object::Controller,C,controllerSize,SIZE_MAX,value,Field::Reader),Reason::ReadDenied,Field::Reader);
    assert(f.reads==0);
}
static void observations(){
    static_assert(sizeof(Observation::reached)==2,"fixed mask width");
    static_assert(sizeof(Observation::mainIndex)==1,"fixed signed index width");
    static_assert(sizeof(Observation::assocState)==4,"fixed state width");
    for(uint8_t enable:{uint8_t(0),uint8_t(1)}){Fixture f;
      f.put<uint8_t>(B,9,enable);const auto before=f.blocks;Observation o;
      assert(check(access(f),C,I,&o).ok()&&o.reached==255);
      assert(o.mainUp==0&&o.mainEnable==enable&&o.mainAP==0&&o.mainAssociated==0);
      assert(o.mainInfra==1&&o.mainIndex==0&&o.assocState==0&&o.scanInProgress==0);
      for(size_t j=0;j<before.size();j++)assert(before[j].bytes==f.blocks[j].bytes);
      const unsigned reads=f.reads;Fixture old;old.put<uint8_t>(B,9,enable);
      assert(check(access(old),C,I).ok());
      assert(reads==old.reads); // Optional observation cannot add driver reads.
      // Reusing an output does not retain fields from the previous invocation.
      f.state=4;expect(check(access(f),C,I,&o),Reason::ValueMismatch,Field::StateValue);
      assert(o.reached==0&&o.mainEnable==0&&o.mainInfra==0&&o.assocState==0);
    }
    {Fixture f;Observation o;f.put<uint8_t>(B,9,2);f.put<uint8_t>(B,0xa,254);
      f.put<uint8_t>(B,0xc,253);f.put<uint8_t>(B,0x18,252);f.put<int8_t>(B,0x60,-128);
      const auto before=f.blocks;
      expect(check(access(f),C,I,&o),Reason::ValueMismatch,Field::MainEnable);
      assert(o.reached==255&&o.mainUp==0&&o.mainEnable==2&&o.mainAP==254);
      assert(o.mainAssociated==253&&o.mainInfra==252&&o.mainIndex==-128);
      assert(o.assocState==0&&o.scanInProgress==0);
      for(size_t j=0;j<before.size();j++)assert(before[j].bytes==f.blocks[j].bytes);
    }
    {Fixture f;Observation o;f.put<Address>(B,0,0);
      expect(check(access(f),C,I,&o),Reason::ValueMismatch,Field::MainOwner);
      assert(o.reached==0); // No main scalar before its owner backlink passes.
    }
    {Fixture f;Observation o;f.put<uint32_t>(A,0xc,UINT32_MAX);
      expect(check(access(f),C,I,&o),Reason::ValueMismatch,Field::AssocState);
      assert(o.reached==255&&o.assocState==UINT32_MAX&&o.scanInProgress==0);
    }
    {Fixture f;Observation o;f.put<uint8_t>(S,0xa,255);
      expect(check(access(f),C,I,&o),Reason::ValueMismatch,Field::ScanInProgress);
      assert(o.reached==255&&o.scanInProgress==255);
    }
    {Fixture f;Observation o;o.reached=255;o.mainEnable=255;auto a=access(f);a.read=nullptr;
      expect(check(a,C,I,&o),Reason::MissingBinding,Field::Reader);
      assert(o.reached==0&&o.mainEnable==0&&f.reads==0);
    }
}
static void infrastructureAdmission(){
    {Fixture f;f.put<uint8_t>(B,0x18,0);Observation o;
      expect(check(access(f),C,I,&o),Reason::ValueMismatch,Field::MainInfra);
      assert(o.reached==255&&o.mainInfra==0&&f.joinCalls==0);
    }
    for(uint8_t infra:{uint8_t(0),uint8_t(1)}){
      Fixture f;f.put<uint8_t>(B,0x18,infra);f.joinAllowed=true;
      auto a=access(f);a.infrastructureJoin=infrastructure;const auto before=f.blocks;
      Observation o;assert(check(a,C,I,&o).ok()&&o.reached==255);
      assert(o.mainInfra==infra&&f.joinCalls==(infra?0U:1U));
      for(size_t j=0;j<before.size();j++)assert(before[j].bytes==f.blocks[j].bytes);
      // Every invocation needs fresh scope proof; never inherit a prior grant.
      f.joinAllowed=false;
      if(infra)assert(check(a,C,I,&o).ok()&&f.joinCalls==0);
      else {expect(check(a,C,I,&o),Reason::ValueMismatch,Field::MainInfra);assert(f.joinCalls==2);}
    }
    for(uint8_t infra:{uint8_t(2),uint8_t(255)}){
      Fixture f;f.put<uint8_t>(B,0x18,infra);f.joinAllowed=true;
      auto a=access(f);a.infrastructureJoin=infrastructure;Observation o;
      expect(check(a,C,I,&o),Reason::ValueMismatch,Field::MainInfra);
      assert(o.reached==255&&o.mainInfra==infra&&f.joinCalls==0);
    }
    // Scope proof cannot authorize prior-invalid roles or any ongoing activity.
    struct Busy{Address base;size_t offset;unsigned value,width;Field field;};
    const Busy busy[]={
      {B,8,1,1,Field::MainUp},{B,9,2,1,Field::MainEnable},
      {B,0xa,1,1,Field::MainAP},{B,0xc,1,1,Field::MainAssociated},
      {B,0x60,1,1,Field::MainIndex},{A,0xc,7,4,Field::AssocState},
      {S,0xa,1,1,Field::ScanInProgress},{W,0x5e8,8,8,Field::WlcAssocQueue},
      {C,0x1aa0,1,1,Field::ControllerPowerSleep},{C,0x249a,1,1,Field::ControllerPowerCycle},
      {C,0x1a90,1,8,Field::ControllerPowerState},{W,0x28e,1,1,Field::WlcGoingDown},
      {W,0x31,0,1,Field::WlcClock},{P,0x20,0,1,Field::PubUp},
      {P,0x21,1,1,Field::PubHardwareOff},{P,0x30,0,1,Field::PubHardwareUp}};
    for(const auto &t:busy)for(uint8_t enable:{uint8_t(0),uint8_t(1)}){
      Fixture f;f.put<uint8_t>(B,0x18,0);f.put<uint8_t>(B,9,enable);f.joinAllowed=true;
      if(t.width==1)f.put<uint8_t>(t.base,t.offset,static_cast<uint8_t>(t.value));
      if(t.width==4)f.put<uint32_t>(t.base,t.offset,t.value);
      if(t.width==8)f.put<uint64_t>(t.base,t.offset,t.value);
      auto a=access(f);a.infrastructureJoin=infrastructure;
      expect(check(a,C,I),Reason::ValueMismatch,t.field);
      if(t.field==Field::MainUp||t.field==Field::MainEnable||t.field==Field::MainAP||
         t.field==Field::MainAssociated)assert(f.joinCalls==0);
      assert(!f.forbiddenRead);
    }
    {Fixture f;f.put<uint8_t>(B,0x18,0);f.joinAllowed=true;f.busy=true;
      auto a=access(f);a.infrastructureJoin=infrastructure;
      expect(check(a,C,I),Reason::ValueMismatch,Field::AssocHelper);assert(f.joinCalls==0);
    }
    const Field revoked[]={Field::Gate,Field::Authorization,Field::LiveLease,Field::Pins,Field::Identity,Field::RegistryUnlocked};
    for(unsigned k=0;k<6;k++){
      Fixture f;f.put<uint8_t>(B,0x18,0);f.joinAllowed=true;f.joinRevoke=true;f.revokeMode=k;
      auto a=access(f);a.infrastructureJoin=infrastructure;Observation o;
      expect(check(a,C,I,&o),Reason::Prerequisite,revoked[k]);
      assert(f.joinCalls==1&&o.reached==255&&!f.forbiddenRead);
    }
}
static void tailObservation(){
    {Fixture f;f.put<uint8_t>(B,0x18,0);f.put<uint32_t>(A,0xc,77);f.put<uint8_t>(S,0xa,255);
      Observation o;expect(check(access(f),C,I,&o),Reason::ValueMismatch,Field::MainInfra);
      assert(o.reached==255&&o.assocState==77&&o.scanInProgress==255);
      f.joinAllowed=true;auto a=access(f);a.infrastructureJoin=infrastructure;
      expect(check(a,C,I,&o),Reason::ValueMismatch,Field::AssocState);
      assert(o.reached==255&&o.scanInProgress==255);
    }
    struct Broken{Address base;size_t offset;Reason reason;Field field;uint16_t reached;};
    const Broken broken[]={
      {B,0x128,Reason::InvalidPointer,Field::MainAssoc,63},
      {S,0,Reason::InvalidPointer,Field::ScanPrivate,127},
      {D,0,Reason::ValueMismatch,Field::ScanPubBacklink,127},
      {D,0x10,Reason::ValueMismatch,Field::ScanOwner,127}};
    for(const auto &t:broken){Fixture f;f.put<uint8_t>(B,0x18,0);f.put<Address>(t.base,t.offset,0);
      f.joinAllowed=true;auto a=access(f);a.infrastructureJoin=infrastructure;Observation o;
      expect(check(a,C,I,&o),t.reason,t.field);assert(o.reached==t.reached&&f.joinCalls==0);
      assert(o.scanInProgress==0&&!f.forbiddenRead);
    }
    Fixture complete;assert(run(complete).ok());
    for(unsigned n=1;n<=complete.reads;n++)for(unsigned k:{0U,2U}){
      Fixture f;f.put<uint8_t>(B,0x18,0);f.joinAllowed=true;f.revokeAt=n;f.revokeMode=k;
      auto a=access(f);a.infrastructureJoin=infrastructure;Observation o;
      expect(check(a,C,I,&o),Reason::Prerequisite,k?Field::LiveLease:Field::Gate);
      assert(f.reads==n&&f.joinCalls==0&&!f.forbiddenRead);
    }
}
int main(int argc,char**argv){assert(argc==2);switch(atoi(argv[1])){
    case 0:success();break;case 1:scalarFields();break;case 2:pointerShapes();break;
    case 3:backlinks();break;case 4:allocationBounds();break;case 5:missingBindings();break;
    case 6:preconditions();break;case 7:readRevocation();break;case 8:getters();break;
    case 9:malformedInputs();break;case 10:observations();break;
    case 11:infrastructureAdmission();break;case 12:tailObservation();break;default:abort();}}
'''


class PrivateMACStateGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="private-mac-state-gate-", dir="/private/tmp")
        cls.binary = pathlib.Path(cls.tmp.name) / "test"
        # stdio is used solely to report two numeric diagnostic codes on failure.
        source = '#include <stdio.h>\n' + HARNESS
        result = subprocess.run(
            ["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-I",
             str(PROJECT / "src/private_mac_compat"), "-x", "c++", "-", "-o", str(cls.binary)],
            input=source, text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def scenario(self, number):
        result = subprocess.run([str(self.binary), str(number)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_complete_idle_fixture_calls_real_binding_slots_without_writes(self): self.scenario(0)
    def test_every_scalar_role_transition_and_unknown_boolean_value_rejects(self): self.scenario(1)
    def test_every_derived_pointer_rejects_null_unaligned_and_overflow(self): self.scenario(2)
    def test_all_owner_backlinks_table_and_main_getter_must_match(self): self.scenario(3)
    def test_each_allocation_bound_kind_and_unregistered_pointer_is_enforced(self): self.scenario(4)
    def test_every_mandatory_callback_missing_fails_before_any_read(self): self.scenario(5)
    def test_pins_root_real_lease_gate_identity_and_registry_are_mandatory(self): self.scenario(6)
    def test_each_read_denial_or_gate_revocation_stops_without_further_reads(self): self.scenario(7)
    def test_actual_main_association_and_state_getters_cannot_be_skipped(self): self.scenario(8)
    def test_input_pointer_and_offset_overflow_fail_before_reader(self): self.scenario(9)
    def test_numeric_observation_partial_presence_reset_and_source_immutability(self): self.scenario(10)
    def test_optional_current_infrastructure_proof_never_bypasses_busy_or_authority(self): self.scenario(11)
    def test_safe_tail_collection_is_complete_on_scalar_rejection_and_stops_on_structural_failure(self): self.scenario(12)


if __name__ == "__main__":
    unittest.main()
