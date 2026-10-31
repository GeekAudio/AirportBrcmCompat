"""End-to-end host contracts for the ElCap five-argument runtime adapters."""
import pathlib
import subprocess
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/legacy_bridge.hpp"
#include "legacy_wifi_compat/bsd_get_adapter.hpp"
#include "legacy_wifi_compat/bsd_set_adapter.hpp"
#include "legacy_wifi_compat/scan_sequence.hpp"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <thread>

namespace L=LegacyWiFi::LegacyBridge;
namespace S=LegacyWiFi::ScanBridge;
namespace A=LegacyWiFi::AssociationBridge;
namespace M=LegacyWiFi::ScanMultipleBridge;
namespace Q=LegacyWiFi::ScanSequence;
namespace ScanSingleBridge=LegacyWiFi::ScanSingleBridge;
namespace G=LegacyWiFi::BSDGetAdapter;

static void put16(uint8_t *p,uint16_t v){memcpy(p,&v,2);}
static void put32(uint8_t *p,uint32_t v){memcpy(p,&v,4);}
static uint32_t get32(const uint8_t *p){uint32_t v;memcpy(&v,p,4);return v;}
static uint8_t scanUser[ScanCompat::NativeSize];
static uint8_t assocUser[AssociationCompat::NativeSize];
static uint8_t multipleUser[M::NativeSize];
static uint8_t singleUser[ScanSingleBridge::Sequoia15Tahoe26Size];
static uint8_t singleConsumed[ScanSingleBridge::ElCapSize];
static uint8_t expectedSingle[ScanSingleBridge::ElCapSize];
static uint8_t capUser[8], capRaw[8];
static uint8_t stateUser[8], ieUser[0x808], ieRaw[0x400];
static uint8_t authUser[16],authConsumed[12];
static unsigned authOriginalCalls=0;
static bool failAuthCopy=false,mutateAuthAfterSnapshot=false,skipAuthCopy=false;
static bool wrongAuthCaller=false,doubleAuthCopy=false,nestedAuthRequest=false;
static int authOriginalError=0;
static unsigned disassociateOriginalCalls=0;
static bool nestedDisassociateRequest=false;
static int disassociateOriginalError=0;
static L::Request *expectedDisassociateRequest=nullptr;
static void *expectedDisassociateVirtual=nullptr;
static bool expectedDisassociateWide=true;
static uint8_t disassociateUser[12] {};
static bool failDisassociateCopy=false,mutateDisassociateAfterCopy=false;
static unsigned metadataCalls=0;
static uint32_t metadataReason=0,metadataFlush=0;
static int metadataError=0;
static bool metadataDisconnect=false;
static const uintptr_t authCaller=0x4c7b2;
static uint8_t scanIE[16], scanHeader[S::KernelHeaderSize];
static uint8_t assocConsumed[A::MaximumPayloadSize], multipleConsumed[M::ElCapSize];
static uint32_t assocLength=0;
static uint32_t scanLength=0;
static uint32_t singleLength=0;
static size_t capCopyOutSize=8;
static size_t ieActualLength=0, ieExpectedOutputSize=0;
static const uintptr_t ieCopyOutCaller=0x471db;
static unsigned scanOriginalCalls,capOriginalCalls,assocOriginalCalls,multipleOriginalCalls;
static unsigned stateOriginalCalls,ieOriginalCalls;
static unsigned singleOriginalCalls,singleCopyCalls;
static unsigned inputCalls,outputCalls,allocCalls,freeCalls;
static unsigned getResultCalls;
static bool primary=true, multipleSupported=true, advertiseCaps=false;
static bool wrongAssocCaller=false, wrongMultipleCaller=false;
static bool wrongSingleCaller=false,doubleSingleCopy=false,verifySingleCopy=false;
static bool changePrimaryOnCheck=false;
static bool failScanCopyIn=false, failScanCopyOut=false, failAssocCopyIn=false;
static bool failStateCopyOut=false,failIECopyOut=false,wrongIECopyCaller=false;
static bool wrongIECopyController=false,wrongIECopyThread=false,doubleIECopy=false;
static bool mismatchIERequestLength=false;
static bool failMultipleCopyIn=false,failSingleCopyIn=false;
static int stateOriginalError=0,ieOriginalError=0;
static int32_t returnedState=4;
static int singleOriginalError=0;
static int multipleOriginalError=0;
static bool skipMultipleCopy=false;
static bool probeNestedRequests=false;
static unsigned nestedRequestsBlocked=0;
static unsigned primaryChecks;
static bool locked=false;
static L::Runtime *runtime=nullptr;
static void *controller=(void*)0x100,*interface=(void*)0x200;
static const uintptr_t assocCaller=0x4d164,multipleCaller=0x4eed2,singleCaller=0x4cdad;

struct SequenceFake {
 enum Get11Mode { Unmanaged, Pending, Record, Eof, ExplicitError } get11=Unmanaged;
 int pid=4242;
 int pendingError=EBUSY;
 int explicitError=ENETDOWN;
 int prepareError=0;
 int busyError=0;
 int invalidateError=0;
 int submitError=0;
 uint64_t token=0x9a73;
 uint8_t record[ScanCompat::OldSize] {};
 unsigned peekCalls=0,commitCalls=0,submitCalls=0,prepareCalls=0;
 unsigned busyCalls=0,invalidationCalls=0;
 unsigned commitSuccesses=0,commitAborts=0;
 uint32_t lastSubmitJobs=0;
 bool lastCommitCopiedOut=false;
 int lastCommitPID=0;
 uint64_t lastCommitToken=0;
 size_t lastSubmitSize=0;
 uint8_t submitted[M::NativeSize] {};
} sequence;

static void enter(void *p){auto *b=(bool*)p;assert(!*b);*b=true;}
static void leave(void *p){auto *b=(bool*)p;assert(*b);*b=false;}
static uintptr_t threadOverride=0;
static uintptr_t currentThread(){return threadOverride?threadOverride:0x31;}
static bool isPrimary(void *c,void *i,const char name[16]){
 assert(c==controller&&i==interface&&name);primaryChecks++;
 if(changePrimaryOnCheck&&primaryChecks==2)return false;
 return primary;
}
static bool supportsMultiple(void *c,void *i){assert(c==controller&&i==interface);return multipleSupported;}
static bool scanDoneCapability46(void *c,void *i){assert(c==controller&&i==interface);return advertiseCaps;}
static void *allocate(size_t n){allocCalls++;return calloc(1,n);}
static void deallocate(void *p,size_t n){for(size_t j=0;j<n;j++)assert(!((uint8_t*)p)[j]);freeCalls++;free(p);}
static int rawCopyIn(void *c,uint64_t source,void *out,size_t n){
 assert(c==controller);inputCalls++;
 if(source==(uintptr_t)disassociateUser){assert(n==8||n==12);
  if(failDisassociateCopy)return EFAULT;
  memcpy(out,disassociateUser,n);
  if(mutateDisassociateAfterCopy){put32(disassociateUser+4,0xffffffff);put32(disassociateUser+8,1);}
  return 0;}
 if(source==(uintptr_t)authUser){assert(n==12||n==16);if(failAuthCopy)return EFAULT;
  memcpy(out,authUser,n);return 0;}
 if(source==(uintptr_t)capUser){assert(n==sizeof(capUser));memcpy(out,capUser,n);return 0;}
 if(source==(uintptr_t)scanUser){assert(n==scanLength);if(failScanCopyIn)return EFAULT;memcpy(out,scanUser,n);return 0;}
 if(source==(uintptr_t)assocUser){assert(n==assocLength);if(failAssocCopyIn)return EFAULT;memcpy(out,assocUser,n);return 0;}
 if(source==(uintptr_t)multipleUser){assert(n<=sizeof(multipleUser)||n==M::ElCapSize);
  if(failMultipleCopyIn)return EFAULT;memcpy(out,multipleUser,n);return 0;}
 if(source==(uintptr_t)singleUser){assert(n==singleLength);if(failSingleCopyIn)return EFAULT;memcpy(out,singleUser,n);return 0;}
 return EFAULT;
}
static int rawCopyOut(void *c,const void *source,uint64_t dest,size_t n){
 assert(c==controller);outputCalls++;
 if(dest==(uintptr_t)scanUser){assert(n==scanLength);if(failScanCopyOut)return EFAULT;memcpy(scanUser,source,n);return 0;}
 if(dest==(uintptr_t)capUser){assert(n==sizeof(capUser));memcpy(capUser,source,n);return 0;}
 if(dest==(uintptr_t)(stateUser+G::GetStateValueOffset)){
  assert(n==G::GetStateValueSize);if(failStateCopyOut)return EFAULT;
  memcpy(stateUser+G::GetStateValueOffset,source,n);return 0;
 }
 if(dest==(uintptr_t)ieUser){assert(n==ieExpectedOutputSize);if(failIECopyOut)return EFAULT;
  memcpy(ieUser,source,n);return 0;}
 return EFAULT;
}
static void *manager(void *i){assert(i==interface);return (void*)0x400;}
static int getResult(void *m,const uint8_t **out){assert(m==(void*)0x400);getResultCalls++;*out=scanHeader;return 0;}
static int getScanOriginal(void *c,void *i,void *v,ScanCompat::Request *r,bool u){
 assert(c==controller&&i==interface&&!v&&r&&u);scanOriginalCalls++;return 71;
}
static int capOriginal(void *c,void *i,void *v,ScanCompat::Request *r,bool u){
 assert(c==controller&&i==interface&&!v&&r&&u);capOriginalCalls++;
 r->length=8;return runtime->copyOut(c,capRaw,r->userData,capCopyOutSize);
}
static int stateOriginal(void *c,void *i,void *v,ScanCompat::Request *r,bool u){
 assert(c==controller&&i==interface&&!v&&r&&r->type==13&&u);
 stateOriginalCalls++;if(stateOriginalError)return stateOriginalError;
 r->value=returnedState;return 0;
}
static int ieListOriginal(void *c,void *i,void *v,ScanCompat::Request *r,bool u){
 assert(c==controller&&i==interface&&!v&&r&&r->type==48&&u);
 ieOriginalCalls++;if(ieOriginalError)return ieOriginalError;
 const uint32_t capacity=r->length;
 const uintptr_t caller=ieCopyOutCaller+(wrongIECopyCaller?1:0);
 void *copyController=wrongIECopyController?(void*)0x999:c;
 if(wrongIECopyThread)threadOverride=0x32;
 const int copied=runtime->copyOut(copyController,ieRaw,r->userData,ieActualLength,caller);
 threadOverride=0;
 if(copied)return copied;
 if(doubleIECopy){
  const int duplicated=runtime->copyOut(copyController,ieRaw,r->userData,ieActualLength,caller);
  if(duplicated)return duplicated;
 }
 r->length=capacity<ieActualLength?capacity:static_cast<uint32_t>(ieActualLength);
 if(mismatchIERequestLength)r->length++;
 return 0;
}
static int associateOriginal(void *c,void *i,void *,ScanCompat::Request *r,bool){
 assert(c==controller&&i==interface&&r);
 assocOriginalCalls++;
 if(r->length!=A::MaximumPayloadSize)return 71;
 int e=runtime->copyIn(c,r->userData,assocConsumed,sizeof(assocConsumed),
                       assocCaller+(wrongAssocCaller?1:0));
 if(e)return e;
 return 0;
}
static int multipleOriginal(void *c,void *i,void *,ScanCompat::Request *r,bool){
 assert(c==controller&&i==interface&&r&&r->type==86&&r->length==M::ElCapSize);
 multipleOriginalCalls++;
 if(skipMultipleCopy)return multipleOriginalError;
 const int error=runtime->copyIn(c,r->userData,multipleConsumed,sizeof(multipleConsumed),
                        multipleCaller+(wrongMultipleCaller?1:0));
 if(!error&&probeNestedRequests){
  // Model an original handler temporarily yielding/re-entering its WorkLoop.
  // No other request may reach the same scan manager before this one returns.
  std::thread competing([&](){
   assert(runtime->getScanResult(c,i,nullptr,r,true)==EBUSY);
   assert(runtime->getCapabilities(c,i,nullptr,r,true)==EBUSY);
   assert(runtime->setAssociateRequest(c,i,nullptr,r,true)==EBUSY);
   assert(runtime->setScanRequest(c,i,nullptr,r,true)==EBUSY);
   assert(runtime->setScanRequestMultiple(c,i,nullptr,r,true)==EBUSY);
  });
  competing.join();
  nestedRequestsBlocked+=5;
 }
 return error?error:multipleOriginalError;
}
static int singleOriginal(void *c,void *i,void *,ScanCompat::Request *r,bool){
 assert(c==controller&&i==interface&&r&&r->type==10&&
        r->length==ScanSingleBridge::ElCapSize);
 singleOriginalCalls++;singleCopyCalls++;
 int e=runtime->copyIn(c,r->userData,singleConsumed,r->length,
                       singleCaller+(wrongSingleCaller?1:0));
 if(e)return e;
 if(verifySingleCopy)assert(!memcmp(singleConsumed,expectedSingle,sizeof(expectedSingle)));
 if(doubleSingleCopy){
  singleCopyCalls++;
  return runtime->copyIn(c,r->userData,singleConsumed,r->length,singleCaller);
 }
 return singleOriginalError;
}
static int currentPID(){return sequence.pid;}
static int submitSingleSequence(void *context,void *c,void *i,const uint8_t *bytes,size_t size){
 M::NativeLayout layout{};
 assert(context==&sequence&&c==controller&&i==interface&&bytes&&
        M::nativeLayoutForSize(size,layout)&&size<=sizeof(sequence.submitted));
 uint8_t jobs[Q::MaxJobs*Q::SingleScanSize]{};uint32_t jobCount=0;
 const Q::Result planned=Q::build43224Plan(bytes,size,jobs,sizeof(jobs),&jobCount);
 const uint32_t channels=get32(bytes+M::NativeChannelCount);
 const uint32_t expectedJobs=channels?
  static_cast<uint32_t>((channels+Q::SingleChannelCapacity-1)/Q::SingleChannelCapacity):1;
 assert(!planned.error&&jobCount==expectedJobs);
 for(uint32_t chunk=0;chunk<jobCount;chunk++){
  const size_t jobOffset=size_t(chunk)*Q::SingleScanSize;
  const uint32_t start=chunk*Q::SingleChannelCapacity;
  const uint32_t expectedChannels=channels>start?
   (channels-start<Q::SingleChannelCapacity?channels-start:Q::SingleChannelCapacity):0;
  assert(get32(jobs+jobOffset+Q::SingleChannelCount)==expectedChannels);
  if(expectedChannels)assert(!memcmp(jobs+jobOffset+Q::SingleChannels,
   bytes+M::NativeChannels+size_t(start)*M::ChannelStride,
   size_t(expectedChannels)*M::ChannelStride));
 }
 sequence.submitCalls++;sequence.lastSubmitSize=size;
 sequence.lastSubmitJobs=jobCount;
 memcpy(sequence.submitted,bytes,size);
 return sequence.submitError;
}
static bool peekManagedGet11(void *context,void *c,void *i,int pid,uint8_t *bytes,size_t size,
                             uint64_t *token,int *error){
 assert(context==&sequence&&c&&i&&bytes&&size==ScanCompat::OldSize&&token&&error);
 sequence.peekCalls++;*token=0;*error=0;
 if(c!=controller||i!=interface||pid!=sequence.pid||sequence.get11==SequenceFake::Unmanaged)
  return false;
 switch(sequence.get11){
  case SequenceFake::Pending: *error=sequence.pendingError;return true;
  case SequenceFake::Record:
   memcpy(bytes,sequence.record,size);*token=sequence.token;return true;
  case SequenceFake::Eof: *error=EIO;return true;
  case SequenceFake::ExplicitError: *error=sequence.explicitError;return true;
  case SequenceFake::Unmanaged: return false;
 }
 return false;
}
static bool commitManagedGet11(void *context,void *i,int pid,uint64_t token,bool copiedOut){
 assert(context==&sequence&&i==interface);
 sequence.commitCalls++;sequence.lastCommitPID=pid;sequence.lastCommitToken=token;
 sequence.lastCommitCopiedOut=copiedOut;
 if(copiedOut)sequence.commitSuccesses++;else sequence.commitAborts++;
 return pid==sequence.pid&&token==sequence.token;
}
static int prepareAssociation(void *context,void *i){
 assert(context==&sequence&&i==interface);sequence.prepareCalls++;
 return sequence.prepareError;
}
static int checkManagedScanBusy(void *context,void *i){
 assert(context==&sequence&&i==interface);sequence.busyCalls++;
 return sequence.busyError;
}
static int invalidateManagedResults(void *context,void *i){
 assert(context==&sequence&&i==interface);sequence.invalidationCalls++;
 return sequence.invalidateError;
}
static void initRequest(ScanCompat::Request &r,int type,uint32_t size,uintptr_t data){
 memset(&r,0,sizeof(r));memcpy(r.interfaceName,"en0",3);r.type=type;r.length=size;r.userData=data;
}
static void initHeader(){
 memset(scanHeader,0,sizeof(scanHeader));put32(scanHeader,1);scanHeader[0x22]=4;scanHeader[0x60]=8;
 put16(scanHeader+S::IELengthOffset,7);
 uint64_t p=(uintptr_t)scanIE;memcpy(scanHeader+S::KernelIEPointerOffset,&p,8);
 memset(scanIE,0x67,7);
}
static void snapshotConversion(){
 uint8_t fixed[ScanCompat::OldSize]{};put32(fixed,1);fixed[0x22]=4;fixed[0x60]=8;
 put16(fixed+0x8a,7);memset(fixed+ScanCompat::IEOffset,0x5a,7);
 const uint32_t sizes[]={ScanCompat::OldSize,ScanCompat::CompactNativeSize,
                         ScanCompat::WideNativeSize,ScanCompat::NativeSize};
 for(uint32_t n:sizes){
  uint8_t native[ScanCompat::NativeSize]{};put32(native,1);
  put16(native+0x8a,static_cast<uint16_t>(S::resultIECapacity(n)));
  assert(!S::convertFixedSnapshot(native,n,fixed,sizeof(fixed)));
  assert(ScanCompat::read16(native+0x8a)==7);
  for(unsigned i=0;i<7;i++)assert(native[ScanCompat::IEOffset+i]==0x5a);
 }
 uint8_t native[ScanCompat::NativeSize]{};put32(native,1);
 put16(native+0x8a,ScanCompat::NativeIECapacity);
 uint8_t before[sizeof(native)];memcpy(before,native,sizeof(before));
 put16(fixed+0x8a,ScanCompat::OldIECapacity+1);
 assert(S::convertFixedSnapshot(native,ScanCompat::NativeSize,fixed,sizeof(fixed))==EOVERFLOW);
 assert(!memcmp(native,before,sizeof(native)));
}
static void initOpenAssoc(uint8_t *p,size_t n){
 memset(p,0,n);put32(p,1);
 if(n==AssociationProfiles::Sonoma14Size){put16(p+4,2);put16(p+6,0);put16(p+8,0);put32(p+12,3);memcpy(p+16,"abc",3);}
 else {put16(p+4,2);put16(p+6,0);put32(p+8,1);put32(p+16,3);memcpy(p+20,"abc",3);
  if(n==AssociationProfiles::SharedNativeSize)p[899]=2;}
}
static void initMultiple(size_t size=M::NativeSize,uint32_t channels=1){
 M::NativeLayout layout{};assert(M::nativeLayoutForSize(size,layout));
 assert(channels<=layout.channelCapacity);
 memset(multipleUser,0,sizeof(multipleUser));put32(multipleUser,1);put32(multipleUser+4,2);
 put32(multipleUser+M::NativeScanType,1);put32(multipleUser+M::NativePhyMode,3);
 put32(multipleUser+M::NativeDwellTime,900);put32(multipleUser+M::NativeChannelCount,channels);
 for(uint32_t i=0;i<channels;i++){
  put32(multipleUser+M::NativeChannels+size_t(i)*M::ChannelStride,1);
  put32(multipleUser+M::NativeChannels+size_t(i)*M::ChannelStride+4,36+i);
 }
}
static void initSingle(size_t size,uint32_t channels=1){
 ScanSingleBridge::NativeLayout layout{};
 assert(ScanSingleBridge::nativeLayoutForSize(size,layout)&&channels<=layout.channelCapacity);
 singleLength=static_cast<uint32_t>(size);memset(singleUser,0,sizeof(singleUser));
 put32(singleUser+ScanSingleBridge::VersionOffset,1);
 put32(singleUser+ScanSingleBridge::APModeOffset,1);
 put32(singleUser+ScanSingleBridge::SSIDLengthOffset,3);
 memcpy(singleUser+ScanSingleBridge::SSIDBytesOffset,"abc",3);
 put32(singleUser+ScanSingleBridge::ScanTypeOffset,1);
 put32(singleUser+ScanSingleBridge::PHYModeOffset,3);
 put16(singleUser+ScanSingleBridge::DwellTimeOffset,900);
 put32(singleUser+ScanSingleBridge::ChannelCountOffset,channels);
 for(uint32_t i=0;i<channels;i++){
  put32(singleUser+ScanSingleBridge::ChannelsOffset+size_t(i)*ScanSingleBridge::ChannelStride,1);
  put32(singleUser+ScanSingleBridge::ChannelsOffset+size_t(i)*ScanSingleBridge::ChannelStride+4,36+i);
 }
}
static int authOriginal(void *c,void *i,void *v,L::Request *request,bool wide){
 assert(c==controller&&i==interface);authOriginalCalls++;
 if(!request||request->type!=2||request->length<=12)return authOriginalError;
 assert(!v&&wide&&request->length==16);
 if(nestedAuthRequest)assert(runtime->setAuthType(c,i,v,request,wide)==EBUSY);
 if(mutateAuthAfterSnapshot){put32(authUser+4,0xdeadbeef);put32(authUser+12,0x80000000);}
 if(skipAuthCopy)return authOriginalError;
 const int result=runtime->copyIn(c,request->userData,authConsumed,12,
                                wrongAuthCaller?authCaller+1:authCaller);
 if(result)return result;
 if(doubleAuthCopy)return runtime->copyIn(c,request->userData,authConsumed,12,authCaller);
 return authOriginalError;
}
static int disassociateOriginal(void *c,void *i,void *v,L::Request *request,bool wide){
 assert(c==controller&&i==interface&&v==expectedDisassociateVirtual);
 assert(request==expectedDisassociateRequest&&wide==expectedDisassociateWide);
 disassociateOriginalCalls++;
 if(nestedDisassociateRequest)
  assert(runtime->setDisassociate(c,i,v,request,wide)==EBUSY);
 return disassociateOriginalError;
}
static int disassociateMetadata(void *c,void *i,void *v,L::Request *request,bool wide,
                               uint32_t reason,uint32_t flush){
 assert(c==controller&&i==interface&&!v&&wide);
 assert(request==expectedDisassociateRequest);
 assert(reason==metadataReason&&flush==metadataFlush);
 ++metadataCalls;
 assert(runtime->setDisassociate(c,i,v,request,wide)==EBUSY);
 if(metadataDisconnect)(void)disassociateOriginal(c,i,v,request,wide);
 return metadataError;
}
static L::API makeAPI(){
 L::API api;api.getScanResult=getScanOriginal;api.getCapabilities=capOriginal;
 api.getStateReq=stateOriginal;api.getAPIEList=ieListOriginal;
 api.setAssociateRequest=associateOriginal;api.setScanRequestMultiple=multipleOriginal;
 api.setScanRequest=singleOriginal;api.singleCopyInCaller=singleCaller;
 api.copyIn=rawCopyIn;api.copyOut=rawCopyOut;api.allocate=allocate;api.deallocate=deallocate;
 api.currentThread=currentThread;api.scanManager=manager;api.getResult=getResult;
 api.primaryInterface=isPrimary;api.supportsMultiple=supportsMultiple;
 api.admitScanEventCapabilities=scanDoneCapability46;
 api.sequenceContext=&sequence;api.currentPID=currentPID;
 api.submitSingleSequence=submitSingleSequence;api.peekManagedGet11=peekManagedGet11;
 api.commitManagedGet11=commitManagedGet11;api.checkManagedScanBusy=checkManagedScanBusy;
 api.invalidateManagedResults=invalidateManagedResults;
 api.prepareAssociation=prepareAssociation;
 api.associationCopyInCaller=assocCaller;api.multipleCopyInCaller=multipleCaller;
 api.getAPIEListCopyOutCaller=ieCopyOutCaller;
 api.registryLock={&locked,enter,leave};return api;
}
static L::Runtime makeRuntime(){
 return L::Runtime(makeAPI());
}
static void prepareIsOneShot(){
 L::Runtime r;assert(!r.ready());
 L::API api=makeAPI();
 assert(r.prepare(api)&&r.ready());
 assert(!r.prepare(api)&&r.ready());
}
static void scanDispatch(){
 initHeader();
 auto r=makeRuntime();runtime=&r;assert(r.ready());
 ScanCompat::Request q;
 const uint32_t sizes[]={ScanCompat::OldSize,ScanCompat::CompactNativeSize,
                        ScanCompat::WideNativeSize,ScanCompat::NativeSize};
 for(uint32_t n:sizes){
  scanLength=n;memset(scanUser,0,sizeof(scanUser));put32(scanUser,1);
  put16(scanUser+S::IELengthOffset,static_cast<uint16_t>(S::resultIECapacity(n)));
  initRequest(q,11,n,(uintptr_t)scanUser);
  assert(!r.getScanResult(controller,interface,nullptr,&q,true));
  assert(scanOriginalCalls==0);
  assert(ScanCompat::read16(scanUser+S::IELengthOffset)==7);
  for(unsigned j=0;j<7;j++)assert(scanUser[ScanCompat::IEOffset+j]==0x67);
 }
 assert(inputCalls==4&&outputCalls==4&&allocCalls==freeCalls);
 primaryChecks=0;changePrimaryOnCheck=true;const unsigned outBefore=outputCalls;
 assert(r.getScanResult(controller,interface,nullptr,&q,true)==ESTALE);
 assert(outputCalls==outBefore&&scanOriginalCalls==0&&allocCalls==freeCalls);
 changePrimaryOnCheck=false;
 primary=false;assert(r.getScanResult(controller,interface,nullptr,&q,true)==71);
 assert(scanOriginalCalls==1);primary=true;

 // Without the installer-proven event gate, GET12 remains byte-for-byte
 // pass-through, regardless of the advertised buffer profile.
 memset(capRaw,0x11,sizeof(capRaw));memset(capUser,0,sizeof(capUser));
 initRequest(q,12,16,(uintptr_t)capUser);const unsigned beforeIn=inputCalls,beforeOut=outputCalls;
 assert(!r.getCapabilities(controller,interface,nullptr,&q,true));
 assert(capOriginalCalls==1&&inputCalls==beforeIn&&outputCalls==beforeOut+1&&q.length==8);
 assert(!memcmp(capRaw,capUser,sizeof(capRaw)));

 // A verified event gate adds BSD scan-event bit 22 for every known schema;
 // only 14+ profiles also advertise completion bit 46. All other raw bits
 // and bytes must remain unchanged.
 advertiseCaps=true;
 const uint32_t capabilitySizes[]={12,13,16,19,21};
 const uint8_t rawCapabilities[8]={0x21,0x42,0x05,0x80,0x12,0x03,0x55,0x66};
 for(uint32_t n:capabilitySizes){
  memcpy(capRaw,rawCapabilities,sizeof(capRaw));memset(capUser,0,sizeof(capUser));
  initRequest(q,12,n,(uintptr_t)capUser);
  assert(!r.getCapabilities(controller,interface,nullptr,&q,true));
  uint8_t expected[8];memcpy(expected,rawCapabilities,sizeof(expected));
  expected[2]|=0x40;
  if(n>=16)expected[5]|=0x40;
  assert(!memcmp(capUser,expected,sizeof(expected)));
  assert(!memcmp(capRaw,rawCapabilities,sizeof(rawCapabilities)));
  assert(q.length==8);
 }
 assert(capOriginalCalls==1+sizeof(capabilitySizes)/sizeof(capabilitySizes[0]));
 assert(outputCalls==beforeOut+1+sizeof(capabilitySizes)/sizeof(capabilitySizes[0]));

 // Unknown capacity and a non-primary interface both fall through unchanged.
 memcpy(capRaw,rawCapabilities,sizeof(capRaw));memset(capUser,0,sizeof(capUser));
 initRequest(q,12,14,(uintptr_t)capUser);
 assert(!r.getCapabilities(controller,interface,nullptr,&q,true));
 assert(capOriginalCalls==7&&!memcmp(capRaw,capUser,sizeof(capRaw)));
 primary=false;memset(capUser,0,sizeof(capUser));initRequest(q,12,21,(uintptr_t)capUser);
 assert(!r.getCapabilities(controller,interface,nullptr,&q,true));
 assert(capOriginalCalls==8&&!memcmp(capRaw,capUser,sizeof(capRaw)));primary=true;
 // A malformed copyOut shape inside the lease fails closed without reaching
 // the original copyOut trampoline.
 capCopyOutSize=7;const unsigned outputBeforeMalformed=outputCalls;
 initRequest(q,12,16,(uintptr_t)capUser);
 assert(r.getCapabilities(controller,interface,nullptr,&q,true)==EINVAL);
 assert(capOriginalCalls==9&&outputCalls==outputBeforeMalformed);capCopyOutSize=8;
 advertiseCaps=false;
}
static void initManagedRecord(){
 memset(sequence.record,0,sizeof(sequence.record));put32(sequence.record,1);
 sequence.record[0x22]=4;sequence.record[0x60]=8;
 put16(sequence.record+S::IELengthOffset,7);
 memset(sequence.record+ScanCompat::IEOffset,0x67,7);
}
static void managedScanDispatch(){
 auto r=makeRuntime();runtime=&r;assert(r.ready());
 ScanCompat::Request q;scanLength=ScanCompat::CompactNativeSize;
 auto initUser=[&](){memset(scanUser,0,sizeof(scanUser));put32(scanUser,1);
  put16(scanUser+S::IELengthOffset,static_cast<uint16_t>(S::resultIECapacity(scanLength)));
  initRequest(q,11,scanLength,(uintptr_t)scanUser);};
 const unsigned originals=scanOriginalCalls,managerCalls=getResultCalls;

 // Managed pending and persistent EOF belong to the sequence owner. Neither
 // state may fall through to the final child scan's native GET11 result.
 initUser();sequence.get11=SequenceFake::Pending;
 unsigned commits=sequence.commitCalls;
 assert(r.getScanResult(controller,interface,nullptr,&q,true)==sequence.pendingError);
 assert(scanOriginalCalls==originals&&getResultCalls==managerCalls&&sequence.commitCalls==commits);
 initUser();sequence.get11=SequenceFake::Eof;
 assert(r.getScanResult(controller,interface,nullptr,&q,true)==EIO);
 assert(scanOriginalCalls==originals&&getResultCalls==managerCalls&&sequence.commitCalls==commits);

 // A result advances only after conversion and user copyOut both complete.
 initManagedRecord();sequence.get11=SequenceFake::Record;initUser();
 commits=sequence.commitCalls;unsigned successes=sequence.commitSuccesses;
 assert(!r.getScanResult(controller,interface,nullptr,&q,true));
 assert(sequence.commitCalls==commits+1&&sequence.lastCommitCopiedOut&&
        sequence.commitSuccesses==successes+1&&sequence.lastCommitPID==sequence.pid&&
        sequence.lastCommitToken==sequence.token);
 assert(outputCalls>0&&ScanCompat::read16(scanUser+S::IELengthOffset)==7);
 for(unsigned j=0;j<7;j++)assert(scanUser[ScanCompat::IEOffset+j]==0x67);
 assert(scanOriginalCalls==originals&&getResultCalls==managerCalls);

 // A failed copyIn releases the peeked token without consuming it.
 initUser();failScanCopyIn=true;commits=sequence.commitCalls;
 unsigned aborts=sequence.commitAborts;unsigned outputs=outputCalls;
 assert(r.getScanResult(controller,interface,nullptr,&q,true)==EFAULT);
 failScanCopyIn=false;
 assert(sequence.commitCalls==commits+1&&!sequence.lastCommitCopiedOut&&
        sequence.commitAborts==aborts+1&&outputCalls==outputs);

 // A failed copyOut also aborts the lease, so the same result can be retried.
 initUser();failScanCopyOut=true;commits=sequence.commitCalls;aborts=sequence.commitAborts;
 assert(r.getScanResult(controller,interface,nullptr,&q,true)==EFAULT);
 failScanCopyOut=false;
 assert(sequence.commitCalls==commits+1&&!sequence.lastCommitCopiedOut&&
        sequence.commitAborts==aborts+1);

 // Invalid owned result bytes fail conversion and likewise abort the token.
 put32(sequence.record,2);initUser();commits=sequence.commitCalls;aborts=sequence.commitAborts;
 outputs=outputCalls;
 assert(r.getScanResult(controller,interface,nullptr,&q,true)==EOVERFLOW);
 assert(sequence.commitCalls==commits+1&&!sequence.lastCommitCopiedOut&&
        sequence.commitAborts==aborts+1&&outputCalls==outputs);
 sequence.get11=SequenceFake::Unmanaged;put32(sequence.record,1);
}
static void associationDispatch(){
 auto r=makeRuntime();runtime=&r;
 ScanCompat::Request q;
 // The exact ElCap 464-byte ABI remains on the native handler.
 assocLength=L::LegacyAssociationCopySize;
 initOpenAssoc(assocUser,assocLength);
 initRequest(q,20,L::LegacyAssociationCopySize,(uintptr_t)assocUser);
 const unsigned legacyCalls=assocOriginalCalls,busyBefore=sequence.busyCalls;
 const unsigned invalidationsBefore=sequence.invalidationCalls,preparesBefore=sequence.prepareCalls;
 q.value=1;q.padding=9;memcpy(q.interfaceName,"bad0",4);
 assert(!r.setAssociateRequest(controller,interface,(void*)0x300,&q,false));
 assert(assocOriginalCalls==legacyCalls+1&&get32(assocConsumed)==1&&q.length==L::LegacyAssociationCopySize);
 assert(sequence.busyCalls==busyBefore+1&&sequence.invalidationCalls==invalidationsBefore+1&&
        sequence.prepareCalls==preparesBefore);
 // Native copy failure leaves a completed managed result set untouched.
 assocLength=L::LegacyAssociationCopySize;failAssocCopyIn=true;
 initRequest(q,20,L::LegacyAssociationCopySize,(uintptr_t)assocUser);
 const unsigned failedInvalidations=sequence.invalidationCalls,failedCalls=assocOriginalCalls;
 assert(r.setAssociateRequest(controller,interface,(void*)0x300,&q,false)==EFAULT);
 failAssocCopyIn=false;
 assert(assocOriginalCalls==failedCalls+1&&sequence.invalidationCalls==failedInvalidations);
 // A non-null virtual interface and user64=false must still be rejected while
 // an owned queue is active, even though the exact ElCap handler accepts them.
 sequence.busyError=EBUSY;initRequest(q,20,L::LegacyAssociationCopySize,(uintptr_t)assocUser);
 const unsigned busyCalls=sequence.busyCalls,blockedHandlers=assocOriginalCalls;
 const unsigned blockedInvalidations=sequence.invalidationCalls;
 assert(r.setAssociateRequest(controller,interface,(void*)0x300,&q,false)==EBUSY);
 assert(sequence.busyCalls==busyCalls+1&&assocOriginalCalls==blockedHandlers&&
        sequence.invalidationCalls==blockedInvalidations);
 sequence.busyError=0;
 // Unknown enlarged schemas must not reach the fixed 464-byte legacy copy.
 const unsigned beforeUnknown=assocOriginalCalls,beforeUnknownCopy=inputCalls;
 const uint32_t unknownLengths[]={465,500,AssociationProfiles::SharedNativeSize+1};
 for(uint32_t n:unknownLengths){
  initRequest(q,20,n,(uintptr_t)assocUser);
  assert(r.setAssociateRequest(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
 }
 assert(assocOriginalCalls==beforeUnknown&&inputCalls==beforeUnknownCopy);
 const size_t sizes[]={AssociationProfiles::Sonoma14Size,AssociationProfiles::Sequoia15Size,
                       AssociationProfiles::SharedNativeSize};
 for(size_t n:sizes){
  assocLength=static_cast<uint32_t>(n);
  initOpenAssoc(assocUser,n);uint8_t before[sizeof(assocUser)];memcpy(before,assocUser,sizeof(before));
  initRequest(q,20,static_cast<uint32_t>(n),(uintptr_t)assocUser);q.value=0;
  const unsigned oldCalls=assocOriginalCalls;
  assert(!r.setAssociateRequest(controller,interface,nullptr,&q,true));
  assert(assocOriginalCalls==oldCalls+1&&q.length==n&&!locked);
  assert(!memcmp(assocUser,before,sizeof(before)));
  assert(get32(assocConsumed)==1&&ScanCompat::read16(assocConsumed+4)==2);
 }
 // Rejected scope/extension stays out of the old 464-byte consumer.
 assocLength=AssociationProfiles::Sequoia15Size;
 initOpenAssoc(assocUser,AssociationProfiles::Sequoia15Size);assocUser[468]=0x40;
 initRequest(q,20,AssociationProfiles::Sequoia15Size,(uintptr_t)assocUser);
 const unsigned oldCalls=assocOriginalCalls;assert(r.setAssociateRequest(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
 assert(assocOriginalCalls==oldCalls&&!locked);
 // Identity is rechecked after bounded conversion; no original-handler fallback.
 assocLength=AssociationProfiles::SharedNativeSize;
 initOpenAssoc(assocUser,AssociationProfiles::SharedNativeSize);
 initRequest(q,20,AssociationProfiles::SharedNativeSize,(uintptr_t)assocUser);
 primaryChecks=0;changePrimaryOnCheck=true;
 assert(r.setAssociateRequest(controller,interface,nullptr,&q,true)==ESTALE);
 assert(assocOriginalCalls==oldCalls&&!locked);changePrimaryOnCheck=false;primary=true;
 // A modern association schema must not hit ElCap's lossy 464-byte original
 // copy on a non-primary interface.
 primary=false;const unsigned copies=inputCalls;
 assert(r.setAssociateRequest(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
 assert(assocOriginalCalls==oldCalls&&inputCalls==copies);primary=true;
 // Same-thread copyIn at an unexpected return PC must not fall through to the
 // original user pointer, even when all other request arguments match.
 assocLength=AssociationProfiles::SharedNativeSize;
 initOpenAssoc(assocUser,AssociationProfiles::SharedNativeSize);
 initRequest(q,20,AssociationProfiles::SharedNativeSize,(uintptr_t)assocUser);
 wrongAssocCaller=true;const unsigned badCopyStart=inputCalls;
 assert(r.setAssociateRequest(controller,interface,nullptr,&q,true)==EINVAL);
 assert(inputCalls==badCopyStart+1&&!locked);wrongAssocCaller=false;
}
static void singleDispatch(){
 auto r=makeRuntime();runtime=&r;assert(r.ready());
 ScanCompat::Request q;primary=true;multipleSupported=true;sequence.prepareError=0;
 const size_t sizes[]={ScanSingleBridge::Monterey12Size,
                       ScanSingleBridge::Ventura13Size,
                       ScanSingleBridge::Sonoma14Size,
                       ScanSingleBridge::Sequoia15Tahoe26Size};
 unsigned expectedOriginal=singleOriginalCalls,expectedCopies=singleCopyCalls;
 for(size_t n:sizes){
  initSingle(n,2);
  assert(!ScanSingleBridge::convertToElCap(singleUser,n,expectedSingle,
                                           sizeof(expectedSingle)).error);
  verifySingleCopy=true;wrongSingleCaller=false;doubleSingleCopy=false;
  initRequest(q,10,static_cast<uint32_t>(n),(uintptr_t)singleUser);
  const unsigned rawCopies=inputCalls,prepares=sequence.prepareCalls;
  assert(!r.setScanRequest(controller,interface,nullptr,&q,true));
  assert(singleOriginalCalls==++expectedOriginal);
  assert(singleCopyCalls==++expectedCopies);
  assert(inputCalls==rawCopies+1&&sequence.prepareCalls==prepares+1&&
         q.length==n&&!locked);
 }
 verifySingleCopy=false;

 // The exact ElCap SET10 request still reaches the original handler and keeps
 // its original length and bytes.
 singleLength=ScanSingleBridge::ElCapSize;memset(singleUser,0x5c,singleLength);
 initRequest(q,10,ScanSingleBridge::ElCapSize,(uintptr_t)singleUser);
 const unsigned oldHandler=singleOriginalCalls,oldInput=inputCalls;
 const unsigned oldBusy=sequence.busyCalls,oldInvalidations=sequence.invalidationCalls;
 const unsigned oldPrepares=sequence.prepareCalls;
 q.value=1;q.padding=7;memcpy(q.interfaceName,"bad0",4);
 assert(!r.setScanRequest(controller,interface,(void*)0x300,&q,false));
 assert(singleOriginalCalls==oldHandler+1&&inputCalls==oldInput+1&&
        q.length==ScanSingleBridge::ElCapSize&&
        !memcmp(singleConsumed,singleUser,ScanSingleBridge::ElCapSize));
 assert(sequence.busyCalls==oldBusy+1&&sequence.invalidationCalls==oldInvalidations+1&&
        sequence.prepareCalls==oldPrepares);

 // A provider copy fault does not invalidate the aggregate; an active owner
 // blocks the same request even with user64=false and a virtual interface.
 failSingleCopyIn=true;initRequest(q,10,ScanSingleBridge::ElCapSize,(uintptr_t)singleUser);
 const unsigned beforeFailedInvalidation=sequence.invalidationCalls;
 assert(r.setScanRequest(controller,interface,nullptr,&q,true)==EFAULT);
 failSingleCopyIn=false;
 assert(sequence.invalidationCalls==beforeFailedInvalidation);
 sequence.busyError=EBUSY;initRequest(q,10,ScanSingleBridge::ElCapSize,(uintptr_t)singleUser);
 const unsigned busyHandlers=singleOriginalCalls,busyCount=sequence.busyCalls;
 assert(r.setScanRequest(controller,interface,(void*)0x300,&q,false)==EBUSY);
 assert(singleOriginalCalls==busyHandlers&&sequence.busyCalls==busyCount+1&&
        sequence.invalidationCalls==beforeFailedInvalidation);
 sequence.busyError=0;

 // Input faults stop before the old handler or any temporary copyIn scope.
 initSingle(ScanSingleBridge::Ventura13Size,1);
 initRequest(q,10,singleLength,(uintptr_t)singleUser);failSingleCopyIn=true;
 const unsigned handlersBeforeFault=singleOriginalCalls,inputsBeforeFault=inputCalls;
 assert(r.setScanRequest(controller,interface,nullptr,&q,true)==EFAULT);
 failSingleCopyIn=false;
 assert(singleOriginalCalls==handlersBeforeFault&&inputCalls==inputsBeforeFault+1&&
        q.length==singleLength&&!locked&&allocCalls==freeCalls);

 // A same-thread copyIn at the wrong audited return PC is rejected and does
 // not fall through to the raw user-pointer copy routine.
 assert(!ScanSingleBridge::convertToElCap(singleUser,singleLength,expectedSingle,
                                          sizeof(expectedSingle)).error);
 verifySingleCopy=true;wrongSingleCaller=true;
 initRequest(q,10,singleLength,(uintptr_t)singleUser);
 const unsigned handlersBeforeWrong=singleOriginalCalls,inputsBeforeWrong=inputCalls;
 assert(r.setScanRequest(controller,interface,nullptr,&q,true)==EINVAL);
 wrongSingleCaller=false;
 assert(singleOriginalCalls==handlersBeforeWrong+1&&inputCalls==inputsBeforeWrong+1&&
        q.length==singleLength&&!locked&&allocCalls==freeCalls);

 // The payload is one-shot even if the native handler attempts a second read.
 doubleSingleCopy=true;initRequest(q,10,singleLength,(uintptr_t)singleUser);
 const unsigned handlersBeforeDouble=singleOriginalCalls,copiesBeforeDouble=singleCopyCalls;
 const unsigned inputsBeforeDouble=inputCalls;
 assert(r.setScanRequest(controller,interface,nullptr,&q,true)==EINVAL);
 doubleSingleCopy=false;
 assert(singleOriginalCalls==handlersBeforeDouble+1&&singleCopyCalls==copiesBeforeDouble+2&&
        inputCalls==inputsBeforeDouble+1&&q.length==singleLength&&!locked);

 // An original handler error is preserved after a successful leased copy,
 // and the temporary Request length is restored on every return path.
 singleOriginalError=EIO;initRequest(q,10,singleLength,(uintptr_t)singleUser);
 assert(r.setScanRequest(controller,interface,nullptr,&q,true)==EIO);
 singleOriginalError=0;
 assert(q.length==singleLength&&!locked&&allocCalls==freeCalls);
 verifySingleCopy=false;

 // Busy sequence state blocks SET10 before the provider's native handler.
 // 43224 cannot carry >128 channels in SET10. A valid modern request is
 // normalized to the canonical SET86 plan and split by the sequence owner.
 multipleSupported=false;initSingle(ScanSingleBridge::Ventura13Size,129);
 initRequest(q,10,singleLength,(uintptr_t)singleUser);
 const unsigned beforeFallback=sequence.submitCalls,handlersBeforeFallback=singleOriginalCalls;
 assert(!r.setScanRequest(controller,interface,nullptr,&q,true));
 assert(sequence.submitCalls==beforeFallback+1&&
        sequence.lastSubmitSize==M::NativeSize&&sequence.lastSubmitJobs==2&&
        singleOriginalCalls==handlersBeforeFallback&&q.length==singleLength&&!locked);
 multipleSupported=true;
}
static void singleMultiSSIDDispatch(){
 auto r=makeRuntime();runtime=&r;primary=true;multipleSupported=true;
 const size_t sizes[]={ScanSingleBridge::Monterey12Size,ScanSingleBridge::Ventura13Size,
                      ScanSingleBridge::Sonoma14Size,ScanSingleBridge::Sequoia15Tahoe26Size};
 ScanCompat::Request q;
 for(size_t n:sizes){
  ScanSingleBridge::NativeLayout layout{};
  assert(ScanSingleBridge::nativeLayoutForSize(n,layout));
  const uint32_t counts[]={2,9};
  for(uint32_t count:counts){
   initSingle(n,128);put32(singleUser+ScanSingleBridge::SSIDLengthOffset,0);
   memset(singleUser+ScanSingleBridge::SSIDBytesOffset,0,ScanSingleBridge::SSIDCapacity);
   put32(singleUser+layout.ssidCountOffset,count);
   for(uint32_t j=0;j<count;j++){
    uint8_t *entry=singleUser+layout.ssidArrayOffset+size_t(j)*ScanSingleBridge::NativeSSIDStride;
    put32(entry,1);put32(entry+ScanSingleBridge::NativeSSIDLengthOffset,3);
    memcpy(entry+ScanSingleBridge::NativeSSIDBytesOffset,"abc",3);
    entry[ScanSingleBridge::NativeSSIDBytesOffset+2]=uint8_t('0'+j);
   }
   initRequest(q,10,static_cast<uint32_t>(n),(uintptr_t)singleUser);
   const auto savedRequest=q;
   uint8_t savedPayload[sizeof(singleUser)];memcpy(savedPayload,singleUser,sizeof(singleUser));
   const unsigned singles=singleOriginalCalls,multis=multipleOriginalCalls;
   const unsigned submitted=sequence.submitCalls,copies=inputCalls;
   const unsigned blocked=nestedRequestsBlocked;
   probeNestedRequests=true;
   assert(!r.setScanRequest(controller,interface,nullptr,&q,true));
   probeNestedRequests=false;
   assert(nestedRequestsBlocked==blocked+5);
   assert(singleOriginalCalls==singles&&multipleOriginalCalls==multis+1&&
          sequence.submitCalls==submitted&&inputCalls==copies+1);
   assert(!memcmp(&q,&savedRequest,sizeof(q))&&!memcmp(singleUser,savedPayload,sizeof(singleUser)));
   assert(get32(multipleConsumed+M::NativeSSIDCount)==count);
   assert(get32(multipleConsumed+M::ElCapChannelCount)==128);
   // SET10's 56-byte entries become the native driver's 40-byte records.
   for(uint32_t j=0;j<count;j++){
    const auto *entry=multipleConsumed+12+size_t(j)*40;
    assert(get32(entry)==1&&get32(entry+4)==3&&entry[10]==uint8_t('0'+j));
   }
   assert(!locked&&allocCalls==freeCalls);
  }
 }
 // Failure/lease checks operate at SET86's return PC, never SET10's.
 unsigned before=multipleOriginalCalls,copies=inputCalls;
 wrongMultipleCaller=true;
 assert(r.setScanRequest(controller,interface,nullptr,&q,true)==EINVAL);
 wrongMultipleCaller=false;
 assert(multipleOriginalCalls==before+1&&inputCalls==copies+1&&q.type==10&&q.length==singleLength);
 skipMultipleCopy=true;
 assert(r.setScanRequest(controller,interface,nullptr,&q,true)==EIO);
 skipMultipleCopy=false;
 multipleOriginalError=ENETDOWN;
 assert(r.setScanRequest(controller,interface,nullptr,&q,true)==ENETDOWN);
 multipleOriginalError=0;
 before=multipleOriginalCalls;sequence.prepareError=EBUSY;
 assert(r.setScanRequest(controller,interface,nullptr,&q,true)==EBUSY);
 sequence.prepareError=0;
 assert(multipleOriginalCalls==before&&q.type==10&&q.length==singleLength);
 // The native multi consumer still has only 128 channel slots. Never drop
 // the excess or silently switch 4331 to the 43224-only sequence machinery.
 initSingle(ScanSingleBridge::Ventura13Size,129);
 initRequest(q,10,singleLength,(uintptr_t)singleUser);
 const unsigned submitted=sequence.submitCalls;
 assert(r.setScanRequest(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
 assert(multipleOriginalCalls==before&&sequence.submitCalls==submitted&&allocCalls==freeCalls&&!locked);
}
static void multipleDispatch(){
 auto r=makeRuntime();runtime=&r;initMultiple();ScanCompat::Request q;
 // Exact ElCap 0x908 remains native; larger unrecognized requests fail closed.
 initRequest(q,86,M::ElCapSize,(uintptr_t)multipleUser);
 const unsigned originalBeforeLegacy=multipleOriginalCalls,legacyBusy=sequence.busyCalls;
 const unsigned legacyInvalidations=sequence.invalidationCalls;
 assert(!r.setScanRequestMultiple(controller,interface,(void*)0x300,&q,false));
 assert(multipleOriginalCalls==originalBeforeLegacy+1&&q.length==M::ElCapSize&&
        sequence.busyCalls==legacyBusy+1&&sequence.invalidationCalls==legacyInvalidations+1);
 failMultipleCopyIn=true;initRequest(q,86,M::ElCapSize,(uintptr_t)multipleUser);
 const unsigned failedInvalidations=sequence.invalidationCalls;
 assert(r.setScanRequestMultiple(controller,interface,nullptr,&q,true)==EFAULT);
 failMultipleCopyIn=false;
 assert(sequence.invalidationCalls==failedInvalidations);
 const unsigned originalBeforeUnknown=multipleOriginalCalls,inputBeforeUnknown=inputCalls;
 const uint32_t unknownLengths[]={M::ElCapSize+1,M::NativeSize+1};
 for(uint32_t n:unknownLengths){
  initRequest(q,86,n,(uintptr_t)multipleUser);
  assert(r.setScanRequestMultiple(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
 }
 assert(multipleOriginalCalls==originalBeforeUnknown&&inputCalls==inputBeforeUnknown);

 initRequest(q,86,M::NativeSize,(uintptr_t)multipleUser);
 uint8_t before[sizeof(multipleUser)];memcpy(before,multipleUser,sizeof(before));
 assert(!r.setScanRequestMultiple(controller,interface,nullptr,&q,true));
 assert(multipleOriginalCalls==originalBeforeUnknown+1&&q.length==M::NativeSize&&!locked);
 assert(!memcmp(multipleUser,before,sizeof(before))&&get32(multipleConsumed)==1);
 assert(get32(multipleConsumed+M::ElCapChannelCount)==1);
 wrongMultipleCaller=true;const unsigned inputStart=inputCalls;
 assert(r.setScanRequestMultiple(controller,interface,nullptr,&q,true)==EINVAL);
 assert(inputCalls==inputStart+1&&!locked);wrongMultipleCaller=false;
 multipleSupported=false;const unsigned calls=multipleOriginalCalls;
 const unsigned submitted=sequence.submitCalls;
 assert(!r.setScanRequestMultiple(controller,interface,nullptr,&q,true));
 assert(multipleOriginalCalls==calls&&sequence.submitCalls==submitted+1&&!locked);
 multipleSupported=true;
 // Malformed native tails are rejected before either driver dispatch route.
 multipleUser[M::NativeUnmappedTail]=1;
 const unsigned beforeMalformedSubmit=sequence.submitCalls;
 assert(r.setScanRequestMultiple(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
 assert(multipleOriginalCalls==calls&&sequence.submitCalls==beforeMalformedSubmit&&!locked);
}
static void managedDispatchAndBusyPreflight(){
 auto r=makeRuntime();runtime=&r;assert(r.ready());ScanCompat::Request q;
 primary=true;sequence.prepareError=0;sequence.submitError=0;
 const uint32_t assocSize=AssociationProfiles::SharedNativeSize;
 assocLength=assocSize;initOpenAssoc(assocUser,assocSize);
 initRequest(q,20,assocSize,(uintptr_t)assocUser);

 // Invalid converted association data must be rejected before preparing or
 // invalidating the managed scan state.
 assocUser[468]=0x40;unsigned prepares=sequence.prepareCalls;
 unsigned assocCalls=assocOriginalCalls;
 assert(r.setAssociateRequest(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
 assert(sequence.prepareCalls==prepares&&assocOriginalCalls==assocCalls&&!locked);
 assocUser[468]=0;

 // A failed input copy also exits before aggregate preflight.
 failAssocCopyIn=true;const unsigned copyStart=inputCalls;
 assert(r.setAssociateRequest(controller,interface,nullptr,&q,true)==EFAULT);
 failAssocCopyIn=false;
 assert(inputCalls==copyStart+1&&sequence.prepareCalls==prepares&&
        assocOriginalCalls==assocCalls&&!locked);

 // A valid association performs all input conversion first; a busy aggregate
 // then blocks the legacy handler and leaves the original request length intact.
 sequence.prepareError=EBUSY;const unsigned copies=inputCalls;
 assert(r.setAssociateRequest(controller,interface,nullptr,&q,true)==EBUSY);
 assert(inputCalls==copies+1&&sequence.prepareCalls==prepares+1&&
        assocOriginalCalls==assocCalls&&q.length==assocSize&&!locked);
 sequence.prepareError=0;
 assert(!r.setAssociateRequest(controller,interface,nullptr,&q,true));
 assert(sequence.prepareCalls==prepares+2&&assocOriginalCalls==assocCalls+1&&
        q.length==assocSize&&!locked);

 // SET86 for old 43224-only firmware is submitted as a bounded sequence. The
 // ElCap SET86 handler is never called, including when the owner reports busy.
 multipleSupported=false;
 const size_t layouts[]={M::Monterey12Size,M::Ventura13Size,M::NativeSize};
 for(size_t n:layouts){
  M::NativeLayout layout{};assert(M::nativeLayoutForSize(n,layout));
  const uint32_t channels=layout.channelCapacity==128?128:layout.channelCapacity;
  initMultiple(n,channels);initRequest(q,86,static_cast<uint32_t>(n),(uintptr_t)multipleUser);
  const unsigned submitted=sequence.submitCalls,old=multipleOriginalCalls;
  const unsigned beforePrepare=sequence.prepareCalls;
  sequence.submitError=EBUSY;
  assert(r.setScanRequestMultiple(controller,interface,nullptr,&q,true)==EBUSY);
  assert(sequence.submitCalls==submitted+1&&sequence.lastSubmitSize==n&&
         sequence.lastSubmitJobs==(channels+Q::SingleChannelCapacity-1)/Q::SingleChannelCapacity&&
         multipleOriginalCalls==old&&sequence.prepareCalls==beforePrepare&&
         !memcmp(sequence.submitted,multipleUser,n)&&q.length==n&&!locked);

  // Validation failure precedes queue admission and cannot trigger callbacks.
  put32(multipleUser+M::NativeChannelCount,static_cast<uint32_t>(layout.channelCapacity+1));
  const unsigned beforeInvalid=sequence.submitCalls;
  assert(r.setScanRequestMultiple(controller,interface,nullptr,&q,true)==EINVAL);
  assert(sequence.submitCalls==beforeInvalid&&multipleOriginalCalls==old&&!locked);
 }
 sequence.submitError=0;multipleSupported=true;
 // Exact ElCap SET86 still uses the old handler, but an active sequence owner
 // rejects the request before dispatch and preserves completed results.
 initMultiple();initRequest(q,86,M::ElCapSize,(uintptr_t)multipleUser);
 sequence.busyError=EBUSY;const unsigned old=multipleOriginalCalls;
 const unsigned invalidations=sequence.invalidationCalls,busyCalls=sequence.busyCalls;
 assert(r.setScanRequestMultiple(controller,interface,(void*)0x300,&q,false)==EBUSY);
 assert(multipleOriginalCalls==old&&q.length==M::ElCapSize&&!locked&&
        sequence.invalidationCalls==invalidations&&sequence.busyCalls==busyCalls+1);
 sequence.busyError=0;
}
static void stateGetAdapter(){
 auto r=makeRuntime();runtime=&r;assert(r.ready());ScanCompat::Request q;
 returnedState=4;stateOriginalError=0;failStateCopyOut=false;
 memset(stateUser,0xa5,sizeof(stateUser));put32(stateUser,0x12345678);
 initRequest(q,13,G::GetStatePointerSize,(uintptr_t)stateUser);q.value=0x11223344;
 const unsigned beforeOut=outputCalls,beforeState=stateOriginalCalls;
 assert(!r.getStateReq(controller,interface,nullptr,&q,true));
 assert(stateOriginalCalls==beforeState+1&&outputCalls==beforeOut+1);
 assert(get32(stateUser)==0x12345678&&get32(stateUser+G::GetStateValueOffset)==4);
 assert(q.value==0x11223344&&q.length==G::GetStatePointerSize);

 // The disconnected state is copied as the same 32-bit scalar, and the
 // preinitialized version/header dword is untouched.
 returnedState=0;memset(stateUser,0x39,sizeof(stateUser));put32(stateUser,1);
 initRequest(q,13,G::GetStatePointerSize,(uintptr_t)stateUser);q.value=77;
 assert(!r.getStateReq(controller,interface,nullptr,&q,true));
 assert(get32(stateUser)==1&&get32(stateUser+G::GetStateValueOffset)==0&&q.value==77);

 // A failed provider request is returned exactly and does not attempt copyOut.
 stateOriginalError=EBUSY;initRequest(q,13,G::GetStatePointerSize,(uintptr_t)stateUser);q.value=19;
 const unsigned outputBeforeFailure=outputCalls;
 assert(r.getStateReq(controller,interface,nullptr,&q,true)==EBUSY);
 assert(outputCalls==outputBeforeFailure&&q.value==19);
 stateOriginalError=0;

 // A copyOut fault is visible to the caller; request.value and the output
 // bytes are left at their pre-call values by this fixture's failing copyOut.
 uint8_t before[sizeof(stateUser)];memset(stateUser,0x57,sizeof(stateUser));
 memcpy(before,stateUser,sizeof(before));
 initRequest(q,13,G::GetStatePointerSize,(uintptr_t)stateUser);q.value=23;
 failStateCopyOut=true;const unsigned beforeFault=outputCalls;
 assert(r.getStateReq(controller,interface,nullptr,&q,true)==EFAULT);
 assert(outputCalls==beforeFault+1&&q.value==23&&!memcmp(before,stateUser,sizeof(before)));
 failStateCopyOut=false;

 // Old inline callers (including the retained 12.x donor shape) keep the
 // scalar in request.value and do not acquire the pointer-envelope adapter.
 initRequest(q,13,0,0);q.value=99;const unsigned oldPath=outputCalls;
 assert(!r.getStateReq(controller,interface,nullptr,&q,true));
 assert(q.value==returnedState&&outputCalls==oldPath);

 // Reject an overflowing 4-byte destination range before dispatching the
 // legacy provider. The callback itself is never handed a wrapped address.
 initRequest(q,13,G::GetStatePointerSize,UINT64_MAX-6);q.value=31;
 const unsigned callsBeforeOverflow=stateOriginalCalls;
 assert(r.getStateReq(controller,interface,nullptr,&q,true)==EINVAL);
 assert(stateOriginalCalls==callsBeforeOverflow&&q.value==31);
}
static void ieListGetAdapter(){
 auto r=makeRuntime();runtime=&r;assert(r.ready());ScanCompat::Request q;
 ieOriginalError=0;wrongIECopyCaller=false;wrongIECopyController=false;
 wrongIECopyThread=false;doubleIECopy=false;mismatchIERequestLength=false;
 failIECopyOut=false;
 memset(ieRaw,0x63,sizeof(ieRaw));ieActualLength=11;ieRaw[10]=0;
 memset(ieUser,0xa5,sizeof(ieUser));ieExpectedOutputSize=G::GetAPIEListHeaderSize+ieActualLength;
 initRequest(q,48,0x408,(uintptr_t)ieUser);
 const unsigned beforeOut=outputCalls,beforeHandler=ieOriginalCalls;
 assert(!r.getAPIEList(controller,interface,nullptr,&q,true));
 assert(ieOriginalCalls==beforeHandler+1&&outputCalls==beforeOut+1);
 assert(q.length==ieExpectedOutputSize&&get32(ieUser)==1&&ScanCompat::read16(ieUser+4)==11);
 assert(ieUser[6]==0&&ieUser[7]==0&&!memcmp(ieUser+8,ieRaw,11));

 // Sequoia/Tahoe's larger native capacity uses the same header and carries
 // the full 0x400 old payload. Trailing payload zeros remain part of length.
 for(size_t n=0;n<sizeof(ieRaw);n++)ieRaw[n]=static_cast<uint8_t>(n*17U);
 ieRaw[1022]=0;ieRaw[1023]=0;ieActualLength=sizeof(ieRaw);
 memset(ieUser,0xa5,sizeof(ieUser));ieExpectedOutputSize=G::GetAPIEListNativeMaximum;
 initRequest(q,48,0x808,(uintptr_t)ieUser);
 assert(!r.getAPIEList(controller,interface,nullptr,&q,true));
 assert(q.length==G::GetAPIEListNativeMaximum&&get32(ieUser)==1&&
        ScanCompat::read16(ieUser+4)==G::GetAPIEListLegacyCapacity);
 assert(!memcmp(ieUser+8,ieRaw,sizeof(ieRaw)));

 // Empty output still has a valid version/zero-length header.
 ieActualLength=0;ieExpectedOutputSize=G::GetAPIEListHeaderSize;
 memset(ieUser,0xa5,sizeof(ieUser));initRequest(q,48,0x408,(uintptr_t)ieUser);
 assert(!r.getAPIEList(controller,interface,nullptr,&q,true));
 assert(q.length==G::GetAPIEListHeaderSize&&get32(ieUser)==1&&ScanCompat::read16(ieUser+4)==0);

 // The exact 12.x raw 0x400 request stays byte-for-byte on the old path.
 ieActualLength=6;ieExpectedOutputSize=6;memset(ieRaw,0x2b,sizeof(ieRaw));
 memset(ieUser,0xa5,sizeof(ieUser));initRequest(q,48,0x400,(uintptr_t)ieUser);
 assert(!r.getAPIEList(controller,interface,nullptr,&q,true));
 assert(q.length==6&&!memcmp(ieUser,ieRaw,6));

 // Unknown capacities do not guess an inline envelope either.
 ieExpectedOutputSize=6;memset(ieUser,0xa5,sizeof(ieUser));
 initRequest(q,48,0x1000,(uintptr_t)ieUser);
 assert(!r.getAPIEList(controller,interface,nullptr,&q,true));
 assert(q.length==6&&!memcmp(ieUser,ieRaw,6));

 // A raw size that exceeds the verified El Cap capacity is rejected by the
 // scope before it can read past the staging buffer.
 ieActualLength=G::GetAPIEListLegacyCapacity+1;
 initRequest(q,48,0x408,(uintptr_t)ieUser);
 assert(r.getAPIEList(controller,interface,nullptr,&q,true)==EINVAL);

 // A changed copyOut return PC fails closed while the request scope is live.
 wrongIECopyCaller=true;ieActualLength=5;initRequest(q,48,0x408,(uintptr_t)ieUser);
 assert(r.getAPIEList(controller,interface,nullptr,&q,true)==EINVAL);
 wrongIECopyCaller=false;

 // A matching provider callsite still fails closed if controller or thread
 // identity changes while the one-shot copyOut scope is active.
 wrongIECopyController=true;initRequest(q,48,0x408,(uintptr_t)ieUser);
 assert(r.getAPIEList(controller,interface,nullptr,&q,true)==EINVAL);
 wrongIECopyController=false;
 wrongIECopyThread=true;initRequest(q,48,0x408,(uintptr_t)ieUser);
 assert(r.getAPIEList(controller,interface,nullptr,&q,true)==EINVAL);
 wrongIECopyThread=false;

 // The provider's fixed body has one copyOut; a duplicate consumption is an
 // error and can never trigger a second raw write to user memory.
 doubleIECopy=true;initRequest(q,48,0x408,(uintptr_t)ieUser);
 assert(r.getAPIEList(controller,interface,nullptr,&q,true)==EINVAL);
 doubleIECopy=false;

 // The provider-mutated outer length must agree with the actual copyOut size.
 // A mismatch is not used to infer the payload length.
 mismatchIERequestLength=true;initRequest(q,48,0x408,(uintptr_t)ieUser);
 const unsigned beforeLengthMismatch=outputCalls;
 assert(r.getAPIEList(controller,interface,nullptr,&q,true)==EIO);
 assert(outputCalls==beforeLengthMismatch&&q.length==0x408);
 mismatchIERequestLength=false;

 // Provider errors retain their code and avoid a fabricated structured reply.
 ieOriginalError=EBUSY;ieExpectedOutputSize=G::GetAPIEListHeaderSize+5;
 initRequest(q,48,0x408,(uintptr_t)ieUser);const unsigned beforeProviderError=outputCalls;
 assert(r.getAPIEList(controller,interface,nullptr,&q,true)==EBUSY);
 assert(outputCalls==beforeProviderError&&q.length==0x408);
 ieOriginalError=0;

 // The final user copyOut error is propagated and restores the original
 // capacity instead of reporting the shorter raw provider length.
 ieActualLength=5;ieExpectedOutputSize=G::GetAPIEListHeaderSize+5;
 memset(ieUser,0xa5,sizeof(ieUser));uint8_t beforeUser[sizeof(ieUser)];
 memcpy(beforeUser,ieUser,sizeof(beforeUser));initRequest(q,48,0x408,(uintptr_t)ieUser);
 failIECopyOut=true;
 assert(r.getAPIEList(controller,interface,nullptr,&q,true)==EFAULT);
 assert(q.length==0x408&&!memcmp(beforeUser,ieUser,sizeof(beforeUser)));
 failIECopyOut=false;
}
static void requestReservations(){
 L::RequestRegistry registry;registry.lock={&locked,enter,leave};
 L::RequestScope active[L::RequestRegistry::Capacity],extra;
 for(size_t n=0;n<L::RequestRegistry::Capacity;n++){
  active[n].interface=reinterpret_cast<void*>(uintptr_t(0x500+n));
  assert(registry.add(active[n])&&!locked);
 }
 extra.interface=(void*)0x999;
 assert(!registry.add(extra)&&!locked);
 // A different interface can proceed as soon as one reservation is released;
 // re-entrant admission of the same interface remains forbidden.
 registry.remove(active[3]);assert(registry.add(extra));
 registry.remove(active[4]);
 L::RequestScope duplicate;duplicate.interface=active[0].interface;
 assert(!registry.add(duplicate));
 for(auto &scope:active)registry.remove(scope);
 registry.remove(extra);assert(!registry.head&&!locked);
 assert(registry.add(active[0]));registry.remove(active[0]);assert(!registry.head);
}
static void authSetAdapter(){
 auto api=makeAPI();api.setAuthType=authOriginal;api.authCopyInCaller=authCaller;
 L::Runtime r(api);assert(r.ready());runtime=&r;
 primary=true;changePrimaryOnCheck=false;primaryChecks=0;
 L::Request q;initRequest(q,2,16,(uintptr_t)authUser);
 put32(authUser,1);put32(authUser+4,0x12345678);put32(authUser+8,0xfedcba98);put32(authUser+12,0);
 uint8_t saved[sizeof(authUser)];memcpy(saved,authUser,sizeof(saved));
 const auto requestBefore=q;
 unsigned inputs=inputCalls,outputs=outputCalls,calls=authOriginalCalls;
 assert(!r.setAuthType(controller,interface,nullptr,&q,true));
 assert(inputCalls==inputs+1&&authOriginalCalls==calls+1&&outputCalls==outputs);
 assert(!memcmp(authConsumed,saved,12)&&!memcmp(authUser,saved,16));
 assert(!memcmp(&q,&requestBefore,sizeof(q)));

 // The provider's copy sees the validated owned snapshot even if user memory
 // changes before its old copyIn site executes; the outer request stays intact.
 mutateAuthAfterSnapshot=true;nestedAuthRequest=true;
 inputs=inputCalls;
 assert(!r.setAuthType(controller,interface,nullptr,&q,true));
 assert(inputCalls==inputs+1&&!memcmp(authConsumed,saved,12));
 assert(!memcmp(&q,&requestBefore,sizeof(q)));
 mutateAuthAfterSnapshot=false;nestedAuthRequest=false;
 memcpy(authUser,saved,16);

 calls=authOriginalCalls;
 for(unsigned bit=0;bit<32;bit++){
  put32(authUser+12,uint32_t(1)<<bit);
  assert(r.setAuthType(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
  assert(authOriginalCalls==calls&&get32(authUser+12)==(uint32_t(1)<<bit));
 }
 memcpy(authUser,saved,16);
 put32(authUser,2);assert(r.setAuthType(controller,interface,nullptr,&q,true)==EINVAL);
 memcpy(authUser,saved,16);
 failAuthCopy=true;assert(r.setAuthType(controller,interface,nullptr,&q,true)==EFAULT);failAuthCopy=false;
 assert(authOriginalCalls==calls);
 for(uint32_t size:{13U,15U,17U,UINT32_MAX}){
  q.length=size;inputs=inputCalls;
  assert(r.setAuthType(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
  assert(inputCalls==inputs&&authOriginalCalls==calls&&q.length==size);
 }
 q=requestBefore;
 assert(r.setAuthType(controller,interface,nullptr,&q,false)==EINVAL);
 assert(r.setAuthType(controller,interface,(void*)0x999,&q,true)==EOPNOTSUPP);
 primary=false;assert(r.setAuthType(controller,interface,nullptr,&q,true)==EOPNOTSUPP);primary=true;
 q.value=1;assert(r.setAuthType(controller,interface,nullptr,&q,true)==EINVAL);q=requestBefore;
 q.padding=1;assert(r.setAuthType(controller,interface,nullptr,&q,true)==EINVAL);q=requestBefore;
 q.userData=0;assert(r.setAuthType(controller,interface,nullptr,&q,true)==EINVAL);q=requestBefore;
 q.userData=UINT64_MAX-7;assert(r.setAuthType(controller,interface,nullptr,&q,true)==EINVAL);q=requestBefore;
 changePrimaryOnCheck=true;primaryChecks=0;
 assert(r.setAuthType(controller,interface,nullptr,&q,true)==ESTALE);changePrimaryOnCheck=false;
 assert(authOriginalCalls==calls);

 wrongAuthCaller=true;assert(r.setAuthType(controller,interface,nullptr,&q,true)==EINVAL);wrongAuthCaller=false;
 doubleAuthCopy=true;assert(r.setAuthType(controller,interface,nullptr,&q,true)==EINVAL);doubleAuthCopy=false;
 skipAuthCopy=true;assert(r.setAuthType(controller,interface,nullptr,&q,true)==EIO);skipAuthCopy=false;
 authOriginalError=ENETDOWN;
 assert(r.setAuthType(controller,interface,nullptr,&q,true)==ENETDOWN);
 assert(!memcmp(&q,&requestBefore,sizeof(q)));
 authOriginalError=0;
 assert(!r.setAuthType(controller,interface,nullptr,&q,true)); // All failed leases were removed.

 // Original <=12-byte requests retain their old semantics, including errors.
 calls=authOriginalCalls;inputs=inputCalls;authOriginalError=ERANGE;
 for(uint32_t size:{0U,4U,12U}){
  q.length=size;
  assert(r.setAuthType(controller,interface,nullptr,&q,true)==ERANGE);
 }
 assert(authOriginalCalls==calls+3&&inputCalls==inputs);authOriginalError=0;
 api.authCopyInCaller=0;L::Runtime badCaller;assert(!badCaller.prepare(api));
 api=makeAPI();api.authCopyInCaller=authCaller;L::Runtime badHandler;assert(!badHandler.prepare(api));
 assert(!locked);
}
static void disassociateMetadataBoundary(){
 auto api=makeAPI();api.setDisassociate=disassociateOriginal;
 L::Runtime r(api);assert(r.ready());runtime=&r;
 L::Request q;initRequest(q,22,0,0);
 expectedDisassociateRequest=&q;
 const auto empty=q;
 const unsigned inputs=inputCalls,outputs=outputCalls,allocations=allocCalls;
 unsigned calls=disassociateOriginalCalls;
 assert(!r.setDisassociate(controller,interface,nullptr,&q,true));
 assert(disassociateOriginalCalls==++calls&&!memcmp(&q,&empty,sizeof(q)));
 nestedDisassociateRequest=true;disassociateOriginalError=ENETDOWN;
 assert(r.setDisassociate(controller,interface,nullptr,&q,true)==ENETDOWN);
 assert(disassociateOriginalCalls==++calls&&!locked);
 nestedDisassociateRequest=false;disassociateOriginalError=0;

 // Unknown schemas are rejected before reading user memory.
 for(uint32_t size:{1U,7U,9U,16U,UINT32_MAX}){
  q=empty;q.length=size;q.userData=UINT64_MAX;
  const auto before=q;
  assert(r.setDisassociate(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
  assert(r.setDisassociate(controller,interface,(void*)0x999,&q,false)==EOPNOTSUPP);
  primary=false;
  assert(r.setDisassociate(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
  primary=true;
  assert(disassociateOriginalCalls==calls&&!memcmp(&q,&before,sizeof(q)));
  q.userData=0;
  assert(r.setDisassociate(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
 }
 // Preserve native zero-length behavior, original errors and all arguments;
 // the adapter never rewrites the request or substitutes a null request.
 q=empty;q.userData=UINT64_MAX;q.value=0x1234;q.padding=0x5678;
 const auto unusualEmpty=q;
 expectedDisassociateVirtual=(void*)0x999;expectedDisassociateWide=false;
 disassociateOriginalError=ERANGE;
 assert(r.setDisassociate(controller,interface,expectedDisassociateVirtual,&q,false)==ERANGE);
 assert(disassociateOriginalCalls==++calls&&!memcmp(&q,&unusualEmpty,sizeof(q)));
 q.type=99;q.length=12;
 assert(r.setDisassociate(controller,interface,expectedDisassociateVirtual,&q,false)==ERANGE);
 assert(disassociateOriginalCalls==++calls);
 expectedDisassociateRequest=nullptr;
 assert(r.setDisassociate(controller,interface,expectedDisassociateVirtual,nullptr,false)==ERANGE);
 assert(disassociateOriginalCalls==++calls);
 expectedDisassociateVirtual=nullptr;expectedDisassociateWide=true;disassociateOriginalError=0;
 assert(inputCalls==inputs&&outputCalls==outputs&&allocCalls==allocations&&!locked);

 // Known layouts use one owned snapshot. Zero extra actions can reach the
 // ordinary provider; any reason/flush bit is preserved as unsupported until
 // the actual corresponding action has been connected.
 expectedDisassociateRequest=&q;
 unsigned copies=inputCalls;
 for(uint32_t size:{8U,12U}){
  initRequest(q,22,size,(uintptr_t)disassociateUser);
  const auto before=q;
  for(uint32_t header:{0U,1U,0xaaaaaaaaU,UINT32_MAX}){
   memset(disassociateUser,0,sizeof(disassociateUser));put32(disassociateUser,header);
   assert(!r.setDisassociate(controller,interface,nullptr,&q,true));
   assert(disassociateOriginalCalls==++calls && inputCalls==++copies);
   assert(!memcmp(&q,&before,sizeof(q)));
  }
  nestedDisassociateRequest=true;mutateDisassociateAfterCopy=true;
  assert(!r.setDisassociate(controller,interface,nullptr,&q,true));
  assert(disassociateOriginalCalls==++calls && inputCalls==++copies);
  assert(get32(disassociateUser+4)==UINT32_MAX);
  nestedDisassociateRequest=false;mutateDisassociateAfterCopy=false;
  for(unsigned bit=0;bit<32;++bit){
   memset(disassociateUser,0,sizeof(disassociateUser));put32(disassociateUser+4,1U<<bit);
   assert(r.setDisassociate(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
   assert(disassociateOriginalCalls==calls && inputCalls==++copies);
   if(size==12){
    put32(disassociateUser+4,0);put32(disassociateUser+8,1U<<bit);
    assert(r.setDisassociate(controller,interface,nullptr,&q,true)==EOPNOTSUPP);
    assert(disassociateOriginalCalls==calls && inputCalls==++copies);
   }
  }
  memset(disassociateUser,0,sizeof(disassociateUser));
  failDisassociateCopy=true;
  assert(r.setDisassociate(controller,interface,nullptr,&q,true)==EFAULT);
  failDisassociateCopy=false;assert(inputCalls==++copies && disassociateOriginalCalls==calls);
  assert(r.setDisassociate(controller,interface,nullptr,&q,false)==EINVAL);
  assert(r.setDisassociate(controller,interface,(void*)0x999,&q,true)==EOPNOTSUPP);
  primary=false;assert(r.setDisassociate(controller,interface,nullptr,&q,true)==EOPNOTSUPP);primary=true;
  q.value=1;assert(r.setDisassociate(controller,interface,nullptr,&q,true)==EINVAL);q=before;
  q.padding=1;assert(r.setDisassociate(controller,interface,nullptr,&q,true)==EINVAL);q=before;
  q.userData=0;assert(r.setDisassociate(controller,interface,nullptr,&q,true)==EINVAL);q=before;
  q.userData=UINT64_MAX-3;assert(r.setDisassociate(controller,interface,nullptr,&q,true)==EINVAL);q=before;
  assert(inputCalls==copies && disassociateOriginalCalls==calls);
  changePrimaryOnCheck=true;primaryChecks=0;
  assert(r.setDisassociate(controller,interface,nullptr,&q,true)==ESTALE);
  changePrimaryOnCheck=false;assert(inputCalls==++copies && disassociateOriginalCalls==calls);
  disassociateOriginalError=ENETDOWN;
  assert(r.setDisassociate(controller,interface,nullptr,&q,true)==ENETDOWN);
  disassociateOriginalError=0;assert(inputCalls==++copies && disassociateOriginalCalls==++calls);
  assert(!memcmp(&q,&before,sizeof(q)));
 }
 assert(outputCalls==outputs && allocCalls==allocations && !locked);

 // A missing runtime API must not reopen the metadata-dropping path.
 L::Runtime inactive;
 q=empty;q.length=8;
 assert(inactive.setDisassociate(controller,interface,nullptr,&q,true)==ENXIO);
 q.length=0;
 assert(inactive.setDisassociate(controller,interface,nullptr,&q,true)==ENXIO);
}
static void disassociateMetadataOperation(){
 auto api=makeAPI();api.setDisassociateMetadata=disassociateMetadata;
 L::Runtime incomplete;assert(!incomplete.prepare(api));
 api.setDisassociate=disassociateOriginal;
 L::Runtime r(api);runtime=&r;assert(r.ready());
 L::Request q;initRequest(q,22,12,(uintptr_t)disassociateUser);
 expectedDisassociateRequest=&q;expectedDisassociateVirtual=nullptr;expectedDisassociateWide=true;
 const auto before=q;
 const unsigned nativeBefore=disassociateOriginalCalls;
 unsigned copies=inputCalls;
 for(uint32_t reason:{0U,1U,0x80000000U,UINT32_MAX}){
  metadataReason=reason;metadataFlush=0x80000000U;
  put32(disassociateUser,0x1234);put32(disassociateUser+4,reason);put32(disassociateUser+8,metadataFlush);
  metadataError=EIO;assert(r.setDisassociate(controller,interface,nullptr,&q,true)==EIO);
  assert(inputCalls==++copies&&!memcmp(&q,&before,sizeof(q)));
 }
 assert(metadataCalls==4&&disassociateOriginalCalls==nativeBefore);
 metadataReason=0;metadataFlush=8;metadataError=ESTALE;metadataDisconnect=true;
 put32(disassociateUser+4,0);put32(disassociateUser+8,8);mutateDisassociateAfterCopy=true;
 assert(r.setDisassociate(controller,interface,nullptr,&q,true)==ESTALE);
 assert(metadataCalls==5&&disassociateOriginalCalls==nativeBefore+1&&inputCalls==++copies);
 assert(get32(disassociateUser+4)==UINT32_MAX&&get32(disassociateUser+8)==1);
 mutateDisassociateAfterCopy=false;metadataDisconnect=false;
 put32(disassociateUser+4,0);put32(disassociateUser+8,0);
 assert(!r.setDisassociate(controller,interface,nullptr,&q,true));
 assert(metadataCalls==5&&disassociateOriginalCalls==nativeBefore+2&&inputCalls==++copies);
 put32(disassociateUser+8,1);changePrimaryOnCheck=true;primaryChecks=0;
 assert(r.setDisassociate(controller,interface,nullptr,&q,true)==ESTALE);
 changePrimaryOnCheck=false;
 assert(metadataCalls==5&&inputCalls==++copies&&!memcmp(&q,&before,sizeof(q)));
 assert(!locked);
}
int main(){requestReservations();prepareIsOneShot();snapshotConversion();scanDispatch();managedScanDispatch();
 associationDispatch();multipleDispatch();singleDispatch();singleMultiSSIDDispatch();managedDispatchAndBusyPreflight();
 stateGetAdapter();ieListGetAdapter();authSetAdapter();disassociateMetadataBoundary();disassociateMetadataOperation();}
'''


class LegacyBridgeRuntimeTests(unittest.TestCase):
    def test_five_argument_dispatch_and_one_shot_copyin_scopes(self):
        with tempfile.TemporaryDirectory(prefix="legacy-runtime-", dir="/private/tmp") as tmp:
            source = pathlib.Path(tmp) / "runtime.cpp"
            binary = pathlib.Path(tmp) / "runtime"
            source.write_text(HARNESS)
            build = subprocess.run(
                ["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                 "-I", str(PROJECT / "src"), str(source),
                 str(PROJECT / "src/legacy_wifi_compat/legacy_bridge.cpp"), "-o", str(binary)],
                text=True, capture_output=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], text=True, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
