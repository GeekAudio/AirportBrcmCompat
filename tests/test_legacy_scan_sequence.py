"""Host safety contracts for 43224 multiple-to-single scan sequencing."""
import pathlib
import subprocess
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/scan_sequence.hpp"
#include "legacy_wifi_compat/provider_contract.hpp"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

namespace Q=LegacyWiFi::ScanSequence;
namespace M=LegacyWiFi::ScanMultipleBridge;
constexpr size_t ManagerReadSize=LegacyWiFi::ProviderContract::SingleRequestMaxSize;
using Deferred=Q::Deferred;

static void put32(uint8_t *p,uint32_t v){memcpy(p,&v,4);}
static uint32_t get32(const uint8_t *p){uint32_t v;memcpy(&v,p,4);return v;}
struct Ticket {Deferred callback;void *owner;uint64_t generation;};
struct Fake {
 bool locked=false;
 Ticket tickets[64]{};unsigned ticketCount=0,ticketRead=0;
 bool failSchedule=false,failGate=false,completeInStart=false,cancelInStart=false;
 bool completeAfterCancelInStart=false;
 bool failCurrentInStart=false;
 int failStartAt=-1;unsigned startCalls=0;
 int snapshotError=0,lastFinishError=0;unsigned snapshotCalls=0,finishCalls=0;
 uint8_t last[ManagerReadSize]{};
 uint32_t events[16]{};unsigned eventCount=0;
 unsigned failures=0;int lastError=0;
 Q::Coordinator *coordinator=nullptr;
} fake;
static void enter(void *p){auto *v=(bool*)p;assert(!*v);*v=true;}
static void leave(void *p){auto *v=(bool*)p;assert(*v);*v=false;}
static void *allocate(size_t n){return calloc(1,n);}
static void deallocate(void *p,size_t n){for(size_t i=0;i<n;i++)assert(!((uint8_t*)p)[i]);free(p);}
static int schedule(void *ctx,Deferred callback,void *owner,uint64_t generation){
 auto *f=(Fake*)ctx;assert(callback&&owner&&generation);
 if(f->failSchedule){f->failSchedule=false;return EBUSY;}
 assert(f->ticketCount<64);f->tickets[f->ticketCount++]={callback,owner,generation};return 0;
}
static int runOnGate(void *ctx,Deferred callback,void *owner,uint64_t generation){
 auto *f=(Fake*)ctx;if(f->failGate){f->failGate=false;return EBUSY;}
 callback(owner,generation);return 0;
}
static int startSingle(void *ctx,void *manager,const uint8_t *request,size_t size){
 auto *f=(Fake*)ctx;assert(manager==(void*)0x22&&size==Q::SingleScanSize&&request);
 const unsigned call=f->startCalls++;
 // Model both the duplicate-request compare and allocScanReqNode copy in the
 // fixed El Cap manager, each of which reads exactly 0x954 bytes.
 memcpy(f->last,request,ManagerReadSize);
 if(f->completeInStart){
  f->completeInStart=false;
  f->coordinator->highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
  assert(get32(request+Q::SingleVersion)==1); // request storage survives until start returns
 }
 if(f->cancelInStart){
  f->cancelInStart=false;
  f->coordinator->cancel((void*)0x11);
  assert(f->coordinator->state()==Q::State::CancelledInFlight);
  assert(get32(request+Q::SingleVersion)==1); // successful start retains storage through drain
  if(f->completeAfterCancelInStart){
   f->completeAfterCancelInStart=false;
   const uint64_t generation=f->coordinator->activeGeneration((void*)0x11);
   assert(generation);
   f->coordinator->highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
   assert(f->coordinator->state()==Q::State::CancelledInFlight);
   // A duplicate worker after the completion was consumed must preserve the
   // completion marker until the initial start callback returns.
   f->coordinator->cancelGeneration((void*)0x11,generation);
   assert(f->coordinator->state()==Q::State::CancelledInFlight);
  }
 }
 if(f->failCurrentInStart){
  f->failCurrentInStart=false;
  f->coordinator->failCurrent((void*)0x11,EIO);
  // failCurrent has observed a terminal event but startSingle still owns this
  // request buffer until the provider callback returns.
  assert(get32(request+Q::SingleVersion)==1);
  return EIO;
 }
 return f->failStartAt==static_cast<int>(call)?EIO:0;
}
static int snapshotCompleted(void *ctx,void *interface,void *manager){
 auto *f=(Fake*)ctx;assert(interface==(void*)0x11&&manager==(void*)0x22);
 f->snapshotCalls++;return f->snapshotError;
}
static void finishAggregate(void *ctx,int error){
 auto *f=(Fake*)ctx;f->finishCalls++;f->lastFinishError=error;
}
static void publish(void *ctx,void *interface,uint32_t code){
 auto *f=(Fake*)ctx;assert(interface==(void*)0x11);
 assert(code==Q::ScanDoneEvent||code==Q::ScanManagerDoneEvent);
 assert(f->eventCount<16);f->events[f->eventCount++]=code;
}
static void reportFailure(void *ctx,void *interface,int error){
 auto *f=(Fake*)ctx;assert(interface==(void*)0x11);f->failures++;f->lastError=error;
}
static Q::API makeAPI(){
 Q::API api;api.context=&fake;api.lock={&fake.locked,enter,leave};
 api.allocate=allocate;api.deallocate=deallocate;api.runOnGate=runOnGate;api.schedule=schedule;
 api.startSingle=startSingle;api.snapshotCompleted=snapshotCompleted;
 api.finishAggregate=finishAggregate;api.publishFinalEvent=publish;api.reportFailure=reportFailure;
 return api;
}
static uint8_t native[M::NativeSize];
static void initNative(uint32_t ssidCount=2){
 memset(native,0,sizeof(native));put32(native,1);put32(native+4,2);put32(native+M::NativeSSIDCount,ssidCount);
 const char *names[]={"alpha","beta","alpha",""};
 const uint32_t lengths[]={5,4,5,0};
 for(unsigned i=0;i<ssidCount&&i<4;i++){
  size_t rec=M::NativeSSIDArray+i*M::SSIDStride;put32(native+rec,1);
  put32(native+rec+M::SSIDLengthOffset,lengths[i]);
  memcpy(native+rec+M::SSIDBytesOffset,names[i],lengths[i]);
 }
 put32(native+M::NativeBSSIDCount,1);
 const uint8_t bssid[6]={0,1,2,3,4,5};memcpy(native+M::NativeBSSIDArray,bssid,6);
 put32(native+M::NativeScanType,1);put32(native+M::NativePhyMode,3);
 put32(native+M::NativeDwellTime,120);put32(native+M::NativeRestTime,40);
 put32(native+M::NativeChannelCount,2);
 put32(native+M::NativeChannels,1);put32(native+M::NativeChannels+4,36);
 put32(native+M::NativeChannels+M::ChannelStride,1);
 put32(native+M::NativeChannels+M::ChannelStride+4,149);
}
static void runOne(){
 assert(fake.ticketRead<fake.ticketCount);Ticket t=fake.tickets[fake.ticketRead++];
 t.callback(t.owner,t.generation);
}
static bool outbound(Q::Coordinator &c,void *interface,uint32_t code){
 if(c.suppressExternalEvent(interface,code))return false;
 fake.events[fake.eventCount++]=code;return true;
}
static void planTests(){
 assert(Q::SingleScanSize==0x954&&Q::SingleChannelCapacity==128);
 initNative(4);uint8_t jobs[Q::MaxJobs*Q::SingleScanSize]{};uint32_t count=99;
 const size_t nativeProfiles[]={M::Monterey12Size,M::Ventura13Size,M::NativeSize};
 for(size_t profile:nativeProfiles){
  initNative(4);
  auto result=Q::build43224Plan(native,profile,jobs,sizeof(jobs),&count);
  assert(!result.error&&count==2);
  const uint8_t *first=jobs,*second=jobs+Q::SingleScanSize;
  assert(get32(first+Q::SingleSSIDLength)==5&&!memcmp(first+Q::SingleSSID,"alpha",5));
  assert(get32(second+Q::SingleSSIDLength)==4&&!memcmp(second+Q::SingleSSID,"beta",4));
 }
 initNative(4);auto result=Q::build43224Plan(native,sizeof(native),jobs,sizeof(jobs),&count);
 assert(!result.error&&count==2);
 const uint8_t *first=jobs,*second=jobs+Q::SingleScanSize;
 assert(get32(first+Q::SingleVersion)==1&&get32(first+Q::SingleAPMode)==2);
 assert(get32(first+Q::SingleSSIDLength)==5&&!memcmp(first+Q::SingleSSID,"alpha",5));
 assert(get32(second+Q::SingleSSIDLength)==4&&!memcmp(second+Q::SingleSSID,"beta",4));
 assert(!memcmp(first+Q::SingleBSSID,native+M::NativeBSSIDArray,6));
 assert(get32(first+Q::SingleScanType)==1&&get32(first+Q::SinglePhyMode)==3);
 uint16_t dwell=0;memcpy(&dwell,first+Q::SingleDwellTime,2);assert(dwell==120);
 assert(get32(first+Q::SingleRestTime)==40&&get32(first+Q::SingleChannelCount)==2);
 assert(!memcmp(first+Q::SingleChannels,native+M::NativeChannels,2*M::ChannelStride));
 assert(!memcmp(first+Q::SingleChannels,second+Q::SingleChannels,2*M::ChannelStride));
 // The fixed El Cap manager copies the full 0x954 direct startScan input.
 // Only the 128 channel prefix is
 // projected; all remaining bytes must stay zero for that fixed memcpy.
 for(size_t i=0x648;i<Q::SingleScanSize;i++)assert(first[i]==0);

 // An empty SSID list is one wildcard scan; empty records are ignored.
 initNative(0);assert(!Q::build43224Plan(native,sizeof(native),jobs,sizeof(jobs),&count).error);
 assert(count==1&&get32(jobs+Q::SingleSSIDLength)==0);
 initNative(2);put32(native+M::NativeSSIDArray+M::SSIDLengthOffset,0);
 put32(native+M::NativeSSIDArray+M::SSIDStride+M::SSIDLengthOffset,0);
 assert(!Q::build43224Plan(native,sizeof(native),jobs,sizeof(jobs),&count).error);
 assert(count==1&&get32(jobs+Q::SingleSSIDLength)==0);

 initNative();put32(native+M::NativeBSSIDCount,2);
 const uint8_t secondBSSID[6]={6,7,8,9,10,11};
 memcpy(native+M::NativeBSSIDArray+6,secondBSSID,sizeof(secondBSSID));
 assert(!Q::build43224Plan(native,sizeof(native),jobs,sizeof(jobs),&count).error);
 assert(count==4); // Two SSIDs x two independent BSSID filters.
 assert(!memcmp(jobs+Q::SingleBSSID,native+M::NativeBSSIDArray,6));
 assert(!memcmp(jobs+Q::SingleScanSize+Q::SingleBSSID,secondBSSID,6));
 assert(get32(jobs+Q::SingleSSIDLength)==5);
 assert(get32(jobs+Q::SingleScanSize+Q::SingleSSIDLength)==5);
 assert(get32(jobs+2*Q::SingleScanSize+Q::SingleSSIDLength)==4);
 assert(get32(jobs+3*Q::SingleScanSize+Q::SingleSSIDLength)==4);

 // Empty BSSID count means a single unfiltered child per SSID.
 initNative();put32(native+M::NativeBSSIDCount,0);
 assert(!Q::build43224Plan(native,sizeof(native),jobs,sizeof(jobs),&count).error);
 assert(count==2);
 for(uint32_t i=0;i<count;i++)
  for(uint32_t byte=0;byte<6;byte++)assert(jobs[i*Q::SingleScanSize+Q::SingleBSSID+byte]==0);

 // Repeated native filters need only one child scan for that address.
 initNative();put32(native+M::NativeBSSIDCount,2);
 memcpy(native+M::NativeBSSIDArray+6,native+M::NativeBSSIDArray,6);
 assert(!Q::build43224Plan(native,sizeof(native),jobs,sizeof(jobs),&count).error);
 assert(count==2);

 // A zero address means wildcard to the old driver. A mixed list cannot be
 // projected into separate exact filters without broadening the request.
 initNative();put32(native+M::NativeBSSIDCount,2);
 memset(native+M::NativeBSSIDArray+6,0,6);
 memset(jobs,0xa5,sizeof(jobs));count=77;
 auto mixedZero=Q::build43224Plan(native,sizeof(native),jobs,sizeof(jobs),&count);
 assert(mixedZero.error==EOPNOTSUPP&&
        mixedZero.field==M::NativeBSSIDArray+6&&count==77&&jobs[0]==0xa5);
 initNative();memset(native+M::NativeBSSIDArray,0,6);
 auto zeroFilter=Q::build43224Plan(native,sizeof(native),jobs,sizeof(jobs),&count);
 assert(zeroFilter.error==EOPNOTSUPP&&
        zeroFilter.field==M::NativeBSSIDArray);

 // The planner retains its 40-job/95,520-byte ceiling. Five SSIDs, two
 // distinct BSSIDs and four channel chunks exactly fill it; doubling SSIDs
 // is rejected before any destination bytes are changed.
 initNative(10);
 for(uint32_t i=0;i<10;i++){
  const size_t record=M::NativeSSIDArray+size_t(i)*M::SSIDStride;
  put32(native+record+M::SSIDLengthOffset,1);
  native[record+M::SSIDBytesOffset]=static_cast<uint8_t>('A'+i);
 }
 put32(native+M::NativeChannelCount,400);
 for(uint32_t i=0;i<400;i++)put32(native+M::NativeChannels+i*M::ChannelStride,1500+i);
 put32(native+M::NativeBSSIDCount,2);
 memcpy(native+M::NativeBSSIDArray+6,secondBSSID,sizeof(secondBSSID));
 put32(native+M::NativeSSIDCount,5);
 assert(!Q::build43224Plan(native,M::NativeSize,jobs,sizeof(jobs),&count).error);
 assert(count==Q::MaxJobs&&count==40);
 const uint8_t *lastBSSIDJob=jobs+39*Q::SingleScanSize;
 assert(lastBSSIDJob[Q::SingleSSID]=='E');
 assert(get32(lastBSSIDJob+Q::SingleChannelCount)==16);
 assert(!memcmp(lastBSSIDJob+Q::SingleBSSID,secondBSSID,6));
 memset(jobs,0xcc,sizeof(jobs));count=77;put32(native+M::NativeSSIDCount,10);
 auto tooMany=Q::build43224Plan(native,M::NativeSize,jobs,sizeof(jobs),&count);
 assert(tooMany.error==EOVERFLOW&&tooMany.field==M::NativeBSSIDCount&&
        count==77&&jobs[0]==0xcc);

 initNative();put32(native+M::NativeScanType,3);
 assert(Q::build43224Plan(native,sizeof(native),jobs,sizeof(jobs),&count).error==EOPNOTSUPP);
 // Monterey's native table ends at 128 channels; later schemas split larger
 // channel tables into bounded legacy single-scan jobs rather than truncating.
 initNative();put32(native+M::NativeChannelCount,129);
 assert(Q::build43224Plan(native,M::Monterey12Size,jobs,sizeof(jobs),&count).error==EINVAL);
 for(uint32_t i=0;i<400;i++)put32(native+M::NativeChannels+i*M::ChannelStride,1000+i);
 put32(native+M::NativeChannelCount,400);
 assert(!Q::build43224Plan(native,M::Ventura13Size,jobs,sizeof(jobs),&count).error);
 assert(count==8);
 assert(get32(jobs+Q::SingleChannelCount)==128);
 assert(get32(jobs+Q::SingleScanSize+Q::SingleChannelCount)==128);
 assert(get32(jobs+2*Q::SingleScanSize+Q::SingleChannelCount)==128);
 assert(get32(jobs+3*Q::SingleScanSize+Q::SingleChannelCount)==16);
 assert(get32(jobs+4*Q::SingleScanSize+Q::SingleChannelCount)==128);
 assert(!memcmp(jobs+Q::SingleChannels,
                native+M::NativeChannels,128*M::ChannelStride));
 assert(!memcmp(jobs+Q::SingleScanSize+Q::SingleChannels,
                native+M::NativeChannels+128*M::ChannelStride,
                128*M::ChannelStride));
 assert(!memcmp(jobs+3*Q::SingleScanSize+Q::SingleChannels,
                native+M::NativeChannels+384*M::ChannelStride,
                16*M::ChannelStride));

 // Full native limits remain within the bounded plan: ten unique SSIDs by
 // four chunks for a 400-channel request means exactly forty heap jobs.
 initNative(10);
 for(uint32_t i=0;i<10;i++){
  const size_t record=M::NativeSSIDArray+size_t(i)*M::SSIDStride;
  put32(native+record+M::SSIDLengthOffset,1);
  native[record+M::SSIDBytesOffset]=static_cast<uint8_t>('A'+i);
 }
 put32(native+M::NativeChannelCount,400);
 for(uint32_t i=0;i<400;i++)put32(native+M::NativeChannels+i*M::ChannelStride,2000+i);
 assert(!Q::build43224Plan(native,M::NativeSize,jobs,sizeof(jobs),&count).error);
 assert(count==Q::MaxJobs&&count==40);
 const uint8_t *last=jobs+39*Q::SingleScanSize;
 assert(get32(last+Q::SingleSSIDLength)==1&&last[Q::SingleSSID]=='J');
 assert(get32(last+Q::SingleChannelCount)==16);
 initNative();put32(native+M::NativeSSIDArray+M::SSIDLengthOffset,33);
 assert(Q::build43224Plan(native,sizeof(native),jobs,sizeof(jobs),&count).error==EINVAL);
 initNative();native[M::NativeUnmappedTail]=1;
 assert(Q::build43224Plan(native,sizeof(native),jobs,sizeof(jobs),&count).error==EOPNOTSUPP);
}
static void cancellationStateTests(){
 Q::PendingCancellation pending;uint64_t generation=0;bool cancelAll=false;
 assert(pending.requestOwner(41)&&pending.ownerPending());
 // A worker that wins the race with finishSubmitting must leave the target
 // pending so the post-reservation enqueue can run it again deterministically.
 assert(!pending.claim(true,false,&generation,&cancelAll));
 assert(pending.ownerPending()&&pending.ownerGeneration()==41);
 assert(!pending.requestOwner(42)); // a newer reason cannot replace the old target
 assert(pending.claim(false,false,&generation,&cancelAll));
 assert(!cancelAll&&generation==41);
 // Retirement remains an independent reason and does not erase owner state.
 assert(pending.claim(false,true,&generation,&cancelAll));
 assert(cancelAll&&pending.ownerPending()&&pending.ownerGeneration()==41);
 assert(pending.completeOwner(41)&&!pending.ownerPending());
 assert(!pending.claim(false,false,&generation,&cancelAll));

 Q::CancelledOwners owners;
 for(size_t pid=1;pid<=Q::MaxCancelledOwners;pid++)assert(owners.add(static_cast<int>(pid)));
 assert(owners.count()==Q::MaxCancelledOwners&&owners.contains(7));
 assert(!owners.canAdd(100)&&!owners.add(100));
 assert(owners.canAdd(7)&&owners.add(7)); // exact PID reuse keeps one tombstone
 // Store admission failure and provider first-start failure must preserve the
 // prior PID node's tombstone. Only a confirmed successful replacement clears it.
 assert(!owners.clearAfterSuccessfulFirstStart(7,false,false));
 assert(owners.contains(7)&&owners.count()==Q::MaxCancelledOwners);
 assert(!owners.clearAfterSuccessfulFirstStart(7,true,false));
 assert(owners.contains(7)&&owners.count()==Q::MaxCancelledOwners);
 assert(owners.clearAfterSuccessfulFirstStart(7,true,true));
 assert(!owners.contains(7)&&owners.count()==Q::MaxCancelledOwners-1);
 assert(owners.add(100)&&owners.contains(100));
}

static void generationCancellationTests(){
 memset(&fake,0,sizeof(fake));fake.failStartAt=-1;initNative(1);
 Q::Coordinator c(makeAPI());fake.coordinator=&c;
 assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 const uint64_t first=c.activeGeneration((void*)0x11);assert(first);
 Q::CompletionTicket firstTicket{};
 assert(c.captureCompletionTicket((void*)0x11,&firstTicket));
 Q::PendingCompletions queuedCompletion;
 assert(queuedCompletion.enqueue(firstTicket,Q::CompletionKind::Advance));
 Q::PendingCancellation early;assert(early.requestOwner(first));
 uint64_t target=0;bool cancelAll=false;
 assert(!early.claim(true,false,&target,&cancelAll)); // worker ran before submit released
 assert(early.ownerPending());
 assert(early.claim(false,false,&target,&cancelAll)&&target==first&&!cancelAll);
 c.cancelGeneration((void*)0x11,target);
 assert(c.state()==Q::State::CancelledInFlight&&
        c.activeGeneration((void*)0x11)==first);
 Q::CompletionRecord queuedRecord;
 assert(queuedCompletion.pop(&queuedRecord));
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent,
     queuedRecord.ticket.generation,queuedRecord.ticket.startToken);
 assert(c.state()==Q::State::Idle&&early.completeOwner(first));

 // A late worker after natural completion is generation-scoped and cannot
 // cancel a new sequence on the same interface.
 initNative(1);assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 const uint64_t old=c.activeGeneration((void*)0x11);assert(old&&old!=first);
 Q::PendingCancellation late;assert(late.requestOwner(old));
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
 assert(c.state()==Q::State::FinishQueued);runOne();
 assert(c.state()==Q::State::Idle&&late.ownerPending());
 assert(late.claim(false,false,&target,&cancelAll)&&target==old);
 c.cancelGeneration((void*)0x11,target); // old generation is already idle
 assert(c.state()==Q::State::Idle&&late.completeOwner(old));

 initNative(1);assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 const uint64_t current=c.activeGeneration((void*)0x11);assert(current&&current!=old);
 // A duplicated/stale work item after pending was completed has no claim.
 assert(!late.claim(false,false,&target,&cancelAll));
 c.cancelGeneration((void*)0x11,old);
 assert(c.state()==Q::State::InFlight&&c.activeGeneration((void*)0x11)==current);
 c.cancel((void*)0x11);
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
 assert(c.state()==Q::State::Idle);
}

static void completionRecordTests(){
 Q::PendingCompletions records;Q::CompletionRecord record;
 Q::CompletionTicket first{11,21};
 assert(!records.enqueue({},Q::CompletionKind::Advance));
 assert(records.enqueue(first,Q::CompletionKind::Advance));
 assert(records.enqueue(first,Q::CompletionKind::Advance)&&records.count()==1);
 assert(records.enqueue(first,Q::CompletionKind::Failure)&&records.count()==1);
 assert(records.pop(&record)&&record.ticket.generation==11&&
        record.ticket.startToken==21&&record.kind==Q::CompletionKind::Failure);
 assert(!records.pending()&&!records.pop(&record));
 for(uint64_t token=1;token<=Q::MaxPendingCompletions;token++)
  assert(records.enqueue({12,token},Q::CompletionKind::Advance));
 assert(records.count()==Q::MaxPendingCompletions);
 // Overflow discards ambiguous backlog and fails only the ticket that filled it.
 assert(records.enqueue({13,99},Q::CompletionKind::Advance));
 assert(records.count()==1&&records.pop(&record));
 assert(record.ticket.generation==13&&record.ticket.startToken==99&&
        record.kind==Q::CompletionKind::Failure&&!records.pending());
}

static void reentrantTerminalCompletionTests(){
 memset(&fake,0,sizeof(fake));fake.failStartAt=-1;initNative(1);
 Q::Coordinator c(makeAPI());fake.coordinator=&c;
 fake.completeInStart=true;fake.snapshotError=EIO;fake.failSchedule=true;
 bool firstStartSucceeded=false;
 assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native),
                  &firstStartSucceeded));
 assert(firstStartSucceeded&&c.state()==Q::State::Idle);
 assert(fake.finishCalls==1&&fake.lastFinishError==EIO&&fake.eventCount==2);
}

static void failCurrentDuringStartTests(){
 memset(&fake,0,sizeof(fake));fake.failStartAt=-1;initNative(1);
 Q::Coordinator c(makeAPI());fake.coordinator=&c;
 Q::CancelledOwners owners;assert(owners.add(73));
 fake.failCurrentInStart=true;
 bool firstStartSucceeded=true;
 const int error=c.submit((void*)0x11,(void*)0x22,native,sizeof(native),
                          &firstStartSucceeded);
 assert(error==EIO&&!firstStartSucceeded&&c.state()==Q::State::Idle);
 assert(fake.finishCalls==1&&fake.lastFinishError==EIO);
 assert(!owners.clearAfterSuccessfulFirstStart(73,true,firstStartSucceeded));
 assert(owners.contains(73));
}

static void staleCompletionTicketTests(){
 memset(&fake,0,sizeof(fake));fake.failStartAt=-1;initNative(1);
 Q::Coordinator c(makeAPI());fake.coordinator=&c;
 Q::CompletionTicket ticket{};
 assert(!c.captureCompletionTicket((void*)0x11,&ticket)); // idle is not pending

 initNative(2);bool firstStartSucceeded=false;
 assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native),
                  &firstStartSucceeded)&&firstStartSucceeded);
 Q::CompletionTicket oldTicket{};
 assert(c.captureCompletionTicket((void*)0x11,&oldTicket));
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
 assert(c.state()==Q::State::StartQueued);
 assert(!c.captureCompletionTicket((void*)0x11,&ticket)); // next provider start has not run
 c.cancel((void*)0x11);assert(c.state()==Q::State::Idle);

 initNative(1);bool nextStartSucceeded=false;
 assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native),
                  &nextStartSucceeded)&&nextStartSucceeded);
 Q::CompletionTicket newTicket{};
 assert(c.captureCompletionTicket((void*)0x11,&newTicket));
 assert(newTicket.generation!=oldTicket.generation||
        newTicket.startToken!=oldTicket.startToken);
 runOne(); // stale deferred child-start callback from the old sequence
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent,
     oldTicket.generation,oldTicket.startToken);
 c.failCurrent((void*)0x11,EIO,oldTicket.generation,oldTicket.startToken);
 assert(c.state()==Q::State::InFlight&&
        c.activeGeneration((void*)0x11)==newTicket.generation);
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent,
     newTicket.generation,newTicket.startToken);
 assert(c.state()==Q::State::FinishQueued);
 runOne();assert(c.state()==Q::State::Idle);
}

static void queueTests(){
 memset(&fake,0,sizeof(fake));fake.failStartAt=-1;initNative(2);
 Q::Coordinator c(makeAPI());fake.coordinator=&c;assert(c.ready()&&c.aggregateReady());
 assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 assert(c.state()==Q::State::InFlight&&fake.startCalls==1&&fake.ticketCount==0);
 assert(!outbound(c,(void*)0x11,Q::ScanDoneEvent));
 assert(!outbound(c,(void*)0x11,Q::ScanManagerDoneEvent));
 assert(outbound(c,(void*)0x11,2));
 // Manager code 15 is nested inside code 10 processing; neither child event
 // escapes while ScanManager::scanDone updates its cache.
 assert(!outbound(c,(void*)0x11,Q::ScanDoneEvent));
 assert(!outbound(c,(void*)0x11,Q::ScanManagerDoneEvent));
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanManagerDoneEvent);
 assert(c.state()==Q::State::InFlight&&fake.ticketCount==0);
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
 assert(c.state()==Q::State::StartQueued&&fake.ticketCount==1&&fake.eventCount==1);
 runOne();assert(fake.startCalls==2&&c.state()==Q::State::InFlight);
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
 assert(c.state()==Q::State::FinishQueued&&fake.eventCount==1);
 runOne();
 assert(c.state()==Q::State::Idle&&fake.eventCount==3);
 assert(fake.events[1]==Q::ScanDoneEvent&&fake.events[2]==Q::ScanManagerDoneEvent);
 assert(fake.failures==0&&fake.locked==false&&fake.snapshotCalls==2);
 assert(fake.finishCalls==1&&fake.lastFinishError==0);

 // A canceled queued callback is generation-stale; a canceled in-flight job
 // drains silently and does not publish a completion for an abandoned caller.
 initNative(2);assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
 assert(c.state()==Q::State::StartQueued&&fake.ticketCount==3);
 Ticket stale=fake.tickets[fake.ticketCount-1];c.cancel((void*)0x11);
 assert(c.state()==Q::State::Idle);initNative(1);
 assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 stale.callback(stale.owner,stale.generation);assert(fake.startCalls==4);
 runOne();assert(fake.startCalls==4&&c.state()==Q::State::InFlight);
 c.cancel((void*)0x11);assert(c.state()==Q::State::CancelledInFlight);
 assert(!outbound(c,(void*)0x11,Q::ScanDoneEvent));
 const unsigned beforeCancelEvents=fake.eventCount;
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
 assert(c.state()==Q::State::Idle&&fake.eventCount==beforeCancelEvents);

 // Cancellation, a consumed reentrant completion, then a duplicate cancel
 // must preserve the drain marker until the successful start action returns.
 initNative(1);fake.cancelInStart=true;fake.completeAfterCancelInStart=true;
 assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 assert(c.state()==Q::State::Idle&&fake.eventCount==beforeCancelEvents);

 // A duplicate cancel after startSingle returns still waits for the event.
 initNative(1);fake.cancelInStart=true;
 assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 assert(c.state()==Q::State::CancelledInFlight&&fake.eventCount==beforeCancelEvents);
 const uint64_t cancelledDuringStart=c.activeGeneration((void*)0x11);
 assert(cancelledDuringStart);
 // A second delayed worker for the same generation must not detach this
 // in-flight cancellation or re-enable the provider's outward event pair.
 c.cancelGeneration((void*)0x11,cancelledDuringStart);
 assert(c.state()==Q::State::CancelledInFlight&&
        c.activeGeneration((void*)0x11)==cancelledDuringStart);
 assert(!outbound(c,(void*)0x11,Q::ScanDoneEvent));
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
 assert(c.state()==Q::State::Idle&&fake.eventCount==beforeCancelEvents);

 // The initial SET10 child start is workloop-gated and synchronous, so its error is
 // returned to the SET86 caller without fabricating a completion event.
 initNative(1);fake.failStartAt=static_cast<int>(fake.startCalls);
 const unsigned beforeInitialError=fake.eventCount;
 const unsigned beforeInitialStartCalls=fake.startCalls;
 assert(c.submit((void*)0x11,(void*)0x22,native,sizeof(native))==EIO);
 assert(c.state()==Q::State::Idle&&fake.startCalls==beforeInitialStartCalls+1&&
        fake.eventCount==beforeInitialError);
 assert(fake.failures==0);

 // A later child's start can fail only after the request has returned; stop
 // the sequence, report the error, and emit one terminal event pair.
 fake.failStartAt=-1;initNative(2);
 const unsigned beforeLaterStartCalls=fake.startCalls;
 assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 fake.failStartAt=static_cast<int>(fake.startCalls);
 c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
 runOne();assert(c.state()==Q::State::Idle&&fake.startCalls==beforeLaterStartCalls+2);
 assert(fake.failures==1&&fake.lastError==EIO);
 assert(fake.events[fake.eventCount-2]==Q::ScanDoneEvent&&
        fake.events[fake.eventCount-1]==Q::ScanManagerDoneEvent);

 // Failure to schedule a child after cache completion ends once and publishes
 // the terminal pair only after the original code-10 postMessage returned.
 fake.failStartAt=-1;initNative(2);assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 const unsigned beforeScheduleFailure=fake.eventCount;
 fake.failSchedule=true;c.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
 assert(c.state()==Q::State::Idle&&fake.eventCount==beforeScheduleFailure+2);
 assert(fake.lastError==EBUSY&&fake.events[fake.eventCount-2]==Q::ScanDoneEvent);

 // An initial scheduling failure rejects the request without leaving an
 // active slot or emitting events.
 initNative(1);fake.failGate=true;const unsigned beforeInitialFailure=fake.eventCount;
 assert(c.submit((void*)0x11,(void*)0x22,native,sizeof(native))==EBUSY);
 assert(c.state()==Q::State::Idle&&fake.eventCount==beforeInitialFailure);

 // A reentrant completion from inside startSingle defers final publication
 // until that workloop action returns, keeping the request plan alive.
 initNative(1);fake.completeInStart=true;
 assert(!c.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 assert(!fake.completeInStart&&c.state()==Q::State::FinishQueued);
 runOne();assert(c.state()==Q::State::Idle);

 // A failed result snapshot stops before starting the next child and emits a
 // final event pair with the error retained by the managed GET11 layer.
 memset(&fake,0,sizeof(fake));fake.failStartAt=-1;fake.snapshotError=EOVERFLOW;
 Q::Coordinator overflow(makeAPI());fake.coordinator=&overflow;initNative(2);
 assert(!overflow.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 overflow.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
 assert(overflow.state()==Q::State::FinishQueued&&fake.startCalls==1);
 runOne();
 assert(overflow.state()==Q::State::Idle&&fake.startCalls==1);
 assert(fake.finishCalls==1&&fake.lastFinishError==EOVERFLOW);
 assert(fake.eventCount==2&&fake.events[0]==Q::ScanDoneEvent&&
        fake.events[1]==Q::ScanManagerDoneEvent);

 // Drive the maximum forty jobs. ASan catches the old 0x648 stride: the
 // manager's final 0x954-byte read would extend past the allocated plan.
 memset(&fake,0,sizeof(fake));fake.failStartAt=-1;initNative(10);
 for(uint32_t i=0;i<10;i++){
  const size_t record=M::NativeSSIDArray+size_t(i)*M::SSIDStride;
  put32(native+record+M::SSIDLengthOffset,1);
  native[record+M::SSIDBytesOffset]=static_cast<uint8_t>('A'+i);
 }
 put32(native+M::NativeChannelCount,400);
 for(uint32_t i=0;i<400;i++)put32(native+M::NativeChannels+i*M::ChannelStride,3000+i);
 Q::Coordinator maximum(makeAPI());fake.coordinator=&maximum;
 assert(!maximum.submit((void*)0x11,(void*)0x22,native,sizeof(native)));
 for(unsigned job=0;job<Q::MaxJobs;job++){
  assert(maximum.state()==Q::State::InFlight);
  maximum.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
  if(job+1<Q::MaxJobs){
   assert(maximum.state()==Q::State::StartQueued);
   runOne();
  }else{
   assert(maximum.state()==Q::State::FinishQueued);
   runOne();
  }
 }
 assert(maximum.state()==Q::State::Idle&&fake.startCalls==Q::MaxJobs&&
        fake.snapshotCalls==Q::MaxJobs&&fake.eventCount==2);

 // The same sequencer consumes the verified 12/13/25 native wire sizes.
 const size_t profiles[]={M::Monterey12Size,M::Ventura13Size,M::NativeSize};
 for(size_t profile:profiles){
  memset(&fake,0,sizeof(fake));fake.failStartAt=-1;initNative(2);
  Q::Coordinator compatible(makeAPI());fake.coordinator=&compatible;
  assert(!compatible.submit((void*)0x11,(void*)0x22,native,profile));
  assert(compatible.state()==Q::State::InFlight&&fake.startCalls==1);
  compatible.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
  assert(compatible.state()==Q::State::StartQueued);
  runOne();assert(fake.startCalls==2&&compatible.state()==Q::State::InFlight);
  compatible.highLevelPostMessageReturned((void*)0x11,Q::ScanDoneEvent);
  assert(compatible.state()==Q::State::FinishQueued);
  runOne();assert(compatible.state()==Q::State::Idle&&fake.snapshotCalls==2);
  assert(fake.finishCalls==1&&fake.lastFinishError==0&&fake.eventCount==2);
 }
}
int main(){planTests();cancellationStateTests();generationCancellationTests();
 completionRecordTests();reentrantTerminalCompletionTests();
 failCurrentDuringStartTests();staleCompletionTicketTests();queueTests();}
'''


class LegacyScanSequenceTests(unittest.TestCase):
    def test_bounded_split_and_aggregated_completion_state_machine(self):
        with tempfile.TemporaryDirectory(prefix="legacy-scan-sequence-", dir="/private/tmp") as tmp:
            source = pathlib.Path(tmp) / "sequence.cpp"
            binary = pathlib.Path(tmp) / "sequence"
            source.write_text(HARNESS)
            build = subprocess.run(
                ["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                 "-I", str(PROJECT / "src"), str(source), "-o", str(binary)],
                text=True, capture_output=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], text=True, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
