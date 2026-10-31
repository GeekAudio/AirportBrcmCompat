#include "baseline_trace.hpp"
#include "window_alias.h"
#include <assert.h>
#include <atomic>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <vector>
using namespace AWDLKernel::BaselineTrace;
static std::atomic<uint64_t> nowNs {1000000000ULL};
static std::atomic<bool> entered {false},resume {false};
static thread_local bool pauseClock=false;
static uint64_t clockNs() {
    const auto n=nowNs.load();
    if (pauseClock) {entered.store(true);while (!resume.load()) std::this_thread::yield();}
    return n;
}
static uint64_t otherClock() {return nowNs.load();}
static const uint8_t key[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const uint8_t local[6]={2,1,2,3,4,5};
static std::vector<uint8_t> frame(uint8_t subtype=0) {
    std::vector<uint8_t> f(99,0);memcpy(f.data(),local,6);f[12]=1;f[16]=149;
    const uint8_t header[]={127,0,0x17,0xf2,8,0x10,subtype,0};memcpy(f.data()+72,header,8);
    f[88]=12;f[89]=8;f[91]=4;memcpy(f.data()+93,local,6);return f;
}
static void observe(uint8_t kind=0) {auto f=frame(kind);const auto copy=f;observeOwnedMessage48(f.data(),f.size());assert(f==copy);}
static bool collect(const WindowSample &s,void *p) {static_cast<std::vector<WindowSample> *>(p)->push_back(s);return true;}
static std::vector<WindowSample> rows(const WindowSnapshot &s) {std::vector<WindowSample> v;assert(visitWindowSamples(s,collect,&v));return v;}
static void validation() {
    assert(windowSnapshot().generation==0);
    uint8_t zero[16]={},multicast[6]={1,2,3,4,5,6};
    assert(armWindow(0,key,local,clockNs)==ArmResult::Invalid);
    assert(armWindow(121,key,local,clockNs)==ArmResult::Invalid);
    assert(armWindow(1,zero,local,clockNs)==ArmResult::Invalid);
    assert(armWindow(1,key,multicast,clockNs)==ArmResult::Invalid);
    assert(armWindow(1,nullptr,local,clockNs)==ArmResult::Invalid);
    assert(armWindow(1,key,local,nullptr)==ArmResult::Invalid);
    nowNs.store(UINT64_MAX-10);assert(armWindow(1,key,local,clockNs)==ArmResult::Clock);
    nowNs.store(1000000000ULL);
    assert(armWindow(112,key,local,clockNs)==ArmResult::Passed);
    assert(armWindow(1,key,local,clockNs)==ArmResult::Busy);
    for(unsigned j=0;j<112;j++) {
        nowNs.store(1000000000ULL+j*1000000000ULL);observe();observe();observe(3);observe(1);
    }
    auto view=windowSnapshot();assert(view.ready[0]==112&&view.ready[1]==112&&view.ready[2]<=32);
    assert(view.firstNs[0]==1000000000ULL&&view.lastNs[0]==112000000000ULL&&view.thinned>=112);
    assert(!view.droppedCapacity&&!view.closed);
    nowNs.store(view.endNs);observe();view=windowSnapshot();assert(view.closed&&view.afterDeadline==1);
    assert(armWindow(1,key,local,otherClock)==ArmResult::Clock);
    for(unsigned j=2;j<=4;j++) {
        assert(armWindow(1,key,local,clockNs)==ArmResult::Passed);
        view=windowSnapshot();assert(view.generation==j&&!view.ready[0]);nowNs.store(view.endNs);
    }
    assert(armWindow(1,key,local,clockNs)==ArmResult::Exhausted);
}
static void identityAndFence() {
    uint8_t address[6]={0,1,2,3,4,5};assert(awdl_window_alias6(key,address)==0xcbc9466e58fee3ceULL);
    assert(armWindow(1,key,local,clockNs)==ArmResult::Passed);observe();
    const auto first=windowSnapshot();auto a=rows(first);assert(a.size()==1);
    assert(a[0].sourceAlias==awdl_window_alias6(key,local)&&a[0].sourceMatchesLocal);
    assert(a[0].advertisedLocalComparable&&a[0].advertisedMatchesLocal);
    assert(a[0].summary.lastTlv12AwdlAddressPrefixMatchesMetadataSource);
    nowNs.fetch_add(10000000);auto absent=frame(3);absent[91]=0;observeOwnedMessage48(absent.data(),absent.size());
    auto b=rows(windowSnapshot());assert(b.size()==2&&!b[1].advertisedLocalComparable&&!b[1].summary.lastTlv12AwdlAddressAdvertised);
    assert(rows(first).size()==1); // immutable ready-bit fence, despite later rows.
    nowNs.fetch_add(10000000);auto mismatch=frame();mismatch[93]=4;observeOwnedMessage48(mismatch.data(),mismatch.size());
    b=rows(windowSnapshot());assert(b.size()==3&&!b[1].advertisedMatchesLocal&&b[1].advertisedLocalComparable);
    nowNs.store(first.startNs-1);observe();assert(windowSnapshot().state==3&&windowSnapshot().clockRejected==1);
}
static void pausedWriter() {
    assert(armWindow(1,key,local,clockNs)==ArmResult::Passed);
    std::thread writer([]{pauseClock=true;observe();});while(!entered.load())std::this_thread::yield();
    nowNs.store(2000000000ULL);const auto paused=windowSnapshot();
    assert(paused.state==2&&paused.inFlightBefore==1&&paused.inFlightAfter==1&&!paused.closed);
    assert(armWindow(1,key,local,clockNs)==ArmResult::Passed);resume.store(true);writer.join();
    assert(rows(paused).empty()); // old row becoming ready never leaks into prior snapshot.
    const auto next=windowSnapshot();assert(next.generation==2&&!next.ready[0]);
    nowNs.store(next.endNs);assert(windowSnapshot().closed);
    observe();assert(windowSnapshot().closed&&windowSnapshot().afterDeadline==1);
}
static void concurrent() {
    std::atomic<unsigned> passed {0};std::vector<std::thread> arms;
    for(unsigned i=0;i<16;i++)arms.emplace_back([&]{if(armWindow(120,key,local,clockNs)==ArmResult::Passed)passed++;});
    for(auto &t:arms)t.join();assert(passed==1&&windowSnapshot().generation==1);
    std::atomic<bool> done {false};
    std::thread reader([&]{while(!done.load()) {const auto s=windowSnapshot();auto v=rows(s);assert(v.size()==s.ready[0]+s.ready[1]+s.ready[2]);}});
    std::vector<std::thread> writers;
    for(unsigned i=0;i<6;i++)writers.emplace_back([i]{for(unsigned j=0;j<1000;j++){nowNs.fetch_add(1000000);observe(i%2?3:0);}});
    for(auto &t:writers)t.join();done=true;reader.join();const auto s=windowSnapshot();
    assert(s.ready[0]&&s.ready[1]&&!s.pending[0]&&!s.pending[1]);
}
int main(int argc,char **argv) {
    assert(argc==2);switch(atoi(argv[1])) {case 1:validation();break;case 2:identityAndFence();break;
    case 3:pausedWriter();break;case 4:concurrent();break;default:abort();}return 0;
}
