"""Owned current-BSS snapshots and SET22 worker-completion tokens."""
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/current_bss.hpp"
#include <cassert>
#include <cstring>
#include <initializer_list>
#include <new>
#include <type_traits>
namespace C=LegacyWiFi::CurrentBSS;
namespace D=LegacyWiFi::NetworkIdentity;
namespace N=LegacyWiFi::NetworkMatch;

static_assert(!std::is_copy_constructible<C::CompletionToken>::value,
              "a completion token must not be duplicated");
static_assert(!std::is_copy_assignable<C::CompletionToken>::value,
              "a completion token must not be copy-assigned");
static_assert(!std::is_move_constructible<C::CompletionToken>::value,
              "a stack-scoped completion token must not be relocated");
static_assert(!std::is_move_assignable<C::CompletionToken>::value,
              "a stack-scoped completion token must not be move-assigned");

static void put16(uint8_t *p,uint16_t n){memcpy(p,&n,2);}
static void put64(uint8_t *p,uint64_t n){memcpy(p,&n,8);}
static size_t recordSize(D::Source s){return s==D::Source::Pinned4331?0xa0:0x98;}
static size_t capabilityOffset(D::Source s){return s==D::Source::Pinned4331?0x62:0x5e;}
static void init(uint8_t *r,size_t n,D::Source s,uint16_t capability=1){
    memset(r,0,n);r[0]=0x02;r[1]=0xaa;r[2]=0xbb;r[3]=0xcc;r[4]=0xdd;r[5]=0xee;
    r[8]=3;r[9]='a';r[10]=0;r[11]='z';put16(r+capabilityOffset(s),capability);
}
static void expectFailure(D::Source s,const uint8_t *r,size_t rn,
                          const uint8_t *ies,size_t in,int expected){
    C::OwnedSnapshot out{};out.bssid[0]=0x02;out.network.ssid[0]=0xa5;
    out.network.ssidLength=1;out.network.encryptionModes=0xa55a;
    const C::OwnedSnapshot before=out;
    assert(C::decode(s,r,rn,ies,in,&out)==expected);
    assert(!memcmp(&out,&before,sizeof(out)));
}
static C::Binding binding(D::Source source){
    C::Binding b{};b.source=source;b.owner=1;b.generation=2;b.thread=3;
    b.driver=4;b.wlc=5;b.cfg=6;
    const uint8_t address[]={2,0xaa,0xbb,0xcc,0xdd,0xee};
    memcpy(b.bssid,address,sizeof(address));return b;
}
static C::WorkerEntry entry(const C::Binding &b){
    C::WorkerEntry e{};e.binding=b;
    e.returnPCOffset=b.source==D::Source::Pinned4331?
        C::WorkerCallSite4331:C::WorkerCallSite43224;
    e.arg0=b.source==D::Source::Pinned4331?b.cfg:b.wlc;
    e.arg1=1;memcpy(e.liveBSSID,b.bssid,sizeof(e.liveBSSID));return e;
}
static C::WorkerExit exitFor(const C::Binding &b){
    C::WorkerExit e{};e.binding=b;e.status=0;return e;
}

int main(){
    uint8_t record[0xa0],body[C::MaximumBeaconBodyBytes]{};
    const uint8_t ssid[]={ 'a',0,'z' };
    const uint8_t rsn[]={48,2,0,0};
    // These bytes deliberately look like complete RSN and WPA vendor IEs.
    // The fixed beacon body is not an IE list and must never affect security.
    const uint8_t beaconHeader[C::BeaconFixedBodyBytes]={
        48,2,0,0, 221,4,0x00,0x50,0xf2,0x01,0xaa,0xbb
    };
    for(auto source:{D::Source::Pinned4331,D::Source::Pinned43224}){
        const size_t size=recordSize(source);init(record,size,source,0x11);
        put64(record+0x68,UINT64_MAX); // Presence is checked; this is never dereferenced.
        const size_t bodySize=sizeof(beaconHeader)+sizeof(rsn);
        put16(record+0x70,bodySize);
        memcpy(body,beaconHeader,sizeof(beaconHeader));
        memcpy(body+sizeof(beaconHeader),rsn,sizeof(rsn));
        uint8_t before[0xa0];memcpy(before,record,size);
        C::OwnedSnapshot out{};
        assert(C::decode(source,record,size,body,bodySize,&out)==0);
        assert(!memcmp(out.bssid,record,6));
        assert(out.network.ssidLength==sizeof(ssid));
        assert(!memcmp(out.network.ssid,ssid,sizeof(ssid)));
        // Only the RSN tail contributes: fake header RSN + vendor IE must not
        // add the WPA numeric bit.
        assert(out.network.encryptionModes==8 && out.network.apMode==2);
        assert(out.network.fils==N::FILS::Absent);
        assert(!memcmp(record,before,size));
    }
    // An actual 12-byte beacon body with no IE tail is known data, so the
    // fallback classification comes from the BSS capability field. Header
    // bytes that resemble RSN/vendor IEs remain ignored.
    {
        init(record,0xa0,D::Source::Pinned4331,0x11);
        memcpy(body,beaconHeader,sizeof(beaconHeader));
        put64(record+0x68,0x1234);
        put16(record+0x70,C::BeaconFixedBodyBytes);
        C::OwnedSnapshot out{};
        assert(C::decode(D::Source::Pinned4331,record,0xa0,body,
                         C::BeaconFixedBodyBytes,&out)==0);
        assert(out.network.encryptionModes==2);
    }

    // The maximum accepted 1024-byte IE tail follows the fixed body. An
    // all-zero tail is a bounded list of zero-length unknown IEs.
    {
        uint8_t maxBody[C::MaximumBeaconBodyBytes]{};
        init(record,0xa0,D::Source::Pinned4331,0x11);
        memcpy(maxBody,beaconHeader,sizeof(beaconHeader));
        put64(record+0x68,0x1234);
        put16(record+0x70,C::MaximumBeaconBodyBytes);
        C::OwnedSnapshot out{};
        assert(C::decode(D::Source::Pinned4331,record,0xa0,maxBody,
                         sizeof(maxBody),&out)==0);
        assert(out.network.encryptionModes==2);
    }

    init(record,0xa0,D::Source::Pinned4331);
    C::OwnedSnapshot unchanged{};unchanged.bssid[0]=0x02;
    unchanged.network.ssid[0]=0xa5;unchanged.network.ssidLength=1;
    const C::OwnedSnapshot old=unchanged;
    assert(C::decode(D::Source::Unknown,record,0xa0,nullptr,0,&unchanged)==EOPNOTSUPP);
    assert(!memcmp(&old,&unchanged,sizeof(old)));

    // No saved body is unknown even when the record contains enough capability
    // metadata to guess a fallback mode. A real fixed body with no tail above
    // remains distinguishable and decodes successfully.
    put64(record+0x68,0);put16(record+0x70,0);
    expectFailure(D::Source::Pinned4331,record,0xa0,nullptr,0,EOPNOTSUPP);

    expectFailure(D::Source::Pinned4331,record,0x9f,nullptr,0,EINVAL);
    expectFailure(D::Source::Pinned4331,record,0x98,nullptr,0,EINVAL);
    expectFailure(D::Source::Pinned43224,record,0xa0,nullptr,0,EINVAL);
    expectFailure(D::Source::Pinned4331,nullptr,0xa0,nullptr,0,EINVAL);

    // Saved-body length must agree with pointer presence and with the owned
    // copy; a nonzero body shorter than the 12-byte fixed header is invalid.
    uint8_t shortBody[C::BeaconFixedBodyBytes-1]{};
    put64(record+0x68,0x1234);put16(record+0x70,sizeof(shortBody));
    expectFailure(D::Source::Pinned4331,record,0xa0,shortBody,sizeof(shortBody),EINVAL);
    put16(record+0x70,C::BeaconFixedBodyBytes);
    expectFailure(D::Source::Pinned4331,record,0xa0,body,
                  C::BeaconFixedBodyBytes-1,EINVAL);
    expectFailure(D::Source::Pinned4331,record,0xa0,nullptr,
                  C::BeaconFixedBodyBytes,EINVAL);

    // Pointer/length mismatches remain errors, while a zero pointer with a
    // zero length is the distinct unsupported/unknown state above.
    put64(record+0x68,0);put16(record+0x70,4);
    expectFailure(D::Source::Pinned4331,record,0xa0,body,4,EINVAL);
    put64(record+0x68,0x1234);put16(record+0x70,0);
    expectFailure(D::Source::Pinned4331,record,0xa0,body,0,EINVAL);
    put64(record+0x68,0x1234);put16(record+0x70,C::MaximumBeaconBodyBytes+1);
    expectFailure(D::Source::Pinned4331,record,0xa0,body,
                  C::MaximumBeaconBodyBytes+1,EOVERFLOW);

    // A malformed IE exists only in the tail after the fixed 12-byte body.
    uint8_t malformedBody[C::BeaconFixedBodyBytes+3]{};
    memcpy(malformedBody,beaconHeader,sizeof(beaconHeader));
    malformedBody[C::BeaconFixedBodyBytes]=48;
    malformedBody[C::BeaconFixedBodyBytes+1]=4;
    malformedBody[C::BeaconFixedBodyBytes+2]=0;
    put64(record+0x68,0x1234);put16(record+0x70,sizeof(malformedBody));
    expectFailure(D::Source::Pinned4331,record,0xa0,malformedBody,
                  sizeof(malformedBody),EINVAL);

    init(record,0xa0,D::Source::Pinned4331);memset(record,0,6);
    expectFailure(D::Source::Pinned4331,record,0xa0,nullptr,0,EINVAL);
    init(record,0xa0,D::Source::Pinned4331);record[0]=3;
    expectFailure(D::Source::Pinned4331,record,0xa0,nullptr,0,EINVAL);
    init(record,0xa0,D::Source::Pinned4331);record[8]=33;
    expectFailure(D::Source::Pinned4331,record,0xa0,nullptr,0,EINVAL);

    // 4331: the existing worker path is observed once and its local teardown
    // is accepted without requiring IE storage to be released.
    {
        const C::Binding b=binding(D::Source::Pinned4331);
        C::CompletionToken token;C::WorkerTicket ticket{};
        assert(token.arm(b));auto e=entry(b);assert(token.workerEnter(e,&ticket));
        C::WorkerExit x=exitFor(b);x.currentIEPointer=0x1234;x.currentIELength=12;
        assert(token.workerReturn(ticket,x));assert(token.consumeCompleted(b));
        assert(!token.consumeCompleted(b));assert(token.failed());
    }
    // 43224 uses WLC as arg0 and requires the synchronous IE cleanup too.
    {
        const C::Binding b=binding(D::Source::Pinned43224);
        C::CompletionToken token;C::WorkerTicket ticket{};
        assert(token.arm(b));auto e=entry(b);assert(e.arg0==b.wlc);
        assert(token.workerEnter(e,&ticket));
        C::WorkerExit x=exitFor(b);x.currentIEPointer=1;
        assert(!token.workerReturn(ticket,x));assert(token.failed());
    }
    // A successful 43224 local teardown satisfies the complete postcondition.
    {
        const C::Binding b=binding(D::Source::Pinned43224);
        C::CompletionToken token;C::WorkerTicket ticket{};
        assert(token.arm(b));auto e=entry(b);assert(token.workerEnter(e,&ticket));
        assert(token.workerReturn(ticket,exitFor(b)));
        assert(token.consumeCompleted(b));
    }
    // No worker, no-op state, failed status, wrong post-BSSID, or stale/wrong
    // entry binding can never authorize completion.
    {
        const C::Binding b=binding(D::Source::Pinned4331);
        C::CompletionToken token;assert(token.arm(b));
        assert(!token.consumeCompleted(b));assert(token.failed());
    }
    for(unsigned mismatch=0;mismatch<14;++mismatch){
        const C::Binding b=binding(D::Source::Pinned4331);
        C::CompletionToken token;C::WorkerTicket ticket{};assert(token.arm(b));
        auto e=entry(b);
        switch(mismatch){
        case 0:e.returnPCOffset++;break;
        case 1:e.arg0++;break;
        case 2:e.arg1=0;break;
        case 3:e.binding.owner++;break;
        case 4:e.binding.generation++;break;
        case 5:e.liveBSSID[5]^=1;break;
        case 6:e.binding.cfg++;break;
        case 7:e.binding.thread++;break;
        case 8:e.binding.driver++;break;
        case 9:e.binding.wlc++;break;
        case 10:e.binding.bssid[5]^=1;break;
        case 11:e.arg2=1;break;
        case 12:e.arg3=1;break;
        default:e.binding.source=D::Source::Pinned43224;break;
        }
        assert(!token.workerEnter(e,&ticket));assert(token.failed());
    }
    {
        const C::Binding b=binding(D::Source::Pinned4331);
        C::CompletionToken token;C::WorkerTicket ticket{};assert(token.arm(b));
        const auto e=entry(b);assert(token.workerEnter(e,&ticket));
        C::WorkerTicket nested{};assert(!token.workerEnter(e,&nested));
        assert(!token.workerReturn(ticket,exitFor(b)));assert(token.failed());
    }
    for(unsigned mismatch=0;mismatch<10;++mismatch){
        const C::Binding b=binding(D::Source::Pinned4331);
        C::CompletionToken token;C::WorkerTicket ticket{};assert(token.arm(b));
        assert(token.workerEnter(entry(b),&ticket));
        auto x=exitFor(b);
        if(mismatch==0)x.status=-1;
        else if(mismatch==1)x.liveBSSID[0]=2;
        else if(mismatch==2)x.binding.generation++;
        else if(mismatch==3)x.binding.thread++;
        else if(mismatch==4)x.binding.owner++;
        else if(mismatch==5)x.binding.driver++;
        else if(mismatch==6)x.binding.wlc++;
        else if(mismatch==7)x.binding.cfg++;
        else if(mismatch==8)x.binding.bssid[5]^=1;
        else x.binding.source=D::Source::Pinned43224;
        assert(!token.workerReturn(ticket,x));assert(token.failed());
    }
    // 43224 must also prove its synchronous current-IE pointer/length cleanup.
    for(unsigned mismatch=0;mismatch<2;++mismatch){
        const C::Binding b=binding(D::Source::Pinned43224);
        C::CompletionToken token;C::WorkerTicket ticket{};assert(token.arm(b));
        assert(token.workerEnter(entry(b),&ticket));
        auto x=exitFor(b);
        if(mismatch==0)x.currentIEPointer=1;else x.currentIELength=1;
        assert(!token.workerReturn(ticket,x));assert(token.failed());
    }
    // Numeric ticket values are local to a token: two live tokens may both
    // issue value 1, but a ticket from one cannot complete the other.
    {
        const C::Binding b=binding(D::Source::Pinned4331);
        C::CompletionToken first,second;
        C::WorkerTicket firstTicket{},secondTicket{};
        assert(first.arm(b) && second.arm(b));
        assert(first.workerEnter(entry(b),&firstTicket));
        assert(second.workerEnter(entry(b),&secondTicket));
        assert(firstTicket.value==1 && secondTicket.value==1);
        assert(firstTicket.token==&first && secondTicket.token==&second);
        assert(firstTicket.bindingOwner==b.owner &&
               firstTicket.bindingGeneration==b.generation);
        assert(!second.workerReturn(firstTicket,exitFor(b)));
        assert(second.failed());
        assert(first.workerReturn(firstTicket,exitFor(b)));
        assert(first.consumeCompleted(b));
    }
    // Placement-new reuses the token address. A stale ticket from the prior
    // generation must still fail, even though pointer and numeric value match.
    {
        alignas(C::CompletionToken) unsigned char storage[sizeof(C::CompletionToken)];
        C::Binding oldBinding=binding(D::Source::Pinned4331);
        C::WorkerTicket staleTicket{};
        C::CompletionToken *oldToken=new (storage) C::CompletionToken();
        assert(oldToken->arm(oldBinding));
        assert(oldToken->workerEnter(entry(oldBinding),&staleTicket));
        oldToken->~CompletionToken();

        C::Binding newBinding=oldBinding;
        ++newBinding.generation;
        C::WorkerTicket currentTicket{};
        C::CompletionToken *newToken=new (storage) C::CompletionToken();
        assert(newToken==oldToken);
        assert(newToken->arm(newBinding));
        assert(newToken->workerEnter(entry(newBinding),&currentTicket));
        assert(staleTicket.token==newToken && staleTicket.value==currentTicket.value);
        assert(staleTicket.bindingOwner==newBinding.owner);
        assert(staleTicket.bindingGeneration!=newBinding.generation);
        assert(!newToken->workerReturn(staleTicket,exitFor(newBinding)));
        assert(newToken->failed());
        newToken->~CompletionToken();
    }
    {
        C::Binding invalid=binding(D::Source::Pinned4331);invalid.owner=0;
        C::CompletionToken token;assert(!token.arm(invalid));assert(token.failed());
        assert(!token.arm(binding(D::Source::Pinned4331)));
        assert(token.failed());
    }
    return 0;
}
'''


class LegacyCurrentBSSTests(unittest.TestCase):
    def test_owned_snapshot_and_disconnect_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, binary = Path(tmp) / "test.cpp", Path(tmp) / "test"
            source.write_text(HARNESS)
            subprocess.run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                            "-I", str(PROJECT / "src"), str(source), "-o", str(binary)],
                           check=True, capture_output=True, timeout=30)
            subprocess.run([str(binary)], check=True, capture_output=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
