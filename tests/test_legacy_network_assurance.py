"""Bounded CCX Network Assurance parsing and current-BSS integration."""
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/current_bss.hpp"
#include "legacy_wifi_compat/network_assurance.hpp"
#include <cassert>
#include <cstring>
#include <vector>

namespace A=LegacyWiFi::NetworkAssurance;
namespace C=LegacyWiFi::CurrentBSS;
namespace D=LegacyWiFi::NetworkIdentity;

static void put16(uint8_t *p,uint16_t n){memcpy(p,&n,sizeof(n));}
static void put64(uint8_t *p,uint64_t n){memcpy(p,&n,sizeof(n));}
static std::vector<uint8_t> vendor(uint8_t value,uint8_t subtype=0x0b,
                                   uint8_t ouiLast=0x96,uint8_t bodyLength=5) {
    std::vector<uint8_t> ie;
    ie.push_back(221);ie.push_back(bodyLength);
    if(bodyLength>0)ie.push_back(0x00);
    if(bodyLength>1)ie.push_back(0x40);
    if(bodyLength>2)ie.push_back(ouiLast);
    if(bodyLength>3)ie.push_back(subtype);
    if(bodyLength>4)ie.push_back(value);
    while(ie.size()<static_cast<size_t>(bodyLength)+2)ie.push_back(0x5a);
    return ie;
}
static void append(std::vector<uint8_t> &to,const std::vector<uint8_t> &from) {
    to.insert(to.end(),from.begin(),from.end());
}
static void expectParserError(const uint8_t *data,size_t length,int expected) {
    A::State output=A::State::Disabled;
    assert(A::parse(data,length,&output)==expected);
    assert(output==A::State::Disabled);
}
static size_t recordSize(D::Source source) {
    return source==D::Source::Pinned4331?C::Record4331Size:C::Record43224Size;
}
static size_t capabilityOffset(D::Source source) {
    return source==D::Source::Pinned4331?C::Capability4331Offset:C::Capability43224Offset;
}
static void initRecord(uint8_t *record,size_t size,D::Source source,size_t bodySize) {
    memset(record,0,size);
    const uint8_t bssid[6]={0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    memcpy(record,bssid,sizeof(bssid));
    record[C::SSIDLengthOffset]=3;
    memcpy(record+C::SSIDOffset,"net",3);
    put16(record+capabilityOffset(source),0x10);
    put64(record+C::IEPointerOffset,bodySize?0x1234:0);
    put16(record+C::IELengthOffset,static_cast<uint16_t>(bodySize));
}
static void expectCurrent(D::Source source,const std::vector<uint8_t> &tail,
                          A::State expected) {
    const size_t size=recordSize(source);
    uint8_t record[C::Record4331Size]{};
    std::vector<uint8_t> body(C::BeaconFixedBodyBytes+tail.size(),0);
    if(!tail.empty())memcpy(body.data()+C::BeaconFixedBodyBytes,tail.data(),tail.size());
    initRecord(record,size,source,body.size());
    C::OwnedSnapshot output{};
    assert(C::decode(source,record,size,body.data(),body.size(),&output)==0);
    assert(output.networkAssurance==expected);
}

int main() {
    static_assert(A::CCXOUI[0]==0x00 && A::CCXOUI[1]==0x40 && A::CCXOUI[2]==0x96,
                  "must match retained Tahoe native OUI");
    static_assert(A::CCXSubtype==0x0b && A::NetworkAssuranceMask==0x80,
                  "must match native subtype and bit");

    // Empty and unrelated lists do not prove a negative value.
    {
        A::State state=A::State::Enabled;
        assert(A::parse(nullptr,0,&state)==0 && state==A::State::Unknown);
        const uint8_t unrelated[]={1,1,0x42,221,5,0x00,0x50,0xf2,0x0b,0x80};
        assert(A::parse(unrelated,sizeof(unrelated),&state)==0);
        assert(state==A::State::Unknown);
    }

    // Exact OUI/subtype and the bit-7 boundary. Lower bits do not enable it.
    {
        auto enabled=vendor(0x80);
        A::State state=A::State::Unknown;
        assert(A::parse(enabled.data(),enabled.size(),&state)==0);
        assert(state==A::State::Enabled);
        auto disabled=vendor(0x7f);
        assert(A::parse(disabled.data(),disabled.size(),&state)==0);
        assert(state==A::State::Disabled);
        auto wrongOUI=vendor(0x80,0x0b,0x95);
        assert(A::parse(wrongOUI.data(),wrongOUI.size(),&state)==0);
        assert(state==A::State::Unknown);
        auto wrongSubtype=vendor(0x80,0x0a);
        assert(A::parse(wrongSubtype.data(),wrongSubtype.size(),&state)==0);
        assert(state==A::State::Unknown);
        auto shortVendor=vendor(0x80,0x0b,0x96,4);
        assert(A::parse(shortVendor.data(),shortVendor.size(),&state)==0);
        assert(state==A::State::Unknown);
        auto exactMinimum=vendor(0x80,0x0b,0x96,5);
        assert(exactMinimum.size()==7);
        assert(A::parse(exactMinimum.data(),exactMinimum.size(),&state)==0);
        assert(state==A::State::Enabled);
    }

    // The final valid matching IE controls, even with unrelated or invalid
    // (but structurally valid) vendor IEs between the matches.
    {
        std::vector<uint8_t> list;
        append(list,vendor(0x80));
        append(list,vendor(0x80,0x0a));
        append(list,vendor(0x00));
        A::State state=A::State::Unknown;
        assert(A::parse(list.data(),list.size(),&state)==0);
        assert(state==A::State::Disabled);
        list.clear();append(list,vendor(0x00));append(list,vendor(0x80));
        assert(A::parse(list.data(),list.size(),&state)==0);
        assert(state==A::State::Enabled);
    }

    // A later malformed suffix invalidates the entire result and cannot leak
    // the earlier valid match through the output parameter.
    {
        std::vector<uint8_t> list=vendor(0x80);
        list.push_back(221); // truncated IE header
        expectParserError(list.data(),list.size(),EINVAL);
        list=vendor(0x80);list.push_back(1);list.push_back(2);list.push_back(0xaa);
        expectParserError(list.data(),list.size(),EINVAL);
        const uint8_t truncatedHeader[]={1};
        expectParserError(truncatedHeader,sizeof(truncatedHeader),EINVAL);
        const uint8_t tooLong[]={1,3,0xaa,0xbb};
        expectParserError(tooLong,sizeof(tooLong),EINVAL);
    }

    // Bound and argument failures leave output unchanged.
    {
        const uint8_t byte=0;
        expectParserError(nullptr,1,EINVAL);
        expectParserError(&byte,A::MaximumIETailBytes+1,EOVERFLOW);
        assert(A::parse(nullptr,0,nullptr)==EINVAL);
        A::State state=A::State::Disabled;
        assert(A::parse(nullptr,0,&state)==0 && state==A::State::Unknown);
    }

    // CurrentBSS::decode parses only the tail after its fixed 12-byte body,
    // carries Unknown for absence, and exports observed Enabled/Disabled for
    // both pinned child layouts.
    for(auto source:{D::Source::Pinned4331,D::Source::Pinned43224}) {
        expectCurrent(source,{},A::State::Unknown);
        expectCurrent(source,vendor(0x80),A::State::Enabled);
        expectCurrent(source,vendor(0x00),A::State::Disabled);
    }

    // A malformed tail fails the whole CurrentBSS decode without publishing
    // identity or a partially observed assurance state.
    {
        const D::Source source=D::Source::Pinned4331;
        const size_t size=recordSize(source);
        uint8_t record[C::Record4331Size]{};
        std::vector<uint8_t> body(C::BeaconFixedBodyBytes,0);
        append(body,vendor(0x80));body.push_back(221);
        initRecord(record,size,source,body.size());
        C::OwnedSnapshot out{};out.bssid[0]=0x02;
        out.network.ssid[0]=0xa5;out.network.ssidLength=1;
        out.networkAssurance=A::State::Disabled;
        const C::OwnedSnapshot before=out;
        assert(C::decode(source,record,size,body.data(),body.size(),&out)==EINVAL);
        assert(!memcmp(&out,&before,sizeof(out)));
    }

    // The absent-body path remains unsupported/unknown; capability metadata
    // alone is not a substitute for the missing snapshot.
    {
        uint8_t record[C::Record4331Size]{};
        initRecord(record,sizeof(record),D::Source::Pinned4331,0);
        C::OwnedSnapshot out{};out.networkAssurance=A::State::Enabled;
        const C::OwnedSnapshot before=out;
        assert(C::decode(D::Source::Pinned4331,record,sizeof(record),nullptr,0,&out)
               ==EOPNOTSUPP);
        assert(!memcmp(&out,&before,sizeof(out)));
    }
    return 0;
}
'''


class NetworkAssuranceTests(unittest.TestCase):
    def test_native_ccx_bit_and_current_bss_integration(self):
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
