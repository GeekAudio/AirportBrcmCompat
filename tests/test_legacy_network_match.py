"""Boundary tests for the normalized selective-cache network predicate."""
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/network_match.hpp"
#include <cassert>
#include <cstring>
#include <initializer_list>
namespace N=LegacyWiFi::NetworkMatch;
static bool same(const N::Identity &a,const N::Identity &b) {
    bool out=false;assert(N::matches(&a,&b,&out)==0);return out;
}
int main() {
    N::Identity a{},b{};
    a.fils=N::FILS::Absent;
    a.encryptionModes=b.encryptionModes=1;
    assert(same(a,b)); // Empty SSIDs compare by length and bytes, not C strings.
    a.ssidLength=b.ssidLength=32;
    for(unsigned i=0;i<32;++i)a.ssid[i]=b.ssid[i]=static_cast<uint8_t>(i);
    assert(same(a,b));
    b.ssid[31]^=1;assert(!same(a,b));b.ssid[31]^=1;
    b.ssidLength=31;assert(!same(a,b));b.ssidLength=32;
    a.ssidLength=b.ssidLength=3;
    a.ssid[0]=b.ssid[0]='x';a.ssid[1]=b.ssid[1]=0;
    a.ssid[2]='a';b.ssid[2]='b';assert(!same(a,b));b.ssid[2]='a';
    b.ssid[3]^=1;assert(same(a,b)); // Bytes after the declared SSID are ignored.
    for(unsigned i=0;i<16;++i)for(unsigned j=0;j<16;++j) {
        a.encryptionModes=static_cast<uint16_t>(1U<<i);
        b.encryptionModes=static_cast<uint16_t>(1U<<j);
        assert(same(a,b)==(i==j));
    }
    a.encryptionModes=0;b.encryptionModes=0xffff;assert(!same(a,b));
    a.encryptionModes=0xffff;b.encryptionModes=0;assert(!same(a,b));
    b.encryptionModes=0x8000;assert(same(a,b));
    for(unsigned i=0;i<4;++i)for(unsigned j=0;j<4;++j) {
        a.apMode=i;b.apMode=j;assert(same(a,b)==(j==3||i==j));
    }
    a.apMode=b.apMode=2;
    b.fils=N::FILS::Present;assert(same(a,b)); // Exclusion applies to the candidate.
    a.fils=N::FILS::Present;assert(!same(a,b));
    a.fils=N::FILS::Absent;b.fils=N::FILS::Unknown;
    N::Identity beforeA=a,beforeB=b;
    for(bool initial:{false,true}) {
        bool out=initial;
        assert(N::matches(nullptr,&b,&out)==EINVAL && out==initial);
        assert(N::matches(&a,nullptr,&out)==EINVAL && out==initial);
        assert(N::matches(&a,&b,nullptr)==EINVAL);
        a.fils=N::FILS::Unknown;
        assert(N::matches(&a,&b,&out)==EOPNOTSUPP && out==initial);
        a.fils=static_cast<N::FILS>(255);
        assert(N::matches(&a,&b,&out)==EINVAL && out==initial);
        a=beforeA;
        for(unsigned len:{33U,255U}) {
            a.ssidLength=len;
            assert(N::matches(&a,&b,&out)==EINVAL && out==initial);
            a=beforeA;b.ssidLength=len;
            assert(N::matches(&a,&b,&out)==EINVAL && out==initial);
            b=beforeB;
        }
        for(unsigned mode:{4U,0xffffU}) {
            a.apMode=mode;
            assert(N::matches(&a,&b,&out)==EINVAL && out==initial);
            a=beforeA;b.apMode=mode;
            assert(N::matches(&a,&b,&out)==EINVAL && out==initial);
            b=beforeB;
        }
    }
    assert(!memcmp(&a,&beforeA,sizeof(a)) && !memcmp(&b,&beforeB,sizeof(b)));
}
'''


class NetworkMatchTests(unittest.TestCase):
    def test_owned_identity_bounds_and_directional_matching(self):
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
