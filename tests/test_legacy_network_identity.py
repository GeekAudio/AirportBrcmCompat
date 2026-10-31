"""Owned legacy scan-snapshot decoding for selective cache matching."""
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/network_identity.hpp"
#include <cassert>
#include <cstring>
#include <initializer_list>
namespace D=LegacyWiFi::NetworkIdentity;
namespace N=LegacyWiFi::NetworkMatch;
constexpr size_t Size=LegacyWiFi::ScanBridge::FixedLegacyResultSize;
static void put16(uint8_t *p,uint16_t n){memcpy(p,&n,2);}
static void init(uint8_t *p,uint16_t cap=1){
    memset(p,0,Size);p[0]=1;put16(p+0x1a,cap);p[0x60]=3;
    p[0x61]='a';p[0x62]=0;p[0x63]='z';
}
static size_t append(uint8_t *p,size_t cursor,uint8_t type,const uint8_t *body,size_t n){
    assert(n<=255 && cursor+n+2<=1024);
    p[0x8c+cursor]=type;p[0x8c+cursor+1]=n;
    if(n)memcpy(p + 0x8e + cursor,body,n);
    put16(p+0x8a,cursor+n+2);return cursor+n+2;
}
static N::Identity decode(const uint8_t *p,D::Source source=D::Source::Pinned4331){
    N::Identity result{};assert(D::decode(source,p,Size,&result)==0);return result;
}
static void rejected(const uint8_t *p,size_t size,int error,
                     D::Source source=D::Source::Pinned4331){
    N::Identity result{};result.ssid[0]=0xa5;result.ssidLength=1;
    result.encryptionModes=0xa55a;result.apMode=3;result.fils=N::FILS::Present;
    const N::Identity before=result;
    assert(D::decode(source,p,size,&result)==error);
    assert(!memcmp(&before,&result,sizeof(result)));
}
int main(){
    uint8_t p[Size],before[Size];uint8_t body[255]{};
    const uint8_t oui[]={0,0x50,0xf2,1};
    const uint16_t modes[]={0,2,1,3};
    for(auto source:{D::Source::Pinned4331,D::Source::Pinned43224})
    for(uint16_t cap:{0U,1U,2U,3U,0x10U,0x11U,0x12U,0x13U,0xffffU}){
        init(p,cap);memcpy(before,p,Size);auto x=decode(p,source);
        assert(x.encryptionModes==((cap&0x10)?2:1));
        assert(x.apMode==modes[cap&3] && x.fils==N::FILS::Absent);
        assert(x.ssidLength==3 && x.ssid[0]=='a' && x.ssid[1]==0 && x.ssid[2]=='z');
        assert(!memcmp(p,before,Size));
    }
    for(unsigned n=0;n<=255;++n){
        init(p,0x11);append(p,0,48,body,n);
        assert(decode(p).encryptionModes==(n?8:2));
        init(p,1);append(p,0,0x44,body,n);
        assert(decode(p).encryptionModes==(n?16:1));
        init(p,1);memcpy(body,oui,4);append(p,0,221,body,n);
        assert(decode(p).encryptionModes==(n>=4?4:1));
    }
    for(unsigned i=0;i<4;++i){
        init(p,1);memcpy(body,oui,4);body[i]^=1;append(p,0,221,body,4);
        assert(decode(p).encryptionModes==1);
    }
    init(p,0x11);size_t c=0;
    c=append(p,c,48,body,1);c=append(p,c,48,nullptr,0);
    c=append(p,c,221,oui,4);c=append(p,c,0x44,body,1);
    c=append(p,c,221,oui,4);assert(c>0 && decode(p).encryptionModes==0x1c);
    // Empty IEs and unrelated tags cannot change the security classification.
    init(p);for(unsigned i=0;i<512;++i)append(p,2*i,1,nullptr,0);
    assert(decode(p).encryptionModes==1);
    init(p);p[0x60]=32;memset(p+0x61,0x9a,32);
    assert(decode(p).ssidLength==32);
    p[0x60]=0;assert(decode(p).ssidLength==0);
    p[0x60]=33;rejected(p,Size,EINVAL);
    init(p);p[0]=2;rejected(p,Size,EINVAL);
    init(p);for(unsigned bit=0;bit<8;++bit){p[0x88]=1U<<bit;rejected(p,Size,EOPNOTSUPP);}
    init(p);put16(p+0x8a,1025);rejected(p,Size,EOVERFLOW);
    init(p);put16(p+0x8a,1);rejected(p,Size,EINVAL);
    init(p);append(p,0,48,body,14);
    for(unsigned len=1;len<16;++len){put16(p+0x8a,len);rejected(p,Size,EINVAL);}
    // A valid prefix cannot hide an incomplete trailing IE header or body.
    init(p);c=append(p,0,48,body,1);p[0x8c+c]=221;
    put16(p+0x8a,c+1);rejected(p,Size,EINVAL);
    p[0x8c+c+1]=4;put16(p+0x8a,c+5);rejected(p,Size,EINVAL);
    init(p);rejected(p,Size,EOPNOTSUPP,D::Source::Unknown);
    rejected(p,Size,EOPNOTSUPP,static_cast<D::Source>(255));
    rejected(nullptr,Size,EINVAL);rejected(p,Size-1,EINVAL);rejected(p,Size+1,EINVAL);
    assert(D::decode(D::Source::Pinned4331,p,Size,nullptr)==EINVAL);
    // Decoded identities feed the exact predicate, including binary SSIDs.
    auto a=decode(p);p[0x63]='q';auto b=decode(p);bool same=true;
    assert(N::matches(&a,&b,&same)==0&&!same);
}
'''


class NetworkIdentityTests(unittest.TestCase):
    def test_fixed_child_identity_and_ie_boundaries(self):
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
