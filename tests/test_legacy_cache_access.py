"""Exercise selective pruning against the actual pinned provider byte layout."""
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/cache_access.hpp"
#include <cassert>
#include <vector>
namespace C=LegacyWiFi::CacheAccess;
namespace S=LegacyWiFi::SelectiveCache;
namespace N=LegacyWiFi::NetworkMatch;
namespace D=LegacyWiFi::NetworkIdentity;

static void put16(uint8_t *p,uint16_t v){memcpy(p,&v,2);}
static void put32(uint8_t *p,uint32_t v){memcpy(p,&v,4);}
static void put64(uint8_t *p,uintptr_t v){memcpy(p,&v,8);}
static uintptr_t get64(const uint8_t *p){uintptr_t v;memcpy(&v,p,8);return v;}

enum class Role {Other,Node,IE};
struct Region {uint8_t *bytes;size_t size;bool alive=true;Role role=Role::Other;uintptr_t owner=0;};
struct Arena {
    std::vector<Region> regions;
    size_t reads=0,writes=0,destroys=0;
    uintptr_t deny=0;
    uintptr_t partial=0;
    ~Arena(){for(auto &r:regions)if(r.alive)delete[]r.bytes;}
    uint8_t *add(size_t size,Role role=Role::Other,uintptr_t owner=0){auto p=new uint8_t[size]{};regions.push_back({p,size,true,role,owner});return p;}
    Region *locate(uintptr_t address,size_t n){
        for(auto &r:regions) {
            const uintptr_t base=reinterpret_cast<uintptr_t>(r.bytes);
            if(r.alive&&address>=base&&address-base<=r.size&&n<=r.size-(address-base))return &r;
        }
        return nullptr;
    }
    bool alive(uint8_t *p){for(auto &r:regions)if(r.bytes==p)return r.alive;assert(false);return false;}
    void freeRegion(uint8_t *p){for(auto &r:regions)if(r.bytes==p){assert(r.alive);r.alive=false;delete[]p;return;}assert(false);}
    static bool read(void *opaque,uintptr_t address,void *out,size_t n){
        auto &a=*static_cast<Arena *>(opaque);++a.reads;
        if(address==a.deny||!a.locate(address,n))return false;
        if(address==a.partial){memcpy(out,reinterpret_cast<void *>(address),n/2);return false;}
        memcpy(out,reinterpret_cast<void *>(address),n);return true;
    }
    static void write(void *opaque,uintptr_t address,const void *in,size_t n){
        auto &a=*static_cast<Arena *>(opaque);assert(a.locate(address,n));++a.writes;
        memcpy(reinterpret_cast<void *>(address),in,n);
    }
    static void destroy(void *opaque,uintptr_t address){
        auto &a=*static_cast<Arena *>(opaque);auto p=reinterpret_cast<uint8_t *>(address);
        assert(a.locate(address,0xc0));
        assert(!get64(p)&&!get64(p+8)&&LegacyWiFi::ScanBridge::read32(p+0x10)==0);
        if(LegacyWiFi::ScanBridge::read16(p+0xa2))a.freeRegion(reinterpret_cast<uint8_t *>(get64(p+0xa8)));
        a.freeRegion(p);++a.destroys;
    }
    static bool owns(void *opaque,uintptr_t address,size_t size,uintptr_t ie,size_t n){
        auto &a=*static_cast<Arena *>(opaque);auto node=a.locate(address,size);
        if(!node||reinterpret_cast<uintptr_t>(node->bytes)!=address||node->size!=size||node->role!=Role::Node)return false;
        if(!ie&&!n){
            for(const auto &r:a.regions)if(r.alive&&r.role==Role::IE&&r.owner==address)return false;
            return true;
        }
        auto data=a.locate(ie,n);
        return data&&reinterpret_cast<uintptr_t>(data->bytes)==ie&&data->size==n&&
            data->role==Role::IE&&data->owner==address;
    }
    C::Context context(uint8_t *manager,D::Source source=D::Source::Pinned4331){
        C::Context c;c.manager=reinterpret_cast<uintptr_t>(manager);c.source=source;
        c.memory={this,read,write,destroy,owns};assert(c.valid());return c;
    }
};

static uint8_t *node(Arena &a,char ssid,uint32_t refs=1,bool rsn=false){
    auto p=a.add(0xc0,Role::Node);put32(p+0x10,refs);put32(p+0x18,1);
    put16(p+0x18+0x1a,1);p[0x18+0x60]=1;p[0x18+0x61]=ssid;
    // These bookkeeping bytes must survive every link/refcount rewrite.
    memset(p+0xb0,0xa5,0x10);
    if(rsn){auto ie=a.add(3,Role::IE,reinterpret_cast<uintptr_t>(p));ie[0]=48;ie[1]=1;ie[2]=0;
        put16(p+0xa2,3);put64(p+0xa8,reinterpret_cast<uintptr_t>(ie));}
    return p;
}
static void link(uint8_t *manager,const std::vector<uint8_t *> &nodes){
    auto slot=manager+0x18;
    for(auto p:nodes){put64(slot,reinterpret_cast<uintptr_t>(p));put64(p+8,reinterpret_cast<uintptr_t>(slot));slot=p;}
    put64(slot,0);
}
static N::Identity key(char ssid,uint16_t modes=1){
    N::Identity n;n.ssidLength=1;n.ssid[0]=ssid;n.encryptionModes=modes;n.apMode=2;n.fils=N::FILS::Unknown;return n;
}

static void actual_layout_and_deferred_ownership(){
    for(auto source:{D::Source::Pinned4331,D::Source::Pinned43224}) {
        Arena a;auto manager=a.add(0xb0);auto p=node(a,'a',2);auto q=node(a,'a',1,true);auto r=node(a,'b');
        // The same network can have multiple security bits/BSSIDs; the key
        // permits both open and RSN and the predicate removes both matches.
        p[0x34]=0x11;q[0x34]=0x22;
        link(manager,{p,q,r});auto c=a.context(manager,source);
        uint8_t saved[0xc0];memcpy(saved,r,sizeof(saved));
        S::Entry scratch[3];S::Plan plan;const auto wanted=key('a',9);
        assert(S::preflight(c.headSlot(),&wanted,scratch,3,3,c.accessors(),&plan)==S::Status::Ok);
        S::Result result;assert(S::commit(&plan,&result)==S::Status::Ok);
        assert(result.matchedNodes==2&&result.retainedForRequests==1&&result.destroyedNodes==1);
        assert(get64(manager+0x18)==reinterpret_cast<uintptr_t>(r));
        assert(get64(r+8)==reinterpret_cast<uintptr_t>(manager+0x18));
        assert(!get64(p)&&!get64(p+8)&&LegacyWiFi::ScanBridge::read32(p+0x10)==1);
        assert(a.alive(p)&&!a.alive(q)&&a.alive(r));
        assert(!memcmp(r+0x10,saved+0x10,0xb0));
        for(size_t i=0xb0;i<0xc0;++i)assert(p[i]==0xa5);
        // Model the later request-wrapper cleanup using its retained pointer.
        put32(p+0x10,0);Arena::destroy(&a,reinterpret_cast<uintptr_t>(p));
        assert(!a.alive(p)&&a.destroys==2);
    }
}

static void failures_are_read_only(){
    for(unsigned fault=0;fault<18;++fault){
        Arena a;auto manager=a.add(0xb0);auto p=node(a,'a');auto tail=node(a,'a',1,true);
        link(manager,{p,tail});auto c=a.context(manager);
        switch(fault){
            case 0:put32(tail+0x18,2);break;
            case 1:tail[0x78]=33;break;
            case 2:tail[0xa0]=4;break;
            case 3:put16(tail+0xa2,1025);break;
            case 4:put64(tail+0xa8,0);break;
            case 5:put64(tail+0xa8,UINTPTR_MAX-1);break;
            case 6:a.deny=get64(tail+0xa8);break;
            case 7:put16(tail+0xa2,1);break; // incomplete IE header
            case 8:put64(tail+8,reinterpret_cast<uintptr_t>(manager+0x18));break;
            case 9:put32(tail+0x10,0);break;
            case 10:put64(p,reinterpret_cast<uintptr_t>(tail)+1);break;
            case 11:put16(tail+0xa2,0);break;
            case 12:put64(tail+0xa8,reinterpret_cast<uintptr_t>(tail+0x30));break;
            case 13:put64(tail+0xa8,reinterpret_cast<uintptr_t>(manager+0x30));break;
            case 14:{auto foreign=a.add(3);foreign[0]=48;foreign[1]=1;
                put64(tail+0xa8,reinterpret_cast<uintptr_t>(foreign));break;}
            case 15:a.partial=reinterpret_cast<uintptr_t>(tail);break;
            case 16:a.partial=get64(tail+0xa8);break;
            case 17:put16(tail+0xa2,0);put64(tail+0xa8,0);break; // lost owned allocation
        }
        S::Entry scratch[2];S::Plan plan;const auto wanted=key('a',9);
        assert(S::preflight(c.headSlot(),&wanted,scratch,2,2,c.accessors(),&plan)!=S::Status::Ok);
        assert(a.writes==0&&a.destroys==0&&a.alive(p)&&a.alive(tail));
        assert(get64(manager+0x18)==reinterpret_cast<uintptr_t>(p));
    }
}

static void detached_snapshot_and_context_boundaries(){
    Arena a;auto manager=a.add(0xb0);auto p=node(a,'a',1,true);link(manager,{p});auto c=a.context(manager);
    S::Snapshot snapshot;
    assert(C::Context::inspect(&c,p,&snapshot)==S::Status::Ok);
    assert(snapshot.identity.encryptionModes==8&&snapshot.identity.ssid[0]=='a');
    auto ie=reinterpret_cast<uint8_t *>(get64(p+0xa8));ie[0]=1;p[0x79]='b';
    assert(snapshot.identity.encryptionModes==8&&snapshot.identity.ssid[0]=='a');
    const auto before=snapshot;a.deny=reinterpret_cast<uintptr_t>(p);
    assert(C::Context::inspect(&c,p,&snapshot)==S::Status::AccessFailure);
    assert(!memcmp(&before,&snapshot,sizeof(snapshot)));a.deny=0;
    a.partial=reinterpret_cast<uintptr_t>(p);
    assert(C::Context::inspect(&c,p,&snapshot)==S::Status::AccessFailure);
    assert(!memcmp(&before,&snapshot,sizeof(snapshot)));a.partial=0;
    S::Node next=reinterpret_cast<void *>(0x1234);a.partial=reinterpret_cast<uintptr_t>(p);
    assert(C::Context::readLink(&c,p,&next)==S::Status::AccessFailure);
    assert(next==reinterpret_cast<void *>(0x1234));a.partial=0;
    c.source=D::Source::Unknown;assert(!c.valid()&&!c.headSlot()&&!c.accessors().inspect);
    c.source=D::Source::Pinned4331;c.manager=UINTPTR_MAX-7;assert(!c.valid());
    c.manager=reinterpret_cast<uintptr_t>(manager)+1;assert(!c.valid());
    c.manager=reinterpret_cast<uintptr_t>(manager);c.memory.write=nullptr;assert(!c.valid());
    assert(!C::range(0,1)&&!C::range(UINTPTR_MAX,2)&&!C::nodeAddress(UINTPTR_MAX-8));
}
static void empty_ie_preserves_ignored_pointer(){
    for(auto source:{D::Source::Pinned4331,D::Source::Pinned43224}) {
        for(uintptr_t ignored:{uintptr_t(1),UINTPTR_MAX}) {
            Arena a;auto manager=a.add(0xb0);auto p=node(a,'a');
            put64(p+0xa8,ignored);a.deny=ignored;link(manager,{p});auto c=a.context(manager,source);
            S::Snapshot snapshot;assert(C::Context::inspect(&c,p,&snapshot)==S::Status::Ok);
            assert(get64(p+0xa8)==ignored); // Never normalize provider storage.
            S::Entry scratch[1];S::Plan plan;const auto wanted=key('a');
            assert(S::preflight(c.headSlot(),&wanted,scratch,1,1,c.accessors(),&plan)==S::Status::Ok);
            S::Result result;
            assert(S::commit(&plan,&result)==S::Status::Ok);
            assert(a.destroys==1&&!a.alive(p)&&get64(manager+0x18)==0);
        }
    }
}
int main(){actual_layout_and_deferred_ownership();failures_are_read_only();detached_snapshot_and_context_boundaries();empty_ie_preserves_ignored_pointer();}
'''


class LegacyCacheAccessTests(unittest.TestCase):
    def test_raw_provider_layout_snapshot_and_selective_prune(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, binary = Path(tmp) / "test.cpp", Path(tmp) / "test"
            source.write_text(HARNESS)
            subprocess.run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                            "-I", str(PROJECT / "src"), str(source), "-o", str(binary)],
                           check=True, capture_output=True, timeout=30)
            subprocess.run([str(binary)], check=True, capture_output=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
