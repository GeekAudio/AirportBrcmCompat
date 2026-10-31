"""Sequoia 15 SET20 normalization is bounded and preserves strict validation."""
import pathlib
import subprocess
import tempfile
import unittest

PROJECT=pathlib.Path(__file__).resolve().parents[1]
HARNESS=r'''
#include "association_profiles.hpp"
#include "association_compat.hpp"
#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
using namespace AssociationProfiles;

static void put16(uint8_t *p,uint16_t x){p[0]=uint8_t(x);p[1]=uint8_t(x>>8);}
static void put32(uint8_t *p,uint32_t x){for(unsigned j=0;j<4;j++)p[j]=uint8_t(x>>(j*8));}
static void validSequoiaRequest(uint8_t *p){
 memset(p,0,Sequoia15Size);put32(p,1);put16(p+4,2);put16(p+6,0);
 put32(p+8,1);put32(p+16,3);memcpy(p+20,"abc",3);
}
static void validSonomaRequest(uint8_t *p){
 memset(p,0,Sonoma14Size);put32(p,1);put16(p+4,2);put16(p+6,0);
 put16(p+8,0);put32(p+12,3);memcpy(p+16,"abc",3);
}

static void normalization(){
 uint8_t source[Sequoia15Size],snapshot[Sequoia15Size];
 uint8_t normalized[SharedNativeSize],before[SharedNativeSize];
 for(size_t j=0;j<898;j++)source[j]=uint8_t(j*73U+19U);
 source[898]=0x5a;source[899]=0;memcpy(snapshot,source,sizeof(source));
 memset(normalized,0xa7,sizeof(normalized));
 auto result=normalizeSequoia15(source,sizeof(source),normalized,sizeof(normalized));
 assert(!result.error&&!result.field);
 assert(!memcmp(source,snapshot,sizeof(source)));
 assert(!memcmp(normalized,source,899));
 assert(normalized[899]==2); // Internal unspecified policy for absent Sequoia field.
 for(size_t j=900;j<sizeof(normalized);j++)assert(normalized[j]==0);

 // The only synthesized byte must not hide a changed input schema or caller data.
 memcpy(before,normalized,sizeof(before));source[899]=1;
 result=normalizeSequoia15(source,sizeof(source),normalized,sizeof(normalized));
 assert(result.error==EOPNOTSUPP&&result.field==899);
 assert(!memcmp(normalized,before,sizeof(normalized)));
}

static void converterContract(){
 uint8_t source[Sequoia15Size],normalized[SharedNativeSize],old[548];
 validSequoiaRequest(source);
 auto profile=normalizeSequoia15(source,sizeof(source),normalized,sizeof(normalized));
 assert(!profile.error);
 auto converted=AssociationCompat::convert(normalized,sizeof(normalized),old,sizeof(old));
 assert(!converted.error);
 assert(old[0]==1&&old[4]==2&&old[6]==1&&old[8]==0&&old[12]==3&&
        !memcmp(old+16,"abc",3));

 // Valid old tail extensions survive normalization; the common validator
 // remains responsible for refusing unsupported nonzero bytes.
 source[700]=0x81;
 assert(!normalizeSequoia15(source,sizeof(source),normalized,sizeof(normalized)).error);
 converted=AssociationCompat::convert(normalized,sizeof(normalized),old,sizeof(old));
 assert(converted.error==EOPNOTSUPP&&converted.field==700);
 source[700]=0;

 // Appended Tahoe bytes are zeroed by the 900-byte profile but remain guarded
 // by the same strict converter when a 908-byte caller sets one.
 assert(!normalizeSequoia15(source,sizeof(source),normalized,sizeof(normalized)).error);
 normalized[905]=0x44;
 converted=AssociationCompat::convert(normalized,sizeof(normalized),old,sizeof(old));
 assert(converted.error==EOPNOTSUPP&&converted.field==905);
}

static void invalidArguments(){
 uint8_t source[Sequoia15Size]{},storage[Sequoia15Size+SharedNativeSize],before[sizeof(storage)];
 memset(storage,0x69,sizeof(storage));memcpy(before,storage,sizeof(storage));
 auto r=normalizeSequoia15(nullptr,Sequoia15Size,storage,SharedNativeSize);
 assert(r.error==EINVAL&&!memcmp(storage,before,sizeof(storage)));
 r=normalizeSequoia15(source,Sequoia15Size,nullptr,SharedNativeSize);assert(r.error==EINVAL);
 r=normalizeSequoia15(source,Sequoia15Size-1,storage,SharedNativeSize);
 assert(r.error==EINVAL&&!memcmp(storage,before,sizeof(storage)));
 r=normalizeSequoia15(source,Sequoia15Size+1,storage,SharedNativeSize);
 assert(r.error==EINVAL&&!memcmp(storage,before,sizeof(storage)));
 r=normalizeSequoia15(source,Sequoia15Size,storage,SharedNativeSize-1);
 assert(r.error==EINVAL&&!memcmp(storage,before,sizeof(storage)));
 r=normalizeSequoia15(source,Sequoia15Size,storage,SharedNativeSize+1);
 assert(r.error==EINVAL&&!memcmp(storage,before,sizeof(storage)));
 r=normalizeSequoia15(storage,Sequoia15Size,storage+4,SharedNativeSize);
 assert(r.error==EINVAL&&!memcmp(storage,before,sizeof(storage)));
 // Exactly adjacent storage is allowed.
 storage[899]=0;
 r=normalizeSequoia15(storage,Sequoia15Size,storage+Sequoia15Size,SharedNativeSize);
 assert(!r.error&&storage[Sequoia15Size+899]==2);
}

static void guardPages(){
 const size_t page=size_t(sysconf(_SC_PAGESIZE));assert(page>SharedNativeSize);
 auto *srcMap=static_cast<uint8_t*>(mmap(nullptr,page*3,PROT_NONE,MAP_ANON|MAP_PRIVATE,-1,0));
 auto *outMap=static_cast<uint8_t*>(mmap(nullptr,page*3,PROT_NONE,MAP_ANON|MAP_PRIVATE,-1,0));
 assert(srcMap!=MAP_FAILED&&outMap!=MAP_FAILED);
 assert(!mprotect(srcMap+page,page,PROT_READ|PROT_WRITE));
 assert(!mprotect(outMap+page,page,PROT_READ|PROT_WRITE));
 uint8_t *source=srcMap+page*2-Sequoia15Size;
 uint8_t *out=outMap+page*2-SharedNativeSize;
 validSequoiaRequest(source);memset(out,0xc3,SharedNativeSize);
 assert(!mprotect(srcMap+page,page,PROT_READ));
 auto r=normalizeSequoia15(source,Sequoia15Size,out,SharedNativeSize);
 assert(!r.error&&out[899]==2&&out[900]==0&&out[907]==0);
 assert(!mprotect(outMap+page,page,PROT_READ));
 uint8_t snapshot[SharedNativeSize];memcpy(snapshot,out,sizeof(snapshot));
 r=normalizeSequoia15(source,Sequoia15Size,out,SharedNativeSize-1);
 assert(r.error==EINVAL&&!memcmp(snapshot,out,sizeof(snapshot)));
 assert(!munmap(srcMap,page*3)&&!munmap(outMap,page*3));
}

static void sonoma14OpenAndWpa2(){
 uint8_t source[Sonoma14Size],snapshot[Sonoma14Size];
 uint8_t legacy[LegacyAssociationSize],before[LegacyAssociationSize];
 validSonomaRequest(source);put16(source+6,0); // Preserve the native lower-auth value.
 source[464]=0x08; // Uninterpreted old-prefix bit: pass it byte-for-byte.
 memcpy(snapshot,source,sizeof(source));memset(legacy,0xa6,sizeof(legacy));
 auto result=convertSonoma14(source,sizeof(source),legacy,sizeof(legacy));
 assert(!result.error&&!result.field&&!memcmp(source,snapshot,sizeof(source)));
 assert(!memcmp(legacy,source,LegacyPrefixSize));
 for(size_t j=LegacyPrefixSize;j<sizeof(legacy);j++)assert(legacy[j]==0);
 assert(legacy[6]==0&&legacy[464]==0x08); // No synthetic auth or flag rewrite.

 // WPA2 with a zero native lower-auth value remains unchanged, including all
 // key, RSN, PMK and allow-auth bytes supported by the old same-offset layout.
 validSonomaRequest(source);put16(source+8,8);put16(source+6,0);
 put32(source+56,1);put32(source+60,32);put32(source+64,6);
 memset(source+72,0x93,32);put32(source+468,32);memset(source+472,0x37,32);
 put32(source+504,0x40000004U);memcpy(snapshot,source,sizeof(source));
 memset(legacy,0xa6,sizeof(legacy));
 result=convertSonoma14(source,sizeof(source),legacy,sizeof(legacy));
 assert(!result.error&&!memcmp(source,snapshot,sizeof(source)));
 assert(!memcmp(legacy,source,LegacyPrefixSize));
 for(size_t j=LegacyPrefixSize;j<sizeof(legacy);j++)assert(legacy[j]==0);

 // Scope is not representable by the 548-byte consumer.
 validSonomaRequest(source);source[464]=0x40;
 memset(legacy,0xa6,sizeof(legacy));memcpy(before,legacy,sizeof(legacy));
 result=convertSonoma14(source,sizeof(source),legacy,sizeof(legacy));
 assert(result.error==EOPNOTSUPP&&result.field==464&&!memcmp(legacy,before,sizeof(legacy)));
 // Any later native field, including the scope body and semantic hints, is
 // rejected before output writes. This checks every byte through the producer size.
 for(size_t offset=LegacyPrefixSize;offset<Sonoma14Size;offset++){
  validSonomaRequest(source);source[offset]=1;memset(legacy,0xa6,sizeof(legacy));
  memcpy(before,legacy,sizeof(legacy));
  result=convertSonoma14(source,sizeof(source),legacy,sizeof(legacy));
  assert(result.error==EOPNOTSUPP&&result.field==offset);
  assert(!memcmp(legacy,before,sizeof(legacy)));
 }
}

static void sonoma14RejectsUnsupportedInputs(){
 struct Bad {size_t offset;uint32_t value;bool wide;uint32_t field;};
 const Bad bad[]={
  {4,1,false,4},{6,2,false,6},{8,16,false,8},{12,33,true,12},
  {56,2,true,56},{60,65,true,60},{136,9,true,136},{156,17,true,156},
  {176,17,true,176},{204,258,false,204},{468,33,true,468}
 };
 uint8_t source[Sonoma14Size],legacy[LegacyAssociationSize],before[LegacyAssociationSize];
 for(const auto &entry:bad){
  validSonomaRequest(source);if(entry.wide)put32(source+entry.offset,entry.value);
  else put16(source+entry.offset,static_cast<uint16_t>(entry.value));
  memset(legacy,0x5c,sizeof(legacy));memcpy(before,legacy,sizeof(legacy));
  auto result=convertSonoma14(source,sizeof(source),legacy,sizeof(legacy));
  assert(result.error&&result.field==entry.field&&!memcmp(legacy,before,sizeof(legacy)));
 }
 validSonomaRequest(source);put16(source+8,8);put32(source+60,32);
 put32(source+64,5);put32(source+468,32); // Unknown WPA2 carrier.
 memset(legacy,0x5c,sizeof(legacy));memcpy(before,legacy,sizeof(legacy));
 auto result=convertSonoma14(source,sizeof(source),legacy,sizeof(legacy));
 assert(result.error==EOPNOTSUPP&&result.field==64&&!memcmp(legacy,before,sizeof(legacy)));
 validSonomaRequest(source);put16(source+8,8);put32(source+60,32);put32(source+64,6);
 put32(source+504,8); // Auth mask is preserved only for explicit known masks.
 result=convertSonoma14(source,sizeof(source),legacy,sizeof(legacy));
 assert(result.error==EOPNOTSUPP&&result.field==504);

 validSonomaRequest(source);memset(legacy,0x5c,sizeof(legacy));memcpy(before,legacy,sizeof(legacy));
 result=convertSonoma14(source,sizeof(source)-1,legacy,sizeof(legacy));
 assert(result.error==EINVAL&&!memcmp(legacy,before,sizeof(legacy)));
 result=convertSonoma14(source,sizeof(source),legacy,sizeof(legacy)-1);
 assert(result.error==EINVAL&&!memcmp(legacy,before,sizeof(legacy)));
 result=convertSonoma14(nullptr,Sonoma14Size,legacy,sizeof(legacy));assert(result.error==EINVAL);
 result=convertSonoma14(source,Sonoma14Size,nullptr,sizeof(legacy));assert(result.error==EINVAL);
 result=convertSonoma14(source,sizeof(source),source,sizeof(legacy));assert(result.error==EINVAL);
}

static void sonoma14GuardPages(){
 const size_t page=size_t(sysconf(_SC_PAGESIZE));assert(page>Sonoma14Size&&page>LegacyAssociationSize);
 auto *srcMap=static_cast<uint8_t*>(mmap(nullptr,page*3,PROT_NONE,MAP_ANON|MAP_PRIVATE,-1,0));
 auto *outMap=static_cast<uint8_t*>(mmap(nullptr,page*3,PROT_NONE,MAP_ANON|MAP_PRIVATE,-1,0));
 assert(srcMap!=MAP_FAILED&&outMap!=MAP_FAILED);
 assert(!mprotect(srcMap+page,page,PROT_READ|PROT_WRITE));
 assert(!mprotect(outMap+page,page,PROT_READ|PROT_WRITE));
 uint8_t *source=srcMap+page*2-Sonoma14Size;
 uint8_t *legacy=outMap+page*2-LegacyAssociationSize;
 validSonomaRequest(source);assert(!mprotect(srcMap+page,page,PROT_READ));
 auto result=convertSonoma14(source,Sonoma14Size,legacy,LegacyAssociationSize);
 assert(!result.error&&legacy[0]==1&&legacy[507]==0&&legacy[547]==0);
 assert(!mprotect(outMap+page,page,PROT_READ));
 assert(!munmap(srcMap,page*3)&&!munmap(outMap,page*3));
}

int main(){normalization();converterContract();invalidArguments();guardPages();
 sonoma14OpenAndWpa2();sonoma14RejectsUnsupportedInputs();sonoma14GuardPages();}
'''


class AssociationProfileTests(unittest.TestCase):
    def test_sequoia15_normalization_and_tahoe_validation_under_asan_ubsan(self):
        with tempfile.TemporaryDirectory(prefix="association-profile-test-",dir="/private/tmp") as tmp:
            source=pathlib.Path(tmp)/"test.cpp"
            binary=pathlib.Path(tmp)/"test"
            source.write_text(HARNESS)
            subprocess.run(["xcrun","clang++","-std=c++14","-Wall","-Wextra","-Werror",
                            "-fsanitize=address,undefined","-fno-omit-frame-pointer","-g",
                            "-I",str(PROJECT/"src/scan_kernel"),str(source),"-o",str(binary)],check=True)
            subprocess.run([str(binary)],check=True)


if __name__=="__main__":
    unittest.main()
