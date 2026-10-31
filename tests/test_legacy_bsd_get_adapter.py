"""Bounded byte-layout tests for the legacy BSD GET13/GET48 adapters."""
import pathlib
import subprocess
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/bsd_get_adapter.hpp"
#include <assert.h>
#include <stdint.h>
#include <string.h>

namespace G=LegacyWiFi::BSDGetAdapter;

static uint32_t read32(const uint8_t *p){uint32_t v;memcpy(&v,p,4);return v;}
static uint16_t read16(const uint8_t *p){uint16_t v;memcpy(&v,p,2);return v;}

static void envelopeSelection(){
 assert(G::stateUsesPointerEnvelope(8,0x1000));
 assert(!G::stateUsesPointerEnvelope(0,0x1000));
 assert(!G::stateUsesPointerEnvelope(8,0));
 assert(G::ieListUsesHeaderEnvelope(0x408,0x2000));
 assert(G::ieListUsesHeaderEnvelope(G::GetAPIEListNativeExtended,0x2000));
 assert(!G::ieListUsesHeaderEnvelope(0x400,0x2000));
 assert(!G::ieListUsesHeaderEnvelope(0x1000,0x2000));
 assert(!G::ieListUsesHeaderEnvelope(0x408,0));
}

static void userAddressBounds(){
 uint64_t address=0;
 assert(G::addUserAddress(0x1000,4,4,address)&&address==0x1004);
 assert(G::addUserAddress(UINT64_MAX-7,4,4,address)&&address==UINT64_MAX-3);
 assert(!G::addUserAddress(UINT64_MAX-6,4,4,address));
 assert(!G::addUserAddress(0,4,4,address));
 assert(!G::addUserAddress(0x1000,0,0,address));
}

static void stateScalar(){
 uint8_t bytes[G::GetStateValueSize]{};
 const int32_t value=static_cast<int32_t>(0x12345678);
 assert(!G::encodeState(value,bytes));
 int32_t copied=0;memcpy(&copied,bytes,sizeof(copied));assert(copied==value);
 assert(G::encodeState(value,nullptr)==EINVAL);
}

static void ieListEncoding(){
 const uint8_t raw[]={0x30,0x02,0xaa,0x00};
 uint8_t output[G::GetAPIEListNativeMaximum];memset(output,0xa5,sizeof(output));
 size_t encoded=99;
 assert(!G::encodeIEList(raw,sizeof(raw),output,sizeof(output),&encoded));
 assert(encoded==G::GetAPIEListHeaderSize+sizeof(raw));
 assert(read32(output)==1&&read16(output+4)==sizeof(raw));
 assert(output[6]==0&&output[7]==0&&!memcmp(output+8,raw,sizeof(raw)));

 uint8_t maximum[G::GetAPIEListLegacyCapacity];
 for(size_t i=0;i<sizeof(maximum);i++)maximum[i]=static_cast<uint8_t>(i*13U);
 maximum[sizeof(maximum)-1]=0;maximum[sizeof(maximum)-2]=0;
 memset(output,0xa5,sizeof(output));
 assert(!G::encodeIEList(maximum,sizeof(maximum),output,sizeof(output),&encoded));
 assert(encoded==G::GetAPIEListNativeMaximum&&read16(output+4)==0x400);
 assert(!memcmp(output+8,maximum,sizeof(maximum)));

 memset(output,0xa5,sizeof(output));encoded=99;
 assert(!G::encodeIEList(nullptr,0,output,sizeof(output),&encoded));
 assert(encoded==8&&read32(output)==1&&read16(output+4)==0&&output[6]==0&&output[7]==0);

 uint8_t before[sizeof(output)];memset(output,0x6d,sizeof(output));
 memcpy(before,output,sizeof(before));encoded=99;
 assert(G::encodeIEList(maximum,sizeof(maximum)+1,output,sizeof(output),&encoded)==EOVERFLOW);
 assert(!memcmp(output,before,sizeof(before))&&encoded==99);
 assert(G::encodeIEList(raw,sizeof(raw),output,7,&encoded)==ENOBUFS);
 assert(!memcmp(output,before,sizeof(before))&&encoded==99);
 assert(G::encodeIEList(nullptr,1,output,sizeof(output),&encoded)==EINVAL);
 assert(G::encodeIEList(raw,sizeof(raw),nullptr,sizeof(output),&encoded)==EINVAL);
}

int main(){envelopeSelection();userAddressBounds();stateScalar();ieListEncoding();}
'''


class LegacyBSDGetAdapterTests(unittest.TestCase):
    def test_layout_selection_and_bounded_encoding(self):
        with tempfile.TemporaryDirectory(prefix="legacy-bsd-get-", dir="/private/tmp") as tmp:
            source = pathlib.Path(tmp) / "get.cpp"
            binary = pathlib.Path(tmp) / "get"
            source.write_text(HARNESS)
            subprocess.run(["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                            "-I", str(PROJECT / "src"), str(source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
