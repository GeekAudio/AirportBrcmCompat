"""Bounded byte-layout tests for legacy BSD SET adapters."""
import pathlib
import subprocess
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/bsd_set_adapter.hpp"
#include <assert.h>
#include <stdint.h>
#include <string.h>

namespace S=LegacyWiFi::BSDSetAdapter;

static void put32(uint8_t *p, uint32_t value) { memcpy(p, &value, sizeof(value)); }
static uint32_t read32(const uint8_t *p) {
    uint32_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}

static void init(uint8_t *input, uint32_t lower, uint32_t upper,
                 uint32_t upperExtension=0) {
    put32(input, 1);
    put32(input+4, lower);
    put32(input+8, upper);
    put32(input+12, upperExtension);
}

static void rejectedWithoutWrites(const uint8_t *input, size_t inputLength,
                                  uint8_t *output, size_t outputCapacity,
                                  int expected) {
    uint8_t before[32];
    assert(outputCapacity <= sizeof(before));
    memset(output, 0xa5, outputCapacity);
    memcpy(before, output, outputCapacity);
    assert(S::projectAuthType(input, inputLength, output, outputCapacity)==expected);
    assert(!memcmp(before, output, outputCapacity));
}

static void constantsAndValidProjection() {
    assert(S::AuthNativeSize==16);
    assert(S::AuthLegacySize==12);
    uint8_t input[S::AuthNativeSize];
    uint8_t output[S::AuthLegacySize+4];
    const uint32_t patterns[]={0U,1U,0x7fffffffU,0x80000000U,0xffffffffU,
                               0x89abcdefU,0x76543210U};
    for (uint32_t lower : patterns) for (uint32_t upper : patterns) {
        init(input,lower,upper);
        uint8_t inputBefore[sizeof(input)];
        memcpy(inputBefore,input,sizeof(input));
        memset(output,0xa5,sizeof(output));
        assert(S::projectAuthType(input,sizeof(input),output,sizeof(output))==0);
        assert(!memcmp(input,inputBefore,sizeof(input)));
        assert(!memcmp(output,input,S::AuthLegacySize));
        for (size_t i=S::AuthLegacySize;i<sizeof(output);++i) assert(output[i]==0xa5);
        assert(read32(output)==1 && read32(output+4)==lower && read32(output+8)==upper);
    }

    // Every lower/upper bit passes unchanged, with no selector interpretation.
    for (unsigned bit=0;bit<32;++bit) {
        const uint32_t value=static_cast<uint32_t>(1U<<bit);
        init(input,value,0);
        assert(S::projectAuthType(input,sizeof(input),output,sizeof(output))==0);
        assert(!memcmp(output,input,S::AuthLegacySize));
        init(input,0,value);
        assert(S::projectAuthType(input,sizeof(input),output,sizeof(output))==0);
        assert(!memcmp(output,input,S::AuthLegacySize));
    }
}

static void rejectsEveryExtensionBit() {
    uint8_t input[S::AuthNativeSize];
    uint8_t output[S::AuthLegacySize];
    for (unsigned bit=0;bit<32;++bit) {
        init(input,0x89abcdefU,0xfedcba98U,static_cast<uint32_t>(1U<<bit));
        rejectedWithoutWrites(input,sizeof(input),output,sizeof(output),EOPNOTSUPP);
    }
    init(input,0x89abcdefU,0xfedcba98U,0xffffffffU);
    rejectedWithoutWrites(input,sizeof(input),output,sizeof(output),EOPNOTSUPP);
}

static void rejectsInvalidVersionAndLengths() {
    uint8_t input[S::AuthNativeSize];
    uint8_t output[S::AuthLegacySize];
    init(input,7,9);
    put32(input,0);
    rejectedWithoutWrites(input,sizeof(input),output,sizeof(output),EINVAL);
    put32(input,2);
    rejectedWithoutWrites(input,sizeof(input),output,sizeof(output),EINVAL);
    init(input,7,9);
    const size_t invalidLengths[]={0,1,11,12,15,17,32};
    for (size_t length : invalidLengths)
        rejectedWithoutWrites(input,length,output,sizeof(output),EINVAL);
}

static void rejectsNullAndShortOutput() {
    uint8_t input[S::AuthNativeSize];
    uint8_t output[S::AuthLegacySize];
    init(input,7,9);
    rejectedWithoutWrites(nullptr,sizeof(input),output,sizeof(output),EINVAL);
    assert(S::projectAuthType(input,sizeof(input),nullptr,sizeof(output))==EINVAL);
    rejectedWithoutWrites(input,sizeof(input),output,sizeof(output)-1,ENOBUFS);
    rejectedWithoutWrites(input,sizeof(input),output,0,ENOBUFS);
}

static void rejectsOverlapAndAllowsAdjacency() {
    uint8_t storage[S::AuthNativeSize+S::AuthLegacySize+8];
    uint8_t before[sizeof(storage)];
    init(storage,0x80000000U,0x80000001U);

    memcpy(before,storage,sizeof(storage));
    assert(S::projectAuthType(storage,sizeof(uint8_t)*S::AuthNativeSize,
                              storage,S::AuthLegacySize)==EINVAL);
    assert(!memcmp(storage,before,sizeof(storage)));

    assert(S::projectAuthType(storage,sizeof(uint8_t)*S::AuthNativeSize,
                              storage+1,S::AuthLegacySize)==EINVAL);
    assert(!memcmp(storage,before,sizeof(storage)));

    // Even a destination beginning at input+12 overlaps the input extension.
    assert(S::projectAuthType(storage,sizeof(uint8_t)*S::AuthNativeSize,
                              storage+12,S::AuthLegacySize)==EINVAL);
    assert(!memcmp(storage,before,sizeof(storage)));

    // Reverse ordering is rejected too.
    assert(S::projectAuthType(storage+4,S::AuthNativeSize,
                              storage,S::AuthLegacySize)==EINVAL);
    assert(!memcmp(storage,before,sizeof(storage)));

    const uint8_t *wrappedInput = reinterpret_cast<const uint8_t *>(UINTPTR_MAX-7);
    assert(S::projectAuthType(wrappedInput,S::AuthNativeSize,
                              storage,S::AuthLegacySize)==EINVAL);
    assert(!memcmp(storage,before,sizeof(storage)));

    // Exactly adjacent read/write ranges are safe; unaligned input/output are
    // also safe because the implementation only accesses words via memcpy.
    uint8_t unaligned[S::AuthNativeSize+S::AuthLegacySize+2];
    init(unaligned+1,0x12345678U,0x87654321U);
    uint8_t inputBefore[S::AuthNativeSize];
    memcpy(inputBefore,unaligned+1,sizeof(inputBefore));
    memset(unaligned+1+S::AuthNativeSize,0xa5,S::AuthLegacySize);
    assert(S::projectAuthType(unaligned+1,S::AuthNativeSize,
                              unaligned+1+S::AuthNativeSize,S::AuthLegacySize)==0);
    assert(!memcmp(unaligned+1,inputBefore,sizeof(inputBefore)));
    assert(!memcmp(unaligned+1+S::AuthNativeSize,unaligned+1,S::AuthLegacySize));
}

static void disassociateFields() {
    uint8_t storage[13] {}; // Deliberately unaligned input.
    uint8_t *p=storage+1;
    const uint32_t words[]={0U,1U,0xaaaaaaaaU,0x80000000U,0xffffffffU};
    for (uint32_t header:words) for(uint32_t reason:words) for(uint32_t flush:words) {
        put32(p,header);put32(p+4,reason);put32(p+8,flush);
        uint8_t before[12];memcpy(before,p,12);
        S::DisassociateMetadata decoded;
        assert(!S::decodeDisassociate(p,12,&decoded));
        assert(decoded.reason==reason && decoded.flush==flush);
        assert(!S::decodeDisassociate(p,8,&decoded));
        assert(decoded.reason==reason && decoded.flush==0);
        assert(!memcmp(p,before,12));
    }
    S::DisassociateMetadata output;output.reason=7;output.flush=9;
    for(size_t size=0;size<=32;++size) {
        if(size==8 || size==12)continue;
        assert(S::decodeDisassociate(p,size,&output)==EOPNOTSUPP);
        assert(output.reason==7 && output.flush==9);
    }
    assert(S::decodeDisassociate(nullptr,8,&output)==EINVAL);
    assert(output.reason==7 && output.flush==9);
    assert(S::decodeDisassociate(p,12,nullptr)==EINVAL);
    assert(S::decodeDisassociate(reinterpret_cast<uint8_t *>(&output),8,&output)==EINVAL);
    assert(output.reason==7 && output.flush==9);
    assert(S::decodeDisassociate(reinterpret_cast<uint8_t *>(UINTPTR_MAX-3),8,&output)==EINVAL);
}

int main() {
    constantsAndValidProjection();
    rejectsEveryExtensionBit();
    rejectsInvalidVersionAndLengths();
    rejectsNullAndShortOutput();
    rejectsOverlapAndAllowsAdjacency();
    disassociateFields();
}
'''


class LegacyBSDSetAdapterTests(unittest.TestCase):
    def test_auth_type_projection_is_bounded_and_lossless(self):
        with tempfile.TemporaryDirectory(prefix="legacy-bsd-set-", dir="/private/tmp") as tmp:
            source = pathlib.Path(tmp) / "set.cpp"
            binary = pathlib.Path(tmp) / "set"
            source.write_text(HARNESS)
            subprocess.run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                            "-I", str(PROJECT / "src"), str(source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
