#!/usr/bin/env python3
"""Exercise the portable IONetworkInterface callback contract under sanitizers."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]


HARNESS = r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "src/private_mac_compat/network_callback_contract.hpp"

using namespace PrivateMAC::NetworkCallbackContract;

static const size_t kMappedSize=0x5000;
static const size_t kInitOffset=0x1000;
static const size_t kCallbackOffset=kInitOffset+0x142;

static void put32(std::vector<uint8_t> &b, size_t o, uint32_t v) {
    for (unsigned i=0;i<4;++i) b[o+i]=static_cast<uint8_t>(v>>(8*i));
}
static void put64(std::vector<uint8_t> &b, size_t o, uint64_t v) {
    for (unsigned i=0;i<8;++i) b[o+i]=static_cast<uint8_t>(v>>(8*i));
}
static std::vector<uint8_t> fromHex(const char *hex) {
    std::vector<uint8_t> result;
    for (size_t i=0; hex[i]; i+=2) {
        const auto digit=[](char c)->uint8_t {
            if (c>='0' && c<='9') return static_cast<uint8_t>(c-'0');
            if (c>='a' && c<='f') return static_cast<uint8_t>(c-'a'+10);
            return static_cast<uint8_t>(c-'A'+10);
        };
        result.push_back(static_cast<uint8_t>((digit(hex[i])<<4)|digit(hex[i+1])));
    }
    return result;
}

static const std::vector<uint8_t> kInit = fromHex(
    "554889e54156534889f34989fe488b07ff90a008000048894310498b8608010000"
    "8b4804894b208b00894318488d053100000048894328488d050401000048894360"
    "488d057b01000048894368488d0568020000488943704c897358b0015b415e5dc390");
static const std::vector<uint8_t> kCallback = fromHex(
    "554889e5415741564155415453504889d34989f74989fee80253f4fd41bd660000"
    "004885c074494989c44889c7e86ca63afe84c0753a498bb424880000004885f67427"
    "498b0424488b80600900004c89e74c89fa4c89f14989d84883c4085b415c415d415e"
    "415f5dffe041bd160000004489e84883c4085b415c415d415e415f5dc3");

struct Fixture {
    std::vector<uint8_t> bytes;
    ImageView image;
    uintptr_t initAddress;
    uintptr_t callbackAddress;
    uintptr_t softcTarget;
    uintptr_t inactiveTarget;
    Targets targets;

    Fixture() : bytes(kMappedSize,0), image(), initAddress(0),
                callbackAddress(0), softcTarget(0), inactiveTarget(0),targets() {
        const uint64_t textVM=0x100000000ULL;
        // Thin x86_64 Mach-O header and one __TEXT segment. A nonzero
        // container-relative fileoff must not be mistaken for a runtime VA.
        put32(bytes,0,0xfeedfacf);
        put32(bytes,4,0x01000007);
        put32(bytes,8,3);
        put32(bytes,12,0xb);
        put32(bytes,16,1);
        put32(bytes,20,152);
        put32(bytes,24,0);
        put32(bytes,28,0);
        const size_t cmd=32;
        put32(bytes,cmd,0x19);
        put32(bytes,cmd+4,152);
        std::memcpy(bytes.data()+cmd+8,"__TEXT",6);
        put64(bytes,cmd+24,textVM);
        put64(bytes,cmd+32,kMappedSize);
        put64(bytes,cmd+40,0x700000); // deliberately not a mapped offset
        put64(bytes,cmd+48,kMappedSize);
        put32(bytes,cmd+56,7);
        put32(bytes,cmd+60,5);
        put32(bytes,cmd+64,1);
        const size_t sec=cmd+72;
        std::memcpy(bytes.data()+sec,"__text",6);
        std::memcpy(bytes.data()+sec+16,"__TEXT",6);
        put64(bytes,sec+32,textVM+0x100);
        put64(bytes,sec+40,0x3000);
        put32(bytes,sec+48,0x100);
        put32(bytes,sec+52,2);
        put32(bytes,sec+64,0x80000400U);

        std::memcpy(bytes.data()+kInitOffset,kInit.data(),kInit.size());
        std::memcpy(bytes.data()+kCallbackOffset,kCallback.data(),kCallback.size());
        const uintptr_t runtimeBase=reinterpret_cast<uintptr_t>(bytes.data());
        image=ImageView(bytes.data(),bytes.size(),runtimeBase);
        initAddress=runtimeBase+kInitOffset;
        callbackAddress=runtimeBase+kCallbackOffset;
        softcTarget=runtimeBase+0x700000;
        inactiveTarget=runtimeBase+0x700100;
        targets=Targets(runtimeBase+0x1800,runtimeBase+0x1900,
                        runtimeBase+0x1a00);
        patchRel32(kInitOffset+0x2f,initAddress+0x33,targets.output);
        patchRel32(kInitOffset+0x45,initAddress+0x49,targets.bpf);
        patchRel32(kInitOffset+0x50,initAddress+0x54,targets.detach);
        patchRel32(kCallbackOffset+0x18, callbackAddress+0x1c, softcTarget);
        patchRel32(kCallbackOffset+0x2e, callbackAddress+0x32, inactiveTarget);
    }

    void patchRel32(size_t operandOffset, uintptr_t next, uintptr_t target) {
        const int64_t delta=static_cast<int64_t>(target)-static_cast<int64_t>(next);
        assert(delta>=std::numeric_limits<int32_t>::min() &&
               delta<=std::numeric_limits<int32_t>::max());
        put32(bytes,operandOffset,static_cast<uint32_t>(static_cast<int32_t>(delta)));
    }

    bool verify() const {
        return PrivateMAC::NetworkCallbackContract::verify(
            image,initAddress,callbackAddress,softcTarget,inactiveTarget,targets);
    }
};

static void acceptsExactFunctionBodiesAndMachOExecutableRanges() {
    Fixture f;
    assert(f.verify());
    assert(containsExecutableRange(f.image,f.initAddress,InitIfnetParamsSize));
    assert(containsExecutableRange(f.image,f.callbackAddress,IfIoctlSize));
    assert(!containsExecutableRange(f.image,
        f.image.runtimeHeaderAddress+0x3500,16)); // outside __text section
    assert(!containsExecutableRange(f.image,
        std::numeric_limits<uintptr_t>::max()-3,8)); // address addition overflow
    assert(std::string(IfIoctlSymbol)==
        "__ZN18IONetworkInterface8if_ioctlEP7__ifnetmPv");
    assert(std::string(InitIfnetParamsSymbol)==
        "__ZN18IONetworkInterface15initIfnetParamsEP17ifnet_init_params");
    assert(std::string(IfnetOutputSymbol)==
        "__ZN18IONetworkInterface9if_outputEP7__ifnetP6__mbuf");
    assert(std::string(IfnetSetBpfTapSymbol)==
        "__ZN18IONetworkInterface14if_set_bpf_tapEP7__ifnetjPFiS1_P6__mbufE");
    assert(std::string(IfnetDetachSymbol)==
        "__ZN18IONetworkInterface9if_detachEP7__ifnet");
}

static void rejectsSingleByteMutation() {
    Fixture f;
    f.bytes[kCallbackOffset+0x60]^=1;
    assert(!f.verify());
    Fixture g;
    g.bytes[kInitOffset+0x23]^=1;
    assert(!g.verify());
}

static void rejectsEveryNonRelocatedInitAndCallbackByteMutation() {
    for (size_t offset=0;offset<InitIfnetParamsSize;++offset) {
        const bool leaDisp=(offset>=0x2f && offset<0x33) ||
                           (offset>=0x3a && offset<0x3e) ||
                           (offset>=0x45 && offset<0x49) ||
                           (offset>=0x50 && offset<0x54);
        if (leaDisp) continue;
        Fixture f;
        f.bytes[kInitOffset+offset]^=1;
        assert(!f.verify());
    }
    for (size_t offset=0;offset<IfIoctlSize;++offset) {
        const bool importDisp=(offset>=0x18 && offset<0x1c) ||
                              (offset>=0x2e && offset<0x32);
        if (importDisp) continue;
        Fixture f;
        f.bytes[kCallbackOffset+offset]^=1;
        assert(!f.verify());
    }
}

static void rejectsWrongResolvedImportTargets() {
    Fixture f;
    assert(!PrivateMAC::NetworkCallbackContract::verify(f.image,f.initAddress,
        f.callbackAddress,f.softcTarget+1,f.inactiveTarget,f.targets));
    Fixture g;
    g.patchRel32(kCallbackOffset+0x2e,g.callbackAddress+0x32,
                 g.inactiveTarget+1);
    assert(!g.verify());
}

static void rejectsEachMismatchedSameImageLEATarget() {
    for (unsigned which=0;which<4;++which) {
        Fixture f;
        if (which==0)
            f.patchRel32(kInitOffset+0x2f,f.initAddress+0x33,f.targets.output+1);
        else if (which==1)
            f.patchRel32(kInitOffset+0x3a,f.initAddress+0x3e,f.callbackAddress+1);
        else if (which==2)
            f.patchRel32(kInitOffset+0x45,f.initAddress+0x49,f.targets.bpf+1);
        else
            f.patchRel32(kInitOffset+0x50,f.initAddress+0x54,f.targets.detach+1);
        assert(!f.verify());
    }
    Fixture outside;
    outside.targets.output=outside.image.runtimeHeaderAddress+0x8000;
    outside.patchRel32(kInitOffset+0x2f,outside.initAddress+0x33,
                       outside.targets.output);
    assert(!outside.verify());
}

static void rejectsIncorrectRegistrationAndCallbackTarget() {
    Fixture f;
    f.bytes[kInitOffset+0x5b]=0x59; // this stored at params+0x59, not +0x58
    assert(!f.verify());
    Fixture g;
    g.bytes[kInitOffset+0x3a]^=1; // LEA no longer targets if_ioctl
    assert(!g.verify());
}

static void allowsOnlyResolvedRel32Changes() {
    Fixture f;
    const std::vector<uint8_t> before(f.bytes.begin()+kCallbackOffset,
                                      f.bytes.begin()+kCallbackOffset+IfIoctlSize);
    f.softcTarget+=0x100;
    f.inactiveTarget+=0x200;
    f.patchRel32(kCallbackOffset+0x18,f.callbackAddress+0x1c,f.softcTarget);
    f.patchRel32(kCallbackOffset+0x2e,f.callbackAddress+0x32,f.inactiveTarget);
    assert(f.verify());
    for (size_t i=0;i<IfIoctlSize;++i) {
        const bool allowed=(i>=0x18 && i<0x1c) || (i>=0x2e && i<0x32);
        if (!allowed) assert(before[i]==f.bytes[kCallbackOffset+i]);
    }
}

static void acceptsARelocatedMappedImageOnlyAfterRebindingCalls() {
    Fixture f;
    const std::vector<uint8_t> before(f.bytes.begin()+kCallbackOffset,
                                      f.bytes.begin()+kCallbackOffset+IfIoctlSize);
    const uintptr_t newRuntimeBase=f.image.runtimeHeaderAddress+0x100000;
    f.image.runtimeHeaderAddress=newRuntimeBase;
    f.initAddress=newRuntimeBase+kInitOffset;
    f.callbackAddress=newRuntimeBase+kCallbackOffset;
    // Simulate imports that resolve to a different image slide. The fixed
    // function-body bytes and same-image LEA remain unchanged; only call rel32
    // operands may be recalculated.
    f.softcTarget+=0x200000;
    f.inactiveTarget+=0x300000;
    f.targets.output+=0x100000;
    f.targets.bpf+=0x100000;
    f.targets.detach+=0x100000;
    f.patchRel32(kCallbackOffset+0x18,f.callbackAddress+0x1c,f.softcTarget);
    f.patchRel32(kCallbackOffset+0x2e,f.callbackAddress+0x32,f.inactiveTarget);
    assert(f.verify());
    for (size_t i=0;i<IfIoctlSize;++i) {
        const bool allowed=(i>=0x18 && i<0x1c) || (i>=0x2e && i<0x32);
        if (!allowed) assert(before[i]==f.bytes[kCallbackOffset+i]);
    }
}

static void acceptsSameImageReorderingOfAllFourLEATargets() {
    Fixture f;
    const uintptr_t runtimeBase=f.image.runtimeHeaderAddress;
    const size_t oldCallbackOffset=kCallbackOffset;
    const size_t movedCallbackOffset=0x2400;
    std::memcpy(f.bytes.data()+movedCallbackOffset,
                f.bytes.data()+oldCallbackOffset,IfIoctlSize);
    f.callbackAddress=runtimeBase+movedCallbackOffset;
    f.targets.output=runtimeBase+0x1700;
    f.targets.bpf=runtimeBase+0x1900;
    f.targets.detach=runtimeBase+0x1c00;
    f.patchRel32(kInitOffset+0x2f,f.initAddress+0x33,f.targets.output);
    f.patchRel32(kInitOffset+0x3a,f.initAddress+0x3e,f.callbackAddress);
    f.patchRel32(kInitOffset+0x45,f.initAddress+0x49,f.targets.bpf);
    f.patchRel32(kInitOffset+0x50,f.initAddress+0x54,f.targets.detach);
    f.patchRel32(movedCallbackOffset+0x18,f.callbackAddress+0x1c,f.softcTarget);
    f.patchRel32(movedCallbackOffset+0x2e,f.callbackAddress+0x32,f.inactiveTarget);
    assert(f.verify());
}

static void rejectsMalformedOrNonExecutableMachO() {
    Fixture f;
    put32(f.bytes,32+4,0xffffffffU);
    assert(!f.verify());
    Fixture g;
    put32(g.bytes,32+60,3); // __TEXT is no longer executable
    assert(!g.verify());
    Fixture wrongFileType;
    put32(wrongFileType.bytes,12,2); // Not MH_KEXT_BUNDLE.
    assert(!wrongFileType.verify());
    Fixture unalignedCommand;
    put32(unalignedCommand.bytes,32+4,153);
    assert(!unalignedCommand.verify());
    Fixture wrongSectionCount;
    put32(wrongSectionCount.bytes,32+64,0);
    assert(!wrongSectionCount.verify());
    Fixture unalignedCommandTable;
    put32(unalignedCommandTable.bytes,20,153);
    assert(!unalignedCommandTable.verify());
}

static void acceptsZeroTextVMAndDifferentFileOffsets() {
    Fixture zeroVM;
    put64(zeroVM.bytes,32+24,0);
    put64(zeroVM.bytes,32+72+32,0x100);
    assert(zeroVM.verify());
    Fixture zeroFileOffset;
    put64(zeroFileOffset.bytes,32+40,0);
    assert(zeroFileOffset.verify());
    Fixture absoluteKCFileOffset;
    put64(absoluteKCFileOffset.bytes,32+40,0xffffff8000000000ULL);
    assert(absoluteKCFileOffset.verify());
}

int main() {
    acceptsExactFunctionBodiesAndMachOExecutableRanges();
    rejectsSingleByteMutation();
    rejectsEveryNonRelocatedInitAndCallbackByteMutation();
    rejectsWrongResolvedImportTargets();
    rejectsEachMismatchedSameImageLEATarget();
    rejectsIncorrectRegistrationAndCallbackTarget();
    allowsOnlyResolvedRel32Changes();
    acceptsARelocatedMappedImageOnlyAfterRebindingCalls();
    acceptsSameImageReorderingOfAllFourLEATargets();
    rejectsMalformedOrNonExecutableMachO();
    acceptsZeroTextVMAndDifferentFileOffsets();
    return 0;
}
'''


@unittest.skipUnless(shutil.which("clang++"), "requires clang++")
class NetworkCallbackContractTests(unittest.TestCase):
    def test_actual_header_under_address_and_undefined_sanitizers(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "contract_test.cpp"
            binary = Path(temporary) / "contract_test"
            source.write_text(HARNESS)
            subprocess.run([
                "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(PROJECT), str(source), "-o", str(binary)
            ], check=True, cwd=PROJECT)
            subprocess.run([str(binary)], check=True, cwd=PROJECT)


if __name__ == "__main__":
    unittest.main()
