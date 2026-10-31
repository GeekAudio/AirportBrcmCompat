#!/usr/bin/env python3
"""Host-only mutation tests for normalized kernel ABI contracts."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
HEADER = PROJECT / 'src/scan_kernel/kernel_contracts.hpp'

HARNESS = r'''
#include "kernel_contracts.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
using namespace KernelContracts;

static void put32(uint8_t *p, int32_t value) {
    const uint32_t raw=static_cast<uint32_t>(value);
    for (unsigned i=0;i<4;++i) p[i]=static_cast<uint8_t>(raw>>(i*8));
}
static int32_t difference(uintptr_t end,uintptr_t target) {
    if (target>=end) {
        assert(target-end<=static_cast<uintptr_t>(INT32_MAX));
        return static_cast<int32_t>(target-end);
    }
    assert(end-target<=static_cast<uintptr_t>(INT32_MAX)+1U);
    return static_cast<int32_t>(static_cast<int64_t>(target)-static_cast<int64_t>(end));
}
static void setRelocations(std::vector<uint8_t> &bytes,uintptr_t base,
                           const RelocationSpec *specs,size_t count,
                           std::vector<Relocation> &relocs,uintptr_t targetShift) {
    relocs.clear();relocs.reserve(count);
    for (size_t i=0;i<count;++i) {
        const auto &s=specs[i];
        uintptr_t target=base+targetShift+static_cast<uintptr_t>((i+1)*0x20);
        if (s.symbol && !strcmp(s.symbol,"_ux_handler_port"))
            target=base+targetShift+0x1000+static_cast<uintptr_t>(s.addend);
        if (s.kind==RelocationKind::RelativeCall) bytes[s.instructionOffset]=0xe8;
        else {
            bytes[s.instructionOffset]=0x48;
            bytes[s.displacementOffset-1]=0x05; // mod=00,r/m=101: RIP-relative
        }
        put32(bytes.data()+s.displacementOffset,
              difference(base+s.instructionEndOffset,target));
        relocs.push_back({s.instructionOffset,s.displacementOffset,s.instructionEndOffset,target,s.kind});
    }
}
static void setAnonymousIfnetTargets(std::vector<uint8_t> &bytes,uintptr_t base) {
    for (size_t i=0;i<IfnetMappedTargetCount;++i) {
        const auto &s=IfnetMappedTargetSpecs[i];
        const uintptr_t target=base+0x30000+static_cast<uintptr_t>((i+1)*0x20);
        if (s.kind==RelocationKind::RelativeCall) bytes[s.instructionOffset]=0xe8;
        else {
            bytes[s.instructionOffset]=0x48;
            bytes[s.displacementOffset-1]=0x05;
        }
        put32(bytes.data()+s.displacementOffset,
              difference(base+s.instructionEndOffset,target));
    }
}
static void digestFor(const std::vector<uint8_t> &bytes,uintptr_t base,
                      const std::vector<Relocation> &relocs,uint8_t digest[32]) {
    assert(normalizedSha256(bytes.data(),bytes.size(),base,relocs.data(),relocs.size(),digest)==Status::Passed);
}
static bool same(const uint8_t a[32],const uint8_t b[32]) {return equalDigest(a,b);}
static bool fixtureMappedTarget(RelocationKind,uintptr_t target,void *context) {
    const uintptr_t base=*static_cast<const uintptr_t *>(context);
    return target>=base+0x30000&&target<base+0x31000;
}

static std::vector<uint8_t> ifnetFixture(uintptr_t base,std::vector<Relocation> &relocs) {
    std::vector<uint8_t> code(IfnetIoctlContractBytes,0x90);
    static const uint8_t acquire[]={
        0x8b,0x4f,0x78,0x83,0xe1,0x07,0xb8,0x66,0x00,0x00,0x00,0x83,0xf9,0x02,
        0x0f,0x85,0x0c,0x02,0x00,0x00,0x41,0x89,0xf5,0x4c,0x8d,0x77,0x7c,0x8b,
        0x57,0x7c,0x85,0xd2,0x0f,0x84,0xfa,0x01,0x00,0x00,0x89,0xd1,0x8d,0x51,
        0x01,0x89,0xc8,0xf0,0x41,0x0f,0xb1,0x16,0x89,0xc2,0xb8,0x66,0x00,0x00,
        0x00,0x75,0xe3
    };
    static const uint8_t source[]={0x48,0x89,0xfb};
    static const uint8_t save[]={0x4c,0x89,0x75,0xc8,0x48,0x89,0x5d,0xd0};
    static const uint8_t restore[]={0x48,0x8b,0x5d,0xc8};
    static const uint8_t callback[]={
        0x48,0x8b,0x7d,0xd0,0x48,0x8b,0x87,0x80,0x02,0x00,0x00,0x48,0x85,0xc0,
        0x74,0x0d,0x48,0x8b,0x75,0xc0,0x48,0x8b,0x55,0xb8,0xff,0xd0,0x41,0x89,
        0xc6,0x41,0x83,0xfc,0x66
    };
    static const uint8_t release[]={
        0xb9,0xff,0xff,0xff,0xff,0xf0,0x0f,0xc1,0x0b,0x85,0xc9,0x0f,0x84,0xb2,
        0x00,0x00,0x00,0x83,0xf9,0x01,0x0f,0x84
    };
    memcpy(code.data()+0x32,acquire,sizeof(acquire));
    memcpy(code.data()+0x80,source,sizeof(source));
    memcpy(code.data()+0x97,save,sizeof(save));
    memcpy(code.data()+0x194,restore,sizeof(restore));
    memcpy(code.data()+0x1f7,callback,sizeof(callback));
    memcpy(code.data()+0x238,release,sizeof(release));
    setRelocations(code,base,IfnetRelocationSpecs,
                   IfnetRelocationCount,relocs,0x10000);
    setAnonymousIfnetTargets(code,base);
    return code;
}
static std::vector<uint8_t> runActionFixture(uintptr_t base,std::vector<Relocation> &relocs) {
    std::vector<uint8_t> code(RunActionContractBytes,0x90);
    static const uint8_t gateAndWorkLoop[]={0x49,0x89,0xfe,0x48,0x8b,0x5f,0x30,0x48,0x85,0xdb};
    static const uint8_t savedActionAndArguments[]={
        0x49,0x89,0xf7,0x48,0x89,0x55,0xc8,0x48,0x89,0x4d,0xc0,
        0x4c,0x89,0x45,0xb8,0x4c,0x89,0x4d,0xb0
    };
    static const uint8_t ownerAndArguments[]={
        0x49,0x8b,0x7e,0x18,0x48,0x8b,0x75,0xc8,0x48,0x8b,0x55,0xc0,
        0x48,0x8b,0x4d,0xb8,0x4c,0x8b,0x45,0xb0,0x41,0xff,0xd7
    };
    static const uint8_t activeActionAccounting[]={
        0x48,0xc7,0xc1,0x00,0xff,0xff,0xff,0x49,0x03,0x4e,0x48,0x49,0x89,0x4e,0x48
    };
    memcpy(code.data()+0x1a,gateAndWorkLoop,sizeof(gateAndWorkLoop));
    memcpy(code.data()+0x2a,savedActionAndArguments,sizeof(savedActionAndArguments));
    memcpy(code.data()+0x91,ownerAndArguments,sizeof(ownerAndArguments));
    memcpy(code.data()+0xa8,activeActionAccounting,sizeof(activeActionAccounting));
    setRelocations(code,base,RunActionRelocationSpecs,
                   sizeof(RunActionRelocationSpecs)/sizeof(RunActionRelocationSpecs[0]),relocs,0x20000);
    return code;
}

int main(int argc,char **argv) {
    assert(argc==2);const char *mode=argv[1];
    if (!strcmp(mode,"sha")) {
        const uint8_t abc[]={'a','b','c'};uint8_t digest[32];
        assert(normalizedSha256(abc,sizeof(abc),0x1000,nullptr,0,digest)==Status::Passed);
        const uint8_t expected[]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
                                  0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
        assert(same(digest,expected));
    } else if (!strcmp(mode,"relocations")) {
        const uintptr_t base1=0xffffff8001000000ULL,base2=0xffffff8002800000ULL;
        std::vector<uint8_t> first(64,0x90);first[4]=0xe8;first[24]=0x48;first[25]=0x8b;first[26]=0x05;
        const uintptr_t call1=base1+0x1000,rip1=base1+0x2000;
        put32(first.data()+5,difference(base1+9,call1));put32(first.data()+27,difference(base1+31,rip1));
        Relocation a[]={{4,5,9,call1,RelocationKind::RelativeCall},{24,27,31,rip1,RelocationKind::RipRelative}};
        uint8_t digest1[32],digest2[32];
        assert(normalizedSha256(first.data(),first.size(),base1,a,2,digest1)==Status::Passed);
        auto second=first;const uintptr_t call2=base2+0x1000,rip2=base2+0x2000;
        put32(second.data()+5,difference(base2+9,call2));put32(second.data()+27,difference(base2+31,rip2));
        Relocation b[]={{4,5,9,call2,RelocationKind::RelativeCall},{24,27,31,rip2,RelocationKind::RipRelative}};
        assert(normalizedSha256(second.data(),second.size(),base2,b,2,digest2)==Status::Passed);
        assert(same(digest1,digest2));
        second[40]^=1;assert(normalizedSha256(second.data(),second.size(),base2,b,2,digest2)==Status::Passed);
        assert(!same(digest1,digest2));
        second=first;b[0].target=call2+1;
        assert(normalizedSha256(second.data(),second.size(),base2,b,2,digest2)==Status::RelocationTargetMismatch);
        b[0].target=call2;b[0].instructionOffset=20;b[0].displacementOffset=21;
        assert(normalizedSha256(second.data(),second.size(),base2,b,2,digest2)==Status::InvalidRelocation);
    } else if (!strcmp(mode,"ifnet")) {
        const uintptr_t base=0xffffff8000100000ULL;
        uintptr_t fixtureBase=base;
        std::vector<Relocation> relocs;auto code=ifnetFixture(base,relocs);uint8_t digest[32];
        digestFor(code,base,relocs,digest);IfnetIoctlPlan plan;
        assert(validateIfnetIoctl(code.data(),code.size(),base,relocs.data(),relocs.size(),digest,plan)==Status::Passed);
        assert(plan.proofTag==IfnetPlanProof&&plan.imageSpan==IfnetIoctlContractBytes&&plan.callbackReturnPC==base+0x211);
        assert(validateIfnetMappedTargets(code.data(),code.size(),base,fixtureMappedTarget,&fixtureBase)==Status::Passed);
        auto moved=ifnetFixture(base+0x1000000,relocs);
        assert(validateIfnetIoctl(moved.data(),moved.size(),base+0x1000000,relocs.data(),relocs.size(),digest,plan)==Status::Passed);
        assert(plan.callbackReturnPC==base+0x1000000+0x211);
        setRelocations(code,base,IfnetRelocationSpecs,IfnetRelocationCount,relocs,0x10000);
        assert(fixedIfnetRelocationLayout(relocs.data(),relocs.size()));
        auto badLayout=relocs;badLayout[0].displacementOffset++;
        assert(!fixedIfnetRelocationLayout(badLayout.data(),badLayout.size()));
        assert(validateIfnetCurrent(code.data(),code.size(),base,badLayout.data(),badLayout.size(),plan)==Status::InvalidRelocation);
        for (size_t offset : {size_t(0x4b),size_t(0x1f7+24),size_t(0x238+5),size_t(0x180)}) {
            auto bad=code;bad[offset]^=1;
            assert(validateIfnetIoctl(bad.data(),bad.size(),base,relocs.data(),relocs.size(),digest,plan)!=Status::Passed);
        }
        for (size_t offset=0;offset<code.size();++offset) {
            bool isRelocationByte=false;
            for (const auto &reloc:relocs) if (offset>=reloc.displacementOffset && offset-reloc.displacementOffset<4)
                isRelocationByte=true;
            if (isRelocationByte) continue;
            auto bad=code;bad[offset]^=1;
            const auto status=validateIfnetIoctl(bad.data(),bad.size(),base,relocs.data(),relocs.size(),digest,plan);
            assert(status==Status::FingerprintMismatch||status==Status::InvalidRelocation);
            assert(plan.proofTag==0&&plan.callbackReturnPC==0);
        }
        for (size_t i=0;i<IfnetMappedTargetCount;++i) {
            const auto &spec=IfnetMappedTargetSpecs[i];uintptr_t before=0,after=0;
            assert(relativeTargetAt(code.data(),code.size(),base,spec,before)==Status::Passed);
            auto redirected=code;redirected[spec.displacementOffset]++;
            assert(relativeTargetAt(redirected.data(),redirected.size(),base,spec,after)==Status::Passed);
            assert(after!=before);
            assert(validateIfnetMappedTargets(redirected.data(),redirected.size(),base,
                fixtureMappedTarget,&fixtureBase)==Status::Passed);
            assert(validateIfnetIoctl(redirected.data(),redirected.size(),base,
                relocs.data(),relocs.size(),digest,plan)==Status::FingerprintMismatch);
            assert(plan.proofTag==0&&plan.callbackReturnPC==0);
        }
        for (size_t i=0;i<IfnetRelocationCount;++i) {
            const auto &spec=IfnetRelocationSpecs[i];
            if (!spec.symbol||strcmp(spec.symbol,"_ux_handler_port")) continue;
            auto redirected=code;redirected[spec.displacementOffset]++;
            uintptr_t actualTarget=0;
            assert(relativeTargetAt(redirected.data(),redirected.size(),base,spec,actualTarget)==Status::Passed);
            const uintptr_t resolvedSymbol=base+0x10000+0x1000;
            const uintptr_t resolvedTarget=resolvedSymbol+static_cast<uintptr_t>(spec.addend);
            assert(relocs[i].target==resolvedTarget&&actualTarget!=resolvedTarget);
            auto resolved=relocs;resolved[i].target=resolvedTarget;
            assert(validateIfnetIoctl(redirected.data(),redirected.size(),base,
                resolved.data(),resolved.size(),digest,plan)==Status::RelocationTargetMismatch);
            assert(plan.proofTag==0&&plan.callbackReturnPC==0);
        }
        auto badTarget=code;badTarget[0x87]^=1;
        assert(validateIfnetIoctl(badTarget.data(),badTarget.size(),base,relocs.data(),relocs.size(),digest,plan)==Status::RelocationTargetMismatch);
        assert(validateIfnetIoctl(code.data(),code.size()-1,base,relocs.data(),relocs.size(),digest,plan)==Status::Truncated);
    } else if (!strcmp(mode,"runaction")) {
        const uintptr_t base=0xffffff8000200000ULL;
        std::vector<Relocation> relocs;auto code=runActionFixture(base,relocs);uint8_t digest[32];
        digestFor(code,base,relocs,digest);RunActionPlan plan;
        assert(validateRunAction(code.data(),code.size(),base,relocs.data(),relocs.size(),digest,plan)==Status::Passed);
        assert(plan.proofTag==RunActionPlanProof&&plan.imageSpan==RunActionContractBytes&&plan.actionReturnPC==base+0xa8);
        auto moved=runActionFixture(base+0x2000000,relocs);
        assert(validateRunAction(moved.data(),moved.size(),base+0x2000000,relocs.data(),relocs.size(),digest,plan)==Status::Passed);
        assert(plan.actionReturnPC==base+0x2000000+0xa8);
        setRelocations(code,base,RunActionRelocationSpecs,RunActionRelocationCount,relocs,0x20000);
        assert(fixedRunActionRelocationLayout(relocs.data(),relocs.size()));
        auto badLayout=relocs;badLayout[0].kind=RelocationKind::RelativeCall;
        assert(!fixedRunActionRelocationLayout(badLayout.data(),badLayout.size()));
        assert(validateRunActionCurrent(code.data(),code.size(),base,badLayout.data(),badLayout.size(),plan)==Status::InvalidRelocation);
        for (size_t offset : {size_t(0x2a),size_t(0x91),size_t(0xa5),size_t(0xa8),size_t(0x180)}) {
            auto bad=code;bad[offset]^=1;
            assert(validateRunAction(bad.data(),bad.size(),base,relocs.data(),relocs.size(),digest,plan)!=Status::Passed);
        }
        for (size_t offset=0;offset<code.size();++offset) {
            bool isRelocationByte=false;
            for (const auto &reloc:relocs) if (offset>=reloc.displacementOffset && offset-reloc.displacementOffset<4)
                isRelocationByte=true;
            if (isRelocationByte) continue;
            auto bad=code;bad[offset]^=1;
            const auto status=validateRunAction(bad.data(),bad.size(),base,relocs.data(),relocs.size(),digest,plan);
            assert(status==Status::FingerprintMismatch||status==Status::InvalidRelocation);
            assert(plan.proofTag==0&&plan.actionReturnPC==0);
        }
    } else if (!strcmp(mode,"memory")) {
        const uint8_t body[]={0x55,0x48,0x89,0xe5,0xb8,0xc7,0x02,0,0xe0,0x5d,0xc3};
        ClientMemoryPlan plan;
        assert(validateUnsupportedClientMemory(body,sizeof(body),0x1000,plan)==Status::Passed);
        assert(plan.proofTag==ClientMemoryPlanProof&&plan.bodyBytes==11&&plan.routeBytes==9);
        for (size_t i=0;i<sizeof(body);++i) {uint8_t bad[sizeof(body)];memcpy(bad,body,sizeof(body));bad[i]^=1;
            assert(validateUnsupportedClientMemory(bad,sizeof(bad),0x1000,plan)!=Status::Passed);}
        assert(validateUnsupportedClientMemory(body,10,0x1000,plan)==Status::Truncated);
        assert(validateUnsupportedClientMemory(body,sizeof(body),UINTPTR_MAX-10,plan)==Status::InvalidInput);
        assert(plan.proofTag==0&&plan.imageBase==0);
    } else assert(false);
    puts("kernel contract scenario passed");
}
'''


@unittest.skipUnless(shutil.which('clang++'), 'C++ compiler required')
class KernelContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='airport-kernel-contracts-', dir='/private/tmp')
        source = Path(cls.work.name) / 'contracts.cpp'
        source.write_text(HARNESS)
        cls.binary = Path(cls.work.name) / 'contracts'
        built = subprocess.run(
            ['clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror', '-I', str(HEADER.parent),
             str(source), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=30)
        if built.returncode:
            cls.work.cleanup()
            raise AssertionError(built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def scenario(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('kernel contract scenario passed', result.stdout)

    def test_sha256(self): self.scenario('sha')
    def test_symbol_relocations_are_verified_then_normalized(self): self.scenario('relocations')
    def test_ifnet_acquire_callback_release_and_unknown_body_are_pinned(self): self.scenario('ifnet')
    def test_run_action_owner_argument_and_active_count_contract(self): self.scenario('runaction')
    def test_trivial_unsupported_memory_method(self): self.scenario('memory')


if __name__ == '__main__': unittest.main()
