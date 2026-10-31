"""Exercise the production association handler's bounded profile dispatch."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "association_compat.hpp"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace AC = AssociationCompat;
constexpr size_t SonomaSize = AssociationProfiles::Sonoma14Size;
constexpr size_t SequoiaSize = AssociationProfiles::Sequoia15Size;
constexpr size_t TahoeSize = AC::NativeSize;
constexpr size_t OldSize = AC::LegacySize;
constexpr uintptr_t Owner = 0x1010;
constexpr uintptr_t Caller = 0x2020;

static uint8_t user[TahoeSize], userBefore[TahoeSize];
static uint8_t oldConsumed[OldSize];
static size_t requestLength;
static unsigned copyCalls, allocations, frees, originals, flagObservations, surveyObservations;
static unsigned primaryCalls;
static uint8_t *allocationBase;
static bool identity = true, flipIdentityOnSecondCheck = false, lockHeld = false;
static AC::Registry registry;
static ScanCompat::Request request;
static struct Envelope { ScanCompat::Request request; uint8_t trailer[16]; } envelope;

static unsigned checkNumber;
static void checkAt(bool ok,int line) {
    ++checkNumber;
    if (!ok) { fprintf(stderr,"contract check %u failed at line %d\n",checkNumber,line); abort(); }
}
#define check(ok) checkAt((ok),__LINE__)
static void put16(uint8_t *p, uint16_t x) { p[0]=uint8_t(x); p[1]=uint8_t(x>>8); }
static void put32(uint8_t *p, uint32_t x) {
    for (unsigned i=0; i<4; ++i) p[i]=uint8_t(x>>(i*8));
}
static uint16_t get16(const uint8_t *p) { return uint16_t(p[0]) | uint16_t(uint16_t(p[1])<<8); }
static uint32_t get32(const uint8_t *p) {
    return uint32_t(p[0]) | (uint32_t(p[1])<<8) |
           (uint32_t(p[2])<<16) | (uint32_t(p[3])<<24);
}

static void fillSonoma() {
    memset(user,0,SonomaSize);
    put32(user,1); put16(user+4,2); put16(user+6,0); put16(user+8,0);
    put32(user+12,3); memcpy(user+16,"abc",3);
}
static void fillSequoia() {
    memset(user,0,SequoiaSize);
    put32(user,1); put16(user+4,2); put16(user+6,0);
    put32(user+8,1); put32(user+12,0);
    put32(user+16,3); memcpy(user+20,"abc",3);
}
static void fillTahoe() {
    memset(user,0,TahoeSize);
    put32(user,1); put16(user+4,2); put16(user+6,0);
    put32(user+8,1); put32(user+12,0);
    put32(user+16,3); memcpy(user+20,"abc",3);
    user[899]=2;
}

static void enterLock(void *) { check(!lockHeld); lockHeld=true; }
static void leaveLock(void *) { check(lockHeld); lockHeld=false; }
static uintptr_t currentThread() { return Owner; }
static bool primary(void *c, void *i, const char name[16]) {
    ++primaryCalls;
    const bool stillIdentity=identity && (!flipIdentityOnSecondCheck || primaryCalls==1);
    return stillIdentity && c==reinterpret_cast<void *>(0x3030) &&
        i==reinterpret_cast<void *>(0x4040) && memcmp(name,"en0",4)==0;
}
static void *allocate(size_t n) {
    check(!lockHeld && n==AC::StorageSize && !allocationBase);
    allocationBase=static_cast<uint8_t *>(malloc(n+32)); check(allocationBase);
    memset(allocationBase,0x6d,n+32); ++allocations;
    return allocationBase+16;
}
static void deallocate(void *p, size_t n) {
    check(!lockHeld && p==allocationBase+16 && n==AC::StorageSize);
    const auto *bytes=static_cast<const uint8_t *>(p);
    for (size_t j=0; j<n; ++j) check(bytes[j]==0);
    for (size_t j=0; j<16; ++j) check(allocationBase[j]==0x6d);
    for (size_t j=16+n; j<n+32; ++j) check(allocationBase[j]==0x6d);
    ++frees; free(allocationBase); allocationBase=nullptr;
}
static int copyIn(void *c, uint64_t address, void *out, size_t n) {
    check(!lockHeld && c==reinterpret_cast<void *>(0x3030));
    check(address==reinterpret_cast<uint64_t>(user) && n==requestLength);
    ++copyCalls; memcpy(out,user,n); return 0;
}
static void observeFlags(uint32_t flags, uint8_t byte469) {
    check(!lockHeld); ++flagObservations;
    check(flags==0 && byte469==0);
}
static void observeSurvey(const AssociationSurvey::Snapshot &s) {
    check(!lockHeld); ++surveyObservations;
    // Only normalized 900-byte and native 908-byte requests have this layout.
    check(s.authLower8.low16==1 && s.authLower8.high16==0);
    check(s.authUpper12.low16==0 && s.scopeLength580.low16==0);
    check(s.sixGPolicy899==2 && s.unknownTailNonzero==0);
}

static int original(void *c, void *i, void *v, void *infra,
                    ScanCompat::Request *r, bool user64) {
    ++originals;
    check(c==reinterpret_cast<void *>(0x3030) && i==reinterpret_cast<void *>(0x4040));
    check(!v && !infra && r==&envelope.request && user64);
    if (!identity) {
        check(registry.head==nullptr && allocations==0 && copyCalls==0);
        return 73;
    }

    auto *scope=registry.find(Owner,c,i);
    check(scope && scope->thread==Owner && scope->caller==Caller);
    check(scope->source==reinterpret_cast<uintptr_t>(user));
    check(scope->legacy==allocationBase+16+AC::NativeSize);
    check(!scope->privatePlan.requested);
    check(scope->authUpper==0);

    memset(oldConsumed,0xa5,sizeof(oldConsumed));
    const int consumed=registry.consume(Owner,Caller,c,r->userData,oldConsumed,sizeof(oldConsumed));
    check(consumed==0 && scope->consumed);
    if (requestLength==SonomaSize) {
        check(get16(oldConsumed+6)==0); // Sonoma's native lower-auth value is retained exactly.
        check(!memcmp(oldConsumed,user,AssociationProfiles::LegacyPrefixSize));
        for (size_t j=AssociationProfiles::LegacyPrefixSize; j<OldSize; ++j) check(oldConsumed[j]==0);
    } else {
        check(get32(oldConsumed)==1 && get16(oldConsumed+4)==2);
        check(get16(oldConsumed+6)==1 && get16(oldConsumed+8)==0);
        check(get32(oldConsumed+12)==3 && !memcmp(oldConsumed+16,"abc",3));
        for (size_t j=20; j<OldSize; ++j) check(oldConsumed[j]==0);
    }
    return 0;
}

static void resetState(size_t length) {
    memset(user,0xc9,sizeof(user)); requestLength=length;
    if (length==SonomaSize) fillSonoma();
    else if (length==SequoiaSize) fillSequoia();
    else fillTahoe();
    memcpy(userBefore,user,sizeof(user));
    memset(&envelope,0x91,sizeof(envelope));
    memset(&envelope.request,0,sizeof(envelope.request));
    memcpy(envelope.request.interfaceName,"en0",4);
    envelope.request.type=20; envelope.request.value=0;
    envelope.request.length=static_cast<uint32_t>(length);
    envelope.request.padding=0;
    envelope.request.userData=reinterpret_cast<uint64_t>(user);
    memset(envelope.trailer,0x71,sizeof(envelope.trailer));
    request=envelope.request;
    copyCalls=allocations=frees=originals=flagObservations=surveyObservations=0;
    primaryCalls=0;allocationBase=nullptr;identity=true;
    flipIdentityOnSecondCheck=false;lockHeld=false;
    registry=AC::Registry{};
    registry.lock={&registry,enterLock,leaveLock};
}

static int runSuccess(size_t length) {
    resetState(length);
    AC::API api{};
    api.original=original; api.copyIn=copyIn; api.allocate=allocate;
    api.deallocate=deallocate; api.currentThread=currentThread;
    api.registry=&registry; api.caller=Caller; api.primaryInterface=primary;
    api.observeFlags=observeFlags; api.observeSurvey=observeSurvey;
    AC::Result validation{-99,0}; bool consumed=false;
    const int result=AC::handle(api,reinterpret_cast<void *>(0x3030),
        reinterpret_cast<void *>(0x4040),nullptr,nullptr,&envelope.request,true,
        &validation,&consumed);
    if (result || validation.error || !consumed)
        fprintf(stderr,"length=%zu result=%d validation=%d field=%u consumed=%d copies=%u originals=%u\n",
                length,result,validation.error,validation.field,consumed,copyCalls,originals);
    check(result==0 && validation.error==0 && validation.field==0 && consumed);
    check(copyCalls==1 && allocations==1 && frees==1 && originals==1);
    check(!registry.head && !allocationBase && !lockHeld);
    check(!memcmp(user,userBefore,sizeof(user)));
    check(!memcmp(&envelope.request,&request,sizeof(request)));
    for (uint8_t byte:envelope.trailer) check(byte==0x71);
    if (length==SonomaSize) check(flagObservations==0 && surveyObservations==0);
    else check(flagObservations==1 && surveyObservations==1);
    return 0;
}

static int runReject(bool scope) {
    resetState(SonomaSize);
    if (scope) user[464]|=0x40; else user[508]=1;
    memcpy(userBefore,user,sizeof(user));
    AC::API api{};
    api.original=original; api.copyIn=copyIn; api.allocate=allocate;
    api.deallocate=deallocate; api.currentThread=currentThread;
    api.registry=&registry; api.caller=Caller; api.primaryInterface=primary;
    api.observeFlags=observeFlags; api.observeSurvey=observeSurvey;
    AC::Result validation{-99,0}; bool consumed=true;
    const int result=AC::handle(api,reinterpret_cast<void *>(0x3030),
        reinterpret_cast<void *>(0x4040),nullptr,nullptr,&envelope.request,true,
        &validation,&consumed);
    check(result==EOPNOTSUPP && validation.error==EOPNOTSUPP);
    check(validation.field==(scope?464U:508U) && !consumed);
    check(copyCalls==1 && allocations==1 && frees==1 && originals==0);
    check(!registry.head && !allocationBase && !lockHeld);
    check(flagObservations==0 && surveyObservations==0);
    check(!memcmp(user,userBefore,sizeof(user)));
    check(!memcmp(&envelope.request,&request,sizeof(request)));
    return 0;
}

static int runWrongIdentity() {
    resetState(SonomaSize); identity=false;
    AC::API api{};
    api.original=original; api.copyIn=copyIn; api.allocate=allocate;
    api.deallocate=deallocate; api.currentThread=currentThread;
    api.registry=&registry; api.caller=Caller; api.primaryInterface=primary;
    api.observeFlags=observeFlags; api.observeSurvey=observeSurvey;
    AC::Result validation{-99,0}; bool consumed=true;
    const int result=AC::handle(api,reinterpret_cast<void *>(0x3030),
        reinterpret_cast<void *>(0x4040),nullptr,nullptr,&envelope.request,true,
        &validation,&consumed);
    check(result==73 && validation.error==-1 && !consumed);
    check(copyCalls==0 && allocations==0 && frees==0 && originals==1);
    check(!registry.head && !allocationBase && !lockHeld);
    check(flagObservations==0 && surveyObservations==0);
    check(!memcmp(user,userBefore,sizeof(user)));
    check(!memcmp(&envelope.request,&request,sizeof(request)));
    return 0;
}

static int runIdentityInvalidated(size_t length) {
    resetState(length);flipIdentityOnSecondCheck=true;
    AC::API api{};
    api.original=original;api.copyIn=copyIn;api.allocate=allocate;
    api.deallocate=deallocate;api.currentThread=currentThread;
    api.registry=&registry;api.caller=Caller;api.primaryInterface=primary;
    api.observeFlags=observeFlags;api.observeSurvey=observeSurvey;
    AC::Result validation{-99,0};bool consumed=true;
    const int result=AC::handle(api,reinterpret_cast<void *>(0x3030),
        reinterpret_cast<void *>(0x4040),nullptr,nullptr,&envelope.request,true,
        &validation,&consumed);
    check(result==ESTALE && validation.error==0 && validation.field==0 && !consumed);
    check(primaryCalls==2 && copyCalls==1 && allocations==1 && frees==1 && originals==0);
    check(!registry.head && !allocationBase && !lockHeld);
    check(!memcmp(user,userBefore,sizeof(user)));
    check(!memcmp(&envelope.request,&request,sizeof(request)));
    for (uint8_t byte:envelope.trailer) check(byte==0x71);
    if (length==SonomaSize) check(flagObservations==0 && surveyObservations==0);
    else check(flagObservations==1 && surveyObservations==1);
    return 0;
}

int main(int argc,char **argv) {
    check(argc==2);
    switch (atoi(argv[1])) {
        case 1: return runSuccess(SonomaSize);
        case 2: return runSuccess(SequoiaSize);
        case 3: return runSuccess(TahoeSize);
        case 4: return runReject(false);
        case 5: return runReject(true);
        case 6: return runWrongIdentity();
        case 7: return runIdentityInvalidated(SonomaSize);
        case 8: return runIdentityInvalidated(SequoiaSize);
        case 9: return runIdentityInvalidated(TahoeSize);
        default: return 64;
    }
}
'''


@unittest.skipUnless(shutil.which("xcrun"), "Xcode command line tools required")
class AssociationProfileDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="association-profile-dispatch-")
        cls.binary = pathlib.Path(cls.tmp.name) / "dispatch-contract"
        build = subprocess.run(
            ["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
             "-I", str(PROJECT / "src/scan_kernel"), "-x", "c++", "-", "-o", str(cls.binary)],
            input=HARNESS, text=True, capture_output=True, timeout=60)
        if build.returncode:
            raise AssertionError(build.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_case(self, case):
        result = subprocess.run([str(self.binary), str(case)], capture_output=True,
                                text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_dispatches_all_supported_payload_sizes_without_mutation(self):
        for case in (1, 2, 3):
            with self.subTest(payload_size={1: 856, 2: 900, 3: 908}[case]):
                self.run_case(case)

    def test_sonoma_tail_and_scope_fail_closed_after_copy(self):
        self.run_case(4)
        self.run_case(5)

    def test_wrong_primary_identity_passes_directly_to_original(self):
        self.run_case(6)

    def test_primary_identity_lost_after_copy_fails_closed_for_all_profiles(self):
        for case in (7, 8, 9):
            with self.subTest(payload_size={7: 856, 8: 900, 9: 908}[case]):
                self.run_case(case)


if __name__ == "__main__":
    unittest.main()
