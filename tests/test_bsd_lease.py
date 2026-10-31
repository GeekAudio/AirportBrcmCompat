#!/usr/bin/env python3
"""Exercise the production BSDLease implementation with host IOKit/KPI shims."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]


STUBS = {
    'IOKit/IOBSD.h': r'''#ifndef TEST_IOBSD_H
#define TEST_IOBSD_H
#define kIOBSDNameKey "BSD Name"
#endif
''',
    'IOKit/IOService.h': r'''#ifndef TEST_IOSERVICE_H
#define TEST_IOSERVICE_H
#include <string>
class OSObject;
class OSMetaClass {
    const char *name_;
public:
    explicit OSMetaClass(const char *value):name_(value) {}
    const char *getClassName() const { return name_; }
};
class IOService {
    OSMetaClass meta_;
    IOService *provider_=nullptr;
    bool inactive_=false;
public:
    std::string bsdName;
    explicit IOService(const char *className):meta_(className) {}
    virtual ~IOService()=default;
    const OSMetaClass *getMetaClass() const { return &meta_; }
    bool isInactive() const { return inactive_; }
    void setInactive(bool value) { inactive_=value; }
    IOService *getProvider() const { return provider_; }
    void setProvider(IOService *value) { provider_=value; }
    void setBSDName(const char *value) { bsdName=value; }
    OSObject *copyProperty(const char *key);
};
#endif
''',
    'IOKit/IOLocks.h': r'''#ifndef TEST_IOLOCKS_H
#define TEST_IOLOCKS_H
#include <mutex>
struct IOLock { std::mutex mutex; };
inline IOLock *IOLockAlloc() { return new IOLock; }
inline void IOLockLock(IOLock *lock) { lock->mutex.lock(); }
inline void IOLockUnlock(IOLock *lock) { lock->mutex.unlock(); }
#endif
''',
    'libkern/c++/OSString.h': r'''#ifndef TEST_OSSTRING_H
#define TEST_OSSTRING_H
#include <string>
class OSObject {
public:
    virtual ~OSObject()=default;
    virtual void release() { delete this; }
};
class OSString:public OSObject {
    std::string value_;
public:
    explicit OSString(const std::string &value):value_(value) {}
    unsigned int getLength() const { return static_cast<unsigned int>(value_.size()); }
    const char *getCStringNoCopy() const { return value_.c_str(); }
};
#define OSDynamicCast(type,obj) dynamic_cast<type *>(obj)
#endif
''',
    'net/kpi_interface.h': r'''#ifndef TEST_KPI_INTERFACE_H
#define TEST_KPI_INTERFACE_H
#include <stdint.h>
struct IfnetMock { void *softc; const char *name; uint32_t unit; };
using ifnet_t=IfnetMock *;
extern unsigned softcReads, nameReads, unitReads;
inline void *ifnet_softc(ifnet_t value) {
    ++softcReads; return value ? value->softc : nullptr;
}
inline const char *ifnet_name(ifnet_t value) {
    ++nameReads; return value ? value->name : nullptr;
}
inline uint32_t ifnet_unit(ifnet_t value) {
    ++unitReads; return value ? value->unit : 0;
}
#endif
''',
    'kern/thread.h': r'''#ifndef TEST_THREAD_H
#define TEST_THREAD_H
inline void *current_thread() { static thread_local int token; return &token; }
#endif
''',
}


HARNESS = r'''
#include "bsd_lease.hpp"
#include <IOKit/IOBSD.h>
#include <libkern/c++/OSString.h>
#include <kern/thread.h>
#include <net/kpi_interface.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <thread>

constexpr PrivateMAC::BSDLease::CallbackPin kConstInitializedCallbackPin{};
static_assert(sizeof(kConstInitializedCallbackPin)>0,
              "callback pin supports constant initialization");

unsigned softcReads=0, nameReads=0, unitReads=0;
OSObject *IOService::copyProperty(const char *key) {
    return key && !strcmp(key,kIOBSDNameKey)
        ? static_cast<OSObject *>(new OSString(bsdName)) : nullptr;
}

static int runtimeStatus=0;
static int runtimeBuild() { return runtimeStatus; }
static const uintptr_t kProtocol=0x31, kCommand=0x802069c8;
static const uintptr_t kData=0x7f001234;
static const int kNativeError=EIO;
static unsigned nativeIoctlCalls=0, nativeCallbackCalls=0, nativePerformCalls=0;
static unsigned authorizedHeldCalls=0;
static uint64_t lastGeneration=0;
static bool nestedRootAttempt=false;
static bool probeForeignScopes=false;
static bool duplicatePerformEntry=false;
static bool mismatchHeldIdentity=false;
static bool repeatCallbackWithinRoot=false;
static bool invokePerformer=true;
static uintptr_t callbackIfpDelta=0, callbackCommandDelta=0, callbackDataDelta=0;
static uintptr_t performIfpDelta=0, performCommandDelta=0, performDataDelta=0;
static IOService *performInterfaceOverride=nullptr;

static PrivateMAC::BSDLease::CallbackPin pin;
static IOService controller("AirPort_BrcmNIC");
static IOService primary("AirPort_BrcmNIC_Interface");
static IOService otherPrimary("AirPort_BrcmNIC_Interface");
static IfnetMock ifnet{&primary,"en",7};

static ifnet_t adjustedIfnet(ifnet_t base, uintptr_t delta) {
    return reinterpret_cast<ifnet_t>(reinterpret_cast<uintptr_t>(base)^delta);
}
static void *adjustedData(void *base, uintptr_t delta) {
    return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(base)^delta);
}
static int publicWrapper(ifnet_t rootIfp=&ifnet,uintptr_t protocol=kProtocol,
                         uintptr_t command=kCommand,
                         void *data=reinterpret_cast<void *>(kData),
                         bool allowCallback=true);
static int performWrapper(uintptr_t ifpDelta=0,uintptr_t commandDelta=0,
                          uintptr_t dataDelta=0) {
    using namespace PrivateMAC::BSDLease;
    Scope scope;
    IOService *interface=performInterfaceOverride?performInterfaceOverride:&primary;
    const ifnet_t candidate=adjustedIfnet(&ifnet,ifpDelta);
    const uintptr_t command=kCommand^commandDelta;
    void *data=reinterpret_cast<void *>(kData^dataDelta);
    const int admission=scope.enterScoped(pin,&controller,interface,candidate,
                                          command,data);
    if (admission==0) {
        if (duplicatePerformEntry) {
            duplicatePerformEntry=false;
            assert(scope.enterScoped(pin,&controller,interface,candidate,
                                     command,data)==EOPNOTSUPP);
            assert(!held(&controller,interface,candidate,nullptr));
        } else if (mismatchHeldIdentity) {
            mismatchHeldIdentity=false;
            assert(!held(&controller,interface,adjustedIfnet(&ifnet,1),nullptr));
            assert(!held(&controller,interface,candidate,nullptr));
        } else {
            uint64_t generation=0;
            assert(held(&controller,interface,candidate,&generation));
            assert(generation!=0);
            ++authorizedHeldCalls;
            lastGeneration=generation;
        }
    } else {
        assert(!held(&controller,interface,candidate,nullptr));
    }
    ++nativePerformCalls;
    return kNativeError;
}

static int originalCallback(ifnet_t callbackIfp,uintptr_t command,void *data) {
    (void)callbackIfp;(void)command;(void)data;
    ++nativeCallbackCalls;
    return invokePerformer
        ? performWrapper(performIfpDelta,performCommandDelta,performDataDelta)
        : EBUSY;
}
static int callbackWrapper(ifnet_t callbackIfp,uintptr_t command,void *data) {
    using namespace PrivateMAC::BSDLease;
    CallbackScope scope;
    const int admission=scope.enter(pin,adjustedIfnet(callbackIfp,callbackIfpDelta),
                                    command^callbackCommandDelta,
                                    adjustedData(data,callbackDataDelta));
    (void)admission; // The fixed native callback still runs on every path.
    return originalCallback(callbackIfp,command,data);
}

static int originalIfnetIoctl(bool allowCallback) {
    ++nativeIoctlCalls;
    if (probeForeignScopes) {
        bool foreignCallbackRejected=false, foreignRootAccepted=false;
        std::thread other([&] {
            using namespace PrivateMAC::BSDLease;
            CallbackScope foreignCallback;
            foreignCallbackRejected=
                foreignCallback.enter(pin,&ifnet,kCommand,
                                      reinterpret_cast<void *>(kData))==EOPNOTSUPP;
            RootScope independentRoot;
            foreignRootAccepted=
                independentRoot.enter(pin,&ifnet,kProtocol,kCommand,
                                      reinterpret_cast<void *>(kData))==0;
        });
        other.join();
        assert(foreignCallbackRejected && foreignRootAccepted);
        probeForeignScopes=false;
    }
    if (nestedRootAttempt) {
        nestedRootAttempt=false;
        // The nested wrapper's root admission fails, but its original public
        // KPI function still runs exactly once and returns its native error.
        assert(publicWrapper(&ifnet,kProtocol,kCommand,
                             reinterpret_cast<void *>(kData),false)==ENOTTY);
    }
    if (repeatCallbackWithinRoot) {
        repeatCallbackWithinRoot=false;
        invokePerformer=false;
        assert(callbackWrapper(&ifnet,kCommand,reinterpret_cast<void *>(kData))==EBUSY);
        invokePerformer=true;
        return callbackWrapper(&ifnet,kCommand,reinterpret_cast<void *>(kData));
    }
    return allowCallback
        ? callbackWrapper(&ifnet,kCommand,reinterpret_cast<void *>(kData)) : ENOTTY;
}

static int publicWrapper(ifnet_t rootIfp,uintptr_t protocol,
                         uintptr_t command,void *data,bool allowCallback) {
    using namespace PrivateMAC::BSDLease;
    RootScope scope;
    (void)scope.enter(pin,rootIfp,protocol,command,data);
    // This is the wrapper contract under test: admission never skips/repeats
    // the native public KPI call, and its return code is returned unchanged.
    return originalIfnetIoctl(allowCallback);
}

static void resetCounts() {
    nativeIoctlCalls=0;nativeCallbackCalls=0;nativePerformCalls=0;
    authorizedHeldCalls=0;lastGeneration=0;
    softcReads=0;nameReads=0;unitReads=0;
}

int main() {
    using namespace PrivateMAC::BSDLease;
    controller.setBSDName("en7");
    primary.setProvider(&controller);primary.setBSDName("en7");
    otherPrimary.setProvider(&controller);otherPrimary.setBSDName("en7");
    assert(pin.preparePublicKPI(runtimeBuild)==0);
    CallbackPin duplicatePin;
    assert(duplicatePin.preparePublicKPI(runtimeBuild)==EBUSY);

    // Exact public root -> fixed callback -> perform path inherits protocol,
    // claims once, validates identity after claim, and keeps the native error.
    resetCounts();
    const int successPath=publicWrapper();
    assert(successPath==kNativeError);
    assert(nativeIoctlCalls==1 && nativeCallbackCalls==1 && nativePerformCalls==1);
    assert(authorizedHeldCalls==1 && lastGeneration!=0);
    assert(softcReads==1 && nameReads==1 && unitReads==1);
    assert(!held(&controller,&primary,&ifnet,nullptr));

    // A foreign thread cannot borrow the current thread's root callback token,
    // but can own and clean up its independent public root under the same lock.
    resetCounts();probeForeignScopes=true;
    assert(publicWrapper()==kNativeError);
    assert(nativeIoctlCalls==1 && nativeCallbackCalls==1 && nativePerformCalls==1);
    assert(authorizedHeldCalls==1);

    // The root stores only opaque values: an invalid ifnet address is safe
    // when the original call does not enter the fixed callback.
    resetCounts();
    assert(publicWrapper(reinterpret_cast<ifnet_t>(uintptr_t(1)),kProtocol,
                         kCommand,reinterpret_cast<void *>(kData),false)==ENOTTY);
    assert(nativeIoctlCalls==1 && nativeCallbackCalls==0 && nativePerformCalls==0);
    assert(softcReads==0 && nameReads==0 && unitReads==0);

    // An early native return without callback leaves no authorization behind.
    resetCounts();invokePerformer=false;
    assert(publicWrapper()==EBUSY);
    assert(nativeIoctlCalls==1 && nativeCallbackCalls==1 && nativePerformCalls==0);
    invokePerformer=true;
    resetCounts();
    assert(callbackWrapper(&ifnet,kCommand,reinterpret_cast<void *>(kData))==kNativeError);
    assert(nativeCallbackCalls==1 && nativePerformCalls==1);
    assert(authorizedHeldCalls==0 && softcReads==0);

    // Callback tuple mismatch refuses its sub-scope, but preserves the one
    // native callback and perform invocation and their error result.
    for (int mismatch=0;mismatch<3;++mismatch) {
        resetCounts();
        callbackIfpDelta=mismatch==0?1:0;
        callbackCommandDelta=mismatch==1?1:0;
        callbackDataDelta=mismatch==2?1:0;
        assert(publicWrapper()==kNativeError);
        assert(nativeIoctlCalls==1 && nativeCallbackCalls==1 && nativePerformCalls==1);
        assert(authorizedHeldCalls==0 && softcReads==0);
    }
    callbackIfpDelta=callbackCommandDelta=callbackDataDelta=0;

    // A perform with one mismatched tuple field is rejected after the callback
    // began; no driver identity reads or held authorization are allowed.
    for (int mismatch=0;mismatch<3;++mismatch) {
        resetCounts();
        performIfpDelta=mismatch==0?1:0;
        performCommandDelta=mismatch==1?1:0;
        performDataDelta=mismatch==2?1:0;
        assert(publicWrapper()==kNativeError);
        assert(nativeIoctlCalls==1 && nativeCallbackCalls==1 && nativePerformCalls==1);
        assert(authorizedHeldCalls==0 && softcReads==0);
    }
    performIfpDelta=performCommandDelta=performDataDelta=0;

    // A duplicate perform attempt on the same scoped object revokes the
    // single ticket before held() can authorize a private transaction.
    resetCounts();duplicatePerformEntry=true;
    assert(publicWrapper()==kNativeError);
    assert(nativeIoctlCalls==1 && nativeCallbackCalls==1 && nativePerformCalls==1);
    assert(authorizedHeldCalls==0 && softcReads==1);

    // A held() identity mismatch revokes the ticket; a later exact retry on
    // that stack frame cannot restore it.
    resetCounts();mismatchHeldIdentity=true;
    assert(publicWrapper()==kNativeError);
    assert(nativeIoctlCalls==1 && nativeCallbackCalls==1 && nativePerformCalls==1);
    assert(authorizedHeldCalls==0 && softcReads==1);

    // Once the exact perform tuple is claimed, a wrong interface fails the
    // existing softc/provider/name validation and never creates a held scope.
    resetCounts();performInterfaceOverride=&otherPrimary;
    assert(publicWrapper()==kNativeError);
    assert(nativeIoctlCalls==1 && nativeCallbackCalls==1 && nativePerformCalls==1);
    assert(authorizedHeldCalls==0 && softcReads==1 && nameReads==0);
    performInterfaceOverride=nullptr;

    // A repeated fixed callback is a violation even after its first scope has
    // ended; the second callback still runs natively but cannot inherit root.
    resetCounts();repeatCallbackWithinRoot=true;
    assert(publicWrapper()==kNativeError);
    assert(nativeIoctlCalls==1 && nativeCallbackCalls==2 && nativePerformCalls==1);
    assert(authorizedHeldCalls==0 && softcReads==0);

    // Same-thread nested root invalidates the outer ticket until outer exit.
    // The inner rejected wrapper still calls its native KPI exactly once.
    resetCounts();nestedRootAttempt=true;
    assert(publicWrapper()==kNativeError);
    assert(nativeIoctlCalls==2 && nativeCallbackCalls==1 && nativePerformCalls==1);
    assert(authorizedHeldCalls==0 && softcReads==0);

    // Runtime rejection is not converted to success and does not suppress the
    // original public call. A known-mode Scope cannot be used as fallback.
    resetCounts();runtimeStatus=1;
    assert(publicWrapper()==kNativeError);
    assert(nativeIoctlCalls==1 && nativeCallbackCalls==1 && nativePerformCalls==1);
    assert(authorizedHeldCalls==0);
    Scope noLegacyFallback;
    assert(noLegacyFallback.enter(pin,0,&controller,&primary,&ifnet)==ENXIO);
    runtimeStatus=0;
}
'''


class BSDLeaseTests(unittest.TestCase):
    def test_callback_pin_constant_initialization_has_no_global_constructor(self):
        compiler = shutil.which('clang++') or shutil.which('g++')
        nm = shutil.which('nm')
        if not compiler or not nm:
            self.skipTest('C++ compiler and nm required')
        with tempfile.TemporaryDirectory(prefix='bsd-lease-static-init-') as folder:
            root = Path(folder)
            for relative, contents in STUBS.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            source = root / 'static.cpp'
            object_file = root / 'static.o'
            source.write_text(
                '#include "bsd_lease.hpp"\n'
                'PrivateMAC::BSDLease::CallbackPin callbackPin;\n')
            build = subprocess.run(
                [compiler, '-std=c++14', '-Wall', '-Wextra', '-Werror', '-c',
                 '-I', str(root), '-I', str(PROJECT / 'src/private_mac_compat'),
                 '-I', str(PROJECT / 'src/scan_kernel'), str(source), '-o',
                 str(object_file)], text=True, capture_output=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            symbols = subprocess.run([nm, str(object_file)], text=True,
                                     capture_output=True, timeout=10)
            self.assertEqual(symbols.returncode, 0, symbols.stderr)
            self.assertNotRegex(symbols.stdout,
                                r'__cxx_global_var_init|__GLOBAL__sub_I')

    def test_real_bsd_lease_cpp_public_kpi_scopes(self):
        compiler = shutil.which('clang++') or shutil.which('g++')
        if not compiler:
            self.skipTest('C++ compiler unavailable')
        with tempfile.TemporaryDirectory(prefix='bsd-lease-kpi-') as folder:
            root = Path(folder)
            for relative, contents in STUBS.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            source = root / 'harness.cpp'
            binary = root / 'harness'
            source.write_text(HARNESS)
            build = subprocess.run(
                [compiler, '-std=c++14', '-Wall', '-Wextra', '-Werror',
                 '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                 '-pthread', '-I', str(root),
                 '-I', str(PROJECT / 'src/private_mac_compat'),
                 '-I', str(PROJECT / 'src/scan_kernel'), str(source),
                 str(PROJECT / 'src/private_mac_compat/bsd_lease.cpp'),
                 '-o', str(binary)], text=True, capture_output=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            environment = dict(os.environ)
            environment['ASAN_OPTIONS'] = 'detect_leaks=0'
            run = subprocess.run([str(binary)], text=True, capture_output=True,
                                 timeout=10, env=environment)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main()
