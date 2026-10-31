"""Primary Brcm interface identity and production BSD callback lease checks."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[1]

NAME_HARNESS = r'''
#include "primary_interface.hpp"
#include <assert.h>
#include <initializer_list>
#include <string.h>
using namespace PrimaryInterface;

static void fixedName(char (&out)[RequestNameBytes],const char *text) {
    memset(out,0,sizeof(out));size_t n=strlen(text);assert(n<sizeof(out));memcpy(out,text,n);
}
int main() {
    for (const char *text : {"en0","en1","en7"}) {
        char request[RequestNameBytes];fixedName(request,text);
        Name parsed;assert(parseRequestName(request,parsed));
        assert(parsed.length==strlen(text));assert(parsed.unit==static_cast<uint32_t>(text[2]-'0'));
        ServiceFacts facts{true,true,true,true};uint32_t unit=UINT32_MAX;
        assert(requestMatchesPrimaryService(request,text,strlen(text),facts,&unit));
        assert(unit==parsed.unit);
    }
    ServiceFacts good{true,true,true,true};Name parsed;
    for (const char *text : {"","en","enx","awdl0","llw0","en-1","en01",
                             "en4294967296","en7x"}) {
        char request[RequestNameBytes];fixedName(request,text);
        assert(!parseRequestName(request,parsed));
        assert(!requestMatchesPrimaryService(request,text,strlen(text),good));
    }
    char request[RequestNameBytes];fixedName(request,"en7");
    request[15]=1;assert(!parseRequestName(request,parsed));
    fixedName(request,"en7");assert(!sameRequestAndProperty(request,"en1",3));
    ServiceFacts awdl{true,false,true,true};
    assert(!requestMatchesPrimaryService(request,"en7",3,awdl));
    ServiceFacts wrongController{false,true,true,true};
    assert(!requestMatchesPrimaryService(request,"en7",3,wrongController));
    ServiceFacts wrongProvider{true,true,false,true};
    assert(!requestMatchesPrimaryService(request,"en7",3,wrongProvider));
    ServiceFacts inactive{true,true,true,false};
    assert(!requestMatchesPrimaryService(request,"en7",3,inactive));
}
'''

LEASE_HARNESS = r'''
#include "bsd_lease.hpp"
#include <IOKit/IOBSD.h>
#include <libkern/c++/OSString.h>
#include <kern/thread.h>
#include <net/kpi_interface.h>
#include <assert.h>
#include <errno.h>
#include <thread>

OSObject *IOService::copyProperty(const char *key) {
    return key && !strcmp(key,kIOBSDNameKey) ? static_cast<OSObject *>(new OSString(bsdName)) : nullptr;
}

static int runtimeBuild() { return 0; }
int main() {
    IOService controller("AirPort_BrcmNIC");
    IOService primary("AirPort_BrcmNIC_Interface");
    primary.setProvider(&controller);
    primary.setBSDName("en7");
    IfnetMock ifp{&primary,"en",7}; // Darwin ifnet_name() is a prefix; unit is separate.
    IfnetMock sameNameDifferentIfp{&primary,"en",7};

    KernelContracts::IfnetIoctlPlan plan{};
    plan.imageBase=0x1000;plan.callbackReturnPC=0x1272;plan.imageSpan=0x340;
    plan.proofTag=KernelContracts::IfnetPlanProof;
    PrivateMAC::BSDLease::CallbackPin pin;
    assert(pin.prepare(plan,runtimeBuild)==0);

    uint64_t firstGeneration=0;
    {
        PrivateMAC::BSDLease::Scope scope;
        assert(scope.enter(pin,0x1272,&controller,&primary,&ifp)==0);
        assert(PrivateMAC::BSDLease::held(&controller,&primary,&ifp,&firstGeneration));
        assert(firstGeneration!=0);
        assert(!PrivateMAC::BSDLease::held(&controller,&primary,&sameNameDifferentIfp,nullptr));

        bool otherThreadHeld=true;
        std::thread other([&] {
            otherThreadHeld=PrivateMAC::BSDLease::held(&controller,&primary,&ifp,nullptr);
        });
        other.join();
        assert(!otherThreadHeld); // A borrowed callback lease is thread-local.

        IfnetMock wrongPrefix{&primary,"en7",7};
        PrivateMAC::BSDLease::Scope rejected;
        assert(rejected.enter(pin,0x1272,&controller,&primary,&wrongPrefix)==ENXIO);
        IfnetMock wrongUnit{&primary,"en",1};
        assert(rejected.enter(pin,0x1272,&controller,&primary,&wrongUnit)==ENXIO);
    }
    assert(!PrivateMAC::BSDLease::held(&controller,&primary,&ifp,nullptr)); // Scope expired.

    uint64_t nextGeneration=0;
    {
        PrivateMAC::BSDLease::Scope next;
        assert(next.enter(pin,0x1272,&controller,&primary,&ifp)==0);
        assert(PrivateMAC::BSDLease::held(&controller,&primary,&ifp,&nextGeneration));
        assert(nextGeneration>firstGeneration); // A saved generation cannot cross callbacks.
    }
}
'''


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
    const char *name;
public:
    explicit OSMetaClass(const char *value):name(value) {}
    const char *getClassName() const { return name; }
};
class IOService {
    OSMetaClass meta;
    IOService *provider=nullptr;
    bool inactive=false;
public:
    std::string bsdName;
    explicit IOService(const char *className):meta(className) {}
    virtual ~IOService()=default;
    const OSMetaClass *getMetaClass() const { return &meta; }
    bool isInactive() const { return inactive; }
    void setInactive(bool value) { inactive=value; }
    IOService *getProvider() const { return provider; }
    void setProvider(IOService *value) { provider=value; }
    void setBSDName(const char *value) { bsdName=value; }
    OSObject *copyProperty(const char *key);
};
#endif
''',
    'IOKit/IOLocks.h': r'''#ifndef TEST_IOLOCKS_H
#define TEST_IOLOCKS_H
#include <mutex>
struct IOLock { std::mutex value; };
inline IOLock *IOLockAlloc() { return new IOLock; }
inline void IOLockLock(IOLock *lock) { lock->value.lock(); }
inline void IOLockUnlock(IOLock *lock) { lock->value.unlock(); }
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
    std::string value;
public:
    explicit OSString(const std::string &text):value(text) {}
    unsigned int getLength() const { return static_cast<unsigned int>(value.size()); }
    const char *getCStringNoCopy() const { return value.c_str(); }
};
#define OSDynamicCast(type,obj) dynamic_cast<type *>(obj)
#endif
''',
    'net/kpi_interface.h': r'''#ifndef TEST_KPI_INTERFACE_H
#define TEST_KPI_INTERFACE_H
#include <stdint.h>
struct IfnetMock { void *softc; const char *name; uint32_t unit; };
using ifnet_t=IfnetMock *;
inline void *ifnet_softc(ifnet_t value) { return value ? value->softc : nullptr; }
inline const char *ifnet_name(ifnet_t value) { return value ? value->name : nullptr; }
inline uint32_t ifnet_unit(ifnet_t value) { return value ? value->unit : 0; }
#endif
''',
    'kern/thread.h': r'''#ifndef TEST_THREAD_H
#define TEST_THREAD_H
inline void *current_thread() { static thread_local int token; return &token; }
#endif
''',
}


@unittest.skipUnless(shutil.which('clang++'), 'C++ compiler required')
class PrimaryInterfaceTests(unittest.TestCase):
    def compile_and_run(self, source_text, include_dirs, extra_sources=()):
        with tempfile.TemporaryDirectory(prefix='primary-interface-') as folder:
            temp = pathlib.Path(folder)
            source = temp / 'test.cpp'
            binary = temp / 'test'
            source.write_text(source_text)
            command = ['clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror']
            command.extend(f'-I{directory}' for directory in include_dirs)
            command.extend([str(source), *(str(path) for path in extra_sources), '-o', str(binary)])
            build = subprocess.run(command, text=True, capture_output=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], text=True, capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_names_and_primary_service_identity(self):
        self.compile_and_run(NAME_HARNESS, [PROJECT / 'src/scan_kernel'])

    def test_actual_bsd_lease_uses_ifnet_prefix_and_exact_borrowed_lifetime(self):
        with tempfile.TemporaryDirectory(prefix='primary-interface-stubs-') as folder:
            stub_root = pathlib.Path(folder)
            for name, body in STUBS.items():
                path = stub_root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            self.compile_and_run(
                LEASE_HARNESS,
                [stub_root, PROJECT / 'src/private_mac_compat', PROJECT / 'src/scan_kernel'],
                [PROJECT / 'src/private_mac_compat/bsd_lease.cpp'],
            )


if __name__ == '__main__':
    unittest.main()
