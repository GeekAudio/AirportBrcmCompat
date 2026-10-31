#!/usr/bin/env python3
"""Behavior-test scoped reset admission using the production function bodies."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
SOURCE = (PROJECT / 'src/awdl_kernel/scoped_reset.cpp').read_text()
HEADER = (PROJECT / 'src/awdl_kernel/scoped_reset.hpp').read_text()


def extract_cpp_block(source, marker, include_semicolon=False):
    """Extract one balanced C++ declaration/function starting at marker."""
    start = source.index(marker)
    opening = source.index('{', start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == '{':
            depth += 1
        elif source[index] == '}':
            depth -= 1
            if depth == 0:
                end = index + 1
                if include_semicolon:
                    while end < len(source) and source[end].isspace():
                        end += 1
                    if end < len(source) and source[end] == ';':
                        end += 1
                return source[start:end]
    raise AssertionError(f'unclosed C++ block for {marker!r}')


def behavior_harness():
    scope = extract_cpp_block(SOURCE, 'struct Scope {', include_semicolon=True)
    enter = extract_cpp_block(SOURCE, 'bool enter(Scope &scope)')
    leave = extract_cpp_block(SOURCE, 'void leave(Scope &scope)')
    active = extract_cpp_block(
        SOURCE, 'bool activeScopeForClientOnCurrentThread(IOUserClient *client)')
    gated = extract_cpp_block(SOURCE, 'IOReturn wrappedGated(')
    action = extract_cpp_block(SOURCE, 'IOReturn resetAction(')
    reset = extract_cpp_block(SOURCE, 'void wrappedReset(IOUserClient *client)')

    return r'''
#include <cassert>
#include <cstddef>
#include <cstdint>

using IOReturn = int;
using thread_t = uintptr_t;
constexpr thread_t THREAD_NULL = 0;
constexpr IOReturn kIOReturnSuccess = 0;
constexpr IOReturn kIOReturnNotReady = -1;
constexpr IOReturn kIOReturnFallback = 91;

struct OSObject {};
struct IOService : OSObject {};
struct IOUserClient : OSObject { uintptr_t f0=0, f8=0; };
struct IOWorkLoop;
struct IOCommandGate : OSObject {
    IOWorkLoop *loop = nullptr;
    bool enabled = true;
    IOWorkLoop *getWorkLoop() { return loop; }
    bool isEnabled() { return enabled; }
};
struct IOWorkLoop : OSObject {
    bool inside = false;
    bool inGate() { return inside; }
    template <class A>
    IOReturn runAction(IOReturn (*action)(OSObject *, void *, void *, void *, void *),
                       OSObject *owner, A *argument) {
        return action(owner, static_cast<void *>(argument), nullptr, nullptr, nullptr);
    }
};

using IOSimpleLock = int;
IOSimpleLock *scopeLock = nullptr;
unsigned long IOSimpleLockLockDisableInterrupt(IOSimpleLock *) { return 0; }
void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *, unsigned long) {}

thread_t currentThread = 1;
bool interruptContext = false;
thread_t current_thread() { return currentThread; }
bool ml_at_interrupt_context() { return interruptContext; }
bool ml_get_interrupts_enabled() { return true; }

struct ClientHandle {};
enum class ClientStatus { Passed, Failed };
struct ClientWorkLease {
    IOUserClient *clientValue=nullptr;
    IOService *controllerValue=nullptr;
    IOService *providerValue=nullptr;
    IOCommandGate *gateValue=nullptr;
    IOWorkLoop *loopValue=nullptr;
    IOUserClient *client() const { return clientValue; }
    IOService *controller() const { return controllerValue; }
    IOService *provider() const { return providerValue; }
    IOCommandGate *gate() const { return gateValue; }
    IOWorkLoop *workLoop() const { return loopValue; }
};
struct ClientRegistry {
    ClientStatus beginResult = ClientStatus::Failed;
    unsigned beginCalls = 0;
    unsigned acquireCalls = 0;
    ClientStatus beginClose(IOUserClient *, ClientHandle &) {
        ++beginCalls;
        return beginResult;
    }
    ClientStatus acquireClosing(IOUserClient *, ClientWorkLease &) {
        ++acquireCalls;
        return ClientStatus::Failed;
    }
};
ClientRegistry *registry = nullptr;

namespace NativeControlBridge {
unsigned markCalls = 0;
unsigned collectCalls = 0;
void markClientClosing(IOUserClient *) { ++markCalls; }
void collectClient(IOUserClient *) { ++collectCalls; }
}

using Reset = void (*)(IOUserClient *);
unsigned resetCalls = 0;
unsigned retiredProviderCalls = 0;
void mockReset(IOUserClient *) { ++resetCalls; }
Reset originalReset = mockReset;
bool retireOwnProvider(ClientWorkLease &lease) {
    ++retiredProviderCalls;
    lease.client()->f0=0;
    return true;
}
uintptr_t field(IOUserClient *client, size_t offset) {
    if (offset==0xf0) return client->f0;
    if (offset==0xf8) return client->f8;
    return 0;
}

unsigned gatedFallbackCalls = 0;
IOReturn airport_awdl_original_gated(OSObject *, void *, void *, void *, void *) {
    ++gatedFallbackCalls;
    return kIOReturnFallback;
}

bool enabled = true;
unsigned completeCount = 0, noCallbackCount = 0, retiredCount = 0;
''' + scope + r'''
Scope *scopes[8] {};
''' + enter + '\n' + leave + '\n' + active + '\n' + gated + '\n' + action + '\n' + reset + r'''

void clearScopes() {
    for (auto &scope : scopes) scope = nullptr;
}

void setScope(Scope &scope, IOUserClient *client, IOService *controller,
              IOService *provider, IOCommandGate *gate, IOWorkLoop *loop) {
    scope = Scope{};
    scope.thread = currentThread;
    scope.client = client;
    scope.controller = controller;
    scope.provider = provider;
    scope.gate = gate;
    scope.loop = loop;
    assert(enter(scope));
}

void rejectedCallback(int kind) {
    clearScopes();
    enabled = true;
    interruptContext = false;
    currentThread = 1;
    IOUserClient client;
    IOService controller, otherController, provider, otherProvider;
    IOWorkLoop loop, otherLoop;
    IOCommandGate gate;
    gate.loop = &loop;
    gate.enabled = true;
    loop.inside = true;
    Scope scope;
    setScope(scope, &client, &controller, &provider, &gate, &loop);
    OSObject *owner = &controller;
    void *arg0 = &provider;
    void *arg1 = nullptr, *arg2 = nullptr, *arg3 = nullptr;
    switch (kind) {
        case 0: currentThread = 2; break;                 // wrong thread
        case 1: owner = &otherController; break;          // wrong owner
        case 2: arg0 = &otherProvider; break;             // wrong provider
        case 3: arg1 = &client; break;                    // non-null arg1
        case 4: arg2 = &client; break;                    // non-null arg2
        case 5: arg3 = &client; break;                    // non-null arg3
        case 6: gate.enabled = false; break;              // disabled gate
        case 7: loop.inside = false; break;               // outside work loop
        case 8: gate.loop = &otherLoop; break;             // unbound/redirected gate
        case 9: enabled = false; break;                   // bridge disabled
        case 10: interruptContext = true; break;           // interrupt context
        default: assert(false);
    }
    gatedFallbackCalls = 0;
    const auto result = wrappedGated(owner, arg0, arg1, arg2, arg3);
    assert(result == kIOReturnFallback);
    assert(gatedFallbackCalls == 1);
    assert(!scope.consumed);
    if (kind == 0) assert(!activeScopeForClientOnCurrentThread(&client));
    leave(scope);
    clearScopes();
}

int main() {
    // Exact owner/provider/thread/argument tuple consumes once. A replay falls
    // through to the pinned original callback without consuming another scope.
    clearScopes();
    enabled = true;
    interruptContext = false;
    currentThread = 1;
    IOUserClient client;
    IOService controller, provider;
    IOWorkLoop loop;
    IOCommandGate gate;
    loop.inside = true;
    gate.loop = &loop;
    gate.enabled = true;
    Scope scope;
    setScope(scope, &client, &controller, &provider, &gate, &loop);
    assert(activeScopeForClientOnCurrentThread(&client));
    gatedFallbackCalls = 0;
    assert(wrappedGated(&controller, &provider, nullptr, nullptr, nullptr) == kIOReturnSuccess);
    assert(scope.consumed && gatedFallbackCalls == 0);
    assert(wrappedGated(&controller, &provider, nullptr, nullptr, nullptr) == kIOReturnFallback);
    assert(scope.consumed && gatedFallbackCalls == 1);
    leave(scope);
    assert(!activeScopeForClientOnCurrentThread(&client));
    clearScopes();

    // A nested second client on the same thread cannot enter and then invoke
    // the old reset callback with the outer client's matching owner/provider.
    clearScopes();
    IOUserClient outerClient, nestedClient;
    outerClient.f0=reinterpret_cast<uintptr_t>(&provider);
    nestedClient.f0=reinterpret_cast<uintptr_t>(&provider);
    Scope outerScope;
    setScope(outerScope, &outerClient, &controller, &provider, &gate, &loop);
    ClientWorkLease nestedLease;
    nestedLease.clientValue=&nestedClient;
    nestedLease.controllerValue=&controller;
    nestedLease.providerValue=&provider;
    nestedLease.gateValue=&gate;
    nestedLease.loopValue=&loop;
    resetCalls=0;
    retiredProviderCalls=0;
    gatedFallbackCalls=0;
    const auto nestedResult=resetAction(&controller,&nestedLease,nullptr,nullptr,nullptr);
    assert(nestedResult==kIOReturnNotReady);
    assert(resetCalls==0 && retiredProviderCalls==1 && gatedFallbackCalls==0);
    assert(!outerScope.consumed);
    assert(wrappedGated(&controller,&provider,nullptr,nullptr,nullptr)==kIOReturnSuccess);
    assert(outerScope.consumed && gatedFallbackCalls==0);
    leave(outerScope);

    // Same client remains forbidden across threads, while separate clients on
    // separate threads can coexist and consume only their own one-shot scope.
    clearScopes();
    currentThread=1;
    Scope firstThreadScope, sameClientOtherThread;
    setScope(firstThreadScope,&client,&controller,&provider,&gate,&loop);
    currentThread=2;
    sameClientOtherThread.client=&client;
    sameClientOtherThread.thread=currentThread;
    assert(!enter(sameClientOtherThread));
    IOUserClient secondThreadClient;
    Scope secondThreadScope;
    setScope(secondThreadScope,&secondThreadClient,&controller,&provider,&gate,&loop);
    assert(scopes[0]==&firstThreadScope && scopes[1]==&secondThreadScope);
    gatedFallbackCalls=0;
    assert(wrappedGated(&controller,&provider,nullptr,nullptr,nullptr)==kIOReturnSuccess);
    assert(secondThreadScope.consumed && !firstThreadScope.consumed);
    currentThread=1;
    assert(wrappedGated(&controller,&provider,nullptr,nullptr,nullptr)==kIOReturnSuccess);
    assert(firstThreadScope.consumed && secondThreadScope.consumed);
    leave(secondThreadScope);
    leave(firstThreadScope);
    clearScopes();

    for (int kind = 0; kind <= 10; ++kind) rejectedCallback(kind);

    // The actual same-thread close wrapper must recognize an active scope and
    // return before marking/closing the client or making a second reset call.
    clearScopes();
    enabled = true;
    interruptContext = false;
    currentThread = 1;
    ClientRegistry fakeRegistry;
    registry = &fakeRegistry;
    Scope reentrant;
    setScope(reentrant, &client, &controller, &provider, &gate, &loop);
    NativeControlBridge::markCalls = 0;
    resetCalls = 0;
    wrappedReset(&client);
    assert(NativeControlBridge::markCalls == 0);
    assert(fakeRegistry.beginCalls == 0);
    assert(resetCalls == 0);

    // The same close from a different thread is not mistaken for reentry.
    currentThread = 2;
    fakeRegistry.beginResult = ClientStatus::Failed;
    wrappedReset(&client);
    assert(NativeControlBridge::markCalls == 1);
    assert(fakeRegistry.beginCalls == 1);
    assert(resetCalls == 1);
    currentThread = 1;
    leave(reentrant);
    assert(!activeScopeForClientOnCurrentThread(&client));
    return 0;
}
'''


class ScopedResetContractTests(unittest.TestCase):
    def test_host_run_action_layout_is_not_a_precondition(self):
        for token in (
            'RunSymbol', 'RunActionCurrent', 'RunActionPlan',
            'resolveRunActionRelocations', 'actionReturn',
            '__builtin_return_address', 'kernel_contracts.hpp',
        ):
            with self.subTest(token=token):
                self.assertNotIn(token, SOURCE)

    def test_legacy_reset_identity_and_shape_remain_pinned(self):
        for token in (
            'LegacyUUID[16]', 'reset!=base+0xa652c',
            'gated!=base+0xb4974', 'ResetPrefix', 'GatedBody',
        ):
            with self.subTest(token=token):
                self.assertIn(token, SOURCE)

    def test_runtime_scope_admission_and_reentry(self):
        compiler = shutil.which('clang++')
        if not compiler:
            self.skipTest('clang++ unavailable for scoped-reset host harness')
        with tempfile.TemporaryDirectory(prefix='scoped-reset-behavior-') as tmp:
            harness = Path(tmp) / 'scoped_reset_behavior.cpp'
            binary = Path(tmp) / 'scoped_reset_behavior'
            harness.write_text(behavior_harness())
            built = subprocess.run(
                [compiler, '-std=c++14', '-Wall', '-Wextra', '-Werror',
                 str(harness), '-o', str(binary)],
                text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            ran = subprocess.run([str(binary)], text=True, capture_output=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)

    def test_header_documents_captured_synchronous_gate_scope(self):
        self.assertIn('retained synchronous gate scope', HEADER)


if __name__ == '__main__':
    unittest.main()
