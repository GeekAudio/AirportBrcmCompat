#!/usr/bin/env python3
"""Compile and exercise the production ifnet nested-scope core offline."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]


HARNESS = r'''
#include <cassert>
#include <cstdint>
#include <mutex>
#include <thread>
#include <type_traits>
#include <vector>

#include "src/private_mac_compat/ifnet_scope_core.hpp"

using namespace PrivateMAC::IfnetScopeCore;

constexpr Registry kConstInitializedRegistry{};
constexpr Tuple kConstInitializedTuple{1, 2, 3, 4};
static_assert(kConstInitializedTuple.ifp==1, "constexpr tuple initialization");
static_assert(sizeof(kConstInitializedRegistry)>0, "constexpr registry initialization");

static_assert(!std::is_copy_constructible<RootTicket>::value, "root ticket copy");
static_assert(!std::is_move_constructible<RootTicket>::value, "root ticket move");
static_assert(!std::is_copy_constructible<CallbackTicket>::value, "callback ticket copy");
static_assert(!std::is_copy_constructible<PerformTicket>::value, "perform ticket copy");

static Tuple tuple(uintptr_t seed=0) {
    return Tuple(0x1000+seed, 0x2000+seed, 0x3000+seed, 0x4000+seed);
}

static void successfulRouteAndReuse() {
    Registry registry;
    RootTicket root;
    CallbackTicket callback;
    PerformTicket perform;
    const Tuple request = tuple(1);

    assert(registry.beginRoot(11, request, root));
    assert(root.active());
    assert(registry.beginCallback(root, 11, request, callback));
    assert(registry.claimPerform(callback, 11, request, perform));
    assert(registry.held(perform, 11, request));
    assert(registry.held(perform, 11, request));
    assert(registry.endPerform(11, perform));
    assert(!perform.active());
    assert(!registry.held(perform, 11, request));
    assert(registry.endCallback(11, callback));
    assert(!callback.active());
    assert(registry.endRoot(11, root) == RootResult::Performed);
    assert(!root.active());

    // A cleared ticket object can be reused; the new authorization gets a new
    // registry nonce and has no inherited callback/perform state.
    assert(registry.beginRoot(11, request, root));
    assert(registry.endRoot(11, root) == RootResult::NoCallback);
}

static void nestedRootInvalidatesOuter() {
    Registry registry;
    RootTicket outer, nested;
    CallbackTicket callback;
    const Tuple request = tuple(2);
    assert(registry.beginRoot(21, request, outer));
    assert(!registry.beginRoot(21, request, nested));
    assert(!nested.active());
    assert(!registry.beginCallback(outer, 21, request, callback));
    assert(registry.endRoot(21, outer) == RootResult::Rejected);
    assert(!outer.active());
    assert(registry.beginRoot(21, request, nested));
    assert(registry.endRoot(21, nested) == RootResult::NoCallback);
}

static void tupleAndDuplicateFailuresRevoke() {
    {
        Registry registry;
        RootTicket root;
        CallbackTicket callback;
        assert(registry.beginRoot(31, tuple(3), root));
        assert(!registry.beginCallback(root, 31, tuple(4), callback));
        assert(registry.endRoot(31, root) == RootResult::Rejected);
    }
    {
        Registry registry;
        RootTicket root;
        CallbackTicket callback;
        const Tuple request = tuple(5);
        assert(registry.beginRoot(32, request, root));
        assert(registry.beginCallback(root, 32, request, callback));
        assert(registry.endCallback(32, callback));
        assert(!registry.beginCallback(root, 32, request, callback));
        assert(registry.endRoot(32, root) == RootResult::Rejected);
    }
    {
        Registry registry;
        RootTicket root;
        CallbackTicket callback;
        PerformTicket perform;
        const Tuple request = tuple(6);
        assert(registry.beginRoot(33, request, root));
        assert(registry.beginCallback(root, 33, request, callback));
        assert(!registry.claimPerform(callback, 33, tuple(7), perform));
        assert(registry.endCallback(33, callback) == false);
        assert(registry.endRoot(33, root) == RootResult::Rejected);
    }
    {
        Registry registry;
        RootTicket root;
        CallbackTicket callback;
        PerformTicket first, duplicate;
        const Tuple request = tuple(8);
        assert(registry.beginRoot(34, request, root));
        assert(registry.beginCallback(root, 34, request, callback));
        assert(registry.claimPerform(callback, 34, request, first));
        assert(registry.endPerform(34, first));
        assert(!registry.claimPerform(callback, 34, request, duplicate));
        assert(registry.endCallback(34, callback) == false);
        assert(registry.endRoot(34, root) == RootResult::Rejected);
    }
    {
        Registry registry;
        RootTicket root;
        CallbackTicket callback;
        PerformTicket perform;
        const Tuple request = tuple(9);
        assert(registry.beginRoot(35, request, root));
        assert(registry.beginCallback(root, 35, request, callback));
        assert(registry.claimPerform(callback, 35, request, perform));
        assert(!registry.held(perform, 35, tuple(10)));
        assert(!registry.endPerform(35, perform));
        assert(!registry.endCallback(35, callback));
        assert(registry.endRoot(35, root) == RootResult::Rejected);
    }
}

static void everyTupleFieldIsComparedExactly() {
    const Tuple request = tuple(18);
    const Tuple changed[] = {
        Tuple(request.ifp+1, request.protocol, request.command, request.data),
        Tuple(request.ifp, request.protocol+1, request.command, request.data),
        Tuple(request.ifp, request.protocol, request.command+1, request.data),
        Tuple(request.ifp, request.protocol, request.command, request.data+1)
    };
    for (size_t i=0; i<4; ++i) {
        Registry registry;
        RootTicket root;
        CallbackTicket callback;
        assert(registry.beginRoot(36+i, request, root));
        assert(!registry.beginCallback(root, 36+i, changed[i], callback));
        assert(registry.endRoot(36+i, root) == RootResult::Rejected);
    }
}

static void earlyEndAndStaleChildCannotAuthorizeNewRoot() {
    Registry registry;
    RootTicket oldRoot, newRoot;
    CallbackTicket oldCallback;
    PerformTicket stalePerform;
    const Tuple request = tuple(11);

    assert(registry.beginRoot(41, request, oldRoot));
    assert(registry.beginCallback(oldRoot, 41, request, oldCallback));
    assert(registry.claimPerform(oldCallback, 41, request, stalePerform));
    // Ending the root while descendants remain active is a hard failure and
    // removes the slot. Child tickets become stale and cannot reach a reused slot.
    assert(registry.endRoot(41, oldRoot) == RootResult::Rejected);
    assert(!oldRoot.active());
    assert(registry.beginRoot(41, request, newRoot));
    assert(!registry.claimPerform(oldCallback, 41, request, stalePerform));
    assert(!registry.endPerform(41, stalePerform));
    assert(!stalePerform.active());
    assert(!registry.endCallback(41, oldCallback));
    assert(!oldCallback.active());

    CallbackTicket freshCallback;
    assert(registry.beginCallback(newRoot, 41, request, freshCallback));
    assert(registry.endCallback(41, freshCallback));
    assert(registry.endRoot(41, newRoot) == RootResult::CallbackNoPerform);
}

static void wrongThreadRevokesButForeignRootIsIndependent() {
    Registry registry;
    RootTicket first, second;
    CallbackTicket callback;
    const Tuple a = tuple(12), b = tuple(13);
    assert(registry.beginRoot(51, a, first));
    assert(registry.beginRoot(52, b, second));
    assert(!registry.beginCallback(first, 52, a, callback));
    assert(registry.endRoot(51, first) == RootResult::Rejected);
    assert(registry.beginCallback(second, 52, b, callback));
    assert(registry.endCallback(52, callback));
    assert(registry.endRoot(52, second) == RootResult::CallbackNoPerform);
}

static void capacityAndFullRegistryNestedInvalidation() {
    Registry registry;
    RootTicket roots[Registry::Capacity];
    for (size_t i=0; i<Registry::Capacity; ++i)
        assert(registry.beginRoot(100+i, tuple(i), roots[i]));
    RootTicket overflow;
    assert(!registry.beginRoot(1000, tuple(1000), overflow));

    // Even at capacity, a same-thread nested begin invalidates that thread's
    // outer authorization instead of silently leaving it live.
    RootTicket nested;
    assert(!registry.beginRoot(100, tuple(0), nested));
    assert(registry.endRoot(100, roots[0]) == RootResult::Rejected);
    assert(registry.beginRoot(1000, tuple(1000), overflow));
    assert(registry.endRoot(1000, overflow) == RootResult::NoCallback);
    for (size_t i=1; i<Registry::Capacity; ++i)
        assert(registry.endRoot(100+i, roots[i]) == RootResult::NoCallback);
}

static void nonceOverflowPermanentlyRejectsNewScopes() {
    Registry registry(UINT64_MAX-2);
    RootTicket first, last, rejected;
    CallbackTicket callback;
    PerformTicket perform;
    const Tuple request=tuple(14);
    assert(registry.beginRoot(61, request, first)); // nonce UINT64_MAX-1
    assert(registry.beginRoot(62, request, last));  // nonce UINT64_MAX
    assert(registry.beginCallback(last,62,request,callback));
    assert(registry.claimPerform(callback,62,request,perform));
    assert(!registry.beginRoot(63,tuple(15),rejected)); // Overflow poisons all.
    assert(!registry.held(perform,62,request));
    assert(!registry.endPerform(62,perform));
    assert(!registry.endCallback(62,callback));
    assert(registry.endRoot(61,first)==RootResult::Rejected);
    assert(registry.endRoot(62,last)==RootResult::Rejected);
    assert(!registry.beginRoot(63,tuple(16),rejected));
}

static void issuerAndStaleGenerationAreBound() {
    Registry one, two;
    RootTicket root;
    CallbackTicket callback;
    const Tuple request = tuple(17);
    assert(one.beginRoot(71, request, root));
    assert(!two.beginCallback(root, 71, request, callback));
    assert(one.beginCallback(root, 71, request, callback));
    assert(one.endCallback(71, callback));
    assert(one.endRoot(71, root) == RootResult::CallbackNoPerform);
}

static void callerMutexSerializesConcurrentIndependentOwners() {
    Registry registry;
    std::mutex externalLock;
    bool good[2] = {false, false};
    auto worker = [&](size_t index, uintptr_t thread) {
        RootTicket root;
        CallbackTicket callback;
        PerformTicket perform;
        const Tuple request = tuple(30+index);
        {
            std::lock_guard<std::mutex> guard(externalLock);
            good[index] = registry.beginRoot(thread, request, root);
        }
        {
            std::lock_guard<std::mutex> guard(externalLock);
            good[index] = good[index] && registry.beginCallback(root, thread,
                                                                 request, callback);
        }
        {
            std::lock_guard<std::mutex> guard(externalLock);
            good[index] = good[index] && registry.claimPerform(callback, thread,
                                                                request, perform);
        }
        {
            std::lock_guard<std::mutex> guard(externalLock);
            good[index] = good[index] && registry.held(perform, thread, request);
            good[index] = registry.endPerform(thread, perform) && good[index];
            good[index] = registry.endCallback(thread, callback) && good[index];
            good[index] = registry.endRoot(thread, root) == RootResult::Performed &&
                          good[index];
        }
    };
    std::thread a(worker, 0, 81);
    std::thread b(worker, 1, 82);
    a.join();
    b.join();
    assert(good[0] && good[1]);
}

int main() {
    successfulRouteAndReuse();
    nestedRootInvalidatesOuter();
    tupleAndDuplicateFailuresRevoke();
    everyTupleFieldIsComparedExactly();
    earlyEndAndStaleChildCannotAuthorizeNewRoot();
    wrongThreadRevokesButForeignRootIsIndependent();
    capacityAndFullRegistryNestedInvalidation();
    nonceOverflowPermanentlyRejectsNewScopes();
    issuerAndStaleGenerationAreBound();
    callerMutexSerializesConcurrentIndependentOwners();
}
'''


class IfnetScopeCoreTests(unittest.TestCase):
    def test_production_core_under_sanitizers(self):
        compiler = shutil.which('clang++') or shutil.which('g++')
        if not compiler:
            self.skipTest('C++ compiler unavailable')
        with tempfile.TemporaryDirectory(prefix='ifnet-scope-core-') as temp_dir:
            source = Path(temp_dir) / 'harness.cpp'
            binary = Path(temp_dir) / 'harness'
            source.write_text(HARNESS)
            compile_result = subprocess.run(
                [compiler, '-std=c++14', '-Wall', '-Wextra', '-Werror',
                 '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                 '-pthread', '-I', str(PROJECT), str(source), '-o', str(binary)],
                text=True, capture_output=True, check=False)
            self.assertEqual(compile_result.returncode, 0,
                             compile_result.stdout + compile_result.stderr)
            run_result = subprocess.run(
                [str(binary)], text=True, capture_output=True, check=False)
            self.assertEqual(run_result.returncode, 0,
                             run_result.stdout + run_result.stderr)


if __name__ == '__main__':
    unittest.main()
