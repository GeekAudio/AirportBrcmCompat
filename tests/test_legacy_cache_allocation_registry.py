"""ASan/UBSan coverage for the bounded cache-allocation proof registry."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/cache_allocation_registry.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <type_traits>

namespace R = LegacyWiFi::CacheAllocationRegistry;
namespace N = LegacyWiFi::NetworkIdentity;
using Source = N::Source;

static_assert(!std::is_copy_constructible<R::Registry<>>::value,
              "registry state must not be duplicated");
static_assert(!std::is_copy_assignable<R::Registry<>>::value,
              "registry state must not be copy-assigned");
static_assert(!std::is_move_constructible<R::Registry<>>::value,
              "registry owner records must not be relocated");

static uintptr_t address(const void *pointer) {
    return reinterpret_cast<uintptr_t>(pointer);
}

static void *heap(size_t size) {
    void *pointer = std::malloc(size);
    assert(pointer);
    std::memset(pointer, 0xa5, size);
    return pointer;
}

static R::OwnerKey owner(uintptr_t manager, uint64_t generation) {
    return {manager, generation};
}

static R::Tuple tuple(uintptr_t node, uintptr_t ie = 0, size_t ieSize = 0,
                      size_t nodeSize = R::CacheNodeAllocationSize) {
    return {node, nodeSize, ie, ieSize};
}

static void test_exact_registration_source_and_retirement() {
    R::Registry<8, 4> registry;
    const R::OwnerKey key = owner(0x10000, 1);
    void *node = heap(R::CacheNodeAllocationSize);
    void *ie = heap(R::MaximumIEAllocationSize);
    const R::Tuple allocation = tuple(address(node), address(ie),
                                      R::MaximumIEAllocationSize);

    assert(registry.registerAllocation(key, Source::Pinned4331,
                                       allocation) == R::Status::Ok);
    assert(registry.ownsExact(key, Source::Pinned4331, allocation));
    assert(!registry.ownsExact(key, Source::Pinned43224, allocation));
    assert(!registry.ownsExact(owner(key.manager, key.generation + 1),
                               Source::Pinned4331, allocation));
    assert(!registry.ownsExact(key, Source::Pinned4331,
                               tuple(allocation.node, allocation.ie,
                                     allocation.ieSize - 1)));
    assert(registry.registeredNodeCount() == 1);
    assert(registry.occupiedOwnerCount() == 1);

    assert(registry.registerAllocation(key, Source::Pinned4331,
                                       allocation) == R::Status::Duplicate);
    void *otherNode = heap(R::CacheNodeAllocationSize);
    assert(registry.registerAllocation(key, Source::Pinned43224,
        tuple(address(otherNode))) == R::Status::SourceMismatch);
    assert(registry.registeredNodeCount() == 1);
    assert(registry.occupiedOwnerCount() == 1);

    // Detaching from the provider list does not alter this registry entry.
    bool detachedFromManagerList = true;
    assert(detachedFromManagerList);
    assert(registry.ownsExact(key, Source::Pinned4331, allocation));

    // The caller invokes retire immediately before the provider destructor.
    assert(registry.retire(allocation.node) == R::Status::Ok);
    assert(!registry.ownsExact(key, Source::Pinned4331, allocation));
    assert(registry.retire(allocation.node) == R::Status::NodeNotFound);
    assert(registry.registeredNodeCount() == 0);
    // An active owner with no nodes still occupies its owner slot.
    assert(registry.occupiedOwnerCount() == 1);
    assert(registry.retireOwner(key) == R::Status::Ok);
    assert(registry.occupiedOwnerCount() == 0);

    std::free(otherNode);
    std::free(ie);
    std::free(node);
}

static void test_tuple_validation_and_overflow() {
    R::Registry<8, 4> registry;
    const R::OwnerKey key = owner(0x20000, 2);
    void *node = heap(R::CacheNodeAllocationSize);
    void *ie = heap(16);
    const uintptr_t nodeAddress = address(node);
    const uintptr_t ieAddress = address(ie);

    assert(registry.registerAllocation(owner(0, 2), Source::Pinned4331,
        tuple(nodeAddress)) == R::Status::InvalidOwner);
    assert(registry.registerAllocation(owner(key.manager, 0), Source::Pinned4331,
        tuple(nodeAddress)) == R::Status::InvalidOwner);
    assert(registry.registerAllocation(key, Source::Unknown,
        tuple(nodeAddress)) == R::Status::UnsupportedSource);
    assert(registry.registerAllocation(key, Source::Pinned4331,
        tuple(nodeAddress, 0, 0, R::CacheNodeAllocationSize - 1)) ==
        R::Status::InvalidTuple);
    assert(registry.registerAllocation(key, Source::Pinned4331,
        tuple(nodeAddress + 1)) == R::Status::InvalidTuple);
    assert(registry.registerAllocation(key, Source::Pinned4331,
        tuple(nodeAddress, ieAddress, 0)) == R::Status::InvalidTuple);
    assert(registry.registerAllocation(key, Source::Pinned4331,
        tuple(nodeAddress, 0, 1)) == R::Status::InvalidTuple);
    assert(registry.registerAllocation(key, Source::Pinned4331,
        tuple(nodeAddress, ieAddress, R::MaximumIEAllocationSize + 1)) ==
        R::Status::IETooLarge);

    const uintptr_t highAligned =
        std::numeric_limits<uintptr_t>::max() & ~uintptr_t(alignof(uintptr_t) - 1);
    assert(registry.registerAllocation(key, Source::Pinned4331,
        tuple(highAligned)) == R::Status::RangeOverflow);
    assert(registry.registerAllocation(key, Source::Pinned4331,
        tuple(nodeAddress, std::numeric_limits<uintptr_t>::max() - 3, 8)) ==
        R::Status::RangeOverflow);
    assert(registry.registeredNodeCount() == 0);
    assert(registry.occupiedOwnerCount() == 0);

    std::free(ie);
    std::free(node);
}

static void test_allocation_ranges_must_not_alias() {
    // New node versus existing node: two aligned node allocations overlap.
    {
        R::Registry<8, 4> registry;
        void *arena = heap(2 * R::CacheNodeAllocationSize);
        const uintptr_t base = address(arena);
        const R::OwnerKey key = owner(0x30000, 3);
        assert(registry.registerAllocation(key, Source::Pinned4331,
            tuple(base)) == R::Status::Ok);
        assert(registry.registerAllocation(key, Source::Pinned4331,
            tuple(base + 0x40)) == R::Status::Overlap);
        assert(registry.registeredNodeCount() == 1);
        assert(registry.occupiedOwnerCount() == 1);
        std::free(arena);
    }

    // A new IE may not alias an already registered node.
    {
        R::Registry<8, 4> registry;
        void *node = heap(R::CacheNodeAllocationSize);
        void *otherNode = heap(R::CacheNodeAllocationSize);
        const uintptr_t nodeAddress = address(node);
        const R::OwnerKey key = owner(0x31000, 4);
        assert(registry.registerAllocation(key, Source::Pinned4331,
            tuple(nodeAddress)) == R::Status::Ok);
        assert(registry.registerAllocation(key, Source::Pinned4331,
            tuple(address(otherNode), nodeAddress + 0x80, 8)) ==
            R::Status::Overlap);
        assert(registry.registeredNodeCount() == 1);
        std::free(otherNode);
        std::free(node);
    }

    // A new node may not alias an already registered IE allocation.
    {
        R::Registry<8, 4> registry;
        void *node = heap(R::CacheNodeAllocationSize);
        void *ieArena = heap(0x200);
        const uintptr_t ieAddress = address(ieArena);
        const R::OwnerKey key = owner(0x32000, 5);
        assert(registry.registerAllocation(key, Source::Pinned4331,
            tuple(address(node), ieAddress, 0x40)) == R::Status::Ok);
        assert(registry.registerAllocation(key, Source::Pinned4331,
            tuple(ieAddress + 0x20)) == R::Status::Overlap);
        assert(registry.registeredNodeCount() == 1);
        std::free(ieArena);
        std::free(node);
    }

    // Partial IE/IE overlap is rejected even when both tuples have other nodes.
    {
        R::Registry<8, 4> registry;
        void *nodeA = heap(R::CacheNodeAllocationSize);
        void *nodeB = heap(R::CacheNodeAllocationSize);
        void *ieArena = heap(64);
        const uintptr_t ieAddress = address(ieArena);
        const R::OwnerKey key = owner(0x33000, 6);
        assert(registry.registerAllocation(key, Source::Pinned4331,
            tuple(address(nodeA), ieAddress, 24)) == R::Status::Ok);
        assert(registry.registerAllocation(key, Source::Pinned4331,
            tuple(address(nodeB), ieAddress + 8, 24)) == R::Status::Overlap);
        assert(registry.registeredNodeCount() == 1);
        std::free(ieArena);
        std::free(nodeB);
        std::free(nodeA);
    }

    // A tuple cannot overlap its own node allocation.
    {
        R::Registry<4, 2> registry;
        void *arena = heap(2 * R::CacheNodeAllocationSize);
        const uintptr_t base = address(arena);
        assert(registry.registerAllocation(owner(0x34000, 7),
            Source::Pinned4331, tuple(base, base + 0x80, 8)) ==
            R::Status::Overlap);
        assert(registry.registeredNodeCount() == 0);
        assert(registry.occupiedOwnerCount() == 0);
        std::free(arena);
    }
}

static void test_owner_retirement_and_generation_reuse() {
    R::Registry<8, 4> registry;
    void *arena = heap(0x400);
    const uintptr_t base = address(arena);
    const R::OwnerKey oldOwner = owner(0x40000, 10);
    const R::Tuple oldTuple = tuple(base, base + 0x200, 64);
    assert(registry.registerAllocation(oldOwner, Source::Pinned4331,
                                       oldTuple) == R::Status::Ok);

    // Retirement disables lookup but keeps all allocations reserved for the
    // still-live detached/request-referenced node.
    assert(registry.retireOwner(oldOwner) == R::Status::Ok);
    assert(!registry.ownsExact(oldOwner, Source::Pinned4331, oldTuple));
    assert(registry.registeredNodeCount() == 1);
    assert(registry.occupiedOwnerCount() == 1);
    const R::OwnerKey newOwner = owner(oldOwner.manager, oldOwner.generation + 1);
    assert(registry.registerAllocation(newOwner, Source::Pinned4331,
        oldTuple) == R::Status::Overlap);
    assert(!registry.ownsExact(newOwner, Source::Pinned4331, oldTuple));
    assert(registry.registeredNodeCount() == 1);
    assert(registry.occupiedOwnerCount() == 1);

    // Model the allocator reusing these real heap-backed addresses after the
    // old generation's destructor retires its tuple. The registry tracks only
    // address ownership and deliberately never dereferences the allocations.
    assert(registry.retire(oldTuple.node) == R::Status::Ok);
    assert(registry.registeredNodeCount() == 0);
    assert(registry.occupiedOwnerCount() == 0);
    assert(registry.registerAllocation(newOwner, Source::Pinned4331,
                                       oldTuple) == R::Status::Ok);
    assert(registry.ownsExact(newOwner, Source::Pinned4331, oldTuple));
    assert(!registry.ownsExact(oldOwner, Source::Pinned4331, oldTuple));
    assert(registry.retireOwner(newOwner) == R::Status::Ok);
    assert(registry.registerAllocation(newOwner, Source::Pinned4331,
        tuple(base + 0x40)) == R::Status::OwnerRetired);
    assert(registry.retire(oldTuple.node) == R::Status::Ok);
    assert(registry.occupiedOwnerCount() == 0);
    std::free(arena);
}

static void test_active_owner_and_capacity_fail_atomically() {
    // An active generation with zero nodes still occupies its owner slot.
    {
        R::Registry<2, 1> registry;
        void *nodeA = heap(R::CacheNodeAllocationSize);
        void *nodeB = heap(R::CacheNodeAllocationSize);
        const R::OwnerKey a = owner(0x50000, 20);
        const R::OwnerKey b = owner(0x51000, 21);
        const R::Tuple tupleA = tuple(address(nodeA));
        const R::Tuple tupleB = tuple(address(nodeB));
        assert(registry.registerAllocation(a, Source::Pinned4331, tupleA) ==
               R::Status::Ok);
        assert(registry.retire(tupleA.node) == R::Status::Ok);
        assert(registry.registeredNodeCount() == 0);
        assert(registry.occupiedOwnerCount() == 1);
        assert(registry.registerAllocation(b, Source::Pinned4331, tupleB) ==
               R::Status::OwnerCapacityExceeded);
        assert(registry.registeredNodeCount() == 0);
        assert(registry.occupiedOwnerCount() == 1);
        assert(!registry.ownsExact(b, Source::Pinned4331, tupleB));
        assert(registry.retireOwner(a) == R::Status::Ok);
        assert(registry.registerAllocation(b, Source::Pinned4331, tupleB) ==
               R::Status::Ok);
        assert(registry.ownsExact(b, Source::Pinned4331, tupleB));
        assert(registry.retire(tupleB.node) == R::Status::Ok);
        std::free(nodeB);
        std::free(nodeA);
    }

    // A full node table must not leave a half-created owner entry.
    {
        R::Registry<1, 2> registry;
        void *nodeA = heap(R::CacheNodeAllocationSize);
        void *nodeB = heap(R::CacheNodeAllocationSize);
        const R::OwnerKey a = owner(0x52000, 22);
        const R::OwnerKey b = owner(0x53000, 23);
        const R::Tuple tupleA = tuple(address(nodeA));
        const R::Tuple tupleB = tuple(address(nodeB));
        assert(registry.registerAllocation(a, Source::Pinned4331, tupleA) ==
               R::Status::Ok);
        assert(registry.registerAllocation(b, Source::Pinned4331, tupleB) ==
               R::Status::NodeCapacityExceeded);
        assert(registry.registeredNodeCount() == 1);
        assert(registry.occupiedOwnerCount() == 1);
        assert(registry.ownsExact(a, Source::Pinned4331, tupleA));
        assert(!registry.ownsExact(b, Source::Pinned4331, tupleB));
        assert(registry.retire(tupleA.node) == R::Status::Ok);
        assert(registry.registerAllocation(b, Source::Pinned4331, tupleB) ==
               R::Status::Ok);
        assert(registry.ownsExact(b, Source::Pinned4331, tupleB));
        assert(registry.retire(tupleB.node) == R::Status::Ok);
        std::free(nodeB);
        std::free(nodeA);
    }

    // A full owner table likewise leaves the existing entry untouched.
    {
        R::Registry<2, 1> registry;
        void *nodeA = heap(R::CacheNodeAllocationSize);
        void *nodeB = heap(R::CacheNodeAllocationSize);
        const R::OwnerKey a = owner(0x54000, 24);
        const R::OwnerKey b = owner(0x55000, 25);
        const R::Tuple tupleA = tuple(address(nodeA));
        const R::Tuple tupleB = tuple(address(nodeB));
        assert(registry.registerAllocation(a, Source::Pinned4331, tupleA) ==
               R::Status::Ok);
        assert(registry.registerAllocation(b, Source::Pinned4331, tupleB) ==
               R::Status::OwnerCapacityExceeded);
        assert(registry.registeredNodeCount() == 1);
        assert(registry.occupiedOwnerCount() == 1);
        assert(registry.ownsExact(a, Source::Pinned4331, tupleA));
        assert(!registry.ownsExact(b, Source::Pinned4331, tupleB));
        assert(registry.retire(tupleA.node) == R::Status::Ok);
        assert(registry.retireOwner(a) == R::Status::Ok);
        assert(registry.registerAllocation(b, Source::Pinned4331, tupleB) ==
               R::Status::Ok);
        assert(registry.retire(tupleB.node) == R::Status::Ok);
        std::free(nodeB);
        std::free(nodeA);
    }
}

static void test_same_manager_generations_require_retirement() {
    R::Registry<4, 3> registry;
    void *nodeA = heap(R::CacheNodeAllocationSize);
    void *nodeB = heap(R::CacheNodeAllocationSize);
    const R::OwnerKey oldOwner = owner(0x60000, 30);
    const R::OwnerKey nextOwner = owner(0x60000, 31);
    const R::Tuple tupleA = tuple(address(nodeA));
    const R::Tuple tupleB = tuple(address(nodeB));
    assert(registry.registerAllocation(oldOwner, Source::Pinned43224, tupleA) ==
           R::Status::Ok);
    assert(registry.registerAllocation(nextOwner, Source::Pinned43224, tupleB) ==
           R::Status::ActiveGenerationConflict);
    assert(registry.registeredNodeCount() == 1);
    assert(registry.occupiedOwnerCount() == 1);
    assert(registry.retireOwner(oldOwner) == R::Status::Ok);
    assert(registry.registerAllocation(nextOwner, Source::Pinned43224, tupleB) ==
           R::Status::Ok);
    assert(registry.registeredNodeCount() == 2);
    assert(registry.occupiedOwnerCount() == 2);
    assert(registry.retire(tupleA.node) == R::Status::Ok);
    assert(registry.retire(tupleB.node) == R::Status::Ok);
    assert(registry.retireOwner(nextOwner) == R::Status::Ok);
    std::free(nodeB);
    std::free(nodeA);
}

int main() {
    test_exact_registration_source_and_retirement();
    test_tuple_validation_and_overflow();
    test_allocation_ranges_must_not_alias();
    test_owner_retirement_and_generation_reuse();
    test_active_owner_and_capacity_fail_atomically();
    test_same_manager_generations_require_retirement();
    return 0;
}
'''


class LegacyCacheAllocationRegistryTests(unittest.TestCase):
    def test_registry_boundaries_and_lifetime_under_asan_ubsan(self):
        compiler = shutil.which("clang++")
        if not compiler:
            self.skipTest("clang++ is required for the portable C++ harness")
        with tempfile.TemporaryDirectory(prefix="legacy-cache-allocation-registry-") as tmp:
            source = Path(tmp) / "registry.cpp"
            binary = Path(tmp) / "registry"
            source.write_text(HARNESS)
            subprocess.run([
                compiler, "-std=c++14", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(PROJECT / "src"), str(source), "-o", str(binary),
            ], check=True, capture_output=True, timeout=60)
            subprocess.run([str(binary)], check=True,
                           capture_output=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
