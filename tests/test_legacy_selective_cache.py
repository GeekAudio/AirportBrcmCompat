"""Host-side lifetime and fail-closed tests for selective cache pruning."""
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/selective_cache.hpp"

#include <cassert>
#include <cstdint>
#include <initializer_list>
#include <vector>

namespace SC = LegacyWiFi::SelectiveCache;
namespace NM = LegacyWiFi::NetworkMatch;

struct CacheNode {
    CacheNode *next = nullptr;
    CacheNode **previousLink = nullptr;
    uint32_t references = 1;
    NM::Identity identity {};
    uint8_t bssidTag = 0;
    bool destroyed = false;
};

struct Fixture {
    explicit Fixture(size_t count) : nodes(count) {}

    std::vector<CacheNode> nodes;
    CacheNode *head = nullptr;
    std::vector<CacheNode *> requestReferences;
    std::vector<int> destructionOrder;
    size_t writes = 0;

    bool ownsNode(const CacheNode *candidate) const {
        for (const CacheNode &node : nodes) if (&node == candidate) return true;
        return false;
    }

    bool ownsSlot(SC::LinkSlot slot) const {
        if (static_cast<const void *>(slot) == static_cast<const void *>(&head)) return true;
        for (const CacheNode &node : nodes) {
            if (static_cast<const void *>(slot) == static_cast<const void *>(&node.next))
                return true;
        }
        return false;
    }

    SC::Accessors accessors() {
        SC::Accessors result {};
        result.context = this;
        result.readLink = &readLink;
        result.inspect = &inspect;
        result.writeLink = &writeLink;
        result.writePreviousLink = &writePreviousLink;
        result.writeReferenceCount = &writeReferenceCount;
        result.destroy = &destroy;
        return result;
    }

    void link(std::initializer_list<size_t> indexes) {
        head = nullptr;
        for (CacheNode &node : nodes) {
            node.next = nullptr;
            node.previousLink = nullptr;
        }
        CacheNode **slot = &head;
        for (size_t index : indexes) {
            assert(index < nodes.size());
            CacheNode *node = &nodes[index];
            *slot = node;
            node->previousLink = slot;
            slot = &node->next;
        }
        writes = 0;
        destructionOrder.clear();
    }

    static SC::Status readLink(void *context, SC::LinkSlot slot, SC::Node *value) {
        auto *self = static_cast<Fixture *>(context);
        if (!slot || !value || !self->ownsSlot(slot)) return SC::Status::AccessFailure;
        *value = *static_cast<CacheNode **>(slot);
        return SC::Status::Ok;
    }

    static SC::Status inspect(void *context, SC::Node raw, SC::Snapshot *snapshot) {
        auto *self = static_cast<Fixture *>(context);
        auto *node = static_cast<CacheNode *>(raw);
        if (!node || !snapshot || !self->ownsNode(node) || node->destroyed)
            return SC::Status::AccessFailure;
        snapshot->node = node;
        snapshot->nextSlot = &node->next;
        snapshot->previousLink = node->previousLink;
        snapshot->referenceCount = node->references;
        snapshot->identity = node->identity;
        return SC::Status::Ok;
    }

    static void writeLink(void *context, SC::LinkSlot slot, SC::Node raw) {
        auto *self = static_cast<Fixture *>(context);
        assert(slot && self->ownsSlot(slot));
        *static_cast<CacheNode **>(slot) = static_cast<CacheNode *>(raw);
        ++self->writes;
    }

    static void writePreviousLink(void *context, SC::Node raw, SC::LinkSlot slot) {
        auto *self = static_cast<Fixture *>(context);
        auto *node = static_cast<CacheNode *>(raw);
        assert(node && self->ownsNode(node) && !node->destroyed);
        assert(!slot || self->ownsSlot(slot));
        node->previousLink = static_cast<CacheNode **>(slot);
        ++self->writes;
    }

    static void writeReferenceCount(void *context, SC::Node raw, uint32_t value) {
        auto *self = static_cast<Fixture *>(context);
        auto *node = static_cast<CacheNode *>(raw);
        assert(node && self->ownsNode(node) && !node->destroyed);
        node->references = value;
        ++self->writes;
    }

    static void destroy(void *context, SC::Node raw) {
        auto *self = static_cast<Fixture *>(context);
        auto *node = static_cast<CacheNode *>(raw);
        assert(node && self->ownsNode(node) && !node->destroyed);
        assert(node->references == 0 && node->next == nullptr &&
               node->previousLink == nullptr);
        node->destroyed = true;
        self->destructionOrder.push_back(static_cast<int>(node - self->nodes.data()));
    }

    SC::Status prepare(const NM::Identity &key, SC::Entry *scratch,
                       size_t capacity, size_t maxNodes, SC::Plan *plan) {
        return SC::preflight(&head, &key, scratch, capacity, maxNodes,
                             accessors(), plan);
    }
};

static NM::Identity identity(const char *ssid, uint16_t encryption = 1,
                             uint16_t apMode = 1,
                             NM::FILS fils = NM::FILS::Absent) {
    NM::Identity value {};
    size_t length = 0;
    while (ssid[length] != '\0') ++length;
    assert(length <= NM::MaximumSSIDLength);
    value.ssidLength = static_cast<uint8_t>(length);
    for (size_t i = 0; i < length; ++i) value.ssid[i] = static_cast<uint8_t>(ssid[i]);
    value.encryptionModes = encryption;
    value.apMode = apMode;
    value.fils = fils;
    return value;
}

static bool sameIdentity(const NM::Identity &a, const NM::Identity &b) {
    bool matches = false;
    assert(NM::matches(&a, &b, &matches) == 0);
    return matches;
}

static void test_successful_unlink_preserves_request_ownership() {
    Fixture f(5);
    const NM::Identity key = identity("home", 3, 1, NM::FILS::Unknown);
    f.nodes[0].identity = identity("home", 1, 1); // one BSSID
    f.nodes[0].bssidTag = 1;
    f.nodes[0].references = 3; // manager plus two live request wrappers
    f.nodes[1].identity = identity("home", 3, 1); // a second BSSID, same network
    f.nodes[1].bssidTag = 2;
    f.nodes[1].references = 1;
    f.nodes[2].identity = identity("guest", 3, 1);
    f.nodes[2].references = 2;
    f.nodes[3].identity = identity("home", 4, 1); // no encryption-bit intersection
    f.nodes[4].identity = identity("home", 3, 2); // incompatible AP mode
    f.link({0, 1, 2, 3, 4});
    f.requestReferences = {&f.nodes[0], &f.nodes[0], &f.nodes[2]};
    const std::vector<CacheNode *> originalRequestReferences = f.requestReferences;

    SC::Entry scratch[5] {};
    SC::Plan plan;
    assert(f.prepare(key, scratch, 5, 5, &plan) == SC::Status::Ok);
    assert(plan.nodeCount() == 5 && plan.matchingNodeCount() == 2 && f.writes == 0);
    assert(f.destructionOrder.empty());

    SC::Result result {};
    assert(SC::commit(&plan, &result) == SC::Status::Ok);
    assert(result.examinedNodes == 5 && result.matchedNodes == 2);
    assert(result.retainedForRequests == 1 && result.destroyedNodes == 1);
    assert(f.writes == 13); // 2 fields per node, head, 2 manager-ref drops
    assert((f.destructionOrder == std::vector<int>{1}));

    assert(f.head == &f.nodes[2]);
    assert(f.nodes[2].next == &f.nodes[3]);
    assert(f.nodes[3].next == &f.nodes[4]);
    assert(f.nodes[4].next == nullptr);
    assert(f.nodes[2].previousLink == &f.head);
    assert(f.nodes[3].previousLink == &f.nodes[2].next);
    assert(f.nodes[4].previousLink == &f.nodes[3].next);

    assert(f.nodes[0].next == nullptr && f.nodes[0].previousLink == nullptr);
    assert(f.nodes[0].references == 2 && !f.nodes[0].destroyed);
    assert(f.nodes[1].references == 0 && f.nodes[1].destroyed);
    assert(f.nodes[2].references == 2 && !f.nodes[2].destroyed);
    assert(f.requestReferences == originalRequestReferences);
    const size_t committedWrites = f.writes;
    assert(SC::commit(&plan, &result) == SC::Status::PlanConsumed);
    assert(f.writes == committedWrites && f.nodes[0].references == 2 &&
           (f.destructionOrder == std::vector<int>{1}));

    // A later request-wrapper cleanup needs only its held node pointer and
    // reference count; detached list links are intentionally null.
    CacheNode *held = f.requestReferences[0];
    assert(held == &f.nodes[0] && held->next == nullptr && held->previousLink == nullptr);
    f.requestReferences[0] = nullptr;
    assert(held->references == 2);
    --held->references;
    if (held->references == 0) Fixture::destroy(&f, held);
    assert(!held->destroyed && held->references == 1);
    held = f.requestReferences[1];
    assert(held == &f.nodes[0] && held->next == nullptr && held->previousLink == nullptr);
    f.requestReferences[1] = nullptr;
    --held->references;
    if (held->references == 0) Fixture::destroy(&f, held);
    assert(held->destroyed && f.destructionOrder.back() == 0);
    assert(f.requestReferences[2] == &f.nodes[2]);
}

static void test_bad_tail_is_read_only_failure() {
    Fixture f(3);
    const NM::Identity key = identity("home", 1, 1);
    for (CacheNode &node : f.nodes) node.identity = identity("home", 1, 1);
    f.link({0, 1, 2});
    f.nodes[2].previousLink = &f.nodes[0].next; // corrupt only at the tail
    CacheNode *originalHead = f.head;
    CacheNode *original0Next = f.nodes[0].next;
    CacheNode *original1Next = f.nodes[1].next;
    CacheNode **original0Back = f.nodes[0].previousLink;
    CacheNode **original1Back = f.nodes[1].previousLink;
    CacheNode **original2Back = f.nodes[2].previousLink;
    uint32_t refs[3] = {1, 1, 1};
    SC::Entry scratch[3] {};
    SC::Plan plan;
    assert(f.prepare(key, scratch, 3, 3, &plan) == SC::Status::CorruptList);
    assert(f.writes == 0 && f.destructionOrder.empty());
    assert(f.head == originalHead && f.nodes[0].next == original0Next &&
           f.nodes[1].next == original1Next);
    assert(f.nodes[0].previousLink == original0Back &&
           f.nodes[1].previousLink == original1Back &&
           f.nodes[2].previousLink == original2Back);
    for (size_t i = 0; i < 3; ++i) assert(f.nodes[i].references == refs[i]);

    f.nodes[2].previousLink = original2Back;
    f.nodes[2].references = 0;
    assert(f.prepare(key, scratch, 3, 3, &plan) == SC::Status::CorruptList);
    assert(f.writes == 0 && f.destructionOrder.empty());
    assert(f.head == originalHead && f.nodes[0].next == original0Next &&
           f.nodes[1].next == original1Next && f.nodes[2].references == 0);
}

static void test_unknown_identity_fails_without_partial_prune() {
    Fixture f(2);
    const NM::Identity key = identity("home", 1, 1);
    f.nodes[0].identity = identity("home", 1, 1);
    f.nodes[1].identity = identity("home", 1, 1, NM::FILS::Unknown);
    f.link({0, 1});
    SC::Entry scratch[2] {};
    SC::Plan plan;
    assert(f.prepare(key, scratch, 2, 2, &plan) == SC::Status::IdentityUnavailable);
    assert(f.writes == 0 && f.destructionOrder.empty());
    assert(f.head == &f.nodes[0] && f.nodes[0].next == &f.nodes[1]);
    assert(f.nodes[0].references == 1 && f.nodes[1].references == 1);

    // A known FILS-present candidate is classifiable and simply does not match.
    f.nodes[1].identity = identity("home", 1, 1, NM::FILS::Present);
    assert(f.prepare(key, scratch, 2, 2, &plan) == SC::Status::Ok);
    assert(plan.matchingNodeCount() == 1);
    assert(!sameIdentity(f.nodes[1].identity, key));

    Fixture presentOnly(1);
    presentOnly.nodes[0].identity = identity("home", 1, 1, NM::FILS::Present);
    presentOnly.link({0});
    SC::Entry presentScratch[1] {};
    SC::Plan presentPlan;
    assert(presentOnly.prepare(key, presentScratch, 1, 1, &presentPlan) ==
           SC::Status::Ok);
    assert(presentPlan.matchingNodeCount() == 0);
    SC::Result noOp {};
    assert(SC::commit(&presentPlan, &noOp) == SC::Status::Ok);
    assert(noOp.examinedNodes == 1 && noOp.matchedNodes == 0);
    assert(presentOnly.writes == 0 && presentOnly.head == &presentOnly.nodes[0]);
}

static void test_invalid_tail_identity_fails_closed() {
    Fixture f(2);
    const NM::Identity key = identity("home", 1, 1);
    f.nodes[0].identity = identity("home", 1, 1);
    f.nodes[1].identity = identity("home", 1, 1);
    f.nodes[1].identity.apMode = 4;
    f.link({0, 1});
    SC::Entry scratch[2] {};
    SC::Plan plan;
    assert(f.prepare(key, scratch, 2, 2, &plan) == SC::Status::InvalidIdentity);
    assert(f.writes == 0 && f.destructionOrder.empty());
    assert(f.head == &f.nodes[0] && f.nodes[0].next == &f.nodes[1]);
    assert(f.nodes[0].references == 1 && f.nodes[1].references == 1);
}

static void test_stale_snapshots_consume_plan_without_writes() {
    enum class Mutation { Head, Next, Backlink, ReferenceCount, Identity, InvalidIdentity };
    for (Mutation mutation : {Mutation::Head, Mutation::Next, Mutation::Backlink,
                              Mutation::ReferenceCount, Mutation::Identity,
                              Mutation::InvalidIdentity}) {
        Fixture f(2);
        const NM::Identity key = identity("home", 1, 1);
        f.nodes[0].identity = identity("home", 1, 1);
        f.nodes[1].identity = identity("guest", 1, 1);
        f.link({0, 1});
        SC::Entry scratch[2] {};
        SC::Plan plan;
        assert(f.prepare(key, scratch, 2, 2, &plan) == SC::Status::Ok);
        switch (mutation) {
            case Mutation::Head: f.head = &f.nodes[1]; break;
            case Mutation::Next: f.nodes[0].next = nullptr; break;
            case Mutation::Backlink: f.nodes[1].previousLink = &f.head; break;
            case Mutation::ReferenceCount: ++f.nodes[1].references; break;
            case Mutation::Identity: f.nodes[1].identity.ssid[0] ^= 1; break;
            case Mutation::InvalidIdentity: f.nodes[1].identity.ssidLength = 255; break;
        }

        SC::Result result {91, 92, 93, 94};
        assert(SC::commit(&plan, &result) == SC::Status::Stale);
        assert(result.examinedNodes == 91 && result.matchedNodes == 92 &&
               result.retainedForRequests == 93 && result.destroyedNodes == 94);
        assert(f.writes == 0 && f.destructionOrder.empty());
        assert(SC::commit(&plan, &result) == SC::Status::PlanConsumed);
        assert(f.writes == 0 && f.destructionOrder.empty());
    }
}

static void test_bounds_cycle_and_empty_plan() {
    const NM::Identity key = identity("home", 1, 1);
    {
        Fixture f(2);
        f.nodes[0].identity = key;
        f.nodes[1].identity = key;
        f.link({0, 1});
        SC::Entry scratch[1] {};
        SC::Plan plan;
        assert(f.prepare(key, scratch, 1, 2, &plan) == SC::Status::CapacityExceeded);
        assert(f.writes == 0 && f.head == &f.nodes[0]);
        SC::Entry enough[2] {};
        assert(f.prepare(key, enough, 2, 1, &plan) == SC::Status::NodeLimitExceeded);
        assert(f.writes == 0 && f.head == &f.nodes[0]);
    }
    {
        Fixture f(1);
        f.nodes[0].identity = key;
        f.link({0});
        f.nodes[0].next = &f.nodes[0];
        SC::Entry scratch[3] {};
        SC::Plan plan;
        assert(f.prepare(key, scratch, 3, 3, &plan) == SC::Status::CorruptList);
        assert(f.writes == 0 && f.destructionOrder.empty());
    }
    {
        Fixture f(0);
        SC::Entry *noScratch = nullptr;
        SC::Plan plan;
        assert(f.prepare(key, noScratch, 0, 0, &plan) == SC::Status::Ok);
        SC::Result result {};
        assert(SC::commit(&plan, &result) == SC::Status::Ok);
        assert(result.examinedNodes == 0 && result.matchedNodes == 0 && f.writes == 0);
        assert(SC::commit(&plan, &result) == SC::Status::PlanConsumed);
    }
}

static void test_every_eight_node_removal_topology() {
    const NM::Identity key=identity("home");
    for(unsigned mask=0;mask<256;++mask) {
        Fixture f(8);
        std::vector<CacheNode *> expected;
        size_t matches=0,retained=0,destroyed=0;
        for(size_t i=0;i<8;++i) {
            const bool remove=(mask & (1U<<i))!=0;
            f.nodes[i].identity=identity(remove?"home":"other");
            f.nodes[i].references=1+(i%3);
            if(!remove)expected.push_back(&f.nodes[i]);
            else {++matches;if(i%3)++retained;else ++destroyed;}
        }
        f.link({0,1,2,3,4,5,6,7});
        SC::Entry scratch[8] {};
        SC::Plan plan;SC::Result result;
        assert(f.prepare(key,scratch,8,8,&plan)==SC::Status::Ok);
        assert(SC::commit(&plan,&result)==SC::Status::Ok);
        assert(result.examinedNodes==8 && result.matchedNodes==matches);
        assert(result.retainedForRequests==retained && result.destroyedNodes==destroyed);
        CacheNode **slot=&f.head;
        for(CacheNode *node:expected) {
            assert(*slot==node && node->previousLink==slot);
            slot=&node->next;
        }
        assert(*slot==nullptr);
        for(size_t i=0;i<8;++i) {
            const bool removed=(mask & (1U<<i))!=0;
            const auto &node=f.nodes[i];
            assert(node.references==1+(i%3)-(removed?1:0));
            assert(node.destroyed==(removed && i%3==0));
            if(removed)assert(node.next==nullptr && node.previousLink==nullptr);
        }
        if(mask==0)assert(f.writes==0);
    }
}

static void test_changed_scratch_is_rejected_before_writes() {
    const NM::Identity key=identity("home");
    for(unsigned mutation=0;mutation<7;++mutation) {
        Fixture f(3);f.link({0,1,2});
        f.nodes[0].identity=key;
        f.nodes[1].identity=identity("other");f.nodes[2].identity=identity("other");
        SC::Entry scratch[3] {};SC::Plan plan;
        assert(f.prepare(key,scratch,3,3,&plan)==SC::Status::Ok);
        switch(mutation) {
            case 0:scratch[0].matches=false;break;
            case 1:scratch[1].matches=true;break;
            case 2:scratch[1].finalNext=nullptr;break;
            case 3:scratch[2].finalPreviousLink=&f.head;break;
            case 4:scratch[0].finalNext=&f.nodes[1];break;
            case 5:scratch[0].finalPreviousLink=&f.head;break;
            case 6:{const auto saved=scratch[1];scratch[1]=scratch[2];scratch[2]=saved;break;}
        }
        SC::Result result;result.examinedNodes=99;
        assert(SC::commit(&plan,&result)==SC::Status::Stale);
        assert(f.writes==0 && f.destructionOrder.empty() && f.head==&f.nodes[0]);
        assert(result.examinedNodes==99);
        assert(SC::commit(&plan,&result)==SC::Status::PlanConsumed);
    }
}

int main() {
    test_successful_unlink_preserves_request_ownership();
    test_bad_tail_is_read_only_failure();
    test_unknown_identity_fails_without_partial_prune();
    test_invalid_tail_identity_fails_closed();
    test_stale_snapshots_consume_plan_without_writes();
    test_bounds_cycle_and_empty_plan();
    test_every_eight_node_removal_topology();
    test_changed_scratch_is_rejected_before_writes();
}
'''


class SelectiveCacheTests(unittest.TestCase):
    def test_bounded_transactional_unlink_and_lifetime_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "test.cpp"
            binary = Path(tmp) / "test"
            source.write_text(HARNESS)
            subprocess.run(
                ["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                 "-I", str(PROJECT / "src"), str(source), "-o", str(binary)],
                check=True, capture_output=True, timeout=30)
            subprocess.run([str(binary)], check=True, capture_output=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
