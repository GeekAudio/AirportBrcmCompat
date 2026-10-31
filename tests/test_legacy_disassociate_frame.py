"""Sanitizer-backed tests for the pure legacy disassociation frame route."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/disassociate_frame.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

namespace DF = LegacyWiFi::DisassociateFrame;

struct Packet {
    uint8_t bytes[64];
    uint8_t *body;
    size_t length;
    bool freed;
};

struct TestEnv {
    DF::RouteContext route;
    DF::Callbacks callbacks;
    DF::DriverKind driver = DF::DriverKind::Brcm4331;
    DF::HookContract contract = DF::pinnedElCap4331Contract();
    uintptr_t thread = 0x31;
    uintptr_t wrongThread = 0x32;
    uint8_t ownerStorage = 0;
    uint8_t wlcStorage = 0;
    const void *owner = &ownerStorage;
    void *wlc = &wlcStorage;
    uint64_t requestID = 0x101;
    uint64_t generation = 0x202;
    DF::MacAddress bssid {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
    uint8_t address3[6] {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t otherAddress[6] {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    uint32_t ieReason = 0x12345678;
    uint32_t frameReason = 0x0000abcd;
    bool ownerCurrent = true;
    bool staleBeforeBuilder = false;
    bool staleDuringBuilder = false;
    bool reenterMatchingSenderDuringBuilder = false;
    bool reenterDuplicateScopeDuringBuilder = false;
    bool reentrantBuilderActionDone = false;
    bool failReadAddress = false;
    bool failBuilder = false;
    bool failFallbackBuilder = false;
    bool failWrite = false;
    bool injectNested = false;
    bool nestedMatching = false;
    bool nestedDone = false;
    bool duplicateBuilder = false;
    bool duplicateDone = false;
    bool badBuilderPC = false;
    bool badBuilderSubtype = false;
    bool badBuilderLength = false;
    unsigned recursionDepth = 0;
    unsigned senderCalls = 0;
    unsigned builderCalls = 0;
    unsigned readAddressCalls = 0;
    unsigned bodyWriteCalls = 0;
    unsigned bodyOutReads = 0;
    unsigned freeCalls = 0;
    unsigned packetCount = 0;
    unsigned length15Calls = 0;
    unsigned length2Calls = 0;
    unsigned eventSequence = 0;
    unsigned freeEventOrder = 0;
    unsigned fallbackBuilderEventOrder = 0;
    Packet packets[32] {};
    void *bodySlots[32] {};
    DF::RouteResult nestedResult {};
    DF::RouteResult reentrantSenderResult {};
    DF::RouteResult duplicateBuilderResult {};
    DF::RouteResult lastRouteResult {};
    DF::Status duplicateScopeStatus = DF::Status::InvalidArgument;
    void *lastSenderPacket = nullptr;
    uint8_t *lastBody = nullptr;

    TestEnv() {
        callbacks.context = this;
        callbacks.currentThread = &currentThread;
        callbacks.ownerGenerationCurrent = &ownerIsCurrent;
        callbacks.readAddress3 = &readAddress3;
        callbacks.originalSender = &originalSender;
        callbacks.originalBuilder = &originalBuilder;
        callbacks.writeBodyBytes = &writeBodyBytes;
        callbacks.freeUnqueuedPacket = &freeUnqueuedPacket;
    }

    static uintptr_t currentThread(void *context) {
        return static_cast<TestEnv *>(context)->thread;
    }

    static bool ownerIsCurrent(void *context, const void *owner,
                               uint64_t requestID, uint64_t generation) {
        auto *self = static_cast<TestEnv *>(context);
        return self->ownerCurrent && owner == self->owner &&
            requestID == self->requestID && generation == self->generation;
    }

    static bool readAddress3(void *context, DF::DriverKind,
                             const void *address, DF::MacAddress *output) {
        auto *self = static_cast<TestEnv *>(context);
        ++self->readAddressCalls;
        if (!address || !output || self->failReadAddress) return false;
        if (address == self->address3) {
            memcpy(output->bytes, self->address3, sizeof(output->bytes));
            return true;
        }
        if (address == self->otherAddress) {
            memcpy(output->bytes, self->otherAddress, sizeof(output->bytes));
            return true;
        }
        return false;
    }

    static void *originalBuilder(void *context,
                                 const DF::BuilderInvocation &invocation) {
        auto *self = static_cast<TestEnv *>(context);
        ++self->builderCalls;
        const unsigned eventOrder = ++self->eventSequence;
        if (invocation.bodyLength == DF::ExtendedBodyBytes) ++self->length15Calls;
        if (invocation.bodyLength == DF::OriginalReasonBytes) {
            ++self->length2Calls;
            if (self->length15Calls)
                self->fallbackBuilderEventOrder = eventOrder;
        }
        assert(self->packetCount < 32);
        if (self->failBuilder ||
            (self->failFallbackBuilder &&
             invocation.bodyLength == DF::OriginalReasonBytes))
            return nullptr; // Does not inspect or touch bodyOutSlot.

        Packet &packet = self->packets[self->packetCount];
        memset(packet.bytes, 0xcc, sizeof(packet.bytes));
        packet.body = packet.bytes + 24;
        packet.length = 24 + invocation.bodyLength;
        packet.freed = false;
        self->bodySlots[self->packetCount] = invocation.bodyOutSlot;
        ++self->packetCount;
        assert(invocation.bodyOutSlot);
        *static_cast<uint8_t **>(invocation.bodyOutSlot) = packet.body;
        if (invocation.bodyLength == DF::ExtendedBodyBytes &&
            !self->reentrantBuilderActionDone) {
            self->reentrantBuilderActionDone = true;
            if (self->reenterMatchingSenderDuringBuilder) {
                DF::SenderInvocation nested {};
                nested.driver = self->driver;
                nested.callerReturnPC = self->contract.senderCallerPCs[0];
                nested.wlc = self->wlc;
                nested.address3 = self->address3;
                nested.scb = &self->ownerStorage;
                nested.reason = self->frameReason;
                self->reentrantSenderResult = DF::interceptSender(
                    self->route, nested, self->callbacks);
            }
            if (self->reenterDuplicateScopeDuringBuilder) {
                DF::RequestScope duplicate(
                    self->route, self->contract, self->driver, self->owner,
                    self->requestID, self->generation, self->wlc,
                    self->bssid, self->ieReason, self->callbacks);
                self->duplicateScopeStatus = duplicate.status();
            }
        }
        if (self->staleDuringBuilder &&
            invocation.bodyLength == DF::ExtendedBodyBytes)
            self->ownerCurrent = false;
        return &packet;
    }

    static bool writeBodyBytes(void *context, DF::DriverKind driver,
                               void *bodyOutSlot, size_t offset,
                               const uint8_t *bytes, size_t length) {
        auto *self = static_cast<TestEnv *>(context);
        ++self->bodyWriteCalls;
        if (self->failWrite || driver != self->driver || !bodyOutSlot ||
            !bytes || length != DF::ReasonIEBytes ||
            offset != DF::ReasonIEAppendOffset) return false;
        size_t index = self->packetCount;
        while (index && self->bodySlots[index - 1] != bodyOutSlot) --index;
        if (!index || self->packets[index - 1].freed) return false;
        --index;
        ++self->bodyOutReads;
        uint8_t *body = *static_cast<uint8_t **>(bodyOutSlot);
        if (body != self->packets[index].body ||
            offset > self->packets[index].length - 24 ||
            length > self->packets[index].length - 24 - offset) return false;
        memcpy(body + offset, bytes, length);
        return true;
    }

    static void freeUnqueuedPacket(void *context, DF::DriverKind driver,
                                   void *wlc, void *rawPacket) {
        auto *self = static_cast<TestEnv *>(context);
        assert(driver == self->driver && wlc == self->wlc && rawPacket);
        auto *packet = static_cast<Packet *>(rawPacket);
        assert(packet >= self->packets && packet < self->packets + self->packetCount);
        assert(!packet->freed);
        packet->freed = true;
        ++self->freeCalls;
        self->freeEventOrder = ++self->eventSequence;
    }

    static void *originalSender(void *context,
                                const DF::SenderInvocation &invocation) {
        auto *self = static_cast<TestEnv *>(context);
        ++self->senderCalls;

        if (self->injectNested && !self->nestedDone && self->recursionDepth == 0) {
            self->nestedDone = true;
            DF::SenderInvocation nested = invocation;
            if (!self->nestedMatching) nested.callerReturnPC = 0xdeadbeef;
            ++self->recursionDepth;
            self->nestedResult = DF::interceptSender(
                self->route, nested, self->callbacks);
            --self->recursionDepth;
        }

        uint8_t *bodyOut = reinterpret_cast<uint8_t *>(uintptr_t(0x1));
        DF::BuilderInvocation builder {};
        builder.driver = invocation.driver;
        builder.callerReturnPC = self->badBuilderPC
            ? self->contract.builderReturnPC + 1 : self->contract.builderReturnPC;
        builder.wlc = invocation.wlc;
        builder.address3 = invocation.address3;
        builder.subtype = self->badBuilderSubtype
            ? 0x00 : DF::DisassociateSubtype;
        builder.bodyLength = self->badBuilderLength
            ? 3 : DF::OriginalReasonBytes;
        builder.bodyOutSlot = self->failBuilder
            ? reinterpret_cast<void *>(uintptr_t(1)) : &bodyOut;
        builder.opaque = invocation.opaque;

        if (self->staleBeforeBuilder) self->ownerCurrent = false;

        DF::RouteResult built = DF::interceptBuilder(
            self->route, builder, self->callbacks);
        if (built.packet) {
            assert(bodyOut != reinterpret_cast<uint8_t *>(uintptr_t(0x1)));
            bodyOut[0] = static_cast<uint8_t>(invocation.reason);
            bodyOut[1] = static_cast<uint8_t>(invocation.reason >> 8);
            self->lastBody = bodyOut;
        }
        self->lastSenderPacket = built.packet;

        if (self->duplicateBuilder && !self->duplicateDone) {
            self->duplicateDone = true;
            uint8_t *secondBody = nullptr;
            DF::BuilderInvocation duplicate = builder;
            duplicate.callerReturnPC = self->contract.builderReturnPC;
            duplicate.subtype = DF::DisassociateSubtype;
            duplicate.bodyLength = DF::OriginalReasonBytes;
            duplicate.bodyOutSlot = &secondBody;
            self->duplicateBuilderResult = DF::interceptBuilder(
                self->route, duplicate, self->callbacks);
        }
        return built.packet;
    }
};

static void runOneSender(TestEnv &env, uintptr_t callerPC,
                         const void *address3 = nullptr,
                         DF::DriverKind driver = DF::DriverKind::Invalid,
                         void *wlc = nullptr, uint32_t reason = 0x0000abcd) {
    DF::SenderInvocation sender {};
    sender.driver = driver == DF::DriverKind::Invalid ? env.driver : driver;
    sender.callerReturnPC = callerPC;
    sender.wlc = wlc ? wlc : env.wlc;
    sender.address3 = address3 ? address3 : env.address3;
    sender.scb = &env.ownerStorage;
    sender.reason = reason;
    env.lastRouteResult = DF::interceptSender(env.route, sender, env.callbacks);
}

static void test_ie_encoder() {
    uint8_t output[DF::ReasonIEBytes] {};
    assert(DF::encodeReasonIE(0x12345678, output, sizeof(output)));
    const uint8_t expected[DF::ReasonIEBytes] = {
        0xdd, 0x0b, 0x00, 0x17, 0xf2, 0x0a, 0x02, 0x01, 0x04,
        0x78, 0x56, 0x34, 0x12
    };
    assert(memcmp(output, expected, sizeof(expected)) == 0);
    assert(DF::encodeReasonIE(0xffffffffU, output, sizeof(output)));
    assert(output[9] == 0xff && output[10] == 0xff &&
           output[11] == 0xff && output[12] == 0xff);
    memset(output, 0x5a, sizeof(output));
    assert(!DF::encodeReasonIE(1, output, sizeof(output) - 1));
    for (uint8_t byte : output) assert(byte == 0x5a);
    assert(!DF::encodeReasonIE(1, nullptr, DF::ReasonIEBytes));
}

static void test_success_for_each_driver(DF::DriverKind driver) {
    TestEnv env;
    env.driver = driver;
    env.contract = driver == DF::DriverKind::Brcm4331
        ? DF::pinnedElCap4331Contract() : DF::pinnedElCap43224Contract();
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    assert(scope.active());
    const uintptr_t senderPC = env.contract.senderCallerPCs[0];
    DF::SenderInvocation sender {};
    sender.driver = driver;
    sender.callerReturnPC = senderPC;
    sender.wlc = env.wlc;
    sender.address3 = env.address3;
    sender.scb = &env.ownerStorage;
    sender.reason = env.frameReason;
    env.lastRouteResult = DF::interceptSender(env.route, sender, env.callbacks);
    DF::RouteResult result = env.lastRouteResult;
    assert(result.matched && result.extended);
    assert(env.lastRouteResult.extended);
    assert(result.packet && result.packet == env.lastSenderPacket);
    assert(scope.complete() && scope.status() == DF::Status::Enhanced);
    assert(env.builderCalls == 1 && env.length15Calls == 1 && env.length2Calls == 0);
    assert(env.bodyWriteCalls == 1 && env.bodyOutReads == 1 && env.freeCalls == 0);
    assert(env.lastBody && env.lastBody[0] == 0xcd && env.lastBody[1] == 0xab);
    const uint8_t expectedIE[DF::ReasonIEBytes] = {
        0xdd, 0x0b, 0x00, 0x17, 0xf2, 0x0a, 0x02, 0x01, 0x04,
        0x78, 0x56, 0x34, 0x12
    };
    assert(memcmp(env.lastBody + 2, expectedIE, sizeof(expectedIE)) == 0);
    auto *packet = static_cast<Packet *>(result.packet);
    assert(packet->length == 39 && !packet->freed);
}

static void test_success_alternate_4331_sender_callsite() {
    TestEnv env;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    assert(env.contract.senderCallerPCCount == 2);
    runOneSender(env, env.contract.senderCallerPCs[1]);
    assert(env.length15Calls == 1 && env.length2Calls == 0);
    assert(scope.complete());
}

static void test_unrelated_callers_do_not_consume_token() {
    TestEnv env;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    runOneSender(env, 0xdeadbeef);
    assert(env.length15Calls == 0 && !scope.complete());
    assert(scope.status() == DF::Status::Pending);
}

static void test_wrong_bssid_and_controller_do_not_route() {
    TestEnv env;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    runOneSender(env, env.contract.senderCallerPCs[0], env.otherAddress);
    runOneSender(env, env.contract.senderCallerPCs[0], env.address3,
                 env.driver, reinterpret_cast<void *>(uintptr_t(0x55)));
    assert(env.length15Calls == 0 && env.length2Calls == 2);
    assert(!scope.complete() && scope.status() == DF::Status::Pending);
}

static void test_wrong_thread_does_not_route() {
    TestEnv env;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    env.thread = env.wrongThread;
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.length15Calls == 0 && env.length2Calls == 1);
    assert(!scope.complete());
}

static void test_nested_unrelated_sender_preserves_outer_lease() {
    TestEnv env;
    env.injectNested = true;
    env.nestedMatching = false;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.senderCalls == 2 && env.builderCalls == 2);
    assert(env.length2Calls == 1 && env.length15Calls == 1);
    assert(scope.complete());
}

static void test_matching_nested_sender_cancels_unused_lease() {
    TestEnv env;
    env.injectNested = true;
    env.nestedMatching = true;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.senderCalls == 2 && env.builderCalls == 2);
    assert(env.length2Calls == 2 && env.length15Calls == 0);
    assert(!env.lastRouteResult.extended && env.lastRouteResult.packet);
    assert(!scope.complete() && scope.status() == DF::Status::ContractViolation);
    assert(env.freeCalls == 0);
}

static void test_duplicate_scope_and_sender_are_reported() {
    TestEnv env;
    DF::RequestScope outer(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    {
        DF::RequestScope duplicate(env.route, env.contract, env.driver, env.owner,
                                   env.requestID, env.generation, env.wlc,
                                   env.bssid, env.ieReason, env.callbacks);
        assert(!duplicate.active());
        assert(duplicate.status() == DF::Status::ContractViolation);
    }
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.length15Calls == 0 && !outer.complete());
    assert(outer.status() == DF::Status::ContractViolation);
    assert(!env.lastRouteResult.extended);

    TestEnv second;
    DF::RequestScope scope(second.route, second.contract, second.driver,
                           second.owner, second.requestID, second.generation,
                           second.wlc, second.bssid, second.ieReason,
                           second.callbacks);
    runOneSender(second, second.contract.senderCallerPCs[0]);
    assert(scope.complete());
    void *firstExtendedPacket = second.lastRouteResult.packet;
    assert(firstExtendedPacket && second.lastRouteResult.extended);
    runOneSender(second, second.contract.senderCallerPCs[0]);
    assert(second.length15Calls == 1 && second.length2Calls == 1);
    assert(!scope.complete() && scope.status() == DF::Status::ContractViolation);
    assert(second.lastRouteResult.packet && !second.lastRouteResult.extended);
    assert(!static_cast<Packet *>(firstExtendedPacket)->freed);
}

static void test_duplicate_builder_is_reported() {
    TestEnv env;
    env.duplicateBuilder = true;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.length15Calls == 1 && env.length2Calls == 1);
    assert(!scope.complete() && scope.status() == DF::Status::ContractViolation);
    assert(env.lastRouteResult.extended && env.lastRouteResult.packet);
    assert(env.freeCalls == 0);
}

static void test_builder_callsite_subtype_and_length_guards() {
    for (unsigned which = 0; which < 3; ++which) {
        TestEnv env;
        if (which == 0) env.badBuilderPC = true;
        if (which == 1) env.badBuilderSubtype = true;
        if (which == 2) env.badBuilderLength = true;
        DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                               env.requestID, env.generation, env.wlc,
                               env.bssid, env.ieReason, env.callbacks);
        runOneSender(env, env.contract.senderCallerPCs[0]);
        assert(env.length15Calls == 0 && env.bodyWriteCalls == 0);
        assert(!scope.complete());
        if (which != 0) assert(scope.status() == DF::Status::ContractViolation);
        else assert(scope.status() == DF::Status::ContractViolation); // missing native builder hit
    }
}

static void test_builder_failure_never_reads_uninitialized_body_out() {
    TestEnv env;
    env.failBuilder = true;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.length15Calls == 1 && env.bodyWriteCalls == 0);
    assert(env.bodyOutReads == 0 && env.freeCalls == 0);
    assert(!scope.complete() && scope.status() == DF::Status::BuilderFailed);
}

static void test_zero_extended_reason_does_not_create_active_scope() {
    TestEnv env;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           0, env.callbacks);
    assert(!scope.active() && scope.status() == DF::Status::InvalidArgument);
    runOneSender(env, env.contract.senderCallerPCs[0], nullptr,
                 DF::DriverKind::Invalid, nullptr, 0xa1b2c3d4U);
    assert(env.length15Calls == 0 && env.length2Calls == 1);
    assert(env.bodyWriteCalls == 0 && env.bodyOutReads == 0 && env.freeCalls == 0);
    assert(env.lastRouteResult.packet && !env.lastRouteResult.extended);
    assert(env.lastBody && env.lastBody[0] == 0xd4 && env.lastBody[1] == 0xc3);
}

static void test_write_failure_frees_then_rebuilds_original_packet() {
    TestEnv env;
    env.failWrite = true;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.length15Calls == 1 && env.length2Calls == 1 &&
           env.builderCalls == 2 && env.bodyWriteCalls == 1);
    assert(env.bodyOutReads == 0);
    assert(env.freeCalls == 1 && env.packetCount == 2 && env.packets[0].freed &&
           !env.packets[1].freed);
    assert(env.freeEventOrder && env.fallbackBuilderEventOrder &&
           env.freeEventOrder < env.fallbackBuilderEventOrder);
    assert(env.lastSenderPacket == &env.packets[1]);
    assert(env.lastRouteResult.packet == &env.packets[1] &&
           !env.lastRouteResult.extended &&
           env.lastRouteResult.status == DF::Status::WriteFailed);
    assert(env.lastBody && env.lastBody[0] == 0xcd && env.lastBody[1] == 0xab);
    assert(!scope.complete() && scope.status() == DF::Status::WriteFailed);
}

static void test_write_failure_fallback_builder_failure_returns_null() {
    TestEnv env;
    env.failWrite = true;
    env.failFallbackBuilder = true;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.length15Calls == 1 && env.length2Calls == 1 &&
           env.builderCalls == 2 && env.bodyWriteCalls == 1);
    assert(env.bodyOutReads == 0 && env.freeCalls == 1 && env.packetCount == 1 &&
           env.packets[0].freed);
    assert(env.freeEventOrder && env.fallbackBuilderEventOrder &&
           env.freeEventOrder < env.fallbackBuilderEventOrder);
    assert(env.lastSenderPacket == nullptr && !env.lastRouteResult.packet &&
           !env.lastRouteResult.extended &&
           env.lastRouteResult.status == DF::Status::WriteFailed);
    assert(!scope.complete() && scope.status() == DF::Status::WriteFailed);
}

static void test_null_original_builder_does_not_read_or_free_body_out() {
    TestEnv env;
    env.callbacks.originalBuilder = nullptr;
    DF::BuilderInvocation invocation {};
    invocation.driver = env.driver;
    invocation.callerReturnPC = env.contract.builderReturnPC;
    invocation.wlc = env.wlc;
    invocation.address3 = env.address3;
    invocation.subtype = DF::DisassociateSubtype;
    invocation.bodyLength = DF::OriginalReasonBytes;
    invocation.bodyOutSlot = reinterpret_cast<void *>(uintptr_t(1));
    DF::RouteResult result = DF::interceptBuilder(
        env.route, invocation, env.callbacks);
    assert(!result.packet && result.status == DF::Status::InvalidArgument);
    assert(env.bodyOutReads == 0 && env.freeCalls == 0 &&
           env.builderCalls == 0 && env.packetCount == 0);
}

static void test_stale_owner_does_not_route() {
    TestEnv env;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    env.ownerCurrent = false;
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.length15Calls == 0 && !scope.complete());
    assert(scope.status() == DF::Status::OwnerStale);
}

static void test_stale_generation_at_builder_falls_back_without_ie() {
    TestEnv env;
    env.staleBeforeBuilder = true;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.length15Calls == 0 && env.length2Calls == 1);
    assert(env.bodyWriteCalls == 0 && env.freeCalls == 0);
    assert(env.lastRouteResult.packet && !env.lastRouteResult.extended);
    assert(!scope.complete() && scope.status() == DF::Status::OwnerStale);
}

static void test_generation_stale_during_builder_frees_unqueued_extended_packet() {
    TestEnv env;
    env.staleDuringBuilder = true;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.length15Calls == 1 && env.length2Calls == 1);
    assert(env.bodyWriteCalls == 0 && env.freeCalls == 1);
    assert(env.packetCount == 2 && env.packets[0].freed && !env.packets[1].freed);
    assert(env.lastRouteResult.packet == &env.packets[1]);
    assert(!env.lastRouteResult.extended);
    assert(!scope.complete() && scope.status() == DF::Status::OwnerStale);
}

static void test_reentrant_matching_sender_cancels_builder_packet_before_write() {
    TestEnv env;
    env.reenterMatchingSenderDuringBuilder = true;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.length15Calls == 1 && env.length2Calls == 2);
    assert(env.bodyWriteCalls == 0 && env.freeCalls == 1);
    assert(env.packetCount == 3 && env.packets[0].freed);
    assert(!env.packets[1].freed && !env.packets[2].freed);
    assert(env.reentrantSenderResult.packet == &env.packets[1]);
    assert(!env.reentrantSenderResult.extended);
    assert(env.lastRouteResult.packet == &env.packets[2]);
    assert(!env.lastRouteResult.extended);
    assert(!scope.complete() && scope.status() == DF::Status::ContractViolation);
}

static void test_reentrant_duplicate_scope_cancels_builder_packet_before_write() {
    TestEnv env;
    env.reenterDuplicateScopeDuringBuilder = true;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.duplicateScopeStatus == DF::Status::ContractViolation);
    assert(env.length15Calls == 1 && env.length2Calls == 1);
    assert(env.bodyWriteCalls == 0 && env.freeCalls == 1);
    assert(env.packetCount == 2 && env.packets[0].freed);
    assert(!env.packets[1].freed);
    assert(env.lastRouteResult.packet == &env.packets[1]);
    assert(!env.lastRouteResult.extended);
    assert(!scope.complete() && scope.status() == DF::Status::ContractViolation);
}

static void test_scope_cleanup_disables_late_builder_and_sender() {
    TestEnv env;
    {
        DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                               env.requestID, env.generation, env.wlc,
                               env.bssid, env.ieReason, env.callbacks);
        assert(scope.active());
    }
    runOneSender(env, env.contract.senderCallerPCs[0]);
    assert(env.length15Calls == 0 && env.length2Calls == 1);
}

static void test_nested_request_scope_restores_outer_scope() {
    TestEnv env;
    DF::RequestScope outer(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    {
        uint8_t secondOwner = 0;
        DF::MacAddress secondBSSID {{0x02, 0x61, 0x62, 0x63, 0x64, 0x65}};
        memcpy(env.otherAddress, secondBSSID.bytes, 6);
        env.owner = &secondOwner;
        env.requestID = 0x303;
        env.generation = 0x404;
        DF::RequestScope inner(env.route, env.contract, env.driver, env.owner,
                               env.requestID, env.generation, env.wlc,
                               secondBSSID, 0x99, env.callbacks);
        assert(inner.active());
        runOneSender(env, env.contract.senderCallerPCs[0], env.address3);
        assert(env.length15Calls == 0);
    }
    env.owner = &env.ownerStorage;
    env.requestID = 0x101;
    env.generation = 0x202;
    runOneSender(env, env.contract.senderCallerPCs[0], env.address3);
    assert(env.length15Calls == 1 && outer.complete());
}

static void test_no_lease_builder_is_passthrough() {
    TestEnv env;
    DF::RequestScope scope(env.route, env.contract, env.driver, env.owner,
                           env.requestID, env.generation, env.wlc, env.bssid,
                           env.ieReason, env.callbacks);
    uint8_t *out = reinterpret_cast<uint8_t *>(uintptr_t(0x1));
    DF::BuilderInvocation builder {};
    builder.driver = env.driver;
    builder.callerReturnPC = env.contract.builderReturnPC;
    builder.wlc = env.wlc;
    builder.address3 = env.address3;
    builder.subtype = DF::DisassociateSubtype;
    builder.bodyLength = DF::OriginalReasonBytes;
    builder.bodyOutSlot = &out;
    DF::RouteResult result = DF::interceptBuilder(env.route, builder, env.callbacks);
    assert(result.packet && !result.extended);
    assert(env.length2Calls == 1 && env.length15Calls == 0);
    assert(env.bodyWriteCalls == 0 && !scope.complete());
}

int main() {
    test_ie_encoder();
    test_success_for_each_driver(DF::DriverKind::Brcm4331);
    test_success_for_each_driver(DF::DriverKind::Brcm43224);
    test_success_alternate_4331_sender_callsite();
    test_unrelated_callers_do_not_consume_token();
    test_wrong_bssid_and_controller_do_not_route();
    test_wrong_thread_does_not_route();
    test_nested_unrelated_sender_preserves_outer_lease();
    test_matching_nested_sender_cancels_unused_lease();
    test_duplicate_scope_and_sender_are_reported();
    test_duplicate_builder_is_reported();
    test_builder_callsite_subtype_and_length_guards();
    test_builder_failure_never_reads_uninitialized_body_out();
    test_zero_extended_reason_does_not_create_active_scope();
    test_write_failure_frees_then_rebuilds_original_packet();
    test_write_failure_fallback_builder_failure_returns_null();
    test_null_original_builder_does_not_read_or_free_body_out();
    test_stale_owner_does_not_route();
    test_stale_generation_at_builder_falls_back_without_ie();
    test_generation_stale_during_builder_frees_unqueued_extended_packet();
    test_reentrant_matching_sender_cancels_builder_packet_before_write();
    test_reentrant_duplicate_scope_cancels_builder_packet_before_write();
    test_scope_cleanup_disables_late_builder_and_sender();
    test_nested_request_scope_restores_outer_scope();
    test_no_lease_builder_is_passthrough();
    return 0;
}
'''


class LegacyDisassociateFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang++")
        if not compiler:
            raise unittest.SkipTest("clang++ is required for the portable C++ harness")
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="legacy-disassoc-frame-")
        cls.binary = Path(cls.temp_dir.name) / "disassociate-frame-tests"
        command = [
            compiler,
            "-std=c++14",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-I",
            str(PROJECT / "src"),
            "-x",
            "c++",
            "-",
            "-o",
            str(cls.binary),
        ]
        built = subprocess.run(command, input=HARNESS, text=True,
                               capture_output=True, timeout=60)
        if built.returncode != 0:
            raise AssertionError(built.stdout + built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_scope_ie_and_failure_contracts_under_asan_ubsan(self):
        completed = subprocess.run([str(self.binary)], text=True,
                                   capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 0,
                         completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
