#!/usr/bin/env python3
"""Verify the pinned El Cap cache-provider contract and its C++ guard.

This only maps and inspects the retained Mach-O file, then relays its declared
external branch relocations to synthetic host addresses for the C++ guard
harness. It does not load the kext, execute provider code, mutate a cache, or
validate runtime/hardware behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
sys.path.insert(0, str(PROJECT / "tools"))
import build_namespace  # noqa: E402
import verify_ifnet_kernel_contracts as macho  # noqa: E402
from verify_legacy_provider_contracts import mapped_provider, relocation_sites  # noqa: E402

PROVIDER_SHA256 = "8ecd8f8a027d93205a493518c50a772f520ee774d2fa4d24b564dc67722c54b0"
PROVIDER_UUID = bytes.fromhex("b6a43edc47e93db89887812d1c77f38c")
DEFAULT_PROVIDER = PROJECT / "build/research/oclp-legacy/elcap-analysis-inputs/IO80211ElCap.bin"

# True function extents come from terminal instructions, then are cross-checked
# against the next independent Mach-O symbol. Do not infer end from a guessed
# neighboring symbol: several bodies have a single alignment NOP after the ret/
# indirect jump, and scanDone's next symbol begins one byte after its ret.
FUNCTIONS = (
    {"index": 0, "name": "__ZN18IO80211ScanManager30initWithControllerAndInterfaceEP17IO80211ControllerP16IO80211Interface",
     "start": 0x5F70A, "end": 0x5F86E, "next_name": "__ZN18IO80211ScanManager17cachePurgeTimeoutEP8OSObjectP18IOTimerEventSource", "next": 0x5F86E,
     "external": True, "terminal": 0x5F869, "terminal_kind": "import_call", "terminal_target": "___stack_chk_fail",
     "sha256": "14a16380b462fe3c72670b3c710a12bb9bb877d30a0b3bd791c5af203bb6aa14"},
    {"index": 1, "name": "__ZN18IO80211ScanManager17cachePurgeTimeoutEP8OSObjectP18IOTimerEventSource",
     "start": 0x5F86E, "end": 0x5F87A, "next_name": "__ZN18IO80211ScanManager26createScanManagerReportSetEv", "next": 0x5F87A,
     "external": True, "terminal": 0x5F875, "terminal_kind": "internal_jump", "terminal_target": 0x6203C,
     "sha256": "6fa9e5b0993f93ad29f4882738ef51eb8beabbf75afc057649bd082483a23c83"},
    {"index": 2, "name": "__ZN18IO80211ScanManager4freeEv",
     "start": 0x5FC78, "end": 0x5FD45, "next_name": "__ZN18IO80211ScanManager16destroyReportersEv", "next": 0x5FD46,
     "external": True, "terminal": 0x5FD3F, "terminal_kind": "indirect_jump", "terminal_target": 0xA0,
     "sha256": "edcf3f1ccdc6b06aa4327258fe123566b4e2b57cebb5ae862a87f40739ad1df9"},
    {"index": 3, "name": "__ZN18IO80211ScanManager20getCachedScanResultsEP20apple80211_scan_dataP23apple80211scan_req_nodeP10ether_addrj",
     "start": 0x60186, "end": 0x60435, "next_name": "__ZN18IO80211ScanManager8fastScanEP20apple80211_scan_datai", "next": 0x60436,
     "external": True, "terminal": 0x60434, "terminal_kind": "return", "terminal_target": None,
     "sha256": "53e115ec9447bd371429e7956d2d975b31bc48d02a26c91f53ee9a1695608d79"},
    {"index": 4, "name": "__ZN18IO80211ScanManager13getScanResultEPP22apple80211_scan_result",
     "start": 0x61B1E, "end": 0x61CC2, "next_name": "__ZN18IO80211ScanManager11updateCacheEP25apple80211scan_cache_nodeP23apple80211scan_req_node", "next": 0x61CC2,
     "external": True, "terminal": 0x61CBD, "terminal_kind": "import_call", "terminal_target": "___stack_chk_fail",
     "sha256": "d2f8fec6ac150ba5256815240dce4f3a4e3e2eae8ec0b2bcece91718c6c38be3"},
    {"index": 5, "name": "__ZN18IO80211ScanManager11updateCacheEP25apple80211scan_cache_nodeP23apple80211scan_req_node",
     "start": 0x61CC2, "end": 0x61D9E, "next_name": "__ZN18IO80211ScanManager8scanDoneEb", "next": 0x61D9E,
     "external": True, "terminal": 0x61D9D, "terminal_kind": "return", "terminal_target": None,
     "sha256": "4973b46838d077b588f69216e3e06b7acc1bf43100920b08bbc2725c429867b0"},
    {"index": 6, "name": "__ZN18IO80211ScanManager8scanDoneEb",
     "start": 0x61D9E, "end": 0x6203B, "next_name": "__ZN18IO80211ScanManager10cachePurgeEb", "next": 0x6203C,
     "external": True, "terminal": 0x6203A, "terminal_kind": "return", "terminal_target": None,
     "sha256": "134fbc1e9b7b560d6a483e1691c700c36bc67bd0b73617533b87ec256ee7dd58"},
    {"index": 7, "name": "__ZN18IO80211ScanManager10cachePurgeEb",
     "start": 0x6203C, "end": 0x62302, "next_name": "__ZN18IO80211ScanManager20setCacheAgeThresholdEj", "next": 0x62302,
     "external": True, "terminal": 0x62301, "terminal_kind": "return", "terminal_target": None,
     "sha256": "432883d68b72828486f6581a4d939e1e512ff31b5e34b3220f05b42fffd7246e"},
    {"index": 8, "name": "__ZL15_releaseReqNodeP23apple80211scan_req_node",
     "start": 0x625CE, "end": 0x6265A, "next_name": "__ZL17_releaseCacheNodeP25apple80211scan_cache_node", "next": 0x6265A,
     "external": False, "terminal": 0x62655, "terminal_kind": "import_jump", "terminal_target": "_IOFree",
     "sha256": "2ce7ce8c59f4ee13a4c063c4ee59a2e1efc640fadcacc6be3838224b235f9e38"},
    {"index": 9, "name": "__ZL17_releaseCacheNodeP25apple80211scan_cache_node",
     "start": 0x6265A, "end": 0x626AA, "next_name": "__ZL14_phyModeForAsrP22apple80211_scan_result2071", "next": 0x626AA,
     "external": False, "terminal": 0x626A5, "terminal_kind": "import_jump", "terminal_target": "_IOFree",
     "sha256": "35fd564b468c2ee50a23c47a9e90b684eb756bd137d2b17ba62040d20a04d942"},
    {"index": 10, "name": "__ZN16IO80211Interface23detachFromDataLinkLayerEjPv",
     "start": 0x58126, "end": 0x5819E, "next_name": "__ZN16IO80211Interface20reportTransmitStatusEP6__mbufiP14packet_info_tx", "next": 0x5819E,
     "external": True, "terminal": 0x58198, "terminal_kind": "indirect_jump", "terminal_target": 0x9B8,
     "sha256": "4a8f52e52adca30897aa4f23de3e17874b6dd998f303b6590f11a09c2a2cbf73"},
    {"index": 11, "name": "__ZN16IO80211Interface27finishAttachToDataLinkLayerEv",
     "start": 0x578BA, "end": 0x57B63, "next_name": "__ZN16IO80211Interface22updateStaticPropertiesEv", "next": 0x57B64,
     "external": True, "terminal": 0x57B5E, "terminal_kind": "import_call", "terminal_target": "___stack_chk_fail",
     "sha256": "12b1c4705c59c39a0f124cdc6b97c86411e1ca17660c762c64afc8294f82f7a4"},
    {"index": 12, "name": "__ZN17IO80211Controller20apple80211_ioctl_setEP16IO80211InterfaceP23IO80211VirtualInterfaceP7__ifnetPv",
     "start": 0x55460, "end": 0x55519, "next_name": "__ZN17IO80211Controller16stringFromReturnEi", "next": 0x5551A,
     "external": True, "terminal": 0x55518, "terminal_kind": "return", "terminal_target": None,
     "sha256": "0fa6c4b0946ad3684a07d0f5fe37d9fce6b88415a3f16d0e30ed248f5c81399e"},
)

IMPORTS = (
    "_IOLog", "_IOMalloc", "_IOFree", "_bzero", "_memcpy", "_memcmp",
    "_clock_get_calendar_nanotime", "_proc_selfpid", "_proc_selfname",
    "__ZN18IOTimerEventSource16timerEventSourceEP8OSObjectPFvS1_PS_E",
    "___stack_chk_fail", "_ifnet_remove_multicast", "_ifmaddr_release",
    "__ZTV19IOEthernetInterface", "_ifnet_index", "_ifnet_add_multicast",
    "_ifnet_lladdr", "_ifnet_type", "_registerPrioritySleepWakeInterest",
    "_buf_kernel_addrperm_addr", "_ifnet_set_eflags", "_proc_self",
    "_proc_is64bit", "_proc_rele",
)
IMPORT_ENUMS = (
    "IOLog", "IOMalloc", "IOFree", "Bzero", "Memcpy", "Memcmp",
    "ClockGetCalendarNanotime", "ProcSelfPID", "ProcSelfName",
    "TimerEventSource", "StackCheckFail", "IfnetRemoveMulticast",
    "IfmaddrRelease", "EthernetInterfaceVTable", "IfnetIndex",
    "IfnetAddMulticast", "IfnetLLAddr", "IfnetType",
    "RegisterPrioritySleepWakeInterest", "BufKernelAddrpermAddr",
    "IfnetSetEflags", "ProcSelf", "ProcIs64Bit", "ProcRele",
)

# instruction address and import. Each must have exactly one Mach-O external
# BRANCH relocation at instruction+1, with pcrel=1, length=2, type=2.
EXTERNAL_CALLS = (
    (0x5F7F1, "_IOLog"), (0x5F767, IMPORTS[9]), (0x5F869, "___stack_chk_fail"),
    (0x603BF, "_IOMalloc"), (0x601AE, "_clock_get_calendar_nanotime"),
    (0x60207, "_memcmp"), (0x602AF, "_memcmp"), (0x602E0, "_memcmp"), (0x6032E, "_memcmp"),
    (0x61C68, "_IOFree"), (0x61C34, "_IOLog"), (0x61CBD, "___stack_chk_fail"),
    (0x61BA4, "_clock_get_calendar_nanotime"), (0x61C04, "_proc_selfname"), (0x61B46, "_proc_selfpid"),
    (0x61CFF, "_memcmp"),
    (0x61F73, "_IOFree"), (0x62000, "_IOLog"), (0x61E2B, "_IOMalloc"),
    (0x61E71, "_IOMalloc"), (0x61EE0, "_IOMalloc"), (0x61E44, "_bzero"),
    (0x61DC1, "_clock_get_calendar_nanotime"), (0x61E59, "_memcpy"), (0x61EA9, "_memcpy"),
    (0x6207E, "_IOLog"), (0x620EE, "_IOLog"), (0x62206, "_IOLog"),
    (0x6229F, "_IOLog"), (0x622E4, "_IOLog"), (0x62097, "_clock_get_calendar_nanotime"),
    (0x621DB, "_memcpy"), (0x62224, "_memcpy"),
    (0x625E6, "_IOFree"), (0x62611, "_IOFree"), (0x62655, "_IOFree"),
    (0x62692, "_IOFree"), (0x626A5, "_IOFree"), (0x6267A, "_IOLog"),
    (0x58145, "_ifnet_remove_multicast"), (0x58151, "_ifmaddr_release"),
    (0x57926, "_bzero"), (0x5793E, "_ifnet_index"), (0x57959, "_memcpy"),
    (0x5796B, "_ifnet_add_multicast"), (0x57973, "_ifnet_lladdr"),
    (0x57982, "_ifnet_type"), (0x579A1, "_registerPrioritySleepWakeInterest"),
    (0x579B4, "_buf_kernel_addrperm_addr"), (0x579CF, "_buf_kernel_addrperm_addr"),
    (0x579DA, "_buf_kernel_addrperm_addr"), (0x579F1, "_buf_kernel_addrperm_addr"),
    (0x57A0B, "_IOLog"), (0x57ACA, "_IOLog"), (0x57ADC, "_ifnet_set_eflags"),
    (0x57B5E, "___stack_chk_fail"),
    (0x5547A, "_proc_self"), (0x5548F, "_proc_is64bit"),
    (0x5549A, "_proc_rele"),
)

# Non-BRANCH external relocation used by detach's tail dispatch: the
# RIP-relative load reads the IOEthernetInterface vtable through this slot.
EXTERNAL_POINTERS = ((0x98090, "__ZTV19IOEthernetInterface", 0, 3, 0),)
INDIRECT_CALLS = ((0x58170, 0x28, "OSObject::release"),)

INTERNAL_BRANCHES = (
    (0x5F840, 0x537A6), (0x5F875, 0x6203C),
    (0x5FCE5, 0x625CE), (0x5FD0F, 0x6265A),
    (0x61C91, 0x625CE), (0x61D6C, 0x6265A), (0x61ED1, 0x61CC2),
    (0x62117, 0x625CE), (0x62159, 0x6265A), (0x62273, 0x6265A),
    (0x62642, 0x6265A),
    (0x57990, 0x57B64), (0x57A41, 0x5F70A), (0x57AAF, 0x5C4E8),
    (0x57AF3, 0x57DD8), (0x57B0F, 0x6A886), (0x57B2F, 0x56DEA),
    (0x55500, 0x53E34),
)
INTERNAL_BRANCH_OPCODES = {0x5F875: 0xE9}

INTERNAL_TARGET_SYMBOLS = {
    0x537A6: "__ZN17IO80211Controller22apple80211RequestIoctlEjiP16IO80211InterfacePv",
    0x57B64: "__ZN16IO80211Interface22updateStaticPropertiesEv",
    0x5F70A: "__ZN18IO80211ScanManager30initWithControllerAndInterfaceEP17IO80211ControllerP16IO80211Interface",
    0x5C4E8: "__ZN16IO80211Interface9bpfAttachEjjP8OSObjectMS0_FjP6__mbufPvEMS0_FijjEP10IOWorkLoop",
    0x57DD8: "__ZN16IO80211Interface17createIOReportersEP9IOService",
    0x6A886: "__ZN30IO80211AssociationJoinSnapshot22withInterfaceAndLengthEP9IOServiceP16IO80211Interfacej",
    0x56DEA: "__ZN16IO80211Interface8logDebugEPKcz",
    0x53E34: "__ZN17IO80211Controller8logDebugEPKcz",
    0x6203C: "__ZN18IO80211ScanManager10cachePurgeEb",
    0x625CE: "__ZL15_releaseReqNodeP23apple80211scan_req_node",
    0x6265A: "__ZL17_releaseCacheNodeP25apple80211scan_cache_node",
    0x61CC2: "__ZN18IO80211ScanManager11updateCacheEP25apple80211scan_cache_nodeP23apple80211scan_req_node",
}

PADDING = ((0x5FD45, 0x90), (0x60435, 0x90), (0x6203B, 0x90),
           (0x57B63, 0x90), (0x55519, 0x90))
EXTERNAL_JUMPS = frozenset((0x62655, 0x626A5))
MANAGER_SIZE_INSTRUCTION = 0x5F60F
MANAGER_SIZE_BYTES = bytes.fromhex("b9b0000000")

LAYOUT = {
    "scan_manager_size": 0xB0,
    "manager_cache_head_offset": 0x18,
    "pending_request_head_offset": 0x10,
    "cache_node_size": 0xC0,
    "cache_node_next_offset": 0x00,
    "cache_node_previous_link_offset": 0x08,
    "cache_node_reference_count_offset": 0x10,
    "cache_node_scan_result_offset": 0x18,
    "cache_node_scan_result_size": 0x98,
    "cache_node_bssid_offset": 0x34,
    "cache_node_ssid_length_offset": 0x78,
    "cache_node_ssid_bytes_offset": 0x79,
    "cache_node_ie_length_offset": 0xA2,
    "cache_node_ie_pointer_offset": 0xA8,
    "cache_node_age_offset": 0xB8,
    "request_cache_reference_owner_offset": 0x1288,
    "request_pid_result_queue_offset": 0x1290,
    "request_cache_reference_size": 0x18,
    "request_cache_reference_node_offset": 0x10,
}

HARNESS = r'''#include "legacy_wifi_compat/cache_provider_contract.hpp"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>
namespace C = LegacyWiFi::CacheProviderContract;
namespace P = LegacyWiFi::ProviderContract;
int main(int argc, char **argv) {
    assert(argc == 2);
    std::ifstream input(argv[1], std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(input)), {});
    assert(!data.empty());
@@CONTRACT_TABLE_ASSERTS@@
    P::Image image {data.data(), data.size(), 0xffffff8001000000ULL};
    C::Symbols symbols {};
    for (size_t index=0; index<C::FunctionCount; ++index)
        symbols.addresses[index]=image.base+C::Functions[index].start;
    C::Imports imports {};
    for (size_t index=0; index<C::ImportCount; ++index)
        imports.addresses[index]=image.base+image.size+0x1000+index*0x1000;
    auto relocate=[&](size_t instruction, C::Import imported, uint8_t opcode) {
        assert(data[instruction]==opcode);
        const uintptr_t target=imports.addresses[static_cast<size_t>(imported)];
        const uintptr_t returnPC=image.base+instruction+5;
        const int64_t delta=target>=returnPC ? static_cast<int64_t>(target-returnPC)
                                             : -static_cast<int64_t>(returnPC-target);
        assert(delta>=INT32_MIN && delta<=INT32_MAX);
        const int32_t encoded=static_cast<int32_t>(delta);
        std::memcpy(data.data()+instruction+1,&encoded,sizeof(encoded));
    };
    const uint8_t uuid[16]={0xb6,0xa4,0x3e,0xdc,0x47,0xe9,0x3d,0xb8,
                            0x98,0x87,0x81,0x2d,0x1c,0x77,0xf3,0x8c};
    assert(!C::verify(image,uuid,symbols,imports));
    for (size_t index=0; index<C::ExternalCallCount; ++index) {
        const C::RelocationCall &call=C::ExternalCalls[index];
        relocate(call.instruction,call.target,call.opcode);
    }
    for (size_t index=0; index<C::ExternalPointerCount; ++index) {
        const C::ExternalPointer &pointer=C::ExternalPointers[index];
        const uintptr_t target=imports.addresses[static_cast<size_t>(pointer.target)];
        std::memcpy(data.data()+pointer.offset,&target,sizeof(target));
    }
    assert(C::verify(image,uuid,symbols,imports));

    assert(C::isFreshFinishAttachManagerInitReturn(
        image,image.base+C::FinishAttachManagerInitReturnPC,symbols));
    size_t rejectedFinishAttachInitReturnMutations=0;
    assert(!C::isFreshFinishAttachManagerInitReturn(
        image,image.base+C::FinishAttachManagerInitReturnPC+1,symbols));
    ++rejectedFinishAttachInitReturnMutations;
    C::Symbols wrongSymbols=symbols;
    ++wrongSymbols.addresses[C::InterfaceFinishAttach];
    assert(!C::isFreshFinishAttachManagerInitReturn(
        image,image.base+C::FinishAttachManagerInitReturnPC,wrongSymbols));
    ++rejectedFinishAttachInitReturnMutations;
    wrongSymbols=symbols;
    ++wrongSymbols.addresses[C::ManagerInit];
    assert(!C::isFreshFinishAttachManagerInitReturn(
        image,image.base+C::FinishAttachManagerInitReturnPC,wrongSymbols));
    ++rejectedFinishAttachInitReturnMutations;
    data[C::FinishAttachManagerInitCall+1]^=1;
    assert(!C::isFreshFinishAttachManagerInitReturn(
        image,image.base+C::FinishAttachManagerInitReturnPC,symbols));
    data[C::FinishAttachManagerInitCall+1]^=1;
    ++rejectedFinishAttachInitReturnMutations;

    const uintptr_t disassociateHandler=image.base+P::Offsets[P::SetDisassociate];
    assert(C::isCanonicalSetDisassociateHandlerDispatch(
        image,image.base+C::DisassociateHandlerReturnPC,disassociateHandler));
    size_t rejectedDisassociateDispatchMutations=0;
    assert(!C::isCanonicalSetDisassociateHandlerDispatch(
        image,image.base+C::DisassociateHandlerReturnPC+1,disassociateHandler));
    ++rejectedDisassociateDispatchMutations;
    assert(!C::isCanonicalSetDisassociateHandlerDispatch(
        image,image.base+C::DisassociateHandlerReturnPC,disassociateHandler+1));
    ++rejectedDisassociateDispatchMutations;
    assert(!C::isCanonicalSetDisassociateHandlerDispatch(
        image,image.base+C::DisassociateHandlerReturnPC,image.base+image.size+1));
    ++rejectedDisassociateDispatchMutations;
    P::Image otherImageBase=image;
    otherImageBase.base+=0x1000;
    assert(!C::isCanonicalSetDisassociateHandlerDispatch(
        otherImageBase,otherImageBase.base+C::DisassociateHandlerReturnPC,
        disassociateHandler));
    ++rejectedDisassociateDispatchMutations;
    data[C::DisassociateHandlerCallInstruction]^=1;
    assert(!C::isCanonicalSetDisassociateHandlerDispatch(
        image,image.base+C::DisassociateHandlerReturnPC,disassociateHandler));
    data[C::DisassociateHandlerCallInstruction]^=1;
    ++rejectedDisassociateDispatchMutations;

    data[C::SetHandlerTableCountOffset]^=1;
    assert(!C::verify(image,uuid,symbols,imports));
    data[C::SetHandlerTableCountOffset]^=1;

    for (size_t index=0; index<C::IndirectCallCount; ++index) {
        const C::IndirectCall &call=C::IndirectCalls[index];
        assert(data[call.instruction]==0xff && data[call.instruction+1]==0x50 &&
               data[call.instruction+2]==call.vtableSlot);
    }

    size_t rejectedBodyByteMutations=0;
    for (size_t functionIndex=0; functionIndex<C::FunctionCount; ++functionIndex) {
        const C::FunctionContract &function=C::Functions[functionIndex];
        for (size_t offset=function.start; offset<function.end; ++offset) {
            data[offset]^=1;
            assert(!C::verify(image,uuid,symbols,imports));
            data[offset]^=1;
            ++rejectedBodyByteMutations;
        }
    }
    size_t rejectedPaddingMutations=0;
    const size_t paddingOffsets[]={0x5fd45,0x60435,0x6203b,0x57b63,0x55519};
    for (size_t offset : paddingOffsets) {
        data[offset]^=1;
        assert(!C::verify(image,uuid,symbols,imports));
        data[offset]^=1;
        ++rejectedPaddingMutations;
    }
    data[0x5f60f]^=1;
    assert(!C::verify(image,uuid,symbols,imports));
    data[0x5f60f]^=1;
    size_t rejectedSymbolMutations=0;
    for (size_t index=0; index<C::FunctionCount; ++index) {
        ++symbols.addresses[index];
        assert(!C::verify(image,uuid,symbols,imports));
        --symbols.addresses[index];
        ++rejectedSymbolMutations;
    }
    size_t rejectedImportMutations=0;
    for (size_t index=0; index<C::ImportCount; ++index) {
        ++imports.addresses[index];
        assert(!C::verify(image,uuid,symbols,imports));
        --imports.addresses[index];
        ++rejectedImportMutations;
    }
    size_t rejectedExternalPointerMutations=0;
    for (size_t index=0; index<C::ExternalPointerCount; ++index) {
        const C::ExternalPointer &pointer=C::ExternalPointers[index];
        data[pointer.offset]^=1;
        assert(!C::verify(image,uuid,symbols,imports));
        data[pointer.offset]^=1;
        ++rejectedExternalPointerMutations;
    }
    uint8_t badUUID[16]; std::memcpy(badUUID,uuid,sizeof(uuid)); badUUID[0]^=1;
    assert(!C::verify(image,badUUID,symbols,imports));
    assert(!C::verify(image,nullptr,symbols,imports));
    P::Image shortImage=image; shortImage.size=0x62000;
    assert(!C::verify(shortImage,uuid,symbols,imports));
    P::Image nullImage=image; nullImage.base=0;
    assert(!C::verify(nullImage,uuid,symbols,imports));
    std::printf("{\"accepted_after_synthetic_import_relocations\":true,"
                "\"accepted_finish_attach_init_return\":true,"
                "\"rejected_finish_attach_init_return_mutations\":%zu,"
                "\"accepted_disassociate_dispatch_callsite\":true,"
                "\"rejected_disassociate_dispatch_mutations\":%zu,"
                "\"rejected_set_handler_table_count_mutation\":true,"
                "\"external_import_branches\":%zu,\"internal_branches\":%zu,"
                "\"rejected_body_byte_mutations\":%zu,\"rejected_padding_mutations\":%zu,"
                "\"rejected_manager_size_mutation\":true,"
                "\"rejected_symbol_address_mutations\":%zu,\"rejected_import_address_mutations\":%zu,"
                "\"rejected_external_pointer_mutations\":%zu,"
                "\"rejected_uuid_mutation\":true,\"rejected_invalid_bounds\":3}\n",
                rejectedFinishAttachInitReturnMutations,rejectedDisassociateDispatchMutations,
                C::ExternalCallCount,C::CacheBranchCount,rejectedBodyByteMutations,
                rejectedPaddingMutations,rejectedSymbolMutations,rejectedImportMutations,
                rejectedExternalPointerMutations);
}'''


def _cpp_table_assertions() -> str:
    terminal_names = {
        "return": "Return", "import_call": "ImportedCall",
        "import_jump": "ImportedJump", "internal_jump": "InternalJump",
        "indirect_jump": "IndirectJump",
    }
    lines = [
        f'assert(std::strcmp(C::SourceSHA256, "{PROVIDER_SHA256}") == 0);',
        "const uint8_t expectedSourceUUID[16]={" +
        ",".join(f"0x{byte:02x}" for byte in PROVIDER_UUID) +
        "};",
        "assert(std::memcmp(C::SourceUUID, expectedSourceUUID, 16) == 0);",
        "assert(C::FunctionCount == %d);" % len(FUNCTIONS),
        "assert(C::ImportCount == %d);" % len(IMPORTS),
        "assert(C::ExternalCallCount == %d);" % len(EXTERNAL_CALLS),
        "assert(C::ExternalPointerCount == %d);" % len(EXTERNAL_POINTERS),
        "assert(C::IndirectCallCount == %d);" % len(INDIRECT_CALLS),
        "assert(C::CacheBranchCount == %d);" % len(INTERNAL_BRANCHES),
        f"static_assert(C::ScanManagerInstanceSize=={hex(LAYOUT['scan_manager_size'])}, \"manager size changed\");",
        f"static_assert(C::ScanManagerInstanceSizeInstructionOffset=={hex(MANAGER_SIZE_INSTRUCTION)}, \"manager size location changed\");",
        "static_assert(C::FinishAttachManagerInitCall==0x57a41, \"finishAttach init callsite changed\");",
        "static_assert(C::ManagerInitReturn==0x57a46 && C::FinishAttachManagerInitReturnPC==C::ManagerInitReturn, \"finishAttach init return PC changed\");",
    ]
    for index, enum_name in enumerate(IMPORT_ENUMS):
        lines.append(f"assert(static_cast<size_t>(C::{enum_name}) == {index});")
    lines.extend([
        "const char *expectedImportNames[] = {" + ",".join(json.dumps(item) for item in IMPORTS) + "};",
        "for (size_t i=0; i<C::ImportCount; ++i)",
        "  assert(std::strcmp(C::ImportNames[i],expectedImportNames[i])==0);",
    ])
    lines.extend([
        "const char *expectedNames[] = {" + ",".join(json.dumps(item["name"]) for item in FUNCTIONS) + "};",
        "const size_t expectedStarts[] = {" + ",".join(hex(item["start"]) for item in FUNCTIONS) + "};",
        "const size_t expectedEnds[] = {" + ",".join(hex(item["end"]) for item in FUNCTIONS) + "};",
        "const size_t expectedNextSymbols[] = {" + ",".join(hex(item["next"]) for item in FUNCTIONS) + "};",
        "const size_t expectedTerminals[] = {" + ",".join(hex(item["terminal"]) for item in FUNCTIONS) + "};",
        "const uint8_t expectedFunctionHashes[][32] = {" + ",".join(
            "{" + ",".join(f"0x{byte:02x}" for byte in bytes.fromhex(item["sha256"])) + "}"
            for item in FUNCTIONS) + "};",
        "const C::TerminalKind expectedTerminalKinds[] = {" + ",".join(
            f"C::{terminal_names[item['terminal_kind']]}" for item in FUNCTIONS) + "};",
        "const uint8_t expectedTerminalImports[] = {" + ",".join(
            str(IMPORTS.index(item["terminal_target"])) if isinstance(item["terminal_target"], str) else "0"
            for item in FUNCTIONS) + "};",
        "const uintptr_t expectedTerminalTargets[] = {" + ",".join(
            hex(item["terminal_target"]) if isinstance(item["terminal_target"], int) else "0"
            for item in FUNCTIONS) + "};",
        "for (size_t i=0; i<C::FunctionCount; ++i) {",
        "  const C::FunctionContract &f=C::Functions[i];",
        "  assert(std::strcmp(f.name,expectedNames[i])==0 && f.start==expectedStarts[i] &&",
        "         f.end==expectedEnds[i] && f.nextSymbol==expectedNextSymbols[i] &&",
        "         f.terminal==expectedTerminals[i] && f.terminalKind==expectedTerminalKinds[i] &&",
        "         f.terminalImport==expectedTerminalImports[i] && f.terminalTarget==expectedTerminalTargets[i] &&",
        "         std::memcmp(f.sha256,expectedFunctionHashes[i],32)==0);",
        "}",
        "const size_t expectedCallSites[] = {" + ",".join(hex(site) for site, _ in EXTERNAL_CALLS) + "};",
        "const C::Import expectedCallImports[] = {" + ",".join(
            f"static_cast<C::Import>({IMPORTS.index(symbol)})" for _, symbol in EXTERNAL_CALLS) + "};",
        "const uint8_t expectedCallOpcodes[] = {" + ",".join(
            "0xe9" if site in EXTERNAL_JUMPS else "0xe8" for site, _ in EXTERNAL_CALLS) + "};",
        "for (size_t i=0; i<C::ExternalCallCount; ++i) {",
        "  assert(C::ExternalCalls[i].instruction==expectedCallSites[i] &&",
        "         C::ExternalCalls[i].target==expectedCallImports[i] &&",
        "         C::ExternalCalls[i].opcode==expectedCallOpcodes[i]);",
        "}",
        "const size_t expectedExternalPointerOffsets[] = {" + ",".join(
            hex(offset) for offset,_,_,_,_ in EXTERNAL_POINTERS) + "};",
        "const C::Import expectedExternalPointerImports[] = {" + ",".join(
            f"static_cast<C::Import>({IMPORTS.index(symbol)})" for _,symbol,_,_,_ in EXTERNAL_POINTERS) + "};",
        "for (size_t i=0; i<C::ExternalPointerCount; ++i) {",
        "  assert(C::ExternalPointers[i].offset==expectedExternalPointerOffsets[i] &&",
        "         C::ExternalPointers[i].target==expectedExternalPointerImports[i]);",
        "}",
        "const size_t expectedIndirectCallSites[] = {" + ",".join(
            hex(site) for site,_,_ in INDIRECT_CALLS) + "};",
        "const uint8_t expectedIndirectCallSlots[] = {" + ",".join(
            hex(slot) for _,slot,_ in INDIRECT_CALLS) + "};",
        "for (size_t i=0; i<C::IndirectCallCount; ++i) {",
        "  assert(C::IndirectCalls[i].instruction==expectedIndirectCallSites[i] &&",
        "         C::IndirectCalls[i].vtableSlot==expectedIndirectCallSlots[i]);",
        "}",
        "const size_t expectedInternalSites[] = {" + ",".join(hex(site) for site, _ in INTERNAL_BRANCHES) + "};",
        "const uintptr_t expectedInternalTargets[] = {" + ",".join(hex(target) for _, target in INTERNAL_BRANCHES) + "};",
        "const uint8_t expectedInternalOpcodes[] = {" + ",".join(
            "0xe9" if site in INTERNAL_BRANCH_OPCODES else "0xe8" for site, _ in INTERNAL_BRANCHES) + "};",
        "for (size_t i=0; i<C::CacheBranchCount; ++i) {",
        "  assert(C::CacheBranches[i].instruction==expectedInternalSites[i] &&",
        "         C::CacheBranches[i].targetOffset==expectedInternalTargets[i] &&",
        "         C::CacheBranches[i].opcode==expectedInternalOpcodes[i]);",
        "}",
    ])
    for key, value in LAYOUT.items():
        header_name = {
            "scan_manager_size": "ScanManagerInstanceSize",
            "manager_cache_head_offset": "ManagerCacheHeadOffset",
            "pending_request_head_offset": "PendingRequestHeadOffset",
            "cache_node_size": "CacheNodeSize",
            "cache_node_next_offset": "CacheNodeNextOffset",
            "cache_node_previous_link_offset": "CacheNodePreviousLinkOffset",
            "cache_node_reference_count_offset": "CacheNodeReferenceCountOffset",
            "cache_node_scan_result_offset": "CacheNodeScanResultOffset",
            "cache_node_scan_result_size": "CacheNodeScanResultSize",
            "cache_node_bssid_offset": "CacheNodeBSSIDOffset",
            "cache_node_ssid_length_offset": "CacheNodeSSIDLengthOffset",
            "cache_node_ssid_bytes_offset": "CacheNodeSSIDBytesOffset",
            "cache_node_ie_length_offset": "CacheNodeIELengthOffset",
            "cache_node_ie_pointer_offset": "CacheNodeIEPointerOffset",
            "cache_node_age_offset": "CacheNodeAgeOffset",
            "request_cache_reference_owner_offset": "RequestCacheReferenceOwnerOffset",
            "request_pid_result_queue_offset": "RequestPIDResultQueueOffset",
            "request_cache_reference_size": "RequestCacheReferenceSize",
            "request_cache_reference_node_offset": "RequestCacheReferenceNodeOffset",
        }[key]
        if header_name:
            lines.append(f"static_assert(C::{header_name}=={hex(value)}, \"{header_name} changed\");")
    return "\n".join(lines)


def _one_symbol(linkage: dict, name: str, address: int, external: bool) -> dict:
    candidates = linkage["symbols"].get(name, [])
    matching = [item for item in candidates if item.get("defined") and item.get("value") == address]
    if len(matching) != 1 or matching[0].get("external") is not external:
        raise ValueError(f"provider symbol mismatch: {name} at {address:#x}")
    return matching[0]


def _uuid(raw: bytes) -> bytes:
    header = macho.parse_header(raw, 0, "IO80211ElCap")
    if header["filetype"] != 11:
        raise ValueError("expected MH_KEXT_BUNDLE")
    commands = [command for kind, command, _ in header["commands"] if kind == macho.LC_UUID]
    if len(commands) != 1 or len(commands[0]) != 24:
        raise ValueError("provider must have one complete LC_UUID")
    return commands[0][8:24]


def verify_bytes(raw: bytes) -> dict:
    source_sha = hashlib.sha256(raw).hexdigest()
    if source_sha != PROVIDER_SHA256:
        raise ValueError("IO80211ElCap executable does not match the pinned provider SHA-256")
    uuid = _uuid(raw)
    if uuid != PROVIDER_UUID:
        raise ValueError("IO80211ElCap UUID differs from the pinned provider")
    mapped = mapped_provider(raw)
    linkage = build_namespace.macho_linkage(raw)

    for function in FUNCTIONS:
        _one_symbol(linkage, function["name"], function["start"], function["external"])
        _one_symbol(linkage, function["next_name"], function["next"], True if function["next_name"].startswith("__ZN") else False)
        if function["next"] < function["end"]:
            raise ValueError(f"symbol overlaps audited body: {function['name']}")
        terminal_kind = function["terminal_kind"]
        terminal_size = 1 if terminal_kind == "return" else 6 if terminal_kind == "indirect_jump" else 5
        if function["terminal"] + terminal_size != function["end"]:
            raise ValueError(f"terminal instruction does not bound {function['name']}")

    for target_offset, target_name in INTERNAL_TARGET_SYMBOLS.items():
        _one_symbol(linkage, target_name, target_offset, target_name.startswith("__ZN"))

    _one_symbol(linkage, "_gSetHandlerTable", 0xA30E0, True)
    _one_symbol(linkage, "_gSetHandlerTableCount", 0xA3840, True)

    if mapped[MANAGER_SIZE_INSTRUCTION:MANAGER_SIZE_INSTRUCTION + len(MANAGER_SIZE_BYTES)] != MANAGER_SIZE_BYTES:
        raise ValueError("ScanManager metaclass allocation size changed")
    if int.from_bytes(mapped[0xA3840:0xA3844], "little") != 236:
        raise ValueError("SET handler table count changed")

    def rip_target(instruction: int, length: int, displacement_offset: int) -> int:
        displacement = int.from_bytes(
            mapped[instruction + displacement_offset:instruction + displacement_offset + 4],
            "little", signed=True)
        return instruction + length + displacement

    dispatcher_table = rip_target(0x554BC, 7, 3)
    dispatcher_count_a = rip_target(0x554B0, 6, 2)
    dispatcher_count_b = rip_target(0x554EE, 6, 2)
    if (dispatcher_table != 0xA30E0 or dispatcher_count_a != 0xA3840 or
            dispatcher_count_b != 0xA3840):
        raise ValueError("apple80211_ioctl_set RIP-relative table/count targets changed")
    if mapped[0x554E4:0x554E6] != b"\xff\xd0":
        raise ValueError("SET handler indirect-call instruction changed")

    external_records, local_records = relocation_sites(raw)
    expected = []
    selected_ranges = [(item["start"], item["end"]) for item in FUNCTIONS]
    for instruction, symbol in EXTERNAL_CALLS:
        relocation_address = instruction + 1
        expected.append({"address": relocation_address, "symbol": symbol,
                         "pcrel": 1, "length": 2, "type": 2})
        expected_opcode = 0xE9 if instruction in EXTERNAL_JUMPS else 0xE8
        if mapped[instruction] != expected_opcode:
            raise ValueError(f"external branch opcode changed at {instruction:#x}")
    actual_selected = [item for item in external_records
                       if any(start <= item["address"] < end for start, end in selected_ranges)]
    if sorted(actual_selected, key=lambda item: (item["address"], item["symbol"])) != \
       sorted(expected, key=lambda item: (item["address"], item["symbol"])):
        raise ValueError("selected function external relocation records differ from the audited import table")
    local_selected = [item for item in local_records
                      if any(start <= item["address"] < end for start, end in selected_ranges)]
    if local_selected:
        raise ValueError(f"selected cache function contains unexpected local relocations: {local_selected}")

    expected_pointer_records = [
        {"address": offset, "symbol": symbol, "pcrel": pcrel,
         "length": length, "type": relocation_type}
        for offset,symbol,pcrel,length,relocation_type in EXTERNAL_POINTERS
    ]
    actual_pointer_records = [item for item in external_records
                              if any(item.get("address") == entry[0] for entry in EXTERNAL_POINTERS)]
    if sorted(actual_pointer_records, key=lambda item: item["address"]) != expected_pointer_records:
        raise ValueError("detach vtable external pointer relocation differs from audited symbol/format")
    local_pointer_records = [item for item in local_records
                             if any(item.get("address") == entry[0] for entry in EXTERNAL_POINTERS)]
    if local_pointer_records:
        raise ValueError(f"detach vtable pointer slot has unexpected local relocations: {local_pointer_records}")

    for instruction,slot,_ in INDIRECT_CALLS:
        if mapped[instruction:instruction+3] != bytes((0xff,0x50,slot)):
            raise ValueError(f"indirect release dispatch changed at {instruction:#x}")
    for function in FUNCTIONS:
        if function["terminal_kind"] == "indirect_jump":
            expected_terminal = b"\xff\xa0" + function["terminal_target"].to_bytes(4,"little")
            if mapped[function["terminal"]:function["end"]] != expected_terminal:
                raise ValueError(f"indirect terminal/vtable slot changed at {function['terminal']:#x}")

    for instruction, target in INTERNAL_BRANCHES:
        if not (0 <= instruction < len(mapped)-5) or mapped[instruction] not in (0xE8, 0xE9):
            raise ValueError(f"internal call/jump opcode changed at {instruction:#x}")
        expected_opcode = INTERNAL_BRANCH_OPCODES.get(instruction, 0xE8)
        if mapped[instruction] != expected_opcode:
            raise ValueError(f"internal branch kind changed at {instruction:#x}")
        delta = int.from_bytes(mapped[instruction+1:instruction+5], "little", signed=True)
        if instruction + 5 + delta != target:
            raise ValueError(f"internal branch target changed at {instruction:#x}")
        if mapped[instruction] == 0xE8 and target not in INTERNAL_TARGET_SYMBOLS:
            raise ValueError(f"internal call target lacks a pinned symbol: {target:#x}")
    for offset, value in PADDING:
        if mapped[offset] != value:
            raise ValueError(f"alignment padding changed at {offset:#x}")

    with tempfile.TemporaryDirectory(prefix="legacy-cache-contract-") as directory:
        temporary = Path(directory)
        source, binary, fixture = (temporary / name for name in ("contract.cpp", "contract", "provider.bin"))
        source.write_text(HARNESS.replace("@@CONTRACT_TABLE_ASSERTS@@", _cpp_table_assertions()))
        fixture.write_bytes(mapped)
        subprocess.run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        "-I", str(PROJECT / "src"), str(source), "-o", str(binary)],
                       check=True, timeout=45)
        run = subprocess.run([str(binary), str(fixture)], check=True,
                             capture_output=True, text=True, timeout=60)
    harness_result = json.loads(run.stdout)
    header_path = PROJECT / "src/legacy_wifi_compat/cache_provider_contract.hpp"
    if harness_result["external_import_branches"] != len(EXTERNAL_CALLS):
        raise ValueError("C++ external relocation table count differs from Mach-O audit")
    if harness_result["rejected_external_pointer_mutations"] != len(EXTERNAL_POINTERS):
        raise ValueError("C++ harness did not reject every external pointer relocation mutation")
    if harness_result["internal_branches"] != len(INTERNAL_BRANCHES):
        raise ValueError("C++ internal branch table count differs from offline audit")
    expected_body_bytes = sum(item["end"] - item["start"] for item in FUNCTIONS)
    if harness_result["rejected_body_byte_mutations"] != expected_body_bytes:
        raise ValueError("C++ mutation harness did not exercise every selected function byte")
    return {
        "provider_sha256": source_sha,
        "provider_uuid": uuid.hex(),
        "scope": "Fixed El Cap IO80211 cache lifetime/provider contract; not runtime cache mutation or hardware validation",
        "cache_layout": LAYOUT,
        "manager_size": {"bytes": LAYOUT["scan_manager_size"],
                         "verified_instruction": hex(MANAGER_SIZE_INSTRUCTION),
                         "verified_bytes": MANAGER_SIZE_BYTES.hex()},
        "finish_attach_manager_init_callsite": {
            "function": FUNCTIONS[11]["name"],
            "function_start": hex(FUNCTIONS[11]["start"]),
            "call_instruction": hex(0x57A41),
            "return_pc": hex(0x57A46),
            "target_function": FUNCTIONS[0]["name"],
            "target_instruction": hex(0x5F70A),
            "test_mutations_rejected": harness_result["rejected_finish_attach_init_return_mutations"],
            "scope": "Exact pinned provider callsite and rel32 target; caller must already have accepted the complete provider contract",
        },
        "set_dispatcher": {
            "function": FUNCTIONS[12]["name"],
            "start": hex(FUNCTIONS[12]["start"]),
            "end_exclusive": hex(FUNCTIONS[12]["end"]),
            "next_symbol": FUNCTIONS[12]["next_name"],
            "next_symbol_offset": hex(FUNCTIONS[12]["next"]),
            "padding": {"offset": "0x55519", "value": "0x90"},
            "handler_table_symbol": "_gSetHandlerTable",
            "handler_table_address": hex(dispatcher_table),
            "handler_count_symbol": "_gSetHandlerTableCount",
            "handler_count_address": hex(dispatcher_count_a),
            "handler_count_value": 236,
            "indirect_call": "0x554e4: ff d0",
            "disassociate_handler_return_pc": "0x554e6",
            "type22_slot_checked": False,
            "scope": "Exact dispatcher callsite plus request-type validation; table slot 22 is relocated data and is not read by this contract",
        },
        "functions": [{"symbol": item["name"], "start": hex(item["start"]),
                       "end_exclusive": hex(item["end"]), "size": item["end"]-item["start"],
                       "next_symbol": item["next_name"], "next_symbol_offset": hex(item["next"]),
                       "terminal": hex(item["terminal"]), "terminal_kind": item["terminal_kind"],
                       "terminal_dispatch_slot": hex(item["terminal_target"]) if item["terminal_kind"] == "indirect_jump" else None,
                       "sha256_normalized_external_rel32": item["sha256"]}
                      for item in FUNCTIONS],
        "external_relocations": {"count": len(expected), "unique_imports": sorted({item[1] for item in EXTERNAL_CALLS}),
                                 "records": [{"instruction": hex(site), "relocation_address": hex(site+1),
                                              "symbol": symbol, "pcrel": 1, "length": 2, "type": 2}
                                             for site, symbol in EXTERNAL_CALLS]},
        "external_pointer_relocations": {"count": len(expected_pointer_records),
                                         "records": expected_pointer_records,
                                         "runtime_target_imports": sorted({item[1] for item in EXTERNAL_POINTERS})},
        "indirect_calls": [{"instruction": hex(site), "vtable_slot": hex(slot), "target": name}
                           for site,slot,name in INDIRECT_CALLS],
        "internal_branches": [{"instruction": hex(site), "target": hex(target)} for site, target in INTERNAL_BRANCHES],
        "padding": [{"offset": hex(offset), "value": value} for offset, value in PADDING],
        "selected_function_relocations": {"external": len(actual_selected), "local": len(local_selected)},
        "guard_header_sha256": hashlib.sha256(header_path.read_bytes()).hexdigest(),
        "sanitizers": ["address", "undefined"],
        "provider_code_executed": False,
        "driver_loaded": False,
        "hardware_validated": False,
        **harness_result,
    }


def verify(path: Path = DEFAULT_PROVIDER) -> dict:
    return verify_bytes(path.read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", type=Path, default=DEFAULT_PROVIDER)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.provider)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        parser.exit(1, f"verify_legacy_cache_contracts: {error}\n")
    output = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
