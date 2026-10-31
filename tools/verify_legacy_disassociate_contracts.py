#!/usr/bin/env python3
"""Verify pinned El Cap Broadcom child binaries and SET22 capture-route guards.

This is an offline check of retained source binaries plus the production C++
contract under ASan/UBSan. It does not load a kext, install hooks, authorize raw
current-BSS/IE memory reads, or establish hardware/runtime support. Live capture
still requires the matching serialized native gate, bounded reads, and copying
IE bytes into owned storage before calling the original SET22 path.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import Any


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
import build_namespace  # noqa: E402

VERIFY_IFNET_PATH = PROJECT / "tools/verify_ifnet_kernel_contracts.py"
_spec = importlib.util.spec_from_file_location("verify_ifnet_kernel_contracts", VERIFY_IFNET_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load the existing strict Mach-O parser")
macho = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = macho
_spec.loader.exec_module(macho)

CHILDREN = {
    "4331": {
        "kind": 0,
        "label": "AirPortBrcm4331",
        "sha256": "c5baef22eca03600ad255ac034d825d4a251b0538596a50ac92f845b2c86e62e",
        "uuid": "59C1F2A3-D3B8-3C3E-8D7D-3E58CBD54500",
        "functions": [
            {"symbol": "__ZN16AirPort_Brcm43319getVirtIfEP8OSObject", "start": 0xC2E0,
             "end": 0xC332, "next": "__ZN16AirPort_Brcm433125getLINK_QUAL_EVENT_PARAMSEP8OSObjectP31apple80211_link_qual_event_data",
             "next_offset": 0xC332, "external": True,
             "sha256": "b1401a2a1d8c29b4ae9b57e0d38bdaf59a7da248720f8a6adcfd1ce38ad43a0d"},
            {"symbol": "_wlc_get_current_bss", "start": 0x248FD,
             "end": 0x24931, "next": "_wlc_full_phy_cal", "next_offset": 0x24931,
             "external": True,
             "sha256": "2415a98f227376535928294a59a6d4e8a3b03242908bec4c937141e5bfd27d82"},
            {"symbol": "__ZN16AirPort_Brcm433115setDISASSOCIATEEP8OSObject", "start": 0xDA90,
             "end": 0xDB4A, "next": "__ZN16AirPort_Brcm433112setAUTH_TYPEEP8OSObjectP24apple80211_authtype_data",
             "next_offset": 0xDB4A, "external": True,
             "sha256": "58b841a0bfd67ef771110dcf6b4c7b78b910b9a89904b66927324a5e174b6347"},
            {"symbol": "_wlc_disassociate_client", "start": 0xB0B53,
             "end": 0xB10D0, "next": "_wlc_disassoc_complete", "next_offset": 0xB10D0,
             "external": True,
             "sha256": "7e72faf5bce4787251a26cf60ded58a0e2ddcd4073f982adec11fc19e0853d6d"},
            {"symbol": "_wlc_senddisassoc", "start": 0x4D728,
             "end": 0x4D7CE, "next": "_wlc_rateprobe", "next_offset": 0x4D7CE,
             "external": True,
             "sha256": "c3713efd4426c548a98effb807a9cf02db19af863f6e310418f96e01735501dd"},
            {"symbol": "_wlc_frame_get_mgmt_int", "start": 0x4A5F3,
             "end": 0x4A70D, "next": "_wlc_pdu_push_txparams", "next_offset": 0x4A70D,
             "external": False,
             "sha256": "c21fd2b83f6d70365c9778dbe24a950b4906f695a6efbeb3a881400c1e749d4b"},
            {"symbol": "_wlc_bsscfg_find_by_wlcif", "start": 0x5F3B8,
             "end": 0x5F3EA, "next": "_wlc_bsscfg_find_by_hwaddr", "next_offset": 0x5F3EA,
             "external": True,
             "sha256": "100d50bf18cf00f4615a393523d7b30b447f7049fb6f832d886a16bf0f958739"},
            {"symbol": "_wlc_bsscfg_malloc", "start": 0xB47E9,
             "end": 0xB49A9, "next": "_wlc_bsscfg_mfree", "next_offset": 0xB49A9,
             "external": True,
             "sha256": "c0f2c835d4a85c2ffbd6f2f53a6ebd914a59cd5c14b65d69f989f6b14788ef91"},
            {"symbol": "_wlc_BSSinit", "start": 0x26BE8,
             "end": 0x27680, "next": "_wlc_freqtrack_reset", "next_offset": 0x27680,
             "external": True,
             "sha256": "c5f5dd8690beb349f556bfef91dfe71cbabd7c549a4d43b0ceafd0874f9f8be8"},
            {"symbol": "_wlc_bsscfg_disable", "start": 0x5E0AA,
             "end": 0x5E28D, "next": "_wlc_bsscfg_disablemulti", "next_offset": 0x5E28D,
             "external": True,
             "sha256": "bb41fbe66e31bb616dad2ce3aeff3d21f30ea719022a0f7c2111f7e2f5eb908a"},
            {"symbol": "_wlc_ioctl", "start": 0x323CC,
             "end": 0x323D6, "next": "_wlc_get", "next_offset": 0x323D6,
             "external": True,
             "sha256": "d002a506fc2c55b510bd8e34554ff5200043e663185183ce2006daf923c7451c"},
            {"symbol": "_wlc_bss_clear_bssid", "start": 0x25D2F,
             "end": 0x25DA2, "next": "_wlc_stas_connected", "next_offset": 0x25DA2,
             "external": True,
             "sha256": "308a728489d2e1954df280bcf2a2979cc2ac728ede8b152e8917bcb2e548865e",
             "entry_abi": "RDI=cfg",
             "return_abi": "opaque RAX forwarded from tail-called _wlc_bsscfg_tx_start"},
            {"symbol": "_wlc_bsscfg_mfree", "start": 0xB49A9,
             "end": 0xB4C43, "next": "_wlc_attach_malloc", "next_offset": 0xB4C43,
             "external": True,
             "sha256": "b04e01a18c4abb8204250d2feef2e43e8f06478f8d8daa159a2ee12c4170fc62",
             "entry_abi": "RDI=osh, RSI=cfg",
             "return_abi": "void-style; native callsites ignore RAX"},
            {"symbol": "_wlc_detach", "start": 0x2F9CB,
             "end": 0x2FE3F, "next": "_wlc_radio_monitor_stop", "next_offset": 0x2FE3F,
             "external": True,
             "sha256": "3f04ea11d70dc821615ee221587ced3af604766f878f452594cae354c42f3041",
             "entry_abi": "RDI=wlc",
             "return_abi": "int32 status in EAX; wrapper must forward"},
            {"symbol": "_wlc_bsscfg_free", "start": 0x5E6BE,
             "end": 0x5E92D, "next": "_wlc_bsscfg_reset", "next_offset": 0x5E92D,
             "external": True,
             "sha256": "9f7ec17e6acf72479dff6632134e2f319c6838f8ea5444e9becfa5b6da48e221",
             "entry_abi": "RDI=wlc, RSI=cfg",
             "return_abi": "void-style; frees cfg before clearing wlc+0x2e0+index*8"},
            {"symbol": "__ZN16AirPort_Brcm43317wlcStopEv", "start": 0x49E8,
             "end": 0x4A9A, "next": "__ZN16AirPort_Brcm43314stopEP9IOService",
             "next_offset": 0x4A9A, "external": True,
             "sha256": "ff3a127fdb58db07a177cbc464384db29762b5d9bb9645f24f36aac352e60649",
             "entry_abi": "RDI=controller this",
             "return_abi": "void; clears controller+0x468 after _wlc_detach returns"},
            {"symbol": "_osl_pktfree", "start": 0x1680,
             "end": 0x17AD, "next": "__Z19osl_is_private_mbufP6__mbuf",
             "next_offset": 0x17AD, "external": True,
             "sha256": "5a57c1c211d92c5bbeb578eb46727c613ba308db86ef12dad422b48b135d45a4",
             "entry_abi": "RDI=osh, RSI=mbuf, EDX=freeFlag",
             "return_abi": "void; exact adapter ABI is (osh, unqueued packet, 1)"},
            {"symbol": "_wlc_recv_parse_bcn_prb", "start": 0x473C9,
             "end": 0x47C46, "next": "_wlc_parse_rates", "next_offset": 0x47C46,
             "external": True,
             "sha256": "f3fae6687148cfd1d76cde14e6b58d3eb16bb0172a28acb0f66ddd7c35502a15",
             "normalized_sha256": "f3fae6687148cfd1d76cde14e6b58d3eb16bb0172a28acb0f66ddd7c35502a15",
             "entry_abi": "RDI=wlc, RSI=rx metadata, RDX=BSSID source, ECX=beacon flag, R8=raw body, R9D=body length, stack arg 7=output record",
             "return_abi": "int32 status in EAX; zero means parsed record was written"},
            {"symbol": "_wlc_recvctl", "start": 0x434E1,
             "end": 0x47389, "next": "_wlc_compute_bcn_payloadtsfoff", "next_offset": 0x4738E,
             "external": False,
             "sha256": "2674752aa8d694cd7ac10fe3d6230a8dccfa9a496c89a879b04d33dc1833bc82",
             "normalized_sha256": "2674752aa8d694cd7ac10fe3d6230a8dccfa9a496c89a879b04d33dc1833bc82",
             "entry_abi": "RDI=wlc, RSI=cfg, RDX=mbuf, RCX=rx metadata",
             "return_abi": "native receive-control result; retq at 0x47388"},
            {"symbol": "_wlc_join_complete", "start": 0xAF453,
             "end": 0xAFAD7, "next": "_wlc_join_adopt_bss", "next_offset": 0xAFAD7,
             "external": True,
             "sha256": "dd58903500bb521f52871aaf7faa41e97745494cad0983effc231e50a627c052",
             "normalized_sha256": "dd58903500bb521f52871aaf7faa41e97745494cad0983effc231e50a627c052",
             "entry_abi": "RDI=wlc, RSI=join context, RDX=receive context, RCX=full body, R8D=body length; R9 unused",
             "return_abi": "void-style retq at 0xafad1; both guarded callers ignore RAX"},
            {"symbol": "_wlc_assoc_change_state", "start": 0xAD25F,
             "end": 0xAD420, "next": "_wlc_join_bss_start", "next_offset": 0xAD420,
             "external": True,
             "sha256": "844b6f8769f7bc76e1dbfffd2cee998ce9a92a6d3130277da6fefd3b2ae26fc0",
             "normalized_sha256": "844b6f8769f7bc76e1dbfffd2cee998ce9a92a6d3130277da6fefd3b2ae26fc0",
             "entry_abi": "RDI=cfg, ESI=new state; state dword read/written via cfg+0x320+0x0c",
             "return_abi": "field/layout guard only; this audit does not infer a general return contract"},
            {"symbol": "_wlc_bsscfg_down", "start": 0x5DE67,
             "end": 0x5E0AA, "next": "_wlc_bsscfg_disable", "next_offset": 0x5E0AA,
             "external": True,
             "sha256": "85399723ce40f5fb67f937f9affd645434da68d8f35999486a475f1bd2b37886",
             "normalized_sha256": "85399723ce40f5fb67f937f9affd645434da68d8f35999486a475f1bd2b37886",
             "entry_abi": "RDI=wlc, RSI=cfg; reads type cfg+0x08 and assoc state cfg+0x320+0x0c",
             "return_abi": "field/layout guard only; no return claim used"},
            {"symbol": "_wlc_assoc_timeout", "start": 0xADE7E,
             "end": 0xAE0A8, "next": "_wlc_auth_complete", "next_offset": 0xAE0A8,
             "external": True,
             "sha256": "6a61ed3aed1e805f0cc6a788c58f1eb7e1908598d2c4206ea6abbf7136a13a7f",
             "normalized_sha256": "6a61ed3aed1e805f0cc6a788c58f1eb7e1908598d2c4206ea6abbf7136a13a7f",
             "entry_abi": "RDI=cfg; timeout dispatch reads cfg+0x320+0x0c",
             "return_abi": "state-zero handoff is guarded; no general callback completion claim"},
            {"symbol": "_wlc_auth_complete", "start": 0xAE0A8,
             "end": 0xAE54C, "next": "_wlc_assoc_complete", "next_offset": 0xAE54C,
             "external": False,
             "sha256": "2713a960fdf39752b97ddfa3f129c042f37ee02a8b946f5239c4e782cbfbc704",
             "normalized_sha256": "2713a960fdf39752b97ddfa3f129c042f37ee02a8b946f5239c4e782cbfbc704",
             "entry_abi": "RDI=cfg; RSI=status; RDX=address; state at cfg+0x320+0x0c",
             "return_abi": "static branch guard only; no external event-consumer guarantee"},
            {"symbol": "_wlc_bss_mac_event", "start": 0x259E9,
             "end": 0x25A1D, "next": "_wlc_bss_list_free", "next_offset": 0x25A1D,
             "external": True,
             "sha256": "63272f65ee56dd705c62a99ff1ef598e5acd397d5c70f373e179e3699fcbf8e8",
             "normalized_sha256": "63272f65ee56dd705c62a99ff1ef598e5acd397d5c70f373e179e3699fcbf8e8",
             "entry_abi": "wrapper forwards the native event arguments to _wlc_bss_mac_rxframe_event",
             "return_abi": "wrapper-only; native event helper return is forwarded"},
            {"symbol": "_wlc_bss_mac_rxframe_event", "start": 0x4EEBB,
             "end": 0x4EFF6, "next": "_wlc_pmkid_event", "next_offset": 0x4EFF6,
             "external": True,
             "sha256": "3bdd8d8cae743cec9c0cc87b624eb13b17ac52a12d0d9ef5f7fb151887dc208e",
             "normalized_sha256": "3bdd8d8cae743cec9c0cc87b624eb13b17ac52a12d0d9ef5f7fb151887dc208e",
             "entry_abi": "RDI=wlc; event code from stack arg; event payload is passed to _wl_event_sync before queue insertion",
             "return_abi": "event path is void-style; no association-state effect is inferred from this alone"},
            {"symbol": "_wlc_eventq_enq", "start": 0x811D3,
             "end": 0x81247, "next": "_wlc_eventq_deq", "next_offset": 0x81247,
             "external": True,
             "sha256": "8b133276ce2dcd9af808af82213d4936f1f96578f5e74cc816198f97f6f6ec85",
             "normalized_sha256": "8b133276ce2dcd9af808af82213d4936f1f96578f5e74cc816198f97f6f6ec85",
             "entry_abi": "RDI=event queue, RSI=event; links event and schedules timer when queue idle",
             "return_abi": "queue handoff only; does not guard higher-level event consumers"},
        ],
        "route_symbols": [
            {"symbol": "__wlc_ioctl", "address": 0x32625, "external": False},
            {"symbol": "_wl_event_sync", "address": 0x16C10, "external": True}
        ],
        "code_ranges": [
            {"start": 0x32625, "end": 0x32848,
             "sha256": "5432bb5d75bdc9cae3402823ebdcc820075587f4112bb49695b24a2ebdf13802"},
            {"start": 0x332B9, "end": 0x332EC,
             "sha256": "852223a0f2d4df60e54b32cbe06d7e9a546a39e8b1087ffbe23f27748664163d"},
            {"start": 0x16C10, "end": 0x16C1C,
             "purpose": "_wl_event_sync entry compare and short mismatch branch for event code 3",
             "sha256": "2aca105f542c69b3d6c61bb97b990e560cc370916973950b744632dbc2842b4e"},
            {"start": 0x16C3C, "end": 0x16C43,
             "purpose": "_wl_event_sync mismatch epilogue; the 0x20 willRoam path is excluded",
             "sha256": "2f9d25a4f4bcc4e7df719764b589d57e53a780ca7d5d5980f311bd7b5d887694"},
        ],
        "relative_conditional_branches": [
            {"instruction": 0x16C1A, "opcode": 0x75, "target": 0x16C3C},
        ],
        "relative_table_entries": [
            {"table_base": 0x354A8, "entry": 0x35578, "target": 0x332B9}
        ],
        "relative_jumps": [
            {"instruction": 0x323D1, "target": 0x32625}
        ],
        "external_calls": [
            (0xC2FA, "__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass", 0xE8),
            (0xDAFD, "__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass", 0xE8),
            (0xDB37, "_bzero", 0xE8), (0xB0BDB, "_bcopy", 0xE8),
            (0xB1093, "_bzero", 0xE8), (0xB10A0, "_bzero", 0xE8),
            (0x4A6A2, "_bcopy", 0xE8), (0x4A6B4, "_bcopy", 0xE8),
            (0x4A6C5, "_bcopy", 0xE8), (0x4A642, "_mbuf_data", 0xE8),
            (0x4A681, "_mbuf_data", 0xE8), (0x4A679, "_mbuf_setlen", 0xE8),
            (0x26CA3, "_bzero", 0xE8), (0x26CB0, "_bzero", 0xE8),
            (0x26D59, "_bcopy", 0xE8), (0x26D8C, "_bcopy", 0xE8),
            (0x26F0C, "_bzero", 0xE8), (0x27211, "_bcopy", 0xE8),
            (0x32789, "_bcopy", 0xE8),
            (0x25D48, "_bzero", 0xE8), (0x25D59, "_bzero", 0xE8),
            (0x4A4E, "_IOLog", 0xE8),
            (0x16D9, "_mbuf_type", 0xE8), (0x1722, "_mbuf_next", 0xE8),
            (0x172F, "_mbuf_setnext", 0xE8), (0x1749, "_bzero", 0xE8),
            (0x1761, "_mbuf_free", 0xE8), (0x1796, "_IOLog", 0xE9),
            (0x17A8, "_mbuf_freem", 0xE9),
            (0x46299, "___stack_chk_fail", 0xE8),
            (0x43B6B, "_bcmp", 0xE8), (0x4416F, "_bcmp", 0xE8),
            (0x44AA3, "_bcmp", 0xE8), (0x4540E, "_bcmp", 0xE8),
            (0x45927, "_bcmp", 0xE8),
            (0x43BB1, "_bcopy", 0xE8), (0x44A26, "_bcopy", 0xE8),
            (0x44A39, "_bcopy", 0xE8), (0x46630, "_bcopy", 0xE8),
            (0x47073, "_bcopy", 0xE8),
            (0x449C8, "_bzero", 0xE8), (0x449F5, "_bzero", 0xE8),
            (0x43516, "_mbuf_data", 0xE8),
            (0x435DB, "_mbuf_len", 0xE8), (0x43927, "_mbuf_len", 0xE8),
            (0x439BC, "_mbuf_len", 0xE8), (0x43CB3, "_mbuf_len", 0xE8),
            (0x43908, "_mbuf_setlen", 0xE8),
            (0x476E5, "_bcmp", 0xE8), (0x4775F, "_bcmp", 0xE8),
            (0x4783E, "_bcmp", 0xE8), (0x4791A, "_bcmp", 0xE8),
            (0x47986, "_bcmp", 0xE8), (0x479F3, "_bcmp", 0xE8),
            (0x47AA2, "_bcmp", 0xE8),
            (0x474A1, "_bcopy", 0xE8), (0x4755D, "_bcopy", 0xE8),
            (0x47BF4, "_bcopy", 0xE8), (0x47490, "_bzero", 0xE8),
            (0xAF73B, "_bcopy", 0xE8), (0xAF766, "_bcopy", 0xE8),
            (0xAF81B, "_bcopy", 0xE8), (0xAF889, "_bcopy", 0xE8),
            (0xAF8DA, "_bcopy", 0xE8), (0xAFAD2, "___stack_chk_fail", 0xE8),
            (0xADFEC, "_bcopy", 0xE8), (0xAE071, "___stack_chk_fail", 0xE8),
            (0xAE112, "_strncpy", 0xE8), (0xAE547, "___stack_chk_fail", 0xE8),
            (0x4EF60, "_bcopy", 0xE8), (0x4EFAE, "_bcopy", 0xE8),
        ],
        "internal_calls": [
            (0xDAA7, 0xC2E0, "__ZN16AirPort_Brcm43319getVirtIfEP8OSObject"),
            (0xDAC5, 0x5F3B8, "_wlc_bsscfg_find_by_wlcif"),
            (0xDAEE, 0x323CC, "_wlc_ioctl"),
            (0xB0DC0, 0x4D728, "_wlc_senddisassoc"),
            (0xB0E3B, 0x4D728, "_wlc_senddisassoc"),
            (0x4D777, 0x4A5F3, "_wlc_frame_get_mgmt_int"),
            (0x3265D, 0x5F3B8, "_wlc_bsscfg_find_by_wlcif"),
            (0x332E7, 0x5E0AA, "_wlc_bsscfg_disable"),
            (0x5E19F, 0x5DE67, "_wlc_bsscfg_down"),
            (0x5E1E9, 0xB0B53, "_wlc_disassociate_client"),
            (0xB499A, 0xB49A9, "_wlc_bsscfg_mfree"),
            (0x49FE, 0x6590, "_wl_down"),
            (0x4A14, 0x2FEBC, "_wlc_module_unregister"),
            (0x4A20, 0x2F9CB, "_wlc_detach"),
            (0x4A2C, 0xF98, "_osl_malloced"),
            (0x4A3C, 0xF98, "_osl_malloced"),
            (0x4A66, 0xEBF, "_osl_assert"),
            (0x5E6CE, 0x5EE1D, "_wlc_bsscfg_deinit"),
            (0x5E6F3, 0xA5AC0, "_wlc_p2p_info_free"),
            (0x5E716, 0xA5D79, "_wlc_p2p_d11cb_free"),
            (0x5E73A, 0x2455B, "_wlc_set_rcmta"),
            (0x5E751, 0xA5E4B, "_wlc_p2p_d11ra_free"),
            (0x5E789, 0x2455B, "_wlc_set_rcmta"),
            (0x5E7A0, 0xA5E4B, "_wlc_p2p_d11ra_free"),
            (0x5E7D1, 0xEBF, "_osl_assert"),
            (0x5E7F5, 0xEBF, "_osl_assert"),
            (0x5E813, 0x11D362, "_wlc_mchan_delete_bss_chan_context"),
            (0x5E823, 0x5ED76, "_wlc_bsscfg_scbclear"),
            (0x5E842, 0x323E8, "_wlc_if_event"),
            (0x5E84E, 0x814F9, "_wlc_eventq_flush"),
            (0x5E86E, 0x16C8E, "_wl_del_if"),
            (0x5E886, 0x502A1, "_wlc_wlcif_free"),
            (0x5E8A8, 0xF47, "_osl_mfree"),
            (0x5E8E5, 0xEBF, "_osl_assert"),
            (0x5E8FE, 0x56F5, "_wl_free_timer"),
            (0x5E90A, 0xB49A9, "_wlc_bsscfg_mfree"),
            (0x16B4, 0xEBF, "_osl_assert"),
            (0x16D1, 0xEBF, "_osl_assert"),
            (0x1716, 0x17AD, "__Z19osl_is_private_mbufP6__mbuf"),
            (0x1737, 0x1809, "_osl_pkt_gettag"),
            (0x1754, 0x15B4, "__Z16osl_mbuf_enqueuePP6__mbufS0_"),
            (0x46C7B, 0x473C9, "_wlc_recv_parse_bcn_prb"),
            (0x46CDB, 0x26BE8, "_wlc_BSSinit"),
            (0x45BBE, 0xAF453, "_wlc_join_complete"),
            (0x46E3F, 0xAF453, "_wlc_join_complete"),
            (0xAF4BB, 0x75C57, "_wlc_scbfind"),
            (0xAF4F0, 0x27DC4, "_wlc_tsf_adopt_bcn"),
            (0xAF527, 0x19EFC, "_bcm_parse_tlvs"),
            (0xAF56A, 0x23ECF, "_wlc_write_shm"),
            (0xAF57B, 0x417E6, "_wlc_set_dtim_programmed"),
            (0xAF598, 0xAA623, "_wlc_p2p_dtim_upd"),
            (0xAF5A4, 0xAF22E, "_wlc_roam_thresh_upd"),
            (0xAF5C4, 0x417BF, "_wlc_set_pmoverride"),
            (0xAF5D8, 0xE68, "_osl_malloc"),
            (0xAF602, 0xAFAD7, "_wlc_join_adopt_bss"),
            (0xAF613, 0xF47, "_osl_mfree"),
            (0xAF65D, 0xEBF, "_osl_assert"), (0xAF697, 0xEBF, "_osl_assert"),
            (0xAF725, 0xE68, "_osl_malloc"), (0xAF750, 0xE68, "_osl_malloc"),
            (0xAF797, 0x19EC2, "_bcm_next_tlv"),
            (0xAF7C4, 0xB35D4, "_wlc_find_ie_match"),
            (0xAF7DC, 0x19EC2, "_bcm_next_tlv"),
            (0xAF7F8, 0xE68, "_osl_malloc"),
            (0xAF89E, 0x19EC2, "_bcm_next_tlv"),
            (0xAF8C2, 0xB35D4, "_wlc_find_ie_match"),
            (0xAF8F0, 0x19EC2, "_bcm_next_tlv"),
            (0xAF927, 0xF47, "_osl_mfree"),
            (0xAF97C, 0x19EFC, "_bcm_parse_tlvs"),
            (0xAF98A, 0x57F6C, "_bcm_find_p2pie"),
            (0xAF9B9, 0x2545E, "_wlc_adopt_country_ie"),
            (0xAF9D3, 0x2276F, "_wlc_ps_allowed"),
            (0xAF9EE, 0x228BE, "_wlc_set_pmstate"),
            (0xAFA15, 0x41C2C, "_wlc_pm2_sleep_ret_timer_start"),
            (0xAFA1D, 0x23DDE, "_wlc_set_ps_ctrl"),
            (0xAFA6E, 0x259E9, "_wlc_bss_mac_event"),
            (0xAFA85, 0xAEC30, "_wlc_assoc_done"),
            (0xAFA94, 0x1974F, "_bcm_ether_ntoa"),
            (0xAFAB5, 0xA144D, "_wlc_extlog_msg"),
            (0xAD29B, 0xEBF, "_osl_assert"), (0xAD323, 0xD54B3, "_wlc_phy_hold_upd"),
            (0xAD36E, 0xAEDCA, "_wlc_assoc_req_remove_entry"),
            (0xAD390, 0x25A1D, "_wlc_bss_list_free"),
            (0xAD3A4, 0xD54B3, "_wlc_phy_hold_upd"),
            (0xAD3CB, 0xAEAEA, "_wlc_assoc_abort"),
            (0xAD3EB, 0x24521, "_wlc_set_wake_ctrl"),
            (0xAD405, 0xEBF, "_osl_assert"),
            (0x5DE93, 0xEBF, "_osl_assert"), (0x5DEBC, 0xAEAEA, "_wlc_assoc_abort"),
            (0x5DEE8, 0x16B3F, "_wl_del_timer"), (0x5DF0D, 0x84D77, "_wlc_ap_down"),
            (0x5DF33, 0x27F91, "_wlc_suspend_mac_and_wait"),
            (0x5DF42, 0x242FE, "_wlc_mctrl"), (0x5DF4A, 0x2415A, "_wlc_enable_mac"),
            (0x5DFAB, 0xEBF, "_osl_assert"),
            (0x5DFB8, 0xAD25F, "_wlc_assoc_change_state"),
            (0x5DFCE, 0x2578D, "_wlc_radio_mpc_upd"),
            (0x5DFD6, 0x24521, "_wlc_set_wake_ctrl"),
            (0x5DFF1, 0x16B3F, "_wl_del_timer"), (0x5E010, 0x16B3F, "_wl_del_timer"),
            (0x5E022, 0x11B5D5, "_wlc_sup_down"),
            (0x5E042, 0x3F651, "_wlc_hwtimer_del_timeout"),
            (0x5E04A, 0xAEAEA, "_wlc_assoc_abort"), (0x5E06B, 0x1916A, "_pktq_flush"),
            (0x5E07C, 0x6FDA4, "_wlc_key_defkeyflag"), (0x5E094, 0x31212, "_wlc_mhf"),
            (0xADEEF, 0x2174C, "_si_deviceremoved"), (0xAE00A, 0xAC7B1, "_wlc_join"),
            (0xAE019, 0xAD25F, "_wlc_assoc_change_state"),
            (0xAE0FB, 0x1974F, "_bcm_ether_ntoa"), (0xAE16B, 0x75C57, "_wlc_scbfind"),
            (0xAE180, 0x7573F, "_wlc_scb_clearstatebit"),
            (0xAE1A4, 0x16B3F, "_wl_del_timer"),
            (0xAE1E2, 0x7573F, "_wlc_scb_clearstatebit"),
            (0xAE288, 0xAD25F, "_wlc_assoc_change_state"),
            (0xAE2D2, 0x4D3CB, "_wlc_sendauth"),
            (0xAE2F6, 0x428FB, "_wlc_pkt_callback_register"),
            (0xAE330, 0x259E9, "_wlc_bss_mac_event"),
            (0xAE376, 0x756CD, "_wlc_scb_setstatebit"),
            (0xAE3AB, 0xAD25F, "_wlc_assoc_change_state"),
            (0xAE3C3, 0x4DA58, "_wlc_sendassocreq"), (0xAE3D6, 0x16B3F, "_wl_del_timer"),
            (0xAE403, 0x428FB, "_wlc_pkt_callback_register"),
            (0xAE43A, 0x259E9, "_wlc_bss_mac_event"),
            (0xAE477, 0x259E9, "_wlc_bss_mac_event"),
            (0xAE49C, 0xA144D, "_wlc_extlog_msg"), (0xAE4D3, 0xEBF, "_osl_assert"),
            (0xAE505, 0x5687, "_wl_add_timer"), (0xAE540, 0x5687, "_wl_add_timer"),
            (0x25A12, 0x4EEBB, "_wlc_bss_mac_rxframe_event"),
            (0x4EEFA, 0x81136, "_wlc_event_alloc"), (0x4EF42, 0xE68, "_osl_malloc"),
            (0x4EFC1, 0x4EE0B, "_wlc_event_if"), (0x4EFD4, 0x16C10, "_wl_event_sync"),
            (0x811FA, 0xEBF, "_osl_assert"),
        ],
        "imports": [
            "__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass",
            "_bzero", "_bcopy", "_mbuf_data", "_mbuf_setlen", "_IOLog",
            "_mbuf_type", "_mbuf_next", "_mbuf_setnext", "_mbuf_free",
            "_mbuf_freem", "_bcmp", "_mbuf_len", "___stack_chk_fail",
            "_strncpy"
        ],
    },
    "43224": {
        "kind": 1,
        "label": "AppleAirPortBrcm43224",
        "sha256": "fcbc111f3aa0d27bc61f17b558f5bcbaa6a8aa3d1d9370bed6eea9be4c9ce165",
        "uuid": "6F074D2E-E7E8-327B-AC63-F504B7367BA4",
        "functions": [
            {"symbol": "__ZN17AirPort_Brcm4322415setDISASSOCIATEEP16IO80211Interface", "start": 0x98BC,
             "end": 0x992A, "next": "__ZN17AirPort_Brcm4322412setAUTH_TYPEEP16IO80211InterfaceP24apple80211_authtype_data",
             "next_offset": 0x992A, "external": True,
             "sha256": "6602f59a340f261f196df78d7f42b91e2a47111e9038f98644ce48fe31a96feb"},
            {"symbol": "_wlc_disassociate_client", "start": 0x67583,
             "end": 0x67AB4, "next": "_wlc_set", "next_offset": 0x67AB4,
             "external": True,
             "sha256": "4f759652c696415158fd20fc4e7cc43ef57f3964fa98981cf796e717b563cb27"},
            {"symbol": "_wlc_senddisassoc", "start": 0x7E44E,
             "end": 0x7E4EC, "next": "_wlc_rateprobe", "next_offset": 0x7E4EC,
             "external": True,
             "sha256": "f03de3661a3c33397f4d3891f746cfe54942fa8e113328067a439c25e6ffce40"},
            {"symbol": "_wlc_frame_get_mgmt", "start": 0x75582,
             "end": 0x75696, "next": "_wlc_sendmgmt", "next_offset": 0x75696,
             "external": True,
             "sha256": "a07eb19ea65c284e4ee8dd7fab00c1880fa90fa05e37a3e1567288a146afd390"},
            {"symbol": "_wlc_BSSinit", "start": 0x5BE74,
             "end": 0x5CA04, "next": "_wlc_assoc_abort", "next_offset": 0x5CA04,
             "external": True,
             "sha256": "7e33e691e3902e48e01bc663a0369fabd4cc8a58af392a54f381ad3baa2206f1"},
            {"symbol": "_wlc_bsscfg_disable", "start": 0x900D5,
             "end": 0x9025B, "next": "_wlc_bsscfg_disablemulti", "next_offset": 0x9025B,
             "external": True,
             "sha256": "f23d275559c772b8eb625597252ed978353a30a634e0a7020dcacf7edf8dc4ba"},
            {"symbol": "_wlc_attach", "start": 0x5F0E1,
             "end": 0x5FD76, "next": "_wlc_ap_upd", "next_offset": 0x5FD76,
             "external": True,
             "sha256": "5ea82de475b30debacec171fc4d601a3273c9f64389bba5a59785d823cf3a60f"},
            {"symbol": "_wlc_set", "start": 0x67AB4,
             "end": 0x67AD6, "next": "_wlc_ioctl", "next_offset": 0x67AD6,
             "external": True,
             "sha256": "2b96336a5233acfc5c62be16f7f4c8aa04bfc33738d69d01d2a97de0b1c17f3e"},
            {"symbol": "_wlc_down", "start": 0x66A26,
             "end": 0x66DEE, "next": "_wlc_set_gmode", "next_offset": 0x66DEE,
             "external": True,
             "sha256": "b5824ef2c9d325fa962c027125551f9ee3d6898848b0ece119148563745551da",
             "entry_abi": "RDI=wlc",
             "return_abi": "int32 accumulated teardown status in EAX; wrapper must forward"},
            {"symbol": "_wlc_detach", "start": 0x65718,
             "end": 0x65BFC, "next": "_wlc_radio_monitor_stop", "next_offset": 0x65BFC,
             "external": True,
             "sha256": "e94708d36f14eae8f3ce67e02af86d6efcdbee3ca26e71c6bbf4fdc6b9f7f42b",
             "entry_abi": "RDI=wlc",
             "return_abi": "int32 detach status in EAX; wrapper must forward"},
            {"symbol": "__ZN17AirPort_Brcm432247wlcStopEv", "start": 0x38AA,
             "end": 0x395B, "next": "__ZN17AirPort_Brcm432244stopEP9IOService",
             "next_offset": 0x395C, "external": True,
             "sha256": "f38a4dc5f3e2d3730c5ee0c542001db5e9eefb358f05c28d9e491a6de26fb588",
             "entry_abi": "RDI=controller this",
             "return_abi": "void; clears controller+0x418 after _wlc_detach returns"},
            {"symbol": "_osl_pktfree", "start": 0x1504,
             "end": 0x1631, "next": "__Z19osl_is_private_mbufP6__mbuf",
             "next_offset": 0x1631, "external": True,
             "sha256": "73b7d183579ea6051345b4299370380026b9e89c1446ddd10a601955b1832830",
             "entry_abi": "RDI=osh, RSI=mbuf, EDX=freeFlag",
             "return_abi": "void; exact adapter ABI is (osh, unqueued packet, 1)"},
            {"symbol": "_wlc_join_complete", "start": 0x81FE3,
             "end": 0x8269E, "next": "_wlc_assocreq_complete", "next_offset": 0x8269E,
             "external": False,
             "sha256": "95423d7bd299fc5f86c033b8a0b5ff0faa24a45485e71a209f20a11924886e28",
             "normalized_sha256": "95423d7bd299fc5f86c033b8a0b5ff0faa24a45485e71a209f20a11924886e28",
             "entry_abi": "RDI=wlc, RSI=full body, EDX=body length",
             "return_abi": "void-style retq at 0x8266e; both guarded callers ignore RAX"},
            {"symbol": "_wlc_assoc_change_state", "start": 0x57347,
             "end": 0x573BB, "next": "_wlc_assoc_scan_complete", "next_offset": 0x573BB,
             "external": True,
             "sha256": "be64d250ee723217f8800d83e4ec7e69d02a4ffc6ce1ef2ef1d953b81d353e5d",
             "normalized_sha256": "be64d250ee723217f8800d83e4ec7e69d02a4ffc6ce1ef2ef1d953b81d353e5d",
             "entry_abi": "RDI=wlc, ESI=new state; state dword at wlc+0x379c",
             "return_abi": "not relied upon by the state-zero timeout predicate"},
            {"symbol": "_wlc_bsscfg_down", "start": 0x8FFA6,
             "end": 0x900D5, "next": "_wlc_bsscfg_disable", "next_offset": 0x900D5,
             "external": True,
             "sha256": "26cd8fe3dbece5ba28e4d8a2185b6cd8dcfd3b4bf8ee3aadddf8687078a08d2b",
             "normalized_sha256": "26cd8fe3dbece5ba28e4d8a2185b6cd8dcfd3b4bf8ee3aadddf8687078a08d2b",
             "entry_abi": "RDI=wlc, RSI=cfg; state wlc+0x379c and type wlc+0x3798",
             "return_abi": "not relied upon by the state-zero timeout predicate"},
            {"symbol": "_wlc_assoc_timeout", "start": 0x5EB02,
             "end": 0x5EC84, "next": "_wlc_apsd_trigger_timeout", "next_offset": 0x5EC84,
             "external": False,
             "sha256": "b7db4df0fb36def632a78e4c551abd8c6a27227b5b248bece862a1ab4b3d5672",
             "normalized_sha256": "b7db4df0fb36def632a78e4c551abd8c6a27227b5b248bece862a1ab4b3d5672",
             "entry_abi": "RDI=wlc; state-zero route emits event code 3/detail 2",
             "return_abi": "timeout branch evidence only; not a callback-quiescence claim"},
            {"symbol": "_wlc_bss_mac_event", "start": 0x7F4CA,
             "end": 0x7F5EC, "next": "_wlc_noise_cb", "next_offset": 0x7F5EC,
             "external": True,
             "sha256": "2bc797a3727278c51c9a9663c33bbe3d82f100973e573b5c2eed096d2cec0ee9",
             "normalized_sha256": "2bc797a3727278c51c9a9663c33bbe3d82f100973e573b5c2eed096d2cec0ee9",
             "entry_abi": "RDI=wlc; constructs event object and passes it to _wlc_eventq_enq",
             "return_abi": "event queue handoff only; no higher-level consumer claim"},
            {"symbol": "_wlc_eventq_enq", "start": 0xA558E,
             "end": 0xA5602, "next": "_wlc_eventq_deq", "next_offset": 0xA5602,
             "external": True,
             "sha256": "b918d27bec59e7305df9cf2971fa1dbcd36b69188746fd53212d10e1a8b503db",
             "normalized_sha256": "b918d27bec59e7305df9cf2971fa1dbcd36b69188746fd53212d10e1a8b503db",
             "entry_abi": "RDI=event queue, RSI=event; links event and schedules timer when queue idle",
             "return_abi": "queue handoff only; does not guard higher-level event consumers"},
            {"symbol": "__ZN17AirPort_Brcm432247setIBSSEb", "start": 0x4D3A,
             "end": 0x4E42, "next": "__ZN17AirPort_Brcm4322411powerChangeEj",
             "next_offset": 0x4E42, "external": True,
             "sha256": "f2dcc22c06603d337d68408c04291f87bb4feb1a7135f3c3a8296957655bb481",
             "normalized_sha256": "f2dcc22c06603d337d68408c04291f87bb4feb1a7135f3c3a8296957655bb481",
             "entry_abi": "RDI=controller this, SIL=IBSS boolean",
             "return_abi": "int32 status in EAX; early false/idle skip returns 0; other paths propagate _wlc_set status"},
        ],
        "route_symbols": [
            {"symbol": "__ZN17AirPort_Brcm432248wlcStartEv",
             "address": 0x2ECC, "external": True}
        ],
        "code_ranges": [
            {"start": 0x2F64, "end": 0x2FB4,
             "sha256": "9c6f970d8bf4597d96f810a94bd3f821004787a425d69f8162cc5ae92f643c2f"},
            {"start": 0x67AD6, "end": 0x67CDC,
             "sha256": "c4c7ab926bb03a878eca6c0e6e328f2e8905d64f8dcb2737fcee799dde82a2b1"},
            {"start": 0x6883E, "end": 0x68875,
             "sha256": "8d89d6f8b5cb4fa3ce887ab9e458c04e7d33a85426386de670f2ea7526501ae3"},
        ],
        "relative_conditional_branches": [],
        "relative_table_entries": [
            {"table_base": 0x6AC28, "entry": 0x6ACF8, "target": 0x6883E}
        ],
        "relative_jumps": [],
        "external_calls": [
            (0x991C, "_bzero", 0xE8), (0x675DC, "_bcopy", 0xE8),
            (0x679A8, "_bzero", 0xE8), (0x75631, "_bcopy", 0xE8),
            (0x75643, "_bcopy", 0xE8), (0x75654, "_bcopy", 0xE8),
            (0x755D1, "_mbuf_data", 0xE8), (0x75610, "_mbuf_data", 0xE8),
            (0x75608, "_mbuf_setlen", 0xE8),
            (0x5C092, "_bcopy", 0xE8), (0x5C0C8, "_bcopy", 0xE8),
            (0x5C3CA, "_bzero", 0xE8), (0x5C6E9, "_bcopy", 0xE8),
            (0x5C9EB, "___stack_chk_fail", 0xE8),
            (0x5F12F, "_bzero", 0xE8), (0x5F456, "_bcopy", 0xE8),
            (0x5F467, "_bcopy", 0xE8), (0x5F8E4, "_bzero", 0xE8),
            (0x5F9F5, "_bcopy", 0xE8), (0x5FA09, "_bcopy", 0xE8),
            (0x5FCE7, "_bcopy", 0xE8), (0x67C06, "_bcopy", 0xE8),
            (0x66AF5, "_IODelay", 0xE8), (0x390F, "_IOLog", 0xE8),
            (0x155D, "_mbuf_type", 0xE8), (0x15A6, "_mbuf_next", 0xE8),
            (0x15B3, "_mbuf_setnext", 0xE8), (0x15CD, "_bzero", 0xE8),
            (0x15E5, "_mbuf_free", 0xE8), (0x161A, "_IOLog", 0xE9),
            (0x162C, "_mbuf_freem", 0xE9),
            (0x821FA, "_bcopy", 0xE8), (0x82232, "_bcopy", 0xE8),
            (0x822EB, "_bcopy", 0xE8), (0x82357, "_bcopy", 0xE8),
            (0x823B4, "_bcopy", 0xE8), (0x8247F, "_memset", 0xE8),
            (0x82493, "_bzero", 0xE8), (0x824D8, "_strncpy", 0xE8),
            (0x82699, "___stack_chk_fail", 0xE8),
            (0x7F547, "_bcopy", 0xE8), (0x7F590, "_bcopy", 0xE8),
        ],
        "internal_calls": [
            (0x98E6, 0x67AB4, "_wlc_set"),
            (0x98F0, 0x4D3A, "__ZN17AirPort_Brcm432247setIBSSEb"),
            (0x6778B, 0x7E44E, "_wlc_senddisassoc"),
            (0x7E49F, 0x75582, "_wlc_frame_get_mgmt"),
            (0x67ACB, 0x67AD6, "_wlc_ioctl"),
            (0x68870, 0x900D5, "_wlc_bsscfg_disable"),
            (0x9019C, 0x8FFA6, "_wlc_bsscfg_down"),
            (0x901E2, 0x67583, "_wlc_disassociate_client"),
            (0x2F98, 0x5F0E1, "_wlc_attach"),
            (0x66AE1, 0x8FFA6, "_wlc_bsscfg_down"),
            (0x66AEB, 0x900D5, "_wlc_bsscfg_disable"),
            (0x66D71, 0x8FFA6, "_wlc_bsscfg_down"),
            (0x38BF, 0x66A26, "_wlc_down"),
            (0x38D5, 0x65C65, "_wlc_module_unregister"),
            (0x38E1, 0x65718, "_wlc_detach"),
            (0x38ED, 0xE2C, "_osl_malloced"),
            (0x38FD, 0xE2C, "_osl_malloced"),
            (0x3927, 0xD53, "_osl_assert"),
            (0x1538, 0xD53, "_osl_assert"),
            (0x1555, 0xD53, "_osl_assert"),
            (0x159A, 0x1631, "__Z19osl_is_private_mbufP6__mbuf"),
            (0x15BB, 0x168D, "_osl_pkt_gettag"),
            (0x15D8, 0x1438, "__Z16osl_mbuf_enqueuePP6__mbufS0_"),
            (0x776A1, 0x81FE3, "_wlc_join_complete"),
            (0x78658, 0x81FE3, "_wlc_join_complete"),
            (0x8201C, 0x9B3CD, "_wlc_scbfind"),
            (0x8202E, 0x5D5CC, "_wlc_tsf_adopt_bcn"),
            (0x8206A, 0x10C88, "_bcm_parse_tlvs"),
            (0x82091, 0xB9116, "_wlc_bmac_write_shm"),
            (0x820A3, 0x6BAE0, "_wlc_roam_thresh_upd"),
            (0x820C5, 0x827CD, "_wlc_join_adopt_bss"),
            (0x82110, 0xD53, "_osl_assert"), (0x82147, 0xD53, "_osl_assert"),
            (0x821E0, 0xCFC, "_osl_malloc"), (0x82218, 0xCFC, "_osl_malloc"),
            (0x8225F, 0x10C4E, "_bcm_next_tlv"),
            (0x8228C, 0x10C4E, "_bcm_next_tlv"),
            (0x822A2, 0x829B0, "_wlc_find_ie_match"),
            (0x822C8, 0xCFC, "_osl_malloc"),
            (0x8236F, 0x10C4E, "_bcm_next_tlv"),
            (0x8239C, 0x829B0, "_wlc_find_ie_match"),
            (0x823CD, 0x10C4E, "_bcm_next_tlv"),
            (0x82407, 0xDDB, "_osl_free"),
            (0x8245A, 0x10C88, "_bcm_parse_tlvs"),
            (0x824AB, 0x58859, "_wlc_parse_country_ie"),
            (0x824EA, 0x92164, "_wlc_country_lookup_ext"),
            (0x824FE, 0x58977, "_wlc_compatible_country"),
            (0x82515, 0x912C6, "_wlc_set_countrycode"),
            (0x8253B, 0xB226E, "_wf_chspec_ctlchan"),
            (0x825D9, 0x6FC3D, "_wlc_pm2_sleep_ret_timer_start"),
            (0x8261F, 0x7F4CA, "_wlc_bss_mac_event"),
            (0x82631, 0x1053D, "_bcm_ether_ntoa"),
            (0x82652, 0xBF90E, "_wlc_extlog_msg"),
            (0x82677, 0x6B1D8, "_wlc_set_pmstate"),
            (0x5736B, 0xD53, "_osl_assert"), (0x573AA, 0x2A0D0, "_wlc_phy_hold_upd"),
            (0x8FFCE, 0xD53, "_osl_assert"), (0x8FFF9, 0xA8BB9, "_wlc_ap_down"),
            (0x90015, 0xB843E, "_wlc_suspend_mac_and_wait"),
            (0x90024, 0xBCD59, "_wlc_mctrl"), (0x9002C, 0xB86CF, "_wlc_enable_mac"),
            (0x90069, 0xD53, "_osl_assert"), (0x90076, 0x57347, "_wlc_assoc_change_state"),
            (0x90084, 0x5CA04, "_wlc_assoc_abort"), (0x9009F, 0xDDB, "_osl_free"),
            (0x900C2, 0x5CA04, "_wlc_assoc_abort"),
            (0x5EB44, 0x175A8, "_si_deviceremoved"), (0x5EBF3, 0x7F4CA, "_wlc_bss_mac_event"),
            (0x7F50A, 0xA54F4, "_wlc_event_alloc"), (0x7F579, 0xCFC, "_osl_malloc"),
            (0x7F59E, 0x7F44C, "_wlc_event_if"), (0xA55B5, 0xD53, "_osl_assert"),
            (0x4D90, 0x66A26, "_wlc_down"),
            (0x4D9A, 0x4B9C, "__ZN17AirPort_Brcm432245setAPEb"),
            (0x4DB6, 0x67AB4, "_wlc_set"),
            (0x4DE3, 0x67AB4, "_wlc_set"),
            (0x4DFB, 0x6B11C, "_wlc_get"),
            (0x4E1D, 0x67AB4, "_wlc_set"),
            (0x4E2C, 0x3FE2, "_wl_up"),
        ],
        "imports": ["_bzero", "_bcopy", "_mbuf_data", "_mbuf_setlen",
                    "___stack_chk_fail", "_IODelay", "_IOLog", "_mbuf_type",
                    "_mbuf_next", "_mbuf_setnext", "_mbuf_free", "_mbuf_freem",
                    "_memset", "_strncpy"],
    },
}

IMPORT_SYMBOLS = sorted({symbol for child in CHILDREN.values()
                         for _, symbol, _ in child["external_calls"]})

HARNESS = r'''
#include "legacy_wifi_compat/disassociate_child_contracts.hpp"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>
namespace D = LegacyWiFi::DisassociateChildContract;
namespace P = LegacyWiFi::ProviderContract;

static void relocate(uint8_t *bytes, uintptr_t base, size_t instruction,
                     uintptr_t target) {
    const uintptr_t returnPC=base+instruction+5;
    int64_t delta=0;
    if (target>=returnPC) delta=static_cast<int64_t>(target-returnPC);
    else delta=-static_cast<int64_t>(returnPC-target);
    assert(delta>=INT32_MIN && delta<=INT32_MAX);
    const int32_t encoded=static_cast<int32_t>(delta);
    std::memcpy(bytes+instruction+1,&encoded,sizeof(encoded));
}

int main(int argc,char **argv) {
    assert(argc==3);
    const D::ChildKind child=std::strcmp(argv[1],"4331")==0
        ? D::Brcm4331 : D::Brcm43224;
    std::ifstream file(argv[2],std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)),{});
    assert(!bytes.empty());
    constexpr uintptr_t base=0xffffff8001000000ULL;
    P::Image image{bytes.data(),bytes.size(),base};
    D::SymbolAddresses symbols{};
    for(size_t i=0;i<D::FunctionCount;++i) {
        const D::FunctionContract &function=D::Functions[child][i];
        symbols.addresses[i]=function.symbol?base+function.start:0;
    }
    D::RouteSymbolAddresses routeSymbols{};
    for(size_t i=0;i<D::RouteSymbolCount;++i) {
        const D::RouteSymbolContract &symbol=D::RouteSymbols[i];
        routeSymbols.addresses[i]=symbol.child==child?base+symbol.address:0;
    }
    D::ImportAddresses imports{};
    bool importUsed[D::ImportCount]{};
    for(size_t i=0;i<D::ExternalCallCount;++i) {
        const D::ExternalCall &branch=D::ExternalCalls[i];
        if(branch.child!=child) continue;
        const size_t targetIndex=static_cast<size_t>(branch.target);
        importUsed[targetIndex]=true;
        imports.addresses[targetIndex]=base+bytes.size()+0x1000+targetIndex*0x100;
    }
    uint8_t uuid[16];
    std::memcpy(uuid,D::SourceUUID[child],sizeof(uuid));
    assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
    for(size_t i=0;i<D::ExternalCallCount;++i) {
        const D::ExternalCall &branch=D::ExternalCalls[i];
        if(branch.child==child) {
            assert(bytes[branch.instruction] == branch.opcode);
            relocate(bytes.data(),base,branch.instruction,
                     imports.addresses[static_cast<size_t>(branch.target)]);
        }
    }
    assert(D::verify(image,uuid,child,symbols,imports,routeSymbols));

    const D::CurrentBSSLayout layout=D::currentBSSLayout(child);
    assert(D::currentBSSFieldsFit(layout));
    assert(D::currentBSSBackingExtentFits(layout));
    if(child==D::Brcm4331) {
        assert(layout.controllerWLCOffset==0x468 &&
               layout.virtualInterfaceListOffset==0x500 &&
               layout.interfaceWLCIFOffset==0x188 &&
               layout.bsscfgCurrentBSSOffset==0x318 &&
               layout.recordSize==0xa0 && layout.bsscfgAllocationSize==0x600 &&
               layout.currentBSSAllocationSize==0xa0 && layout.wlcAllocationSize==0 &&
               layout.capabilityOffset==0x62 &&
               layout.iePointerOffset==0x68 && layout.ieLengthOffset==0x70);
    } else {
        assert(layout.controllerWLCOffset==0x418 &&
               layout.inlineCurrentBSSOffset==0x2f8 &&
               layout.recordSize==0x98 && layout.wlcAllocationSize==0x3b98 &&
               layout.capabilityOffset==0x5e &&
               layout.iePointerOffset==0x68 && layout.ieLengthOffset==0x70);
    }

    const uintptr_t workerPC=base+(child==D::Brcm4331?0x5e1ee:0x901e7);
    assert(D::workerCallerReturnPCMatches(child,image,workerPC));
    assert(!D::workerCallerReturnPCMatches(child,image,workerPC+1));
    const uintptr_t builderPC=base+(child==D::Brcm4331?0x4d77c:0x7e4a4);
    assert(D::builderCallerReturnPCMatches(child,image,builderPC));
    assert(!D::builderCallerReturnPCMatches(child,image,builderPC+1));
    if(child==D::Brcm4331) {
        assert(D::senderCallerReturnPCMatches(child,image,base+0xb0dc5));
        assert(D::senderCallerReturnPCMatches(child,image,base+0xb0e40));
        assert(!D::senderCallerReturnPCMatches(child,image,base+0xb0dc6));
        assert(D::receiveRefreshParserCallerReturnPCMatches(child,image,base+0x46c80));
        assert(!D::receiveRefreshParserCallerReturnPCMatches(child,image,base+0x46c81));
        assert(D::receiveRefreshBSSInitCallerReturnPCMatches(child,image,base+0x46ce0));
        assert(!D::receiveRefreshBSSInitCallerReturnPCMatches(child,image,base+0x46ce1));
    } else {
        assert(D::senderCallerReturnPCMatches(child,image,base+0x67790));
        assert(!D::senderCallerReturnPCMatches(child,image,base+0x67791));
        assert(!D::receiveRefreshParserCallerReturnPCMatches(child,image,base+0x46c80));
        assert(!D::receiveRefreshBSSInitCallerReturnPCMatches(child,image,base+0x46ce0));
    }
    P::Image noBytesImage{nullptr,bytes.size(),base};
    assert(!D::workerCallerReturnPCMatches(child,noBytesImage,workerPC));
    P::Image shortImage=image;
    shortImage.size=1;
    assert(!D::workerCallerReturnPCMatches(child,shortImage,workerPC));
    P::Image nearOverflowImage{bytes.data(),1,UINTPTR_MAX-2};
    assert(!D::workerCallerReturnPCMatches(child,nearOverflowImage,UINTPTR_MAX));
    assert(!D::workerCallerReturnPCMatches(static_cast<D::ChildKind>(2),image,workerPC));

    size_t rejectedBodyBytes=0;
    for(size_t i=0;i<D::FunctionCount;++i) {
        const D::FunctionContract &function=D::Functions[child][i];
        if(!function.symbol) continue;
        for(size_t offset=function.start;offset<function.end;++offset) {
            bytes[offset]^=1;
            assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
            bytes[offset]^=1;
            ++rejectedBodyBytes;
        }
    }
    size_t rejectedCodeRangeBytes=0;
    for(size_t i=0;i<D::CodeRangeCount;++i) {
        const D::CodeRangeContract &range=D::CodeRanges[i];
        if(range.child!=child) continue;
        for(size_t offset=range.start;offset<range.end;++offset) {
            bytes[offset]^=1;
            assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
            bytes[offset]^=1;
            ++rejectedCodeRangeBytes;
        }
    }
    size_t rejectedTableEntryBytes=0;
    for(size_t i=0;i<D::SetCommand34EntryCount;++i) {
        const D::RelativeTableEntry &entry=D::SetCommand34Entries[i];
        if(entry.child!=child) continue;
        for(size_t offset=entry.entryOffset;offset<entry.entryOffset+sizeof(int32_t);++offset) {
            bytes[offset]^=1;
            assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
            bytes[offset]^=1;
            ++rejectedTableEntryBytes;
        }
    }
    size_t rejectedRelativeJumps=0;
    for(size_t i=0;i<D::IoctlEntryJumpCount;++i) {
        const D::RelativeJump &jump=D::IoctlEntryJumps[i];
        if(jump.child!=child) continue;
        bytes[jump.instruction+1]^=1;
        assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
        bytes[jump.instruction+1]^=1;
        ++rejectedRelativeJumps;
    }
    size_t rejectedConditionalBranches=0;
    for(size_t i=0;i<D::EventSyncMismatchBranchCount;++i) {
        const D::RelativeConditionalBranch &branch=D::EventSyncMismatchBranches[i];
        if(branch.child!=child) continue;
        bytes[branch.instruction]^=1;
        assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
        bytes[branch.instruction]^=1;
        bytes[branch.instruction+1]^=1;
        assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
        bytes[branch.instruction+1]^=1;
        ++rejectedConditionalBranches;
    }
    size_t rejectedInternalBranches=0;
    for(size_t i=0;i<D::InternalBranchCount;++i) {
        const D::InternalBranch &branch=D::InternalBranches[i];
        if(branch.child!=child) continue;
        bytes[branch.instruction+1]^=1;
        assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
        bytes[branch.instruction+1]^=1;
        ++rejectedInternalBranches;
    }
    size_t rejectedTailJumpOpcodes=0;
    size_t rejectedTailJumpTargets=0;
    for(size_t i=0;i<D::ExternalCallCount;++i) {
        const D::ExternalCall &branch=D::ExternalCalls[i];
        if(branch.child!=child || branch.opcode!=0xe9) continue;
        bytes[branch.instruction]=0xe8;
        assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
        bytes[branch.instruction]=0xe9;
        ++rejectedTailJumpOpcodes;
        bytes[branch.instruction+1]^=1;
        assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
        bytes[branch.instruction+1]^=1;
        ++rejectedTailJumpTargets;
    }
    size_t rejectedImportTargets=0;
    for(size_t i=0;i<D::ImportCount;++i) {
        if(!importUsed[i]) continue;
        ++imports.addresses[i];
        assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
        --imports.addresses[i];
        ++rejectedImportTargets;
    }
    size_t rejectedSymbolAddresses=0;
    for(size_t i=0;i<D::FunctionCount;++i) {
        if(!D::Functions[child][i].symbol) continue;
        ++symbols.addresses[i];
        assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
        --symbols.addresses[i];
        ++rejectedSymbolAddresses;
    }
    uuid[0]^=1;
    assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
    uuid[0]^=1;
    size_t rejectedRouteSymbols=0;
    for(size_t i=0;i<D::RouteSymbolCount;++i) {
        if(D::RouteSymbols[i].child!=child) continue;
        ++routeSymbols.addresses[i];
        assert(!D::verify(image,uuid,child,symbols,imports,routeSymbols));
        --routeSymbols.addresses[i];
        ++rejectedRouteSymbols;
    }
    D::ImportAddresses wrongImport=imports;
    wrongImport.addresses[child==D::Brcm4331?D::SafeMetaCast:D::Bzero]=0;
    assert(!D::verify(image,uuid,child,symbols,wrongImport,routeSymbols));
    P::Image tooShort=image;
    tooShort.size=0x100;
    assert(!D::verify(tooShort,uuid,child,symbols,imports,routeSymbols));
    P::Image overflowingBase=image;
    overflowingBase.base=UINTPTR_MAX-16;
    assert(!D::verify(overflowingBase,uuid,child,symbols,imports,routeSymbols));

    std::printf("{\"child\":\"%s\",\"accepted\":true,"
                "\"rejected_body_bytes\":%zu,\"rejected_code_range_bytes\":%zu,"
                "\"rejected_table_entry_bytes\":%zu,\"rejected_relative_jumps\":%zu,"
                "\"rejected_conditional_branches\":%zu,"
                "\"rejected_internal_branches\":%zu,\"rejected_tail_jump_opcodes\":%zu,"
                "\"rejected_tail_jump_targets\":%zu,\"rejected_import_targets\":%zu,"
                "\"rejected_symbol_addresses\":%zu,\"rejected_route_symbols\":%zu,"
                "\"rejected_uuid_mutation\":true,\"rejected_unresolved_import\":true,"
                "\"rejected_short_image\":true,\"rejected_base_overflow\":true,"
                "\"rejected_bad_return_pc_contexts\":4}\n",
                child==D::Brcm4331?"4331":"43224",rejectedBodyBytes,
                rejectedCodeRangeBytes,rejectedTableEntryBytes,rejectedRelativeJumps,
                rejectedConditionalBranches,
                rejectedInternalBranches,rejectedTailJumpOpcodes,rejectedTailJumpTargets,
                rejectedImportTargets,rejectedSymbolAddresses,
                rejectedRouteSymbols);
}
'''


def _one_symbol(linkage: dict, name: str, address: int,
                external: bool | None = None) -> dict:
    matches = [record for record in linkage["symbols"].get(name, ())
               if record["defined"] and record["value"] == address]
    if len(matches) != 1 or (external is not None and matches[0]["external"] != external):
        raise ValueError(f"symbol mismatch: {name} expected at {address:#x}")
    return matches[0]


def _uuid(raw: bytes, label: str) -> bytes:
    header = macho.parse_header(raw, 0, label)
    if header["filetype"] != 11:
        raise ValueError(f"{label}: expected MH_KEXT_BUNDLE")
    commands = [command for kind, command, _ in header["commands"] if kind == 0x1B]
    if len(commands) != 1 or len(commands[0]) != 24:
        raise ValueError(f"{label}: expected one complete LC_UUID")
    return commands[0][8:24]


def _segments_and_text(raw: bytes, label: str) -> tuple[dict, list[dict]]:
    header = macho.parse_header(raw, 0, label)
    segments: list[dict] = []
    sections: list[dict] = []
    for kind, command, _ in header["commands"]:
        if kind == 0x19:
            segment, members = macho.parse_segment(command, label)
            segments.append(segment)
            sections.extend(members)
    text = [item for item in segments if item["name"] == "__TEXT"]
    code = [item for item in sections
            if item["segment"] == "__TEXT" and item["name"] == "__text"]
    if (len(text) != 1 or len(code) != 1 or text[0]["vmaddr"] != 0 or
            text[0]["fileoff"] != 0 or code[0]["addr"] != code[0]["fileoff"] or
            text[0]["filesize"] > text[0]["vmsize"] or
            text[0]["filesize"] > len(raw)):
        raise ValueError(f"{label}: __TEXT/__text is not the audited zero-based layout")
    return text[0], sections


def _relocations(raw: bytes, label: str, linkage: dict) -> tuple[list[dict], list[dict]]:
    header = macho.parse_header(raw, 0, label)
    commands = [command for kind, command, _ in header["commands"] if kind == 0xB]
    if len(commands) != 1 or len(commands[0]) != 80:
        raise ValueError(f"{label}: expected one complete LC_DYSYMTAB")
    dysymtab = commands[0]
    local_offset, local_count = struct.unpack_from("<II", dysymtab, 72)
    if local_count > 20_000_000 or local_offset + local_count * 8 > len(raw):
        raise ValueError(f"{label}: local relocation table is out of bounds")
    local: list[dict] = []
    for index in range(local_count):
        address, info = struct.unpack_from("<II", raw, local_offset + index * 8)
        if address & 0x80000000:
            address &= 0x00FFFFFF
        local.append({"address": address, "info": info})
    external = linkage["external_relocations"]
    return external, local


def _section_relocations(raw: bytes, sections: list[dict],
                         ranges: list[tuple[int, int]]) -> list[dict]:
    found: list[dict] = []
    for section in sections:
        if section["segment"] != "__TEXT" or section["name"] != "__text":
            continue
        count = section["nreloc"]
        start = section["reloff"]
        if count > 20_000_000 or start + count * 8 > len(raw):
            raise ValueError("__TEXT,__text relocation table exceeds source binary")
        for index in range(count):
            raw_address, info = struct.unpack_from("<II", raw, start + index * 8)
            address = (raw_address & 0x00FFFFFF
                       if raw_address & 0x80000000 else raw_address)
            absolute = section["addr"] + address
            if any(lo <= absolute < hi for lo, hi in ranges):
                found.append({"address": absolute, "info": info})
    return found


def _verify_raw_child(path: Path, child_key: str) -> dict:
    child = CHILDREN[child_key]
    raw = path.read_bytes()
    actual_sha = hashlib.sha256(raw).hexdigest()
    if actual_sha != child["sha256"]:
        raise ValueError(f"{child['label']}: source SHA-256 mismatch")
    uuid = _uuid(raw, child["label"])
    if uuid.hex().upper() != child["uuid"].replace("-", ""):
        raise ValueError(f"{child['label']}: LC_UUID mismatch")
    text, sections = _segments_and_text(raw, child["label"])
    if max(function["end"] for function in child["functions"]) > min(text["filesize"], text["vmsize"]):
        raise ValueError(f"{child['label']}: selected function exceeds __TEXT")
    linkage = build_namespace.macho_linkage(raw)
    used_imports = sorted({symbol for _,symbol,_ in child["external_calls"]})
    if sorted(child["imports"]) != used_imports:
        raise ValueError(f"{child['label']}: declared imports differ from branch contract")

    normalized_function_hashes: dict[str, str] = {}
    for function in child["functions"]:
        start, end = function["start"], function["end"]
        if start < next(item["addr"] for item in sections
                        if item["segment"] == "__TEXT" and item["name"] == "__text"):
            raise ValueError(f"{child['label']}: function starts before __text: {function['symbol']}")
        code = next(item for item in sections
                    if item["segment"] == "__TEXT" and item["name"] == "__text")
        if end > code["addr"] + code["size"]:
            raise ValueError(f"{child['label']}: function exceeds __text: {function['symbol']}")
        _one_symbol(linkage, function["symbol"], start, function["external"])
        _one_symbol(linkage, function["next"], function["next_offset"])
        if end <= start or function["next_offset"] < end:
            raise ValueError(f"{child['label']}: invalid function boundary for {function['symbol']}")
        body_hash = hashlib.sha256(raw[start:end]).hexdigest()
        if body_hash != function["sha256"]:
            raise ValueError(f"{child['label']}: audited function bytes changed: {function['symbol']}")
        normalized_body = bytearray(raw[start:end])
        for instruction, _symbol, _opcode in child["external_calls"]:
            if start <= instruction and instruction + 5 <= end:
                normalized_body[instruction + 1 - start:instruction + 5 - start] = b"\0\0\0\0"
        normalized_hash = hashlib.sha256(normalized_body).hexdigest()
        expected_normalized = function.get("normalized_sha256", function["sha256"])
        if normalized_hash != expected_normalized:
            raise ValueError(f"{child['label']}: normalized function bytes changed: {function['symbol']}")
        normalized_function_hashes[function["symbol"]] = normalized_hash

    for symbol in child["route_symbols"]:
        _one_symbol(linkage,symbol["symbol"],symbol["address"],symbol["external"])

    for code_range in child["code_ranges"]:
        start,end=code_range["start"],code_range["end"]
        code = next(item for item in sections
                    if item["segment"] == "__TEXT" and item["name"] == "__text")
        if start < code["addr"] or end > code["addr"] + code["size"] or end <= start:
            raise ValueError(f"{child['label']}: route range exceeds __text: {start:#x}-{end:#x}")
        body=bytearray(raw[start:end])
        for instruction,_,_ in child["external_calls"]:
            if start <= instruction and instruction + 5 <= end:
                body[instruction + 1 - start:instruction + 5 - start]=b"\0\0\0\0"
        if hashlib.sha256(body).hexdigest()!=code_range["sha256"]:
            raise ValueError(f"{child['label']}: route range bytes changed at {start:#x}")

    for branch in child["relative_conditional_branches"]:
        instruction=branch["instruction"]
        if instruction < 0 or instruction + 2 > len(raw) or \
           raw[instruction] != branch["opcode"]:
            raise ValueError(f"{child['label']}: conditional branch opcode changed at {instruction:#x}")
        displacement=struct.unpack_from("<b",raw,instruction+1)[0]
        if instruction + 2 + displacement != branch["target"]:
            raise ValueError(f"{child['label']}: conditional branch target changed at {instruction:#x}")

    for entry in child["relative_table_entries"]:
        if entry["entry"] < 0 or entry["entry"] + 4 > len(raw):
            raise ValueError(f"{child['label']}: command table entry exceeds source image")
        displacement=struct.unpack_from("<i",raw,entry["entry"])[0]
        if entry["table_base"] + displacement != entry["target"]:
            raise ValueError(f"{child['label']}: command 0x34 table target changed")

    for jump in child["relative_jumps"]:
        instruction=jump["instruction"]
        if raw[instruction]!=0xE9 or instruction + 5 > len(raw):
            raise ValueError(f"{child['label']}: ioctl entry thunk opcode changed")
        displacement=struct.unpack_from("<i",raw,instruction+1)[0]
        if instruction + 5 + displacement != jump["target"]:
            raise ValueError(f"{child['label']}: ioctl entry thunk target changed")

    selected_ranges = [(item["start"], item["end"]) for item in child["functions"]]
    selected_ranges += [(item["start"], item["end"]) for item in child["code_ranges"]]
    selected_ranges += [(item["entry"], item["entry"]+4)
                        for item in child["relative_table_entries"]]
    external, local = _relocations(raw, child["label"], linkage)
    expected_external = [
        {"address": instruction + 1, "symbol": symbol,
         "pcrel": 1, "length": 2, "type": 2}
        for instruction, symbol, _opcode in child["external_calls"]
    ]
    selected_external = [record for record in external
                         if any(lo <= record["address"] < hi for lo, hi in selected_ranges)]
    if sorted(selected_external, key=lambda item: (item["address"], item["symbol"])) != \
       sorted(expected_external, key=lambda item: (item["address"], item["symbol"])):
        raise ValueError(f"{child['label']}: selected external relocation records changed")
    for instruction, symbol, opcode in child["external_calls"]:
        if opcode not in (0xE8,0xE9) or raw[instruction] != opcode or \
           raw[instruction + 1:instruction + 5] != b"\0\0\0\0":
            raise ValueError(f"{child['label']}: unrelocated external branch body differs at {instruction:#x}")
        undefined = [record for record in linkage["symbols"].get(symbol, ())
                     if not record["defined"]]
        if len(undefined) != 1:
            raise ValueError(f"{child['label']}: import symbol is not uniquely undefined: {symbol}")

    selected_local = [item for item in local
                      if any(lo <= item["address"] < hi for lo, hi in selected_ranges)]
    selected_section = _section_relocations(raw, sections, selected_ranges)
    if selected_local or selected_section:
        raise ValueError(f"{child['label']}: selected code has unaccounted local/section relocations")

    for instruction, target, symbol in child["internal_calls"]:
        if raw[instruction] != 0xE8:
            raise ValueError(f"{child['label']}: internal call opcode changed at {instruction:#x}")
        displacement = struct.unpack_from("<i", raw, instruction + 1)[0]
        if instruction + 5 + displacement != target:
            raise ValueError(f"{child['label']}: internal target changed at {instruction:#x}")
        _one_symbol(linkage, symbol, target)

    return {
        "label": child["label"], "source_path": str(path),
        "source_sha256": actual_sha, "uuid": child["uuid"],
        "text_vmaddr": hex(text["vmaddr"]), "text_fileoff": hex(text["fileoff"]),
        "selected_functions": [
            {"symbol": item["symbol"], "range": [hex(item["start"]), hex(item["end"])],
             "size": item["end"] - item["start"], "raw_sha256": item["sha256"],
             "normalized_sha256": normalized_function_hashes[item["symbol"]],
             "next_symbol": item["next"], "next_offset": hex(item["next_offset"]),
             **({"entry_abi": item["entry_abi"], "return_abi": item["return_abi"]}
                if "entry_abi" in item else {})}
            for item in child["functions"]
        ],
        "route_symbols": [
            {"symbol": item["symbol"], "address": hex(item["address"]),
             "external": item["external"]}
            for item in child["route_symbols"]
        ],
        "selected_code_ranges": [
            {"range": [hex(item["start"]),hex(item["end"])],
             "size": item["end"]-item["start"],
             "normalized_sha256": item["sha256"],
             **({"purpose": item["purpose"]} if "purpose" in item else {})}
            for item in child["code_ranges"]
        ],
        "relative_table_entries": [
            {"table_base": hex(item["table_base"]),"entry": hex(item["entry"]),
             "target": hex(item["target"]),"displacement": hex(item["target"]-item["table_base"])}
            for item in child["relative_table_entries"]
        ],
        "relative_jumps": [
            {"instruction": hex(item["instruction"]),"target": hex(item["target"])}
            for item in child["relative_jumps"]
        ],
        "relative_conditional_branches": [
            {"instruction": hex(item["instruction"]),"opcode": hex(item["opcode"]),
             "target": hex(item["target"])}
            for item in child["relative_conditional_branches"]
        ],
        "imports": sorted({symbol for _,symbol,_ in child["external_calls"]}),
        "external_calls": [
            {"instruction": hex(instruction), "target_symbol": symbol,
             "relocation_address": hex(instruction + 1),
             "opcode": hex(opcode), "type": "x86_64 BRANCH rel32"}
            for instruction, symbol, opcode in child["external_calls"]
        ],
        "internal_calls": [
            {"instruction": hex(instruction), "target": hex(target), "symbol": symbol,
             "return_pc": hex(instruction + 5)}
            for instruction, target, symbol in child["internal_calls"]
        ],
        "selected_local_relocations": len(selected_local),
        "selected_section_relocations": len(selected_section),
    }


def _run_production_harness(audits: list[dict], child_keys: list[str]) -> list[dict]:
    compiler = shutil.which("xcrun")
    clang = shutil.which("clang++")
    command = [compiler, "clang++"] if compiler else [clang]
    if not command[0]:
        raise ValueError("clang++ is required for the ASan/UBSan production guard harness")
    results = []
    with tempfile.TemporaryDirectory(prefix="legacy-disassociate-contract-", dir="/private/tmp") as temp:
        tmp = Path(temp)
        source = tmp / "child_contract.cpp"
        binary = tmp / "child_contract"
        source.write_text(HARNESS)
        subprocess.run(command + ["-std=c++14", "-Wall", "-Wextra", "-Werror",
                                  "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                                  "-I", str(PROJECT / "src"), str(source), "-o", str(binary)],
                       check=True, capture_output=True, text=True, timeout=90)
        for audit, child_key in zip(audits, child_keys):
            run = subprocess.run([str(binary), child_key, audit["source_path"]],
                                 check=True, capture_output=True, text=True, timeout=90)
            results.append(json.loads(run.stdout))
    return results


def verify(bcm4331: Path, bcm43224: Path) -> dict:
    child_keys = ["4331", "43224"]
    paths = [bcm4331, bcm43224]
    audits = [_verify_raw_child(path, key) for path, key in zip(paths, child_keys)]
    runtime = _run_production_harness(audits, child_keys)
    return {
        "scope": "fixed El Cap 4331/43224 current-BSS allocation/copy, SET22-to-worker route, bounded idle-timeout event branches, cfg-free, and WLC-stop publication static guards",
        "accepted": True,
        "raw_binaries": audits,
        "production_header": "src/legacy_wifi_compat/disassociate_child_contracts.hpp",
        "production_header_sha256": hashlib.sha256(
            (PROJECT / "src/legacy_wifi_compat/disassociate_child_contracts.hpp").read_bytes()).hexdigest(),
        "runtime_contract": "selected full-body SHA-256 with external rel32 operands normalized, route-window hashes, relative table entry/thunk/conditional-branch target checks, exact import targets and internal call targets",
        "sanitizers": ["address", "undefined"],
        "runtime_harness": runtime,
        "capture_preconditions": "Capture must occur before original SET22 while the native controller gate is held. A runtime adapter must prove the live controller/interface/WLC/cfg identity and bounds, reject invalid field and IE extents, copy IE bytes into owned storage, and retain no child-owned pointer past the synchronous call. These static guards do not authorize raw memory reads.",
        "current_bss_layout": {
            "4331": {"controller_wlc": "0x468", "virtual_interface_list": "0x500",
                     "interface_wlcif": "0x188", "cfg_current_bss_pointer": "0x318",
                     "cfg_allocation_size": "0x600", "current_bss_allocation_size": "0xa0",
                     "record_size": "0xa0", "bssid": "0x00+6", "ssid_length": "0x08",
                     "ssid_bytes": "0x09", "chanspec": "0x32", "capability": "0x62",
                     "ie_pointer": "0x68", "ie_length_u16": "0x70"},
            "43224": {"controller_wlc": "0x418", "inline_current_bss": "0x2f8",
                      "wlc_allocation_size": "0x3b98",
                      "record_size": "0x98", "bssid": "0x00+6", "ssid_length": "0x08",
                      "ssid_bytes": "0x09", "chanspec": "0x30", "capability": "0x5e",
                      "ie_pointer": "0x68", "ie_length_u16": "0x70"},
            "scope_note": "Pinned allocator and copy code establishes the sampled layout and backing sizes; static guards do not authorize dereference, prove live pointer validity/lifetime, or establish IE allocation readability. Runtime must perform bounded reads and an owned IE copy before original SET22."
        },
        "capture_provenance": {
            "4331": {
                "controller_to_wlc": "controller+0x468",
                "interface_resolution": "AirPort_Brcm4331::getVirtIf at 0xc2e0 validates the supplied OSObject against list head controller+0x500; accepted object has wlcif at +0x188",
                "cfg_resolution": "_wlc_bsscfg_find_by_wlcif at 0x5f3b8; _wlc_get_current_bss at 0x248fd returns *(cfg+0x318)",
                "cfg_allocator": {"symbol": "_wlc_bsscfg_malloc", "range": ["0xb47e9", "0xb49a9"],
                                  "cfg_size": "0x600", "current_record": "cfg+0x318, zero-allocated 0xa0 bytes",
                                  "secondary_record": "cfg+0x310, zero-allocated 0xa0 bytes"},
                "copy_producer": {"symbol": "_wlc_BSSinit", "range": ["0x26be8", "0x27680"],
                                  "record_copy": "0xa0 bytes", "ie_copy": "old IE allocation freed, fields cleared, exact source IE length allocated and copied"}
            },
            "43224": {
                "controller_to_wlc": "controller+0x418",
                "wlc_start": {"symbol": "AirPort_Brcm43224::wlcStart", "symbol_address": "0x2ecc",
                              "guarded_store_window": ["0x2f64", "0x2fb4"],
                              "attach_call": "0x2f98 -> _wlc_attach at 0x5f0e1",
                              "stored_result": "same successful attach result stored in controller+0x418 (WLC base) and controller+0x420 (the WLC pointer used by child state gates)",
                              "attach_allocation": "_wlc_attach allocates and zeroes 0x3b98 bytes"},
                "inline_record": "wlc+0x2f8, 0x98 bytes; extent fits the pinned 0x3b98 allocation",
                "copy_producer": {"symbol": "_wlc_BSSinit", "range": ["0x5be74", "0x5ca04"],
                                  "record_copy": "0x98 bytes", "ie_copy": "frees old wlc+0x360 IE, clears pointer/length, copies record then allocates/copies source IE bytes"}
            },
            "note": "Offsets and allocator/copy behavior are fixed-sample static evidence. They do not prove a future adapter's pointer came from this allocation or remains valid while read."
        },
        "set22_to_worker_closure": {
            "4331": {
                "setter": "AirPort_Brcm4331::setDISASSOCIATE [0xda90,0xdb4a): getVirtIf -> wlcif -> cfg -> _wlc_ioctl(wlc,0x34,&zero,4,wlcif)",
                "entry_thunk": "_wlc_ioctl [0x323cc,0x323d6); E9 at 0x323d1 targets local __wlc_ioctl 0x32625",
                "dispatcher_prefix": ["0x32625", "0x32848"],
                "command_0x34_table": {"base": "0x354a8", "entry": "0x35578", "target": "0x332b9"},
                "command_case": ["0x332b9", "0x332ec"],
                "disable": {"symbol": "_wlc_bsscfg_disable", "range": ["0x5e0aa", "0x5e28d"],
                             "down_call": "0x5e19f -> _wlc_bsscfg_down at 0x5de67",
                             "worker_call": "0x5e1e9 -> _wlc_disassociate_client at 0xb0b53; return PC 0x5e1ee"}
            },
            "43224": {
                "setter": "AirPort_Brcm43224::setDISASSOCIATE [0x98bc,0x992a) -> _wlc_set(wlc,0x34,0)",
                "wlc_set": "_wlc_set [0x67ab4,0x67ad6) -> local _wlc_ioctl at 0x67ad6",
                "dispatcher_prefix": ["0x67ad6", "0x67cdc"],
                "command_0x34_table": {"base": "0x6ac28", "entry": "0x6acf8", "target": "0x6883e"},
                "command_case": ["0x6883e", "0x68875"],
                "disable": {"symbol": "_wlc_bsscfg_disable", "range": ["0x900d5", "0x9025b"],
                             "down_call": "0x9019c -> _wlc_bsscfg_down at 0x8ffa6",
                             "worker_call": "0x901e2 -> _wlc_disassociate_client at 0x67583; return PC 0x901e7"}
            },
            "scope_note": "Dispatcher prefixes, selected command table entries/cases, setter-to-dispatch calls, complete disable functions, the 43224 _wlc_down body/calls, and direct worker callsites are pinned. The whole dispatcher body, _wlc_bsscfg_down bodies, upstream BSD request gate and live instance ownership are outside this child-only guard."
        },
        "teardown_publication_guards": {
            "4331": {
                "cfg_free": {"symbol": "_wlc_bsscfg_free", "range": ["0x5e6be", "0x5e92d"],
                             "abi": "(wlc, cfg), void-style",
                             "ordered_calls": ["0x5e90a -> _wlc_bsscfg_mfree at 0xb49a9",
                                               "0x5e90f clears wlc+0x2e0+cfg.index*8 after free"]},
                "wlc_stop": {"symbol": "AirPort_Brcm4331::wlcStop", "range": ["0x49e8", "0x4a9a"],
                             "detach_call": "0x4a20 -> _wlc_detach at 0x2f9cb",
                             "publish_clear": "0x4a6b clears controller+0x468 after _wlc_detach returns",
                             "abi": "(controller this), void"}
            },
            "43224": {
                "cfg_free": None,
                "wlc_stop": {"symbol": "AirPort_Brcm43224::wlcStop", "range": ["0x38aa", "0x395b"],
                             "detach_call": "0x38e1 -> _wlc_detach at 0x65718",
                             "publish_clear": "0x392c clears controller+0x418 after _wlc_detach returns",
                             "symbol_after_padding": "__ZN17AirPort_Brcm432244stopEP9IOService at 0x395c; byte 0x395b is padding",
                             "abi": "(controller this), void"}
            },
            "boundary": "The selected function bodies, raw source UUID/SHA, exact imports, and all direct internal call targets are guarded. This proves sampled ordering only; runtime serialization still depends on the separately established outer mutation scope."
        },
        "caller_return_pcs": {
            "worker": {"4331": ["0x5e1ee"], "43224": ["0x901e7"]},
            "sender": {"4331": ["0xb0dc5", "0xb0e40"], "43224": ["0x67790"]},
            "builder": {"4331": ["0x4d77c"], "43224": ["0x7e4a4"]}
        },
        "idle_timeout_event_scope": {
            "4331": {
                "state_zero_route": "_wlc_assoc_timeout state 0 -> _wlc_auth_complete status 2 -> _wlc_bss_mac_event(event code 3, detail 2) -> _wlc_bss_mac_rxframe_event",
                "sync_handoff": "Runtime RouteSymbol admission resolves _wl_event_sync as a named child-image symbol at 0x16c10; the _wlc_bss_mac_rxframe_event call at 0x4efd4 is pinned to that target. For this event-code-3 input, the checked compare/conditional branch reaches the mismatch return epilogue at 0x16c3c, then the caller continues to event queue insertion",
                "guarded_ranges": [["0x16c10", "0x16c1c"], ["0x16c3c", "0x16c43"]],
                "conditional_branch": {"instruction": "0x16c1a", "opcode": "0x75", "target": "0x16c3c"},
                "boundary": "Only the event-code-3 mismatch/return path is guarded. The 0x20 willRoam branch and any higher-level event consumer are outside this check."
            },
            "43224": {
                "state_zero_route": "_wlc_assoc_timeout state 0 emits _wlc_bss_mac_event(event code 3, detail 2), which constructs and enqueues an event",
                "boundary": "Selected child functions pin event construction and queue handoff only; no higher-level event consumer or reconnect behavior is checked."
            },
            "claim_boundary": "These static guard prerequisites do not independently validate the runtime idle no-op implementation or establish that no event is queued, no callback is pending, or no later consumer can reconnect."
        },
        "not_guarded": [
            "Static guards do not authorize reads of current-BSS pointers, records, or IE memory and do not prove a live instance's object lifetime.",
            "The full _wlc_ioctl dispatcher is not pinned; selected dispatcher prefixes/table entries/cases, both _wlc_bsscfg_down bodies, the selected 43224 _wlc_down body, cfg-free path on 4331, WLC-stop publication paths, and relevant callsites are guarded.",
            "The 4331 _wl_event_sync 0x20 willRoam branch is not guarded; only the event-code-3 mismatch branch and its return epilogue are checked. No higher-level event consumer or global no-retry property is established.",
            "The child contract does not establish the provider's request gate, runtime adapter ownership, serialized read window, or safe bounded-copy callback.",
            "Runtime lookup and provenance of import target addresses must be supplied by a separately guarded installer path.",
            "No legacy_install integration, kext detour, EFI deployment, boot, or hardware test is included."
        ],
        "required_future_installer_guards": [
            "Before original SET22, prove the native controller gate and exact live controller/interface/WLC/cfg chain; validate field and IE bounds and copy IE bytes to owned memory without retaining raw child pointers.",
            "Guard provider SET22 entry and same-stack dispatch so capture and original request share the exact gated lifetime; the child static route guards alone do not authorize the capture read or worker detour.",
            "Resolve and validate the actual loaded import targets before passing them to this verifier."
        ],
        "runtime_support_claimed": False,
        "nonzero_set22_runtime_support_proven": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bcm4331", type=Path, required=True)
    parser.add_argument("--bcm43224", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.bcm4331, args.bcm43224)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"verify_legacy_disassociate_contracts: {error}\n")
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
