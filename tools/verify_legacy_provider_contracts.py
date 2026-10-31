#!/usr/bin/env python3
"""Check the production legacy request guards against the pinned provider.

Accepts an explicit IO80211ElCap executable, maps its segments in a temporary
host buffer, and exercises the actual C++ guards under ASan/UBSan. No driver is
loaded and no system file is changed. This verifies the fixed dependency's
contract, not the surrounding macOS userspace protocol or hardware behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

import verify_ifnet_kernel_contracts as macho

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
import build_namespace  # noqa: E402

PROVIDER_SHA256 = "8ecd8f8a027d93205a493518c50a772f520ee774d2fa4d24b564dc67722c54b0"

HARNESS = r'''
#include "legacy_wifi_compat/provider_contract.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <utility>
#include <vector>
using namespace LegacyWiFi::ProviderContract;
int main(int argc, char **argv) {
    assert(argc == 2);
    std::ifstream file(argv[1], std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), {});
    uintptr_t symbols[SymbolCount];
    Image image {data.data(), data.size(), 0xffffff8001000000ULL};
    for (size_t index = 0; index < SymbolCount; ++index)
        symbols[index] = image.base + Offsets[index];
    // The raw fixed binary has zero addends at these two external Mach-O
    // relocation sites. Model the loader's nonzero signed rel32 writes to
    // distinct nearby kernel import addresses before checking the live guard.
    const Imports imports {image.base + image.size + 0x1000,
                           image.base + image.size + 0x2000};
    auto relocate = [&](size_t site, uintptr_t target) {
        const uintptr_t returnPC=image.base+site+5;
        const int64_t delta=target>=returnPC ? static_cast<int64_t>(target-returnPC)
                                             : -static_cast<int64_t>(returnPC-target);
        assert(delta>=INT32_MIN && delta<=INT32_MAX);
        const int32_t encoded=static_cast<int32_t>(delta);
        std::memcpy(data.data()+site+1,&encoded,sizeof(encoded));
    };
    assert(!verify(image,symbols,imports)); // Unrelocated file bytes must fail.
    relocate(0x4717c,imports.ioMalloc);
    relocate(0x471f0,imports.ioFree);
    assert(verify(image,symbols,imports));
    const uintptr_t copyOutReturn = image.base + GetAPIEListCopyOutReturn;
    assert(getAPIEListCopyOutCall(image, copyOutReturn, symbols[CopyOut]));
    assert(!getAPIEListCopyOutCall(image, copyOutReturn + 1, symbols[CopyOut]));
    assert(!getAPIEListCopyOutCall(image, copyOutReturn, symbols[CopyOut] + 1));
    uintptr_t authWords = 0, authLastWord = 0;
    assert(ripRelativeTarget(image, 0x4c770, 6, 2, authLastWord));
    assert(ripRelativeTarget(image, 0x4c779, 7, 3, authWords));
    assert(authWords == image.base + 0x7f9ac && authLastWord == authWords + 8);
    const uintptr_t authCopyInReturn = image.base + AuthCopyInReturn;
    assert(setAuthCopyInCall(image, authCopyInReturn, symbols[CopyIn]));
    assert(!setAuthCopyInCall(image, authCopyInReturn + 1, symbols[CopyIn]));
    assert(!setAuthCopyInCall(image, authCopyInReturn, symbols[CopyIn] + 1));

    // Exercise the rel32 guards independently of the full-body fingerprint.
    for (const auto site : {size_t(0x46406), size_t(0x4640d), size_t(0x471ad), size_t(0x471d6)}) {
        uint8_t saved[4];
        std::memcpy(saved, data.data() + site + 1, sizeof(saved));
        data[site + 1] ^= 1;
        const uintptr_t target = site == 0x46406 ? symbols[VirtualRequest] :
            ((site == 0x4640d || site == 0x471ad) ? symbols[RequestIoctl] : symbols[CopyOut]);
        assert(!call(image, site, target));
        std::memcpy(data.data() + site + 1, saved, sizeof(saved));
    }
    unsigned rejectedSetAuthTargets=0;
    for (const auto site : {size_t(0x4c7ad), size_t(0x4c7cf), size_t(0x4c7d9)}) {
        uint8_t saved[4];
        std::memcpy(saved, data.data() + site + 1, sizeof(saved));
        data[site + 1] ^= 1;
        const uintptr_t target = site == 0x4c7ad ? symbols[CopyIn] :
            (site == 0x4c7cf ? symbols[VirtualRequest] : symbols[RequestIoctl]);
        assert(!call(image, site, target));
        assert(!verify(image, symbols, imports));
        std::memcpy(data.data() + site + 1, saved, sizeof(saved));
        ++rejectedSetAuthTargets;
    }
    struct DisassociateCall { size_t site; uintptr_t target; };
    const DisassociateCall setDisassociateCalls[] = {
        {0x4d3a2, symbols[VirtualRequest]}, {0x4d3ac, symbols[RequestIoctl]},
        {0x4d3fc, symbols[VirtualRequest]}, {0x4d406, symbols[RequestIoctl]},
        {0x4d419, image.base + 0x57452}, {0x4d439, image.base + 0x58358},
        {0x4d443, image.base + 0x64cee}
    };
    unsigned rejectedSetDisassociateTargets=0;
    for (const auto &entry : setDisassociateCalls) {
        uint8_t saved[4];
        std::memcpy(saved, data.data() + entry.site + 1, sizeof(saved));
        data[entry.site + 1] ^= 1;
        assert(!call(image, entry.site, entry.target));
        assert(!verify(image, symbols, imports));
        std::memcpy(data.data() + entry.site + 1, saved, sizeof(saved));
        ++rejectedSetDisassociateTargets;
    }
    unsigned rejectedExternalRelocationMutations=0;
    for (const auto site : {size_t(0x4717c),size_t(0x471f0)}) {
        uint8_t saved[4];
        std::memcpy(saved,data.data()+site+1,sizeof(saved));
        data[site+1]^=1;
        assert(!verify(image,symbols,imports));
        std::memcpy(data.data()+site+1,saved,sizeof(saved));
        ++rejectedExternalRelocationMutations;
    }
    assert(!verify(image,symbols,Imports{imports.ioMalloc+1,imports.ioFree}));
    assert(!verify(image,symbols,Imports{imports.ioMalloc,imports.ioFree+1}));
    const size_t sites[] = {
        0x45f2e,0x45f89,0x45fb0,0x4601c,0x46023,0x45fcc,0x46051,
        0x4632a,0x463a0,0x463be,0x4d07c,0x4d12f,0x4d153,0x4d15f,
        0x4ee56,0x4eeac,0x4eebe,0x4eecd,0x55d24,0x55d88,
        0x4cd1a,0x4cd7d,0x4cda8,0x4cddb,0x4cdef,0x615e8
    };
    unsigned rejected = 0;
    for (size_t site : sites) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            data[site] ^= 1U << bit;
            assert(!verify(image, symbols, imports));
            data[site] ^= 1U << bit;
            ++rejected;
        }
    }
    for (size_t index = 0; index < SymbolCount; ++index) {
        ++symbols[index]; assert(!verify(image, symbols, imports)); --symbols[index];
    }
    size_t rejectedGet13BodyBytes = 0, rejectedGet48BodyBytes = 0;
    for (const auto body : {std::pair<size_t,size_t>{0x463d9,0x4c},
                            std::pair<size_t,size_t>{0x47120,0xe6}}) {
        for (size_t offset = 0; offset < body.second; ++offset) {
            const size_t site = body.first + offset;
            data[site] ^= 1;
            assert(!verify(image, symbols, imports));
            data[site] ^= 1;
            if (body.first == 0x463d9) ++rejectedGet13BodyBytes;
            else ++rejectedGet48BodyBytes;
        }
    }
    size_t rejectedSetAuthBodyBytes = 0;
    for (size_t offset = 0; offset < 0x8f; ++offset) {
        const size_t site = 0x4c75a + offset;
        data[site] ^= 1;
        assert(!verify(image, symbols, imports));
        data[site] ^= 1;
        ++rejectedSetAuthBodyBytes;
    }
    size_t rejectedSetAuthInitializerBytes = 0;
    for (size_t offset = 0; offset < 12; ++offset) {
        const size_t site = 0x7f9ac + offset;
        data[site] ^= 1;
        assert(!verify(image, symbols, imports));
        data[site] ^= 1;
        ++rejectedSetAuthInitializerBytes;
    }
    size_t rejectedSetDisassociateBodyBytes = 0;
    for (size_t offset = 0; offset < 0xeb; ++offset) {
        const size_t site = 0x4d36c + offset;
        data[site] ^= 1;
        assert(!verify(image, symbols, imports));
        data[site] ^= 1;
        ++rejectedSetDisassociateBodyBytes;
    }
    image.size = 0x50000;
    assert(!verify(image, symbols, imports));
    image.size = data.size();
    image.base = UINTPTR_MAX - 16;
    assert(!verify(image, symbols, imports));
    image.base = 0;
    assert(!verify(image, symbols, imports));
    printf("{\"accepted\":true,\"rejected_opcode_mutations\":%u,"
           "\"rejected_symbol_mutations\":%zu,\"rejected_get13_body_bytes\":%zu,"
           "\"rejected_get48_body_bytes\":%zu,\"rejected_setauth_body_bytes\":%zu,"
           "\"rejected_setauth_initializer_bytes\":%zu,"
           "\"rejected_setdisassociate_body_bytes\":%zu,"
           "\"rejected_get48_external_relocations\":%u,"
           "\"rejected_setauth_targets\":%u,\"rejected_setdisassociate_targets\":%u,"
           "\"rejected_internal_rel32_targets\":11,"
           "\"rejected_copyout_return_pc_cases\":2,"
           "\"rejected_setauth_return_pc_cases\":2,\"rejected_bounds\":3}\n",
           rejected, static_cast<size_t>(SymbolCount), rejectedGet13BodyBytes,
           rejectedGet48BodyBytes,rejectedSetAuthBodyBytes,
           rejectedSetAuthInitializerBytes,rejectedSetDisassociateBodyBytes,
           rejectedExternalRelocationMutations,rejectedSetAuthTargets,
           rejectedSetDisassociateTargets);
}
'''


def mapped_provider(raw: bytes) -> bytes:
    # A full digest check precedes parsing; unknown dependency builds must not
    # be mistaken for another minor version of the fixed injected provider.
    if hashlib.sha256(raw).hexdigest() != PROVIDER_SHA256:
        raise ValueError("IO80211ElCap executable does not match the pinned dependency")
    header = macho.parse_header(raw, 0, "IO80211ElCap")
    if header["filetype"] != 11:
        raise ValueError("expected MH_KEXT_BUNDLE")
    segments = [macho.parse_segment(command, "IO80211ElCap")[0]
                for kind, command, _ in header["commands"]
                if kind == macho.LC_SEGMENT_64]
    mapped_size = max(segment["vmaddr"] + segment["vmsize"] for segment in segments)
    if mapped_size > 16 * 1024 * 1024:
        raise ValueError("provider mapping exceeds bounded host verification buffer")
    output = bytearray(mapped_size)
    for segment in segments:
        size = segment["filesize"]
        if size > segment["vmsize"]:
            raise ValueError("segment file bytes exceed virtual span")
        payload = macho.checked_slice(raw, segment["fileoff"], size, segment["name"])
        output[segment["vmaddr"]:segment["vmaddr"] + size] = payload
    return bytes(output)


def relocation_sites(raw: bytes) -> tuple[list[dict], list[dict]]:
    """Return external and local Mach-O relocation records for the fixed kext."""
    header = macho.parse_header(raw, 0, "IO80211ElCap")
    dysymtab = [command for kind, command, _ in header["commands"] if kind == 0xB]
    if len(dysymtab) != 1 or len(dysymtab[0]) != 80:
        raise ValueError("provider must have one complete LC_DYSYMTAB")
    local_offset, local_count = struct.unpack_from("<II", dysymtab[0], 72)
    if local_count > 20_000_000 or local_offset + local_count * 8 > len(raw):
        raise ValueError("local relocation table exceeds the fixed provider")
    local = []
    for index in range(local_count):
        raw_address, info = struct.unpack_from("<II", raw, local_offset + index * 8)
        # Scattered relocation_info stores its section-relative address in the
        # low 24 bits of the first word; ordinary records use all 32 bits.
        address = raw_address & 0x00ffffff if raw_address & 0x80000000 else raw_address
        local.append({"address": address, "info": info})
    linkage = build_namespace.macho_linkage(raw)
    return linkage["external_relocations"], local


def assert_no_body_relocations(raw: bytes, body_start: int, body_end: int,
                               label: str) -> dict:
    external, local = relocation_sites(raw)
    external_hits = [item for item in external
                     if body_start <= item["address"] < body_end]
    local_hits = [item for item in local
                  if body_start <= item["address"] < body_end]
    if external_hits or local_hits:
        raise ValueError(f"{label} body contains loader relocations: external={external_hits}, local={local_hits}")
    return {"external": external_hits, "local": local_hits}


def rip_target(mapped: bytes, instruction: int, instruction_size: int,
               displacement_offset: int) -> int:
    if (displacement_offset < 0 or displacement_offset + 4 > instruction_size or
            instruction < 0 or instruction + instruction_size > len(mapped)):
        raise ValueError("SET2 RIP-relative load exceeds the mapped provider")
    displacement = struct.unpack_from("<i", mapped, instruction + displacement_offset)[0]
    return instruction + instruction_size + displacement


def verify(path: Path) -> dict:
    raw = path.read_bytes()
    mapped = mapped_provider(raw)
    linkage = build_namespace.macho_linkage(raw)
    set_auth_name = "__ZL11setAuthTypeP17IO80211ControllerP16IO80211InterfaceP23IO80211VirtualInterfaceP13apple80211reqb"
    auth_symbols = linkage["symbols"].get(set_auth_name, [])
    if not any(item["defined"] and not item["external"] and item["value"] == 0x4c75a
               for item in auth_symbols):
        raise ValueError("SET2 symbol is not the audited local function at 0x4c75a")
    set_auth_targets = (
        ("__ZN17IO80211Controller6copyInEyPvm", 0x55d24),
        ("__ZN17IO80211Controller29apple80211VirtualRequestIoctlEjiP23IO80211VirtualInterfacePv", 0x552ba),
        ("__ZN17IO80211Controller22apple80211RequestIoctlEjiP16IO80211InterfacePv", 0x537a6),
    )
    for name, offset in set_auth_targets:
        if not any(item["defined"] and item["value"] == offset
                   for item in linkage["symbols"].get(name, [])):
            raise ValueError(f"SET2 call target {name} is not defined at {offset:#x}")
    set_auth_body = assert_no_body_relocations(raw, 0x4c75a, 0x4c7e9, "SET2")
    set_disassociate_name = "__ZL15setDisassociateP17IO80211ControllerP16IO80211InterfaceP23IO80211VirtualInterfaceP13apple80211reqb"
    disassociate_symbols = linkage["symbols"].get(set_disassociate_name, [])
    if not any(item["defined"] and not item["external"] and item["value"] == 0x4d36c
               for item in disassociate_symbols):
        raise ValueError("SET22 symbol is not the audited local function at 0x4d36c")
    set_disassociate_targets = (
        ("__ZN17IO80211Controller29apple80211VirtualRequestIoctlEjiP23IO80211VirtualInterfacePv", 0x552ba),
        ("__ZN17IO80211Controller22apple80211RequestIoctlEjiP16IO80211InterfacePv", 0x537a6),
        ("__ZN16IO80211Interface19terminateSupplicantEv", 0x57452),
        ("__ZN16IO80211Interface11postMessageEjPvm", 0x58358),
        ("__ZN23IO80211VirtualInterface11postMessageEjPvm", 0x64cee),
    )
    for name, offset in set_disassociate_targets:
        if not any(item["defined"] and item["value"] == offset
                   for item in linkage["symbols"].get(name, [])):
            raise ValueError(f"SET22 call target {name} is not defined at {offset:#x}")
    set_disassociate_body = assert_no_body_relocations(raw, 0x4d36c, 0x4d457, "SET22")
    auth_initializer = {
        "address": hex(rip_target(mapped, 0x4c779, 7, 3)),
        "third_word_address": hex(rip_target(mapped, 0x4c770, 6, 2)),
        "words": list(struct.unpack_from("<III", mapped, 0x7f9ac)),
    }
    if (auth_initializer["address"] != "0x7f9ac" or
            auth_initializer["third_word_address"] != "0x7f9b4" or
            auth_initializer["words"] != [1, 0, 0]):
        raise ValueError(f"SET2 RIP-relative initializer changed: {auth_initializer}")
    owner_calls = []
    for displacement in (0x61611, 0x61b47):
        matching = [item for item in linkage["external_relocations"]
                    if item["address"] == displacement]
        expected = {"address": displacement, "symbol": "_proc_selfpid",
                    "pcrel": 1, "length": 2, "type": 2}
        if matching != [expected] or mapped[displacement - 1] != 0xe8:
            raise ValueError("scan owner call lacks the exact external proc_selfpid relocation")
        owner_calls.append(hex(displacement - 1))
    external_import_calls = []
    for instruction, displacement, symbol in (
            (0x4717c, 0x4717d, "_IOMalloc"),
            (0x471f0, 0x471f1, "_IOFree")):
        matching = [item for item in linkage["external_relocations"]
                    if item["address"] == displacement]
        expected = {"address": displacement, "symbol": symbol,
                    "pcrel": 1, "length": 2, "type": 2}
        if (matching != [expected] or mapped[instruction] != 0xe8 or
                mapped[instruction + 1:instruction + 5] != b"\0\0\0\0"):
            raise ValueError(f"GET48 call lacks the exact external {symbol} relocation")
        external_import_calls.append({"instruction": hex(instruction),
                                      "relocation_address": hex(displacement),
                                      "symbol": symbol})
    if mapped[0x5f60f:0x5f614] != bytes.fromhex("b9b0000000"):
        raise ValueError("ScanManager metaclass object size changed")
    with tempfile.TemporaryDirectory(prefix="legacy-provider-contract-", dir="/private/tmp") as tmp:
        directory = Path(tmp)
        source, binary, fixture = (directory / name for name in ("contract.cpp", "contract", "provider.bin"))
        source.write_text(HARNESS)
        fixture.write_bytes(mapped)
        subprocess.run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        "-I", str(PROJECT / "src"), str(source), "-o", str(binary)], check=True)
        run = subprocess.run([str(binary), str(fixture)], check=True, capture_output=True, text=True)
    return {"provider_sha256": PROVIDER_SHA256,
            "contract_sha256": hashlib.sha256((PROJECT / "src/legacy_wifi_compat/provider_contract.hpp").read_bytes()).hexdigest(),
            "scope": "fixed dependency request guards",
            "setdisassociate_symbol": {"name": set_disassociate_name, "offset": "0x4d36c"},
            "setdisassociate_body": {"start": "0x4d36c", "end_exclusive": "0x4d457", "size": 235,
                                     "relocations": set_disassociate_body},
            "setdisassociate_calls": {"virtual_ioctl": ["0x4d3a2 -> 0x552ba", "0x4d3fc -> 0x552ba"],
                                      "interface_ioctl": ["0x4d3ac -> 0x537a6", "0x4d406 -> 0x537a6"],
                                      "terminate_supplicant": "0x4d419 -> 0x57452",
                                      "interface_post_message": "0x4d439 -> 0x58358",
                                      "virtual_interface_post_message": "0x4d443 -> 0x64cee"},
            "setdisassociate_target_symbols": [{"name": name, "offset": hex(offset)}
                                               for name, offset in set_disassociate_targets],
            "setauth_symbol": {"name": set_auth_name, "offset": "0x4c75a"},
            "setauth_body": {"start": "0x4c75a", "end_exclusive": "0x4c7e9", "size": 143,
                             "relocations": set_auth_body},
            "setauth_calls": {"copy_in": "0x4c7ad -> 0x55d24",
                               "virtual_ioctl": "0x4c7cf -> 0x552ba",
                               "interface_ioctl": "0x4c7d9 -> 0x537a6",
                               "copy_in_return_pc": "0x4c7b2"},
            "setauth_target_symbols": [{"name": name, "offset": hex(offset)}
                                       for name, offset in set_auth_targets],
            "setauth_rip_initializer": auth_initializer,
            "proc_selfpid_external_call_offsets": owner_calls,
            "get48_external_import_relocations": external_import_calls,
            "get48_loaded_relocation_simulation": "two nonzero signed rel32 destinations",
            "scan_manager_object_size": 176, **json.loads(run.stdout)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.provider)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"verify_legacy_provider_contracts: {error}\n")
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
