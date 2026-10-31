#!/usr/bin/env python3
"""Replay a pinned native network predicate against the normalized helper.

Only two bounded comparison functions are copied into an isolated host process.
Virtual getters are supplied by owned test identities; the SSID comparator's
single memcmp call is relocated to a local thunk. No driver entry, kext loading,
kernel memory access, cache deletion, or radio operation is involved.
This checks matching semantics, not identity decoding or runtime compatibility.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import platform
import subprocess
import tempfile

import verify_ifnet_kernel_contracts as kernel_reader
from verify_legacy_wifi_imports import _inner_member_layout

PROJECT = Path(__file__).resolve().parents[1]
KC_SHA256 = "96c12f421a8e99580b5015dfd39877df38ecde9b9e056b8ccd28f15847bca35c"
MEMBER = "com.apple.iokit.IO80211Family"
MATCH_ADDRESS = 0xffffff80022dc63e
MATCH_SIZE = 138
MATCH_SHA256 = "ab4f6fd23d169de3dbfa00cffec9cce4ef70de5574a64e5380501cc786ba8fac"
SSID_ADDRESS = 0xffffff80022dc256
SSID_SIZE = 42
SSID_SHA256 = "d4e905d701efcea0b38318676e244584c7a9649e4634e2470401ec58708cda6d"

HARNESS = r'''
#include "legacy_wifi_compat/network_match.hpp"
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
namespace N=LegacyWiFi::NetworkMatch;
struct Beacon {
    uintptr_t *vptr;
    uintptr_t unused;
    uint8_t *data;
    const N::Identity *identity;
};
static_assert(offsetof(Beacon,data)==0x10,"native comparison's data pointer");
static bool fils(Beacon *b){return b->identity->fils==N::FILS::Present;}
static uint16_t encryption(Beacon *b){return b->identity->encryptionModes;}
static uint16_t apMode(Beacon *b){return b->identity->apMode;}
using Predicate=bool(*)(Beacon*,const uint8_t*,uint8_t,uint16_t,uint16_t);
static uint32_t seed=0x1933a731U;
static uint32_t next(){seed=seed*1664525U+1013904223U;return seed;}
int main(int argc,char **argv){
    assert(argc==2);
    const rlimit limit{8,8};assert(setrlimit(RLIMIT_CPU,&limit)==0);
    std::ifstream input(argv[1],std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),{});
    assert(bytes.size()==138+42);
    const auto page=static_cast<size_t>(getpagesize());assert(page>=1024);
    auto *code=static_cast<uint8_t*>(mmap(nullptr,page,PROT_READ|PROT_WRITE,
                                         MAP_PRIVATE|MAP_ANON,-1,0));
    assert(code!=MAP_FAILED);
    memcpy(code,bytes.data(),138);memcpy(code+256,bytes.data()+138,42);
    // Original SSID comparator calls memcmp at instruction offset26. Keep
    // its exact decision logic, replacing only that rel32 destination.
    assert(code[256+26]==0xe8);
    const int32_t displacement=512-(256+26+5);
    memcpy(code+256+27,&displacement,sizeof(displacement));
    const uint8_t thunk[]={0x48,0xb8,0,0,0,0,0,0,0,0,0xff,0xe0};
    memcpy(code+512,thunk,sizeof(thunk));
    const uintptr_t compare=reinterpret_cast<uintptr_t>(&memcmp);
    memcpy(code+514,&compare,sizeof(compare));
    assert(mprotect(code,page,PROT_READ|PROT_EXEC)==0);
    const auto native=reinterpret_cast<Predicate>(code);
    uintptr_t table[0x3e0/sizeof(uintptr_t)]{};
    table[0x3d8/8]=reinterpret_cast<uintptr_t>(&fils);
    table[0x2b8/8]=reinterpret_cast<uintptr_t>(&encryption);
    table[0x2c8/8]=reinterpret_cast<uintptr_t>(&apMode);
    table[0x248/8]=reinterpret_cast<uintptr_t>(code+256);
    unsigned cases=0,positive=0;
    auto check=[&](const N::Identity &candidate,const N::Identity &reference){
        assert(N::valid(candidate)&&N::valid(reference));
        assert(candidate.fils!=N::FILS::Unknown);
        uint8_t data[0x300]{};
        memcpy(data+0x218,candidate.ssid,candidate.ssidLength);
        data[0x239]=candidate.ssidLength;
        uint8_t before[sizeof(data)];memcpy(before,data,sizeof(data));
        Beacon beacon{table,0,data,&candidate};
        const bool observed=native(&beacon,reference.ssid,reference.ssidLength,
                                   reference.encryptionModes,reference.apMode);
        bool actual=false;assert(N::matches(&candidate,&reference,&actual)==0);
        assert(actual==observed);assert(!memcmp(before,data,sizeof(data)));
        ++cases;if(actual)++positive;
    };
    N::Identity a{},b{};
    for(unsigned left=0;left<16;++left)for(unsigned right=0;right<16;++right)
    for(unsigned cm=0;cm<4;++cm)for(unsigned rm=0;rm<4;++rm)
    for(unsigned f=0;f<2;++f){
        a.encryptionModes=static_cast<uint16_t>(1U<<left);
        b.encryptionModes=static_cast<uint16_t>(1U<<right);
        a.apMode=cm;b.apMode=rm;a.fils=f?N::FILS::Present:N::FILS::Absent;check(a,b);
    }
    for(unsigned run=0;run<4096;++run){
        a={};a.fils=N::FILS::Absent;a.ssidLength=next()%33;a.encryptionModes=next()>>16;
        a.apMode=next()%4;
        for(unsigned i=0;i<32;++i)a.ssid[i]=next()>>24;
        b=a;check(a,b);
        b.apMode=3;check(a,b);
        b.encryptionModes=static_cast<uint16_t>(~a.encryptionModes);check(a,b);
        b=a;b.encryptionModes=0;check(a,b);
        b=a;b.ssidLength=(b.ssidLength+1)%33;check(a,b);
        b=a;
        if(b.ssidLength)b.ssid[next()%b.ssidLength]^=0x80;
        else b.ssid[0]^=0x80;
        check(a,b);
        b=a;b.fils=N::FILS::Present;check(a,b);
        a.fils=N::FILS::Present;check(a,b);
    }
    // Explicit binary SSIDs, including an embedded zero before a mismatch.
    a={};b={};a.fils=N::FILS::Absent;a.encryptionModes=b.encryptionModes=0xffff;
    a.ssidLength=b.ssidLength=32;a.ssid[31]=1;b.ssid[31]=2;check(a,b);
    b.ssid[31]=1;check(a,b);a.encryptionModes=0;check(a,b);
    assert(munmap(code,page)==0);
    printf("{\"comparisons\":%u,\"matching_cases\":%u,\"production_matches_native\":true,\"input_unchanged\":true}\n",cases,positive);
}
'''


def extract(path: Path) -> tuple[bytes, bytes]:
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if hashlib.sha256(data).hexdigest() != KC_SHA256:
            raise ValueError("expected the explicitly pinned native kernel-collection input")
        outer = kernel_reader.parse_header(data, 0, str(path))
        if outer["filetype"] != kernel_reader.MH_FILESET:
            raise ValueError("expected MH_FILESET input")
        entries = [kernel_reader.parse_fileset_entry(raw)
                   for command, raw, _ in outer["commands"]
                   if command == kernel_reader.LC_FILESET_ENTRY]
        matches = [entry for entry in entries if entry["id"] == MEMBER]
        if len(matches) != 1:
            raise ValueError("native Family member is missing or ambiguous")
        member = _inner_member_layout(data, matches[0], MEMBER)
        body = kernel_reader.read_vm_range(data, member, MATCH_ADDRESS, MATCH_SIZE,
                                           True, "network predicate")
        ssid = kernel_reader.read_vm_range(data, member, SSID_ADDRESS, SSID_SIZE,
                                           True, "SSID comparator")
    if hashlib.sha256(body).hexdigest() != MATCH_SHA256:
        raise ValueError("network predicate body differs")
    if hashlib.sha256(ssid).hexdigest() != SSID_SHA256:
        raise ValueError("SSID comparator body differs")
    # The pinned instruction's only direct external call is replaced locally.
    if ssid[26:31] != bytes.fromhex("e8fb81e2fd"):
        raise ValueError("SSID comparator memcmp call differs")
    return body, ssid


def verify(path: Path) -> dict:
    if platform.system() != "Darwin" or platform.machine() != "x86_64":
        raise ValueError("isolated predicate replay requires an x86_64 macOS host")
    body, ssid = extract(path)
    with tempfile.TemporaryDirectory(prefix="native-network-match-", dir="/private/tmp") as tmp:
        directory = Path(tmp)
        source, binary, fixture = (directory / name for name in ("replay.cpp", "replay", "code.bin"))
        source.write_text(HARNESS)
        fixture.write_bytes(body + ssid)
        subprocess.run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        "-I", str(PROJECT / "src"), str(source), "-o", str(binary)],
                       check=True, timeout=30)
        run = subprocess.run([str(binary), str(fixture)], check=True,
                             capture_output=True, text=True, timeout=15)
    return {"kernel_collection_sha256": KC_SHA256, "member": MEMBER,
            "predicate": {"address": hex(MATCH_ADDRESS), "size": MATCH_SIZE, "sha256": MATCH_SHA256},
            "ssid_comparator": {"address": hex(SSID_ADDRESS), "size": SSID_SIZE, "sha256": SSID_SHA256,
                                "relocation": "Only memcmp rel32 redirected through a host thunk"},
            "virtual_getters": "Owned normalized candidate FILS flag, encryption mask, and AP mode",
            "production_header_sha256": hashlib.sha256(
                (PROJECT / "src/legacy_wifi_compat/network_match.hpp").read_bytes()).hexdigest(),
            "scope": "Normalized network identity predicate; not identity decoding or cache mutation",
            "sanitizers": ["address", "undefined"], "binary_functions_instrumented": False,
            "kernel_functions_invoked_in_kernel": False, "hardware_validated": False,
            **json.loads(run.stdout)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-collection", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.kernel_collection)
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"verify_network_match: {error}\n")
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
