#!/usr/bin/env python3
"""Compare bounded code-4 projection with the pinned provider's pure TLV parser.

The only extracted executable code is a hash-checked, relocation-free 85-byte
parser. It is invoked in a separate x86_64 host process on bounded valid lists;
no kext is loaded, no driver entry point is called and no system file changes.
Malformed inputs are covered by the host unit suite, never by the old parser.
This demonstrates transport equivalence, not Wi-Fi or hardware behavior.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile
from verify_legacy_provider_contracts import (
    PROJECT, PROVIDER_SHA256, mapped_provider, assert_no_body_relocations,
)

PARSER_START = 0x582ea
PARSER_END = 0x5833f
PARSER_SHA256 = "2404ed11c94cc9ce178861e50cc29c5f3c906f32a0924c217b9fb76c8a381e0d"

HARNESS = r'''
#include "legacy_wifi_compat/event_contracts.hpp"
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
using Parser=uint32_t(*)(void*,uint32_t,void**,size_t*);
static void put32(uint8_t *p,uint32_t n){memcpy(p,&n,4);}
int main(int argc,char **argv){
 assert(argc==2);
 const rlimit limit{8,8};assert(setrlimit(RLIMIT_CPU,&limit)==0);
 std::ifstream f(argv[1],std::ios::binary);
 std::vector<uint8_t> body((std::istreambuf_iterator<char>(f)),{});assert(body.size()==85);
 const auto page=static_cast<size_t>(getpagesize());
 void *code=mmap(nullptr,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(code!=MAP_FAILED);memcpy(code,body.data(),body.size());
 assert(mprotect(code,page,PROT_READ|PROT_EXEC)==0);
 auto parse=reinterpret_cast<Parser>(code);
 uint32_t seed=0x17ab33;unsigned calls=0,selected=0;
 for(unsigned run=0;run<20000;++run){
  uint8_t input[2040]{};size_t offsets[32]{},lengths[32]{};uint32_t types[32]{};
  auto next=[&](){seed=seed*1664525U+1013904223U;return seed;};
  const unsigned count=next()%32;size_t size=0;
  for(unsigned k=0;k<count;++k){
   const uint32_t choices[]={4,13,14,99,0};types[k]=choices[next()%5];
   lengths[k]=next()%33;offsets[k]=size+8;
   put32(input+size,types[k]);put32(input+size+4,static_cast<uint32_t>(lengths[k]));
   for(size_t j=0;j<lengths[k];++j)input[size+8+j]=static_cast<uint8_t>(next()>>24);
   size+=8+lengths[k];assert(size<=sizeof(input));
  }
  uint8_t before[sizeof(input)];memcpy(before,input,sizeof(input));
  void *value=input;size_t n=size;bool found=false;
  for(uint32_t wanted:{4U,13U,14U}){
   size_t expectedIndex=count;
   for(size_t k=0;k<count;++k)if(types[k]==wanted){expectedIndex=k;break;}
   const auto result=parse(nullptr,wanted,&value,&n);++calls;
   if(expectedIndex<count){assert(result==0);assert(value==input+offsets[expectedIndex]);assert(n==lengths[expectedIndex]);found=true;break;}
   assert(result==0xe00002f0U);assert(value==input&&n==size);
  }
  LegacyWiFi::EventContracts::LinkEventProjection projection{};
  const bool projected=LegacyWiFi::EventContracts::projectLinkEventPayload(input,size,&projection);
  assert(projected==found);
  if(found){
   ++selected;
   assert(projection.payload==value&&projection.payloadSize==n);
  } else {
   assert(projection.payload==nullptr&&projection.payloadSize==0);
  }
  assert(!memcmp(input,before,sizeof(input)));
 }
 assert(munmap(code,page)==0);
 printf("{\"valid_lists\":20000,\"original_parser_calls\":%u,\"selected_lists\":%u,\"priority\":[4,13,14],\"same_type_rule\":\"first occurrence\",\"input_unchanged\":true,\"production_projection_matches\":true}\n",calls,selected);
}
'''


def verify(provider: Path) -> dict:
    if platform.system() != "Darwin" or platform.machine() != "x86_64":
        raise ValueError("pure parser replay requires an x86_64 macOS host")
    raw = provider.read_bytes()
    mapped = mapped_provider(raw)
    body = mapped[PARSER_START:PARSER_END]
    if hashlib.sha256(body).hexdigest() != PARSER_SHA256:
        raise ValueError("pure parser body changed")
    relocations = assert_no_body_relocations(raw, PARSER_START, PARSER_END, "event TLV parser")
    with tempfile.TemporaryDirectory(prefix="legacy-event-projection-", dir="/private/tmp") as tmp:
        directory = Path(tmp)
        source, binary, fixture = (directory / name for name in ("replay.cpp", "replay", "parser.bin"))
        source.write_text(HARNESS)
        fixture.write_bytes(body)
        subprocess.run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        "-I", str(PROJECT / "src"), str(source), "-o", str(binary)],
                       check=True, timeout=30)
        run = subprocess.run([str(binary), str(fixture)], check=True,
                             capture_output=True, text=True, timeout=15)
    return {"provider_sha256": PROVIDER_SHA256,
            "parser_sha256": PARSER_SHA256,
            "parser_range": [hex(PARSER_START), hex(PARSER_END)],
            "parser_relocations": relocations,
            "production_header_sha256": hashlib.sha256(
                (PROJECT / "src/legacy_wifi_compat/event_contracts.hpp").read_bytes()).hexdigest(),
            "scope": "isolated valid-list parser and production transport projection equivalence",
            "sanitizers": ["address", "undefined"],
            "binary_parser_instrumented": False,
            "hardware_validated": False,
            **json.loads(run.stdout)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.provider)
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"verify_legacy_event_projection: {error}\n")
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
