#!/usr/bin/env python3
"""Offline verifier for production ifnet_ioctl contracts in BootKernelCollections.

The tool reads only BootKC files explicitly named with --kernel-collection,
compiles the production contract headers into a temporary host harness, and
never loads kernel code. Any --output JSON is written only to the requested
path. Results demonstrate byte-contract acceptance, not booted-kernel support.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import Any


PROJECT = Path(__file__).resolve().parents[1]
CONTRACT_HEADER = PROJECT / "src/scan_kernel/kernel_contracts.hpp"
PROFILE_HEADER = PROJECT / "src/scan_kernel/ifnet_profiles.hpp"
CPU_TYPE_X86_64 = 0x01000007
MH_EXECUTE = 2
MH_FILESET = 0xC
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_SYMTAB = 0x2
LC_FILESET_ENTRY = 0x80000035
N_STAB = 0xE0
N_TYPE = 0x0E
N_UNDF = 0x00
VM_PROT_READ = 1
VM_PROT_EXECUTE = 4
EXPECTED_BODY_BY_PROFILE = {
    "mutex-inline": 0x340,
    "mutex-monitor": 0x2D0,
    "25G-current": 0x390,
}


class VerificationError(RuntimeError):
    pass


def checked_slice(data: mmap.mmap, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise VerificationError(f"{label}: out-of-file span {offset:#x}+{size:#x}")
    return data[offset:offset + size]


def decode_name(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", errors="strict")


def parse_header(data: mmap.mmap, offset: int, label: str) -> dict[str, Any]:
    raw = checked_slice(data, offset, 32, f"{label} Mach-O header")
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = \
        struct.unpack("<IiiIIIII", raw)
    if magic != 0xFEEDFACF:
        raise VerificationError(f"{label}: expected little-endian MH_MAGIC_64 at {offset:#x}")
    if cputype != CPU_TYPE_X86_64:
        raise VerificationError(f"{label}: not x86_64 (cputype {cputype:#x})")
    if ncmds > 1_000_000 or sizeofcmds > 256 * 1024 * 1024:
        raise VerificationError(f"{label}: unreasonable load-command bounds")
    command_start = offset + 32
    command_end = command_start + sizeofcmds
    if command_end < command_start or command_end > len(data):
        raise VerificationError(f"{label}: load commands exceed file")
    commands: list[tuple[int, bytes, int]] = []
    cursor = command_start
    for index in range(ncmds):
        if cursor > command_end or command_end - cursor < 8:
            raise VerificationError(f"{label}: truncated load command {index}")
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmdsize < 8 or cmdsize % 8 or cmdsize > command_end - cursor:
            raise VerificationError(f"{label}: invalid load-command size at {cursor:#x}")
        commands.append((cmd, bytes(data[cursor:cursor + cmdsize]), cursor))
        cursor += cmdsize
    if cursor != command_end:
        raise VerificationError(f"{label}: ncmds/sizeofcmds mismatch")
    return {
        "header_offset": offset,
        "cputype": cputype,
        "cpusubtype": cpusubtype,
        "filetype": filetype,
        "ncmds": ncmds,
        "sizeofcmds": sizeofcmds,
        "flags": flags,
        "reserved": reserved,
        "commands": commands,
    }


def parse_segment(command: bytes, source: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if len(command) < 72:
        raise VerificationError(f"{source}: truncated LC_SEGMENT_64")
    segname = decode_name(command[8:24])
    vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", command, 24)
    maxprot, initprot, nsects, flags = struct.unpack_from("<iiII", command, 56)
    if nsects > 1_000_000 or 72 + nsects * 80 != len(command):
        raise VerificationError(f"{source}: invalid sections in {segname}")
    if vmaddr + vmsize > 0xFFFFFFFFFFFFFFFF or fileoff + filesize > 0xFFFFFFFFFFFFFFFF:
        raise VerificationError(f"{source}: overflowing segment {segname}")
    segment = {
        "name": segname,
        "vmaddr": vmaddr,
        "vmsize": vmsize,
        "fileoff": fileoff,
        "filesize": filesize,
        "initprot": initprot,
        "maxprot": maxprot,
        "flags": flags,
    }
    sections: list[dict[str, Any]] = []
    for index in range(nsects):
        offset = 72 + index * 80
        sectname = decode_name(command[offset:offset + 16])
        section_segname = decode_name(command[offset + 16:offset + 32])
        addr, size = struct.unpack_from("<QQ", command, offset + 32)
        file_offset, align, reloff, nreloc, sectflags, reserved1, reserved2, reserved3 = \
            struct.unpack_from("<IIIIIIII", command, offset + 48)
        if section_segname != segname:
            raise VerificationError(f"{source}: section segment mismatch for {sectname}")
        if addr + size > 0xFFFFFFFFFFFFFFFF:
            raise VerificationError(f"{source}: overflowing section {segname},{sectname}")
        sections.append({
            "segment": segname,
            "name": sectname,
            "addr": addr,
            "size": size,
            "fileoff": file_offset,
            "align": align,
            "reloff": reloff,
            "nreloc": nreloc,
            "flags": sectflags,
            "reserved1": reserved1,
            "reserved2": reserved2,
            "reserved3": reserved3,
        })
    return segment, sections


def parse_fileset_entry(command: bytes) -> dict[str, Any]:
    if len(command) < 32:
        raise VerificationError("truncated LC_FILESET_ENTRY")
    vmaddr, fileoff = struct.unpack_from("<QQ", command, 8)
    entry_id_offset, reserved = struct.unpack_from("<II", command, 24)
    if entry_id_offset < 32 or entry_id_offset >= len(command):
        raise VerificationError("invalid LC_FILESET_ENTRY entry_id offset")
    end = command.find(b"\0", entry_id_offset)
    if end < 0:
        raise VerificationError("unterminated LC_FILESET_ENTRY entry_id")
    try:
        entry_id = command[entry_id_offset:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise VerificationError("non-ASCII LC_FILESET_ENTRY identifier") from exc
    return {"id": entry_id, "vmaddr": vmaddr, "fileoff": fileoff, "reserved": reserved}


def parse_inner_image(data: mmap.mmap, header_offset: int, label: str) -> dict[str, Any]:
    parsed = parse_header(data, header_offset, label)
    if parsed["filetype"] != MH_EXECUTE:
        raise VerificationError(f"{label}: fileset member is not MH_EXECUTE")
    segments: list[dict[str, Any]] = []
    sections: list[dict[str, Any]] = []
    uuid: bytes | None = None
    symtab: dict[str, int] | None = None
    for cmd, raw, _ in parsed["commands"]:
        if cmd == LC_SEGMENT_64:
            segment, segment_sections = parse_segment(raw, label)
            if segment["fileoff"] + segment["filesize"] > len(data):
                raise VerificationError(f"{label}: segment {segment['name']} exceeds container")
            segments.append(segment)
            sections.extend(segment_sections)
        elif cmd == LC_UUID:
            if len(raw) != 24 or uuid is not None:
                raise VerificationError(f"{label}: invalid/duplicate LC_UUID")
            uuid = raw[8:24]
        elif cmd == LC_SYMTAB:
            if len(raw) != 24 or symtab is not None:
                raise VerificationError(f"{label}: invalid/duplicate LC_SYMTAB")
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", raw, 8)
            if nsyms > 20_000_000 or strsize > 512 * 1024 * 1024:
                raise VerificationError(f"{label}: unreasonable symbol table bounds")
            symtab = {"symoff": symoff, "nsyms": nsyms, "stroff": stroff, "strsize": strsize}
    if uuid is None or symtab is None:
        raise VerificationError(f"{label}: missing LC_UUID or LC_SYMTAB")
    if not segments:
        raise VerificationError(f"{label}: missing LC_SEGMENT_64")
    return {
        **{key: parsed[key] for key in ("header_offset", "ncmds", "sizeofcmds")},
        "uuid_bytes": uuid,
        "uuid": str(uuid.hex()),
        "segments": segments,
        "sections": sections,
        "symtab": symtab,
    }


def parse_bootkc(data: mmap.mmap, label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    outer = parse_header(data, 0, f"{label} outer")
    if outer["filetype"] != MH_FILESET:
        raise VerificationError(f"{label}: expected MH_FILESET BootKC")
    outer_uuid: bytes | None = None
    entries = []
    for cmd, raw, _ in outer["commands"]:
        if cmd == LC_UUID:
            if len(raw) != 24 or outer_uuid is not None:
                raise VerificationError(f"{label}: invalid/duplicate outer LC_UUID")
            outer_uuid = raw[8:24]
        elif cmd == LC_FILESET_ENTRY:
            entries.append(parse_fileset_entry(raw))
    if outer_uuid is None:
        raise VerificationError(f"{label}: outer BootKC lacks LC_UUID")
    matches = [entry for entry in entries if entry["id"] == "com.apple.kernel"]
    if len(matches) != 1:
        raise VerificationError(f"{label}: expected one com.apple.kernel fileset entry, found {len(matches)}")
    entry = matches[0]
    inner = parse_inner_image(data, entry["fileoff"], f"{label} com.apple.kernel")
    # Symbol parsing happens after the LC_FILESET_ENTRY is attached to the
    # inner image, so the absolute-vs-inner-relative LC_SYMTAB choice can be
    # scored against the actual member vmaddr.
    outer_obj = {
        "uuid": outer_uuid.hex(),
        "cputype": outer["cputype"],
        "ncmds": outer["ncmds"],
        "sizeofcmds": outer["sizeofcmds"],
        "fileset_entry_count": len(entries),
        "kernel_entry": entry,
    }
    return outer_obj, inner


def parse_symbols(data: mmap.mmap, image: dict[str, Any], wanted: set[str], label: str) \
        -> tuple[dict[str, int], dict[str, Any]]:
    symtab = image["symtab"]
    nlist_size = 16
    table_size = symtab["nsyms"] * nlist_size
    candidates: list[tuple[str, int, int]] = []
    for name, adjustment in (("container-absolute", 0), ("inner-relative", image["header_offset"])):
        candidates.append((name, symtab["symoff"] + adjustment, symtab["stroff"] + adjustment))
    best_symbols: dict[str, int] | None = None
    best_origin: dict[str, Any] | None = None
    best_score = -1
    candidate_errors = []
    for origin, nlist_offset, string_offset in candidates:
        try:
            checked_slice(data, nlist_offset, table_size, f"{label} nlist table ({origin})")
            strings = checked_slice(data, string_offset, symtab["strsize"],
                                    f"{label} string table ({origin})")
        except VerificationError as exc:
            candidate_errors.append(str(exc))
            continue
        found: dict[str, set[int]] = {}
        for index in range(symtab["nsyms"]):
            strx, n_type, n_sect, n_desc, value = struct.unpack_from(
                "<IBBHQ", data, nlist_offset + index * nlist_size)
            if (n_type & N_STAB) or (n_type & N_TYPE) == N_UNDF or not strx or strx >= len(strings):
                continue
            end = strings.find(b"\0", strx)
            if end < 0:
                continue
            try:
                name = strings[strx:end].decode("ascii")
            except UnicodeDecodeError:
                continue
            if name in wanted:
                found.setdefault(name, set()).add(value)
        if any(len(values) != 1 for values in found.values()):
            ambiguous = sorted(name for name, values in found.items() if len(values) != 1)
            candidate_errors.append(f"{origin} has ambiguous values for {ambiguous[:8]}")
            continue
        result = {name: next(iter(values)) for name, values in found.items()}
        score = len(result)
        if "_ifnet_ioctl" in result:
            score += 10_000
        if "__mh_execute_header" in result and result["__mh_execute_header"] == image.get("fileset_entry", {}).get("vmaddr"):
            score += 1_000
        if score > best_score:
            best_score = score
            best_symbols = result
            best_origin = {
                "offset_mode": origin,
                "nlist_offset": nlist_offset,
                "string_offset": string_offset,
                "nlist_count": symtab["nsyms"],
                "string_size": symtab["strsize"],
                "matched_wanted_symbols": len(result),
            }
    if best_symbols is None:
        raise VerificationError(f"{label}: cannot parse LC_SYMTAB; " + "; ".join(candidate_errors))
    if best_origin is None:
        raise VerificationError(f"{label}: symtab address mode unresolved")
    return best_symbols, best_origin


def collect_header_symbol_names() -> set[str]:
    text = CONTRACT_HEADER.read_text() + "\n" + PROFILE_HEADER.read_text()
    return set(re.findall(r'"(_[A-Za-z0-9_]+)"', text)) | {
        "_ifnet_ioctl", "__mh_execute_header"
    }


def extract_function(data: mmap.mmap, image: dict[str, Any], symbols: dict[str, int],
                     body_size: int, label: str) -> tuple[bytes, dict[str, Any]]:
    address = symbols["_ifnet_ioctl"]
    sections = [section for section in image["sections"] if section["name"] == "__text"]
    matches = [section for section in sections
               if address >= section["addr"] and address - section["addr"] <= section["size"]
               and body_size <= section["size"] - (address - section["addr"])]
    if len(matches) != 1:
        raise VerificationError(f"{label}: `_ifnet_ioctl` not uniquely inside a __text section")
    section = matches[0]
    segments = [segment for segment in image["segments"] if segment["name"] == section["segment"]]
    if len(segments) != 1:
        raise VerificationError(f"{label}: __text section has no unique segment")
    segment = segments[0]
    if not (segment["initprot"] & VM_PROT_READ and segment["initprot"] & VM_PROT_EXECUTE and
            segment["maxprot"] & VM_PROT_READ and segment["maxprot"] & VM_PROT_EXECUTE):
        raise VerificationError(f"{label}: __text segment is not readable and executable")
    delta = address - section["addr"]
    expected_fileoff = segment["fileoff"] + (section["addr"] - segment["vmaddr"])
    if section["fileoff"] != expected_fileoff:
        raise VerificationError(f"{label}: section offset disagrees with containing segment mapping")
    function_fileoff = section["fileoff"] + delta
    if function_fileoff < segment["fileoff"] or function_fileoff - segment["fileoff"] > segment["filesize"]:
        raise VerificationError(f"{label}: function file offset lies outside __text file-backed range")
    if body_size > segment["filesize"] - (function_fileoff - segment["fileoff"]):
        raise VerificationError(f"{label}: function body extends beyond __text file-backed bytes")
    body = checked_slice(data, function_fileoff, body_size, f"{label} _ifnet_ioctl body")
    metadata = {
        "symbol_va": address,
        "body_size": body_size,
        "section": {
            "segment": section["segment"],
            "name": section["name"],
            "addr": section["addr"],
            "size": section["size"],
            "fileoff": section["fileoff"],
        },
        "text_segment": {
            "name": segment["name"],
            "vmaddr": segment["vmaddr"],
            "vmsize": segment["vmsize"],
            "fileoff": segment["fileoff"],
            "filesize": segment["filesize"],
            "initprot": segment["initprot"],
            "maxprot": segment["maxprot"],
        },
        "function_fileoff": function_fileoff,
    }
    return body, metadata


def c_string(value: str) -> str:
    # Symbol names and sample labels are ASCII. json.dumps produces a C-safe
    # quoted string for this subset and avoids shell/code injection.
    return json.dumps(value, ensure_ascii=True)


def cpp_bytes(name: str, value: bytes) -> str:
    rows = []
    for start in range(0, len(value), 16):
        rows.append(",".join(f"0x{x:02x}" for x in value[start:start + 16]))
    return f"static const uint8_t {name}[] = {{{','.join(rows)}}};"


def cpp_symbols(symbols: dict[str, int]) -> str:
    items = sorted(symbols.items())
    if not items:
        raise VerificationError("no relocation symbols available for C++ resolver")
    rows = ",\n".join(f"{{{c_string(name)}, UINT64_C(0x{value:x})}}" for name, value in items)
    return f"static const SymbolRecord Symbols[] = {{{rows}}};\nstatic constexpr size_t SymbolCount=sizeof(Symbols)/sizeof(Symbols[0]);"


def cpp_segments(segments: list[dict[str, Any]]) -> str:
    rows = []
    for segment in segments:
        rows.append("{%s,UINT64_C(0x%x),UINT64_C(0x%x),%d,%d}" % (
            c_string(segment["name"]), segment["vmaddr"], segment["vmsize"],
            segment["initprot"], segment["maxprot"]))
    return "static const SegmentRecord Segments[] = {" + ",".join(rows) + "};\n" + \
        "static constexpr size_t SegmentCount=sizeof(Segments)/sizeof(Segments[0]);"


def build_harness(samples: list[dict[str, Any]], symbols: dict[str, int],
                  segments: list[dict[str, Any]]) -> str:
    declarations = [
        "#include <cstddef>", "#include <cstdint>", "#include <cstdio>",
        "#include <cstring>", "#include <vector>", "#include <string>",
        f'#include "{CONTRACT_HEADER}"', f'#include "{PROFILE_HEADER}"',
        "using namespace KernelContracts;",
        "struct SymbolRecord {const char *name; uint64_t value;};",
        "struct SegmentRecord {const char *name; uint64_t vmaddr,vmsize; int32_t initprot,maxprot;};",
        cpp_symbols(symbols), cpp_segments(segments),
    ]
    sample_rows = []
    for index, sample in enumerate(samples):
        declarations.append(cpp_bytes(f"Body_{index}", sample["body"]))
        sample_rows.append("{%s,%s,Body_%d,sizeof(Body_%d),UINT64_C(0x%x),%d}" % (
            c_string(sample["label"]), c_string(sample["profile"]), index, index,
            sample["function_va"], sample["descriptor_index"] if sample["descriptor_index"] is not None else 255))
    declarations.append("struct Sample {const char *label,*profile;const uint8_t *bytes;size_t size;uintptr_t functionVA;uint8_t descriptor;};")
    declarations.append("static const Sample Samples[] = {" + ",".join(sample_rows) + "};")
    harness = r'''
static const SymbolRecord *findSymbol(const char *name) {
    for(size_t i=0;i<SymbolCount;i++) if(!strcmp(Symbols[i].name,name)) return &Symbols[i];
    return nullptr;
}
static const SegmentRecord *findSegment(uintptr_t address,uintptr_t slide,
                                        RelocationKind kind) {
    if(address<slide) return nullptr;
    const uintptr_t unslid=address-slide;
    const int needed=kind==RelocationKind::RelativeCall?4:1;
    for(size_t i=0;i<SegmentCount;i++) {
        const auto &s=Segments[i];
        if(!s.vmsize || unslid<s.vmaddr || unslid-s.vmaddr>=s.vmsize) continue;
        if((s.initprot&needed)==needed && (s.maxprot&needed)==needed) return &s;
    }
    return nullptr;
}
static bool mappedValidator(RelocationKind kind,uintptr_t target,void *context) {
    const uintptr_t slide=*static_cast<uintptr_t *>(context);
    return findSegment(target,slide,kind)!=nullptr;
}
static const char *statusName(Status status) {
    switch(status) {
        case Status::Passed:return "Passed";
        case Status::InvalidInput:return "InvalidInput";
        case Status::Truncated:return "Truncated";
        case Status::InvalidRelocation:return "InvalidRelocation";
        case Status::RelocationTargetMismatch:return "RelocationTargetMismatch";
        case Status::SemanticMismatch:return "SemanticMismatch";
        case Status::FingerprintMismatch:return "FingerprintMismatch";
    }
    return "Unknown";
}
static bool addSignedAddress(uintptr_t base,intptr_t addend,uintptr_t &out) {
    if(addend>=0) {auto amount=static_cast<uintptr_t>(addend);if(base>UINTPTR_MAX-amount)return false;out=base+amount;}
    else {auto amount=static_cast<uintptr_t>(-(addend+1))+1U;if(base<amount)return false;out=base-amount;}
    return true;
}
static bool buildRelocations(const RelocationSpec *specs,size_t count,uintptr_t slide,
                             Relocation *out,std::vector<std::string> &resolved) {
    if(!specs||!out||!count||count>IfnetProfiles::MaxRelocations)return false;
    for(size_t i=0;i<count;i++) {
        const auto &spec=specs[i];if(!spec.symbol)return false;
        const SymbolRecord *symbol=findSymbol(spec.symbol);
        const char *chosen=spec.symbol;
        if(!symbol&&spec.alias){symbol=findSymbol(spec.alias);chosen=spec.alias;}
        if(!symbol || symbol->value>UINTPTR_MAX-slide)return false;
        uintptr_t target=0;
        if(!addSignedAddress(static_cast<uintptr_t>(symbol->value)+slide,spec.addend,target))return false;
        if(!findSegment(target,slide,spec.kind))return false;
        out[i]={spec.instructionOffset,spec.displacementOffset,spec.instructionEndOffset,
                target,spec.kind};
        char line[256];
        snprintf(line,sizeof(line),"%zu:%s:0x%llx",i,chosen,
                 static_cast<unsigned long long>(target));
        resolved.emplace_back(line);
    }
    return true;
}
'''
    # Keep the C++ harness's JSON printing simple and quote-free for the fixed
    # Mach-O symbol names. The chosen values contain only ASCII word chars.
    harness += r'''
static Status runValidation(const Sample &sample,const uint8_t *bytes,size_t size,
                            uintptr_t base,const Relocation *relocs,size_t count,
                            IfnetIoctlPlan &plan) {
    if(sample.descriptor==255)
        return KernelContracts::validateIfnetCurrent(bytes,size,base,relocs,count,plan);
    return IfnetProfiles::validate(IfnetProfiles::Additional[sample.descriptor],
                                   bytes,size,base,relocs,count,plan);
}
static Status runMapped(const Sample &sample,const uint8_t *bytes,size_t size,
                        uintptr_t base,uintptr_t slide) {
    if(sample.descriptor==255)
        return KernelContracts::validateIfnetMappedTargets(bytes,size,base,mappedValidator,&slide);
    return IfnetProfiles::validateMapped(IfnetProfiles::Additional[sample.descriptor],
                                         bytes,size,base,mappedValidator,&slide);
}
static const RelocationSpec *specsFor(const Sample &sample,size_t &count) {
    if(sample.descriptor==255){count=IfnetRelocationCount;return IfnetRelocationSpecs;}
    const auto &d=IfnetProfiles::Additional[sample.descriptor];count=d.relocationCount;return d.relocations;
}
static const RelocationSpec *mappedFor(const Sample &sample,size_t &count) {
    if(sample.descriptor==255){count=IfnetMappedTargetCount;return IfnetMappedTargetSpecs;}
    const auto &d=IfnetProfiles::Additional[sample.descriptor];count=d.mappedCount;return d.mapped;
}
static uintptr_t returnOffsetFor(const Sample &sample) {
    if(sample.descriptor==255)return 0x211;
    return IfnetProfiles::Additional[sample.descriptor].returnOffset;
}
static void printResolved(const std::vector<std::string> &resolved) {
    putchar('[');
    for(size_t i=0;i<resolved.size();i++) {if(i)putchar(',');printf("\"%s\"",resolved[i].c_str());}
    putchar(']');
}
static bool zeroPlan(const IfnetIoctlPlan &plan) {
    return plan.imageBase==0&&plan.callbackReturnPC==0&&plan.imageSpan==0&&plan.proofTag==0;
}
static int fail(const Sample &sample,const char *what) {
    fprintf(stderr,"%s: %s\n",sample.label,what);return 1;
}
static int probeResult(const Sample &sample,const char *status,uintptr_t returnPC=0) {
    printf("{\"sample\":\"%s\",\"profile\":\"%s\",\"status\":\"%s\",\"body_size\":%zu,\"callback_return_pc\":\"0x%llx\"}\n",
           sample.label,sample.profile,status,sample.size,
           static_cast<unsigned long long>(returnPC));
    return 0;
}
int main(int argc,char **argv) {
    const bool probeOnly=argc==2&&strcmp(argv[1],"--probe")==0;
    uintptr_t initialSlide=0;
    for(const auto &sample:Samples) {
        size_t count=0;const auto *specs=specsFor(sample,count);
        if(!count||count>IfnetProfiles::MaxRelocations) {
            if(probeOnly)return probeResult(sample,"InvalidRelocationCount");
            return fail(sample,"unexpected relocation count");
        }
        Relocation relocs[IfnetProfiles::MaxRelocations]{};
        std::vector<std::string> resolved;
        if(!buildRelocations(specs,count,initialSlide,relocs,resolved)) {
            if(probeOnly)return probeResult(sample,"SymbolResolutionOrRangeFailed");
            return fail(sample,"LC_SYMTAB symbol/alias resolution or mapped-target validation failed");
        }
        const uintptr_t base=sample.functionVA;
        IfnetIoctlPlan plan{};
        Status result=runValidation(sample,sample.bytes,sample.size,base,relocs,count,plan);
        if(result!=Status::Passed) {
            if(probeOnly)return probeResult(sample,statusName(result));
            {fprintf(stderr,"%s: production validation returned %s\n",sample.label,statusName(result));return 1;}
        }
        result=runMapped(sample,sample.bytes,sample.size,base,initialSlide);
        if(result!=Status::Passed) {
            if(probeOnly)return probeResult(sample,statusName(result));
            {fprintf(stderr,"%s: mapped-target validation returned %s\n",sample.label,statusName(result));return 1;}
        }
        if(plan.callbackReturnPC!=base+returnOffsetFor(sample)||!KernelContracts::IfnetProfiles::knownPlan(plan)) {
            if(probeOnly)return probeResult(sample,"PlanMismatch");
            return fail(sample,"callback return-PC or plan proof mismatch");
        }
        if(probeOnly)return probeResult(sample,"Passed",plan.callbackReturnPC);

        // Every byte of the complete function body must be admission-critical.
        // Displacements of named relocations remain protected by resolved
        // target checks; all other bytes remain in the full-body digest.
        size_t rejected=0;
        std::vector<uint8_t> mutant(sample.bytes,sample.bytes+sample.size);
        for(size_t offset=0;offset<sample.size;offset++) {
            mutant[offset]^=0x01;
            IfnetIoctlPlan mutantPlan{};
            const Status mutantStatus=runValidation(sample,mutant.data(),mutant.size(),base,
                                                     relocs,count,mutantPlan);
            if(mutantStatus==Status::Passed || !zeroPlan(mutantPlan)) {
                fprintf(stderr,"%s: accepted byte mutation at %zu (%s)\n",sample.label,offset,
                        statusName(mutantStatus));return 1;
            }
            ++rejected;
            mutant[offset]^=0x01;
        }
        if(rejected!=sample.size)return fail(sample,"not every byte mutation was tested");

        size_t badTargets=0;
        for(size_t index=0;index<count;index++) {
            Relocation wrong[IfnetProfiles::MaxRelocations]{};
            memcpy(wrong,relocs,count*sizeof(Relocation));
            wrong[index].target^=1U;
            IfnetIoctlPlan wrongPlan{};
            const Status wrongStatus=runValidation(sample,sample.bytes,sample.size,base,
                                                    wrong,count,wrongPlan);
            if(wrongStatus==Status::Passed || !zeroPlan(wrongPlan)) {
                fprintf(stderr,"%s: accepted wrong resolved target at relocation %zu\n",sample.label,index);
                return 1;
            }
            ++badTargets;
        }

        // Translating all code and resolved symbol addresses by the same slide
        // must preserve PC-relative code contracts and move the typed return PC.
        const uintptr_t aslrSlide=static_cast<uintptr_t>(UINT64_C(0x40000000));
        if(sample.functionVA>UINTPTR_MAX-aslrSlide)return fail(sample,"ASLR base overflow");
        Relocation slid[IfnetProfiles::MaxRelocations]{};
        std::vector<std::string> slidResolved;
        if(!buildRelocations(specs,count,aslrSlide,slid,slidResolved))
            return fail(sample,"ASLR relocation resolution failed");
        IfnetIoctlPlan slidPlan{};
        const uintptr_t slidBase=base+aslrSlide;
        Status slidStatus=runValidation(sample,sample.bytes,sample.size,slidBase,slid,count,slidPlan);
        if(slidStatus!=Status::Passed || slidPlan.callbackReturnPC!=slidBase+returnOffsetFor(sample))
            return fail(sample,"ASLR-translated validation did not pass with translated return PC");
        slidStatus=runMapped(sample,sample.bytes,sample.size,slidBase,aslrSlide);
        if(slidStatus!=Status::Passed)return fail(sample,"ASLR-translated mapped targets did not pass");

        size_t mappedCount=0;const auto *mapped=mappedFor(sample,mappedCount);
        std::vector<std::string> mappedTargets;
        for(size_t index=0;index<mappedCount;index++) {
            uintptr_t target=0;
            const Status targetStatus=KernelContracts::relativeTargetAt(
                sample.bytes,sample.size,base,mapped[index],target);
            if(targetStatus!=Status::Passed)return fail(sample,"invalid anonymous mapped target instruction");
            const auto *segment=findSegment(target,initialSlide,mapped[index].kind);
            if(!segment)return fail(sample,"anonymous target outside mapped segment permissions");
            char line[256];
            snprintf(line,sizeof(line),"%zu:%s:0x%llx:%s",index,
                     mapped[index].kind==RelocationKind::RelativeCall?"RelativeCall":"RipRelative",
                     static_cast<unsigned long long>(target),segment->name);
            mappedTargets.emplace_back(line);
        }
        if(!mappedCount || !badTargets)return fail(sample,"missing mapped or wrong-target checks");

        printf("{\"sample\":\"%s\",\"profile\":\"%s\",\"status\":\"Passed\","
               "\"function_va\":\"0x%llx\",\"body_size\":%zu,"
               "\"callback_return_pc\":\"0x%llx\",\"callback_offset\":\"0x%zx\","
               "\"byte_mutations\":%zu,\"mutations_rejected\":%zu,"
               "\"wrong_targets_tested\":%zu,\"aslr_slide\":\"0x%llx\","
               "\"aslr_callback_return_pc\":\"0x%llx\","
               "\"resolved_relocations\":",
               sample.label,sample.profile,static_cast<unsigned long long>(base),sample.size,
               static_cast<unsigned long long>(plan.callbackReturnPC),returnOffsetFor(sample),
               sample.size,rejected,badTargets,static_cast<unsigned long long>(aslrSlide),
               static_cast<unsigned long long>(slidPlan.callbackReturnPC));
        printResolved(resolved);
        printf(",\"anonymous_mapped_targets\":");printResolved(mappedTargets);
        printf("}\n");
    }
    return 0;
}
'''
    return "\n".join(declarations) + "\n" + harness


def classify_label(path: Path, index: int) -> str:
    del path
    return f"BootKC{index + 1}"


def read_image(path: Path, index: int, wanted: set[str]) -> dict[str, Any]:
    if not path.is_file():
        raise VerificationError(f"BootKC path does not exist: {path}")
    with path.open("rb") as stream:
        mapped = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            collection_sha = hashlib.sha256(mapped).hexdigest()
            outer, image = parse_bootkc(mapped, classify_label(path, index))
            # Attach the LC_FILESET_ENTRY so symbol selection can be checked
            # against its mapped inner-kernel address.
            image["fileset_entry"] = outer["kernel_entry"]
            symbols, symtab_mode = parse_symbols(mapped, image, wanted, classify_label(path, index))
            if symbols.get("__mh_execute_header") != outer["kernel_entry"]["vmaddr"]:
                raise VerificationError("__mh_execute_header differs from com.apple.kernel entry vmaddr")
            if "_ifnet_ioctl" not in symbols:
                raise VerificationError("LC_SYMTAB does not define _ifnet_ioctl")
            label = classify_label(path, index)
            text_matches = [section for section in image["sections"] if section["name"] == "__text" and
                            symbols["_ifnet_ioctl"] >= section["addr"] and
                            symbols["_ifnet_ioctl"] - section["addr"] < section["size"]]
            if len(text_matches) != 1:
                raise VerificationError(f"{label}: _ifnet_ioctl is not uniquely located in __text")
            text_section = text_matches[0]
            available = text_section["size"] - (symbols["_ifnet_ioctl"] - text_section["addr"])
            descriptor_indices = {"mutex-inline": 0, "mutex-monitor": 1, "25G-current": None}
            candidates = []
            for profile, body_size in EXPECTED_BODY_BY_PROFILE.items():
                if body_size > available:
                    continue
                body, function_info = extract_function(mapped, image, symbols, body_size, label)
                candidates.append({
                    "profile": profile,
                    "descriptor_index": descriptor_indices[profile],
                    "body_size": body_size,
                    "body": body,
                    "function_info": function_info,
                })
            if not candidates:
                raise VerificationError(f"{label}: no complete candidate body fits in __text")
            segments_for_harness = [segment for segment in image["segments"] if segment["vmsize"]]
            return {
                "label": label,
                "path": str(path.resolve()),
                "collection_sha256": collection_sha,
                "collection_bytes": len(mapped),
                "outer": outer,
                "inner": {
                    "uuid": image["uuid"],
                    "header_offset": image["header_offset"],
                    "ncmds": image["ncmds"],
                    "sizeofcmds": image["sizeofcmds"],
                    "fileset_entry": image["fileset_entry"],
                    "symtab": symtab_mode,
                },
                "symbol_va": symbols["_ifnet_ioctl"],
                "segments": segments_for_harness,
                "symbols": symbols,
                "candidates": candidates,
            }
        finally:
            mapped.close()


def run_host_verifier(samples: list[dict[str, Any]], source_hashes: dict[str, str]) -> list[dict[str, Any]]:
    compiler = shutil.which("clang++")
    if not compiler:
        raise VerificationError("clang++ is required to compile the production host harness")
    outcomes = []
    def compile_candidate(sample: dict[str, Any], candidate: dict[str, Any], directory: Path) -> Path:
        records = {
            "label": sample["label"],
            "profile": candidate["profile"],
            "body": candidate["body"],
            "function_va": sample["symbol_va"],
            "descriptor_index": candidate["descriptor_index"],
        }
        source = directory / "verify.cpp"
        binary = directory / "verify"
        source.write_text(build_harness([records], sample["symbols"], sample["segments"]))
        build = subprocess.run(
            [compiler, "-std=c++14", "-Wall", "-Wextra", "-Werror",
             "-I", str(PROJECT), str(source), "-o", str(binary)],
            capture_output=True, text=True, timeout=120)
        if build.returncode:
            raise VerificationError(
                f"host harness compile failed for {sample['label']} {candidate['profile']}:\n"
                f"{build.stdout}{build.stderr}")
        return binary

    for sample in samples:
        if len(sample["candidates"]) != len(EXPECTED_BODY_BY_PROFILE):
            raise VerificationError(f"{sample['label']}: expected all three production profile candidates")
        candidate_results = []
        passed_candidates = []
        for candidate in sample["candidates"]:
            with tempfile.TemporaryDirectory(prefix="ifnet-contract-probe-") as temp:
                binary = compile_candidate(sample, candidate, Path(temp))
                probe = subprocess.run([str(binary), "--probe"], capture_output=True,
                                       text=True, timeout=120)
                if probe.returncode:
                    raise VerificationError(
                        f"profile probe failed for {sample['label']} {candidate['profile']}:\n"
                        f"{probe.stdout}{probe.stderr}")
                lines = [line for line in probe.stdout.splitlines() if line.strip()]
                if len(lines) != 1:
                    raise VerificationError(
                        f"profile probe emitted unexpected output for {sample['label']}: {probe.stdout}")
                try:
                    probe_result = json.loads(lines[0])
                except json.JSONDecodeError as exc:
                    raise VerificationError(
                        f"profile probe emitted invalid JSON for {sample['label']}: {lines[0]}") from exc
                candidate_result = {
                    "profile": candidate["profile"],
                    "body_size": candidate["body_size"],
                    "status": probe_result.get("status", "MissingStatus"),
                }
                candidate_results.append(candidate_result)
                if probe_result.get("status") == "Passed":
                    passed_candidates.append(candidate)
        if len(passed_candidates) != 1:
            raise VerificationError(
                f"{sample['label']}: exactly one production profile must pass; "
                f"got {len(passed_candidates)} ({candidate_results})")

        selected = passed_candidates[0]
        with tempfile.TemporaryDirectory(prefix="ifnet-contract-host-") as temp:
            binary = compile_candidate(sample, selected, Path(temp))
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=120)
            if run.returncode:
                raise VerificationError(
                    f"host harness failed for {sample['label']} {selected['profile']}:\n"
                    f"{run.stdout}{run.stderr}")
            lines = [line for line in run.stdout.splitlines() if line.strip()]
            if len(lines) != 1:
                raise VerificationError(f"host harness emitted unexpected output for {sample['label']}: {run.stdout}")
            try:
                result = json.loads(lines[0])
            except json.JSONDecodeError as exc:
                raise VerificationError(f"host harness emitted invalid JSON for {sample['label']}: {lines[0]}") from exc
            result["path"] = sample["path"]
            result["symbol_sha256"] = hashlib.sha256(json.dumps(sample["symbols"], sort_keys=True).encode()).hexdigest()
            result["resolved_symbols"] = sample["symbols"]
            result["function_info"] = selected["function_info"]
            result["outer_uuid"] = sample["outer"]["uuid"]
            result["inner_uuid"] = sample["inner"]["uuid"]
            result["kernel_entry"] = sample["outer"]["kernel_entry"]
            result["collection_sha256"] = sample["collection_sha256"]
            result["collection_bytes"] = sample["collection_bytes"]
            result["source_hashes"] = source_hashes
            result["candidate_selection"] = candidate_results
            result["selected_by_unique_production_pass"] = True
            outcomes.append(result)
    return outcomes


def verify(paths: list[Path]) -> dict[str, Any]:
    if not paths:
        raise VerificationError("pass one or more explicit --kernel-collection paths")
    if len({str(path.resolve()) for path in paths}) != len(paths):
        raise VerificationError("duplicate --kernel-collection path")
    wanted = collect_header_symbol_names()
    source_hashes = {
        "kernel_contracts.hpp": hashlib.sha256(CONTRACT_HEADER.read_bytes()).hexdigest(),
        "ifnet_profiles.hpp": hashlib.sha256(PROFILE_HEADER.read_bytes()).hexdigest(),
    }
    samples = [read_image(path, index, wanted) for index, path in enumerate(paths)]
    outcomes = run_host_verifier(samples, source_hashes)
    return {
        "verification": "offline fileset symbol/segment extraction plus production C++ byte validators; not a booted resolver or Wi-Fi validation",
        "tool": str(Path(__file__).resolve()),
        "production_sources": source_hashes,
        "checks": [
            "outer MH_FILESET and unique com.apple.kernel member",
            "LC_SYMTAB exact _ifnet_ioctl and symbol/alias target resolution",
            "__TEXT,__text bounds and actual file-backed function bytes",
            "all three production profiles probed per image; exactly one production C++ validator must pass",
            "production IfnetProfiles::validate/validateMapped or validateIfnetCurrent/validateIfnetMappedTargets",
            "every individual byte mutation rejected with cleared plan",
            "every named resolved target changed by one rejected",
            "anonymous targets checked against actual mapped segment permissions",
            "translated base and all symbol targets pass under a test ASLR slide",
        ],
        "samples": outcomes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-collection", action="append", required=True, type=Path,
                        help="explicit BootKernelExtensions.kc path (repeat for multiple samples)")
    parser.add_argument("--output", type=Path, help="optional path for JSON results")
    args = parser.parse_args(argv)
    try:
        result = verify(args.kernel_collection)
        result["status"] = "passed"
    except (VerificationError, OSError, ValueError, struct.error, subprocess.TimeoutExpired) as exc:
        result = {
            "verification": "offline fileset symbol/segment extraction plus production C++ byte validators; not a booted resolver or Wi-Fi validation",
            "status": "failed",
            "error": str(exc),
            "kernel_collections": [str(path) for path in args.kernel_collection],
        }
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2), file=sys.stderr)
        return 1
    payload = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload)
        print(f"results: {args.output}")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
