#!/usr/bin/env python3
"""Offline verifier for production ifnet_ioctl contracts in explicit kernel images.

The tool reads BootKC files named with --kernel-collection or standalone
MH_EXECUTE images named with --kernel-image. It records these as distinct
sample kinds; a KDK is not evidence of an installed system or its userspace.
Saved --contract-excerpt inputs replay bounded bytes and recorded metadata;
they do not reverify the original image, its symbols, or its provenance.
It compiles the production contract headers into a temporary host harness and
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
    "atomic-reference": 0x340,
    "mutex-inline-alternate": 0x340,
    "mutex-inline-expanded": 0x340,
    "25G-current": 0x390,
}
DESCRIPTOR_INDEX = {"mutex-inline": 0, "mutex-monitor": 1,
                    "atomic-reference": 2, "mutex-inline-alternate": 3,
                    "mutex-inline-expanded": 4, "25G-current": None}
MAX_EXCERPT_BYTES = 1024 * 1024
MAX_SEMANTIC_EVIDENCE_BYTES = 256
CURRENT_IFNET_TARGET_SPECS = (
    (0x2DE, 0x2DF, 0x2E3, "call", "code", 0x29),
    (0x2E3, 0x2E6, 0x2EA, "rip", "data", MAX_SEMANTIC_EVIDENCE_BYTES),
    (0x2EA, 0x2ED, 0x2F1, "rip", "data", MAX_SEMANTIC_EVIDENCE_BYTES),
    (0x2F6, 0x2F7, 0x2FB, "call", "code", 0x27),
    (0x2FE, 0x2FF, 0x303, "call", "code", 0x21),
)


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


def relative_target(raw: bytes, base: int, instruction: int, displacement: int,
                    end: int, kind: str, label: str) -> int:
    if (instruction < 0 or displacement < 0 or end > len(raw) or
            displacement + 4 > len(raw) or instruction >= displacement):
        raise VerificationError(f"{label}: relative target span is out of bounds")
    if kind == "call":
        if displacement != instruction + 1 or end != instruction + 5 or raw[instruction] != 0xE8:
            raise VerificationError(f"{label}: expected direct rel32 call")
    elif kind == "rip":
        if displacement <= instruction or (raw[displacement - 1] & 0xC7) != 0x05:
                raise VerificationError(f"{label}: expected RIP-relative displacement")
    else:
        raise VerificationError(f"{label}: unknown relative target kind")
    result = base + end + struct.unpack_from("<i", raw, displacement)[0]
    if result <= 0 or result > 0xFFFFFFFFFFFFFFFF:
        raise VerificationError(f"{label}: relative target address overflow")
    return result


def read_vm_range(data: mmap.mmap, image: dict[str, Any], address: int, size: int,
                  executable: bool, label: str) -> bytes:
    required = VM_PROT_READ | (VM_PROT_EXECUTE if executable else 0)
    matches = []
    for segment in image["segments"]:
        delta = address - segment["vmaddr"]
        if (address < segment["vmaddr"] or delta > segment["vmsize"] or
                size > segment["vmsize"] - delta or delta > segment["filesize"] or
                size > segment["filesize"] - delta or
                (segment["initprot"] & required) != required or
                (segment["maxprot"] & required) != required):
            continue
        file_offset = segment["fileoff"] + delta
        matches.append(file_offset)
    if len(matches) != 1:
        raise VerificationError(f"{label}: target range is not uniquely file-backed in a permitted segment")
    return checked_slice(data, matches[0], size, label)


def extract_current_semantic_evidence(data: mmap.mmap, image: dict[str, Any],
                                      body: bytes, base: int, label: str) -> list[dict[str, Any]]:
    """Save only small records reached from the fixed 25G ifnet instruction sites."""
    try:
        targets = {
            instruction: relative_target(body, base, instruction, displacement, end, kind,
                                        f"{label} ifnet target {instruction:#x}")
            for instruction, displacement, end, kind, _record_kind, _record_size
            in CURRENT_IFNET_TARGET_SPECS
        }
        records: dict[tuple[int, bool], dict[str, Any]] = {}

        def add_record(address: int, size: int, executable: bool, name: str) -> bytes:
            if not 0 < size <= MAX_SEMANTIC_EVIDENCE_BYTES:
                raise VerificationError(f"{label}: invalid bounded evidence size for {name}")
            raw = read_vm_range(data, image, address, size, executable,
                                f"{label} semantic evidence {name}")
            if not executable and b"\0" not in raw:
                raise VerificationError(f"{label}: semantic string lacks a NUL within the read bound")
            key = (address, executable)
            prior = records.get(key)
            if prior and bytes.fromhex(prior["bytes_hex"]) != raw:
                raise VerificationError(f"{label}: conflicting semantic evidence records")
            records[key] = {
                "address": f"0x{address:x}",
                "executable": executable,
                "bytes_hex": raw.hex(),
            }
            return raw

        # Main-body literals and the stable, symbol+addend identity target.
        for instruction, _displacement, _end, _kind, record_kind, record_size in CURRENT_IFNET_TARGET_SPECS:
            executable = record_kind == "code"
            add_record(targets[instruction], record_size, executable, f"body_{instruction:x}")

        helpers = (
            (0x2DE, 0x29, ((0x0C, 0x10), (0x13, 0x17))),
            (0x2F6, 0x27, ((0x0F, 0x13), (0x16, 0x1A))),
            (0x2FE, 0x21, ((0x0A, 0x0E), (0x11, 0x15))),
        )
        for instruction, code_size, string_refs in helpers:
            target = targets[instruction]
            code = read_vm_range(data, image, target, code_size, True,
                                 f"{label} helper code {instruction:#x}")
            add_record(target, code_size, True, f"helper_{instruction:x}")
            for disp_offset, end_offset in string_refs:
                if (disp_offset <= 0 or disp_offset + 4 > len(code) or
                        end_offset > len(code)):
                    raise VerificationError(f"{label}: helper string reference exceeds code record")
                address = target + end_offset + struct.unpack_from("<i", code, disp_offset)[0]
                if address <= 0 or address > 0xFFFFFFFFFFFFFFFF:
                    raise VerificationError(f"{label}: nested helper string address overflow")
                add_record(address, MAX_SEMANTIC_EVIDENCE_BYTES, False,
                           f"helper_{instruction:x}_string_{disp_offset:x}")

        # Reject oversized/duplicate address sets instead of constructing an
        # arbitrary-address memory dump in the replay evidence.
        result = list(records.values())
        if not 8 <= len(result) <= 16:
            raise VerificationError(f"{label}: unexpected semantic evidence record count {len(result)}")
        return result
    except (VerificationError, struct.error, OverflowError):
        # The exact historical digest route remains available. A missing or
        # malformed auxiliary excerpt makes only the semantic route fail closed.
        return []


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
        "static constexpr uint32_t HostSemanticEvidenceBudgetBytes=8192U;",
        "struct SymbolRecord {const char *name; uint64_t value;};",
        "struct SegmentRecord {const char *name; uint64_t vmaddr,vmsize; int32_t initprot,maxprot;};",
        "struct EvidenceRecord {uint64_t address; const uint8_t *bytes; size_t size; bool executable;};",
        cpp_symbols(symbols), cpp_segments(segments),
    ]
    semantic_evidence = samples[0].get("semantic_evidence", []) if samples else []
    evidence_rows = []
    for index, record in enumerate(semantic_evidence):
        name = f"EvidenceBytes_{index}"
        declarations.append(cpp_bytes(name, bytes.fromhex(record["bytes_hex"])))
        evidence_rows.append("{UINT64_C(0x%x),%s,sizeof(%s),%s}" % (
            int(record["address"], 16), name, name,
            "true" if record["executable"] else "false"))
    if evidence_rows:
        declarations.append("static const EvidenceRecord EvidenceRecords[] = {" + ",".join(evidence_rows) + "};")
        declarations.append("static constexpr size_t EvidenceRecordCount=sizeof(EvidenceRecords)/sizeof(EvidenceRecords[0]);")
    else:
        declarations.append("static const EvidenceRecord EvidenceRecords[] = {{0,nullptr,0,false}};")
        declarations.append("static constexpr size_t EvidenceRecordCount=0;")
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
static bool findEvidenceRange(uintptr_t address,uintptr_t slide,size_t size,bool executable) {
    if(!size||address<slide||size>UINTPTR_MAX-address)return false;
    const uintptr_t unslid=address-slide;
    const int needed=executable?5:1;
    for(size_t i=0;i<SegmentCount;i++) {
        const auto &s=Segments[i];
        if(!s.vmsize||unslid<s.vmaddr)continue;
        const uintptr_t offset=unslid-s.vmaddr;
        if(offset>s.vmsize||size>s.vmsize-offset)continue;
        if((s.initprot&needed)==needed&&(s.maxprot&needed)==needed)return true;
    }
    return false;
}
struct EvidenceContext {
    uintptr_t slide;
    uint32_t remaining;
    const EvidenceRecord *records;
    size_t count;
};
static bool readEvidence(uintptr_t address,uint8_t *destination,size_t size,
                         bool executable,void *opaque) {
    auto *context=static_cast<EvidenceContext *>(opaque);
    if(!context||!destination||!size||size>MaxIfnetSemanticEvidenceRead||
       size>UINT32_MAX/2U||context->remaining<size*2U)return false;
    context->remaining-=static_cast<uint32_t>(size*2U);
    if(!findEvidenceRange(address,context->slide,size,executable))return false;
    for(size_t i=0;i<context->count;i++) {
        const auto &record=context->records[i];
        if(record.executable!=executable||record.address>UINTPTR_MAX-context->slide)continue;
        const uintptr_t start=static_cast<uintptr_t>(record.address)+context->slide;
        if(address<start||address-start>record.size||size>record.size-(address-start))continue;
        memcpy(destination,record.bytes+(address-start),size);return true;
    }
    return false;
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
                            uintptr_t slide,IfnetIoctlPlan &plan,bool *semanticRoute=nullptr,
                            const EvidenceRecord *evidenceRecords=EvidenceRecords,
                            size_t evidenceCount=EvidenceRecordCount) {
    if(semanticRoute)*semanticRoute=false;
    if(sample.descriptor==255) {
        Status status=KernelContracts::validateIfnetCurrent(bytes,size,base,relocs,count,plan);
        if(status!=Status::FingerprintMismatch||!evidenceCount)return status;
        RelocationSpec dynamicSpecs[IfnetCurrentDynamicRelocationCount]{};
        if(!copyIfnetCurrentDynamicRelocationSpecs(dynamicSpecs,IfnetCurrentDynamicRelocationCount))
            return Status::InvalidRelocation;
        Relocation dynamicRelocations[IfnetProfiles::MaxRelocations]{};
        std::vector<std::string> dynamicResolved;
        if(!buildRelocations(dynamicSpecs,IfnetCurrentDynamicRelocationCount,slide,
                             dynamicRelocations,dynamicResolved))return Status::InvalidRelocation;
        const SymbolRecord *panic=findSymbol(IfnetSemanticPanicSymbol);
        if(!panic||panic->value>UINTPTR_MAX-slide)return Status::SemanticMismatch;
        const uintptr_t panicTarget=static_cast<uintptr_t>(panic->value)+slide;
        if(!findSegment(panicTarget,slide,RelocationKind::RelativeCall))return Status::SemanticMismatch;
        EvidenceContext context{slide,HostSemanticEvidenceBudgetBytes,evidenceRecords,evidenceCount};
        status=KernelContracts::validateIfnetCurrentSemantic(bytes,size,base,dynamicRelocations,
            IfnetCurrentDynamicRelocationCount,panicTarget,readEvidence,&context,plan);
        if(status==Status::Passed&&semanticRoute)*semanticRoute=true;
        return status;
    }
    return IfnetProfiles::validate(IfnetProfiles::Additional[sample.descriptor],
                                   bytes,size,base,relocs,count,plan);
}
static bool buildSemanticSetup(uintptr_t slide,Relocation *relocs,uintptr_t &panicTarget) {
    RelocationSpec specs[IfnetCurrentDynamicRelocationCount]{};
    if(!copyIfnetCurrentDynamicRelocationSpecs(specs,IfnetCurrentDynamicRelocationCount))return false;
    std::vector<std::string> resolved;
    if(!buildRelocations(specs,IfnetCurrentDynamicRelocationCount,slide,relocs,resolved))return false;
    const SymbolRecord *panic=findSymbol(IfnetSemanticPanicSymbol);
    if(!panic||panic->value>UINTPTR_MAX-slide)return false;
    panicTarget=static_cast<uintptr_t>(panic->value)+slide;
    return findSegment(panicTarget,slide,RelocationKind::RelativeCall)!=nullptr;
}
static void cloneEvidenceRecords(size_t count,std::vector<std::vector<uint8_t>> &storage,
                                 std::vector<EvidenceRecord> &records) {
    storage.clear();records.clear();storage.reserve(count);records.reserve(count);
    for(size_t i=0;i<count;i++) {
        const auto &source=EvidenceRecords[i];
        storage.emplace_back(source.bytes,source.bytes+source.size);
        records.push_back({source.address,storage.back().data(),storage.back().size(),source.executable});
    }
}
static int32_t rel32(uintptr_t end,uintptr_t target) {
    if(target>=end) {const uintptr_t d=target-end;if(d>static_cast<uintptr_t>(INT32_MAX))return INT32_MAX;return static_cast<int32_t>(d);}
    const uintptr_t d=end-target;if(d>static_cast<uintptr_t>(INT32_MAX)+1U)return INT32_MIN;
    return static_cast<int32_t>(-static_cast<int64_t>(d));
}
static void put32(uint8_t *p,int32_t value) {
    const uint32_t raw=static_cast<uint32_t>(value);
    for(unsigned i=0;i<4;i++)p[i]=static_cast<uint8_t>(raw>>(i*8));
}
static bool zeroPlan(const IfnetIoctlPlan &plan);
static bool semanticVariantRejected(const uint8_t *bytes,uintptr_t base,uintptr_t slide,
                                    const Relocation *relocs,uintptr_t panicTarget,
                                    const std::vector<EvidenceRecord> &records,
                                    uint32_t budget=HostSemanticEvidenceBudgetBytes) {
    EvidenceContext context{slide,budget,records.data(),records.size()};
    IfnetIoctlPlan plan{};
    const Status status=KernelContracts::validateIfnetCurrentSemantic(
        bytes,IfnetIoctlContractBytes,base,relocs,IfnetCurrentDynamicRelocationCount,
        panicTarget,readEvidence,&context,plan);
    return status!=Status::Passed&&zeroPlan(plan);
}
static bool testCurrentSemanticMutations(const Sample &sample,uintptr_t slide,
                                         const Relocation *relocs,uintptr_t panicTarget) {
    if(sample.descriptor!=255||!EvidenceRecordCount)return true;
    std::vector<uint8_t> body(sample.bytes,sample.bytes+sample.size);
    std::vector<std::vector<uint8_t>> storage;std::vector<EvidenceRecord> records;
    cloneEvidenceRecords(EvidenceRecordCount,storage,records);
    const uintptr_t base=sample.functionVA+slide;
    const uintptr_t move=static_cast<uintptr_t>(0x1000);
    std::vector<uint8_t> moved=body;
    std::vector<std::vector<uint8_t>> movedStorage;std::vector<EvidenceRecord> movedRecords;
    cloneEvidenceRecords(EvidenceRecordCount,movedStorage,movedRecords);
    for(auto &record:movedRecords)record.address+=move;
    for(size_t i=0;i<IfnetCurrentSemanticTargetCount;i++) {
        const auto &spec=IfnetCurrentSemanticTargetSpecs[i];uintptr_t oldTarget=0;
        if(KernelContracts::relativeTargetAt(body.data(),body.size(),base,spec,oldTarget)!=Status::Passed)
            return false;
        put32(moved.data()+spec.displacementOffset,
              rel32(base+spec.instructionEndOffset,oldTarget+move));
    }
    EvidenceContext movedContext{slide,HostSemanticEvidenceBudgetBytes,movedRecords.data(),movedRecords.size()};
    IfnetIoctlPlan movedPlan{};
    const Status movedStatus=KernelContracts::validateIfnetCurrentSemantic(
        moved.data(),moved.size(),base,relocs,IfnetCurrentDynamicRelocationCount,
        panicTarget+move,readEvidence,&movedContext,movedPlan);
    if(movedStatus!=Status::Passed||movedPlan.callbackReturnPC!=base+0x211)return false;
    // Exercise the exact-miss production dispatcher with only the anonymous
    // helper functions moved; their referenced strings and resolved _panic
    // symbol stay fixed, and nested rel32 operands are updated accordingly.
    std::vector<uint8_t> dispatchBody=body;
    std::vector<std::vector<uint8_t>> dispatchStorage;std::vector<EvidenceRecord> dispatchRecords;
    cloneEvidenceRecords(EvidenceRecordCount,dispatchStorage,dispatchRecords);
    const size_t helperTargetIndex[]={0,3,4};
    const size_t helperSizes[]={0x29,0x27,0x21};
    const RelocationSpec nested[3][3]={
        {{0x09,0x0c,0x10,RelocationKind::RipRelative,nullptr,nullptr,0},
         {0x10,0x13,0x17,RelocationKind::RipRelative,nullptr,nullptr,0},
         {0x24,0x25,0x29,RelocationKind::RelativeCall,nullptr,nullptr,0}},
        {{0x0c,0x0f,0x13,RelocationKind::RipRelative,nullptr,nullptr,0},
         {0x13,0x16,0x1a,RelocationKind::RipRelative,nullptr,nullptr,0},
         {0x22,0x23,0x27,RelocationKind::RelativeCall,nullptr,nullptr,0}},
        {{0x07,0x0a,0x0e,RelocationKind::RipRelative,nullptr,nullptr,0},
         {0x0e,0x11,0x15,RelocationKind::RipRelative,nullptr,nullptr,0},
         {0x1c,0x1d,0x21,RelocationKind::RelativeCall,nullptr,nullptr,0}}
    };
    for(size_t helper=0;helper<3;helper++) {
        const auto &targetSpec=IfnetCurrentSemanticTargetSpecs[helperTargetIndex[helper]];
        uintptr_t oldHelper=0;
        if(KernelContracts::relativeTargetAt(body.data(),body.size(),base,targetSpec,oldHelper)!=Status::Passed)
            return false;
        size_t recordIndex=dispatchRecords.size();
        for(size_t i=0;i<dispatchRecords.size();i++)
            if(dispatchRecords[i].executable&&dispatchRecords[i].address+slide==oldHelper)recordIndex=i;
        if(recordIndex==dispatchRecords.size())return false;
        for(size_t ref=0;ref<3;ref++) {
            uintptr_t nestedTarget=0;
            if(KernelContracts::relativeTargetAt(dispatchStorage[recordIndex].data(),helperSizes[helper],
                oldHelper,nested[helper][ref],nestedTarget)!=Status::Passed)return false;
            put32(dispatchStorage[recordIndex].data()+nested[helper][ref].displacementOffset,
                  rel32(oldHelper+move+nested[helper][ref].instructionEndOffset,nestedTarget));
        }
        dispatchRecords[recordIndex].address+=move;
        put32(dispatchBody.data()+targetSpec.displacementOffset,
              rel32(base+targetSpec.instructionEndOffset,oldHelper+move));
    }
    IfnetIoctlPlan dispatchedPlan{};bool usedSemanticRoute=false;
    const Status dispatched=runValidation(sample,dispatchBody.data(),dispatchBody.size(),base,relocs,
        IfnetCurrentDynamicRelocationCount,slide,dispatchedPlan,&usedSemanticRoute,
        dispatchRecords.data(),dispatchRecords.size());
    if(dispatched!=Status::Passed||!usedSemanticRoute||
       dispatchedPlan.callbackReturnPC!=base+0x211)return false;

    // Wrong target, out-of-record read, instruction, nested panic call, string,
    // missing auxiliary bytes, budget exhaustion, and opaque 0x377 mutations.
    for(size_t i=0;i<IfnetCurrentSemanticTargetCount;i++) {
        const auto &spec=IfnetCurrentSemanticTargetSpecs[i];auto bad=body;uintptr_t target=0;
        if(KernelContracts::relativeTargetAt(body.data(),body.size(),base,spec,target)!=Status::Passed)return false;
        put32(bad.data()+spec.displacementOffset,rel32(base+spec.instructionEndOffset,target+0x10000000U));
        if(!semanticVariantRejected(bad.data(),base,slide,relocs,panicTarget,records))return false;
    }
    size_t overflowIndex=EvidenceRecordCount;
    uintptr_t overflowTarget=0;
    if(KernelContracts::relativeTargetAt(body.data(),body.size(),base,
        IfnetCurrentSemanticTargetSpecs[0],overflowTarget)!=Status::Passed)return false;
    for(size_t i=0;i<records.size();i++)
        if(records[i].executable&&records[i].address+slide==overflowTarget)overflowIndex=i;
    if(overflowIndex==EvidenceRecordCount)return false;

    auto changedCode=storage;auto codeRecords=records;
    changedCode[overflowIndex][0]^=1;codeRecords[overflowIndex].bytes=changedCode[overflowIndex].data();
    if(!semanticVariantRejected(body.data(),base,slide,relocs,panicTarget,codeRecords))return false;

    auto changedCall=storage;auto callRecords=records;
    put32(changedCall[overflowIndex].data()+0x25,
          rel32(overflowTarget+0x29,panicTarget+0x10));
    callRecords[overflowIndex].bytes=changedCall[overflowIndex].data();
    if(!semanticVariantRejected(body.data(),base,slide,relocs,panicTarget,callRecords))return false;

    size_t stringIndex=EvidenceRecordCount;
    for(size_t i=0;i<records.size();i++)if(!records[i].executable){stringIndex=i;break;}
    if(stringIndex==EvidenceRecordCount)return false;
    auto changedString=storage;auto stringRecords=records;
    changedString[stringIndex][0]^=1;stringRecords[stringIndex].bytes=changedString[stringIndex].data();
    if(!semanticVariantRejected(body.data(),base,slide,relocs,panicTarget,stringRecords))return false;

    auto truncated=records;truncated.pop_back();
    if(!semanticVariantRejected(body.data(),base,slide,relocs,panicTarget,truncated))return false;
    if(!semanticVariantRejected(body.data(),base,slide,relocs,panicTarget,records,1))return false;

    auto identityChanged=body;identityChanged[0x378]^=1;
    if(!semanticVariantRejected(identityChanged.data(),base,slide,relocs,panicTarget,records))return false;
    Relocation wrongSymbol[IfnetProfiles::MaxRelocations]{};
    memcpy(wrongSymbol,relocs,IfnetCurrentDynamicRelocationCount*sizeof(Relocation));
    wrongSymbol[0].target^=1U;
    if(!semanticVariantRejected(body.data(),base,slide,wrongSymbol,panicTarget,records))return false;
    return true;
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
        bool semanticRoute=false;
        Status result=runValidation(sample,sample.bytes,sample.size,base,relocs,count,
                                    initialSlide,plan,&semanticRoute);
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
                                                     relocs,count,initialSlide,mutantPlan);
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
            const Status wrongStatus=sample.descriptor==255 ?
                KernelContracts::validateIfnetCurrent(sample.bytes,sample.size,base,wrong,count,wrongPlan) :
                IfnetProfiles::validate(IfnetProfiles::Additional[sample.descriptor],
                                        sample.bytes,sample.size,base,wrong,count,wrongPlan);
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
        bool slidSemanticRoute=false;
        Status slidStatus=runValidation(sample,sample.bytes,sample.size,slidBase,slid,count,
                                        aslrSlide,slidPlan,&slidSemanticRoute);
        if(slidStatus!=Status::Passed || slidPlan.callbackReturnPC!=slidBase+returnOffsetFor(sample))
            return fail(sample,"ASLR-translated validation did not pass with translated return PC");
        slidStatus=runMapped(sample,sample.bytes,sample.size,slidBase,aslrSlide);
        if(slidStatus!=Status::Passed)return fail(sample,"ASLR-translated mapped targets did not pass");

        size_t semanticMutations=0;bool semanticRelocationPassed=false;
        bool semanticExactMissPassed=false;
        if(sample.descriptor==255&&EvidenceRecordCount) {
            Relocation semanticRelocations[IfnetProfiles::MaxRelocations]{};uintptr_t panicTarget=0;
            if(!buildSemanticSetup(initialSlide,semanticRelocations,panicTarget) ||
               !testCurrentSemanticMutations(sample,initialSlide,semanticRelocations,panicTarget))
                return fail(sample,"semantic target relocation or content/call/bounds mutation check failed");
            semanticMutations=12;semanticRelocationPassed=true;semanticExactMissPassed=true;
        }

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
               "\"aslr_callback_return_pc\":\"0x%llx\",\"validation_route\":\"%s\","
               "\"semantic_relocation_positive\":%s,\"semantic_exact_miss_dispatch\":%s,"
               "\"semantic_mutations_rejected\":%zu,"
               "\"resolved_relocations\":",
               sample.label,sample.profile,static_cast<unsigned long long>(base),sample.size,
               static_cast<unsigned long long>(plan.callbackReturnPC),returnOffsetFor(sample),
               sample.size,rejected,badTargets,static_cast<unsigned long long>(aslrSlide),
               static_cast<unsigned long long>(slidPlan.callbackReturnPC),
               semanticRoute?"semantic-targets":"exact-layout",
               semanticRelocationPassed?"true":"false",
               semanticExactMissPassed?"true":"false",semanticMutations);
        printResolved(resolved);
        printf(",\"anonymous_mapped_targets\":");printResolved(mappedTargets);
        printf("}\n");
    }
    return 0;
}
'''
    return "\n".join(declarations) + "\n" + harness


def classify_label(path: Path, index: int, standalone: bool = False) -> str:
    del path
    return f"{'KernelImage' if standalone else 'BootKC'}{index + 1}"


def read_image(path: Path, index: int, wanted: set[str], *, standalone: bool = False) -> dict[str, Any]:
    if not path.is_file():
        raise VerificationError(f"kernel input path does not exist: {path}")
    with path.open("rb") as stream:
        mapped = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            image_sha = hashlib.sha256(mapped).hexdigest()
            label = classify_label(path, index, standalone)
            if standalone:
                image = parse_inner_image(mapped, 0, label)
                header_bytes = 32 + image["sizeofcmds"]
                headers = [segment for segment in image["segments"]
                           if segment["fileoff"] == 0 and segment["filesize"] >= header_bytes
                           and segment["vmsize"] >= header_bytes
                           and segment["initprot"] & VM_PROT_READ
                           and segment["maxprot"] & VM_PROT_READ]
                if len(headers) != 1 or not headers[0]["vmaddr"]:
                    raise VerificationError(f"{label}: no unique readable header mapping")
                header_address = headers[0]["vmaddr"]
                outer = {"uuid": None, "kernel_entry": None}
            else:
                outer, image = parse_bootkc(mapped, label)
                # Resolve symbols against the actual fileset member mapping.
                image["fileset_entry"] = outer["kernel_entry"]
                header_address = outer["kernel_entry"]["vmaddr"]
            symbols, symtab_mode = parse_symbols(mapped, image, wanted, label)
            if symbols.get("__mh_execute_header") != header_address:
                raise VerificationError("__mh_execute_header differs from the actual kernel header mapping")
            if "_ifnet_ioctl" not in symbols:
                raise VerificationError("LC_SYMTAB does not define _ifnet_ioctl")
            text_matches = [section for section in image["sections"] if section["name"] == "__text" and
                            symbols["_ifnet_ioctl"] >= section["addr"] and
                            symbols["_ifnet_ioctl"] - section["addr"] < section["size"]]
            if len(text_matches) != 1:
                raise VerificationError(f"{label}: _ifnet_ioctl is not uniquely located in __text")
            text_section = text_matches[0]
            available = text_section["size"] - (symbols["_ifnet_ioctl"] - text_section["addr"])
            candidates = []
            for profile, body_size in EXPECTED_BODY_BY_PROFILE.items():
                if body_size > available:
                    continue
                body, function_info = extract_function(mapped, image, symbols, body_size, label)
                candidates.append({
                    "profile": profile,
                    "descriptor_index": DESCRIPTOR_INDEX[profile],
                    "body_size": body_size,
                    "body": body,
                    "function_info": function_info,
                })
            if not candidates:
                raise VerificationError(f"{label}: no complete candidate body fits in __text")
            semantic_candidate = next((candidate for candidate in candidates
                                       if candidate["profile"] == "25G-current"), None)
            semantic_evidence = []
            if semantic_candidate:
                semantic_evidence = extract_current_semantic_evidence(
                    mapped, image, semantic_candidate["body"], symbols["_ifnet_ioctl"], label)
            segments_for_harness = [segment for segment in image["segments"] if segment["vmsize"]]
            return {
                "label": label,
                "path": str(path.resolve()),
                "image_kind": "standalone-MH_EXECUTE" if standalone else "BootKC-MH_FILESET",
                "image_sha256": image_sha,
                "image_bytes": len(mapped),
                "outer": outer,
                "inner": {
                    "uuid": image["uuid"],
                    "header_offset": image["header_offset"],
                    "ncmds": image["ncmds"],
                    "sizeofcmds": image["sizeofcmds"],
                    "fileset_entry": image.get("fileset_entry"),
                    "symtab": symtab_mode,
                },
                "symbol_va": symbols["_ifnet_ioctl"],
                "segments": segments_for_harness,
                "symbols": symbols,
                "candidates": candidates,
                "semantic_evidence": semantic_evidence,
            }
        finally:
            mapped.close()


def excerpt_bytes(sample: dict[str, Any]) -> bytes:
    """Keep only the bounded inputs needed to rerun the production validators."""
    result = {key: value for key, value in sample.items() if key != "candidates"}
    result["evidence_kind"] = "bounded excerpt; original image is not reverified during replay"
    result["candidates"] = [
        {**{key: value for key, value in candidate.items() if key != "body"},
         "body_hex": candidate["body"].hex()}
        for candidate in sample["candidates"]
    ]
    return (json.dumps(result, indent=2) + "\n").encode()


def read_excerpt(path: Path, index: int, wanted: set[str]) -> dict[str, Any]:
    """Validate serialized harness inputs, without claiming image extraction."""
    with path.open("rb") as stream:
        raw = stream.read(MAX_EXCERPT_BYTES + 1)
    if len(raw) > MAX_EXCERPT_BYTES:
        raise VerificationError("contract excerpt exceeds 1 MiB")

    def unique_object(items):
        result = {}
        for key, value in items:
            if key in result:
                raise VerificationError(f"duplicate excerpt key: {key}")
            result[key] = value
        return result

    def uint(value, label, maximum=0xffffffffffffffff):
        if type(value) is not int or not 0 <= value <= maximum:
            raise VerificationError(f"invalid excerpt {label}")
        return value

    try:
        sample = json.loads(raw, object_pairs_hook=unique_object)
        if sample["image_kind"] not in ("BootKC-MH_FILESET", "standalone-MH_EXECUTE"):
            raise VerificationError("invalid excerpt original image kind")
        if not re.fullmatch(r"[0-9a-f]{64}", sample["image_sha256"]):
            raise VerificationError("invalid excerpt original image digest")
        uint(sample["image_bytes"], "image size")
        address = uint(sample["symbol_va"], "function address")
        if not isinstance(sample["path"], str) or not address:
            raise VerificationError("invalid excerpt original path or function address")
        for item in (sample["outer"], sample["inner"]):
            if not isinstance(item, dict) or "uuid" not in item:
                raise VerificationError("missing excerpt image metadata")
        if "kernel_entry" not in sample["outer"]:
            raise VerificationError("missing excerpt kernel entry metadata")
        symbols = sample["symbols"]
        if not isinstance(symbols, dict) or not symbols or set(symbols) - wanted:
            raise VerificationError("invalid excerpt symbol names")
        for value in symbols.values():
            uint(value, "symbol address")
        if symbols.get("_ifnet_ioctl") != address:
            raise VerificationError("excerpt function symbol mismatch")
        evidence = sample.get("semantic_evidence", [])
        if not isinstance(evidence, list) or len(evidence) > 16:
            raise VerificationError("invalid semantic evidence record count")
        evidence_seen = set()
        for record in evidence:
            if not isinstance(record, dict) or set(record) != {"address", "executable", "bytes_hex"}:
                raise VerificationError("invalid semantic evidence record shape")
            raw_address = record["address"]
            if not isinstance(raw_address, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", raw_address):
                raise VerificationError("invalid semantic evidence address")
            evidence_address = int(raw_address, 16)
            if not evidence_address or type(record["executable"]) is not bool:
                raise VerificationError("invalid semantic evidence target metadata")
            encoded = record["bytes_hex"]
            if not isinstance(encoded, str) or not re.fullmatch(r"[0-9a-fA-F]{2,512}", encoded):
                raise VerificationError("invalid semantic evidence bytes")
            evidence_bytes = bytes.fromhex(encoded)
            if not record["executable"] and b"\0" not in evidence_bytes:
                raise VerificationError("semantic string evidence lacks bounded NUL")
            key = (evidence_address, record["executable"])
            if key in evidence_seen:
                raise VerificationError("duplicate semantic evidence target")
            evidence_seen.add(key)
        sample["semantic_evidence"] = evidence
        segments = sample["segments"]
        if not isinstance(segments, list) or not 1 <= len(segments) <= 128:
            raise VerificationError("invalid excerpt segment count")
        for segment in segments:
            if not isinstance(segment["name"], str) or not re.fullmatch(r"[\x20-\x7e]{1,16}", segment["name"]):
                raise VerificationError("invalid excerpt segment name")
            base = uint(segment["vmaddr"], "segment address")
            size = uint(segment["vmsize"], "segment size")
            if not size or size > 0xffffffffffffffff - base:
                raise VerificationError("invalid excerpt segment range")
            for key in ("initprot", "maxprot"):
                uint(segment[key], "segment permissions", 7)
        candidates = sample["candidates"]
        if not isinstance(candidates, list) or len(candidates) != len(EXPECTED_BODY_BY_PROFILE):
            raise VerificationError("excerpt must contain every production profile")
        seen = set()
        for candidate in candidates:
            profile = candidate["profile"]
            if profile not in EXPECTED_BODY_BY_PROFILE or profile in seen:
                raise VerificationError("invalid or duplicate excerpt profile")
            seen.add(profile)
            size = EXPECTED_BODY_BY_PROFILE[profile]
            if (type(candidate["body_size"]) is not int or candidate["body_size"] != size or
                    candidate["descriptor_index"] != DESCRIPTOR_INDEX[profile] or
                    (candidate["descriptor_index"] is not None and
                     type(candidate["descriptor_index"]) is not int)):
                raise VerificationError("excerpt profile descriptor mismatch")
            encoded = candidate.pop("body_hex")
            if not isinstance(encoded, str) or not re.fullmatch(r"[0-9a-fA-F]{%d}" % (size * 2), encoded):
                raise VerificationError("invalid excerpt function bytes")
            candidate["body"] = bytes.fromhex(encoded)
            info = candidate["function_info"]
            if (not isinstance(info, dict) or info.get("symbol_va") != address or
                    info.get("body_size") != size):
                raise VerificationError("excerpt function metadata mismatch")
        longest = max(candidates, key=lambda candidate: candidate["body_size"])["body"]
        if any(candidate["body"] != longest[:candidate["body_size"]] for candidate in candidates):
            raise VerificationError("excerpt candidates disagree on function bytes")
    except (KeyError, TypeError, ValueError) as exc:
        raise VerificationError(f"invalid contract excerpt: {exc}") from exc
    sample["label"] = f"Excerpt{index + 1}"
    sample["input_kind"] = "contract-excerpt"
    sample["excerpt_path"] = str(path.resolve())
    sample["excerpt_sha256"] = hashlib.sha256(raw).hexdigest()
    sample["original_image_reverified"] = False
    return sample


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
            "semantic_evidence": sample.get("semantic_evidence", []),
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
            raise VerificationError(f"{sample['label']}: expected every registered production profile candidate")
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
            for key in ("image_kind", "image_sha256", "image_bytes"):
                result[key] = sample[key]
            result["input_kind"] = sample.get("input_kind", "image")
            result["original_image_reverified"] = sample.get("original_image_reverified", True)
            for key in ("excerpt_path", "excerpt_sha256"):
                if key in sample:
                    result[key] = sample[key]
            if sample["image_kind"] == "BootKC-MH_FILESET":
                result["collection_sha256"] = sample["image_sha256"]
                result["collection_bytes"] = sample["image_bytes"]
            result["source_hashes"] = source_hashes
            result["candidate_selection"] = candidate_results
            result["selected_by_unique_production_pass"] = True
            outcomes.append(result)
    return outcomes


def verify(paths: list[Path], kernel_images: list[Path] | None = None,
           excerpts: list[Path] | None = None, save_excerpts: Path | None = None) -> dict[str, Any]:
    kernel_images = kernel_images or []
    excerpts = excerpts or []
    all_paths = paths + kernel_images + excerpts
    if not all_paths:
        raise VerificationError("pass an explicit --kernel-collection, --kernel-image or --contract-excerpt path")
    if save_excerpts is not None and (excerpts or save_excerpts.exists()):
        raise VerificationError("--save-excerpts requires image inputs only and a new directory")
    if len({str(path.resolve()) for path in all_paths}) != len(all_paths):
        raise VerificationError("duplicate kernel input path")
    wanted = collect_header_symbol_names()
    source_hashes = {
        "kernel_contracts.hpp": hashlib.sha256(CONTRACT_HEADER.read_bytes()).hexdigest(),
        "ifnet_profiles.hpp": hashlib.sha256(PROFILE_HEADER.read_bytes()).hexdigest(),
    }
    samples = [read_image(path, index, wanted) for index, path in enumerate(paths)]
    samples += [read_image(path, index, wanted, standalone=True)
                for index, path in enumerate(kernel_images)]
    samples += [read_excerpt(path, index, wanted) for index, path in enumerate(excerpts)]
    outcomes = run_host_verifier(samples, source_hashes)
    if save_excerpts is not None:
        save_excerpts.mkdir(parents=True, exist_ok=False)
        for sample in samples:
            (save_excerpts / f"{sample['label']}.json").write_bytes(excerpt_bytes(sample))
    return {
        "verification": "offline production C++ byte validators; excerpt inputs replay recorded metadata without reverifying the original image; not boot or Wi-Fi validation",
        "tool": str(Path(__file__).resolve()),
        "production_sources": source_hashes,
        "image_input_checks": [
            "explicit input kind: MH_FILESET with unique com.apple.kernel member, or standalone x86_64 MH_EXECUTE with unique readable header mapping",
            "LC_SYMTAB exact _ifnet_ioctl and symbol/alias target resolution",
            "__TEXT,__text bounds and actual file-backed function bytes",
        ] if paths or kernel_images else [],
        "checks": [
            "all registered production profiles probed per sample; exactly one production C++ validator must pass",
            "production IfnetProfiles::validate/validateMapped or validateIfnetCurrent/validateIfnetMappedTargets",
            "every individual byte mutation rejected with cleared plan",
            "every named resolved target changed by one rejected",
            "anonymous targets checked against supplied segment permissions (recorded metadata for excerpt inputs)",
            "translated base and all symbol targets pass under a test ASLR slide",
        ],
        "samples": outcomes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-collection", action="append", default=[], type=Path,
                        help="explicit BootKernelExtensions.kc path (repeat for multiple samples)")
    parser.add_argument("--kernel-image", action="append", default=[], type=Path,
                        help="explicit standalone x86_64 MH_EXECUTE kernel, for example a KDK release kernel")
    parser.add_argument("--contract-excerpt", action="append", default=[], type=Path,
                        help="replay saved bounded bytes/metadata; does not reverify the original kernel image")
    parser.add_argument("--save-excerpts", type=Path,
                        help="save image-derived bounded inputs in a new directory after verification")
    parser.add_argument("--output", type=Path, help="optional path for JSON results")
    args = parser.parse_args(argv)
    try:
        result = verify(args.kernel_collection, args.kernel_image, args.contract_excerpt, args.save_excerpts)
        result["status"] = "passed"
    except (VerificationError, OSError, ValueError, struct.error, subprocess.TimeoutExpired) as exc:
        result = {
            "verification": "offline explicit-image symbol/segment extraction plus production C++ byte validators; not a booted resolver or Wi-Fi validation",
            "status": "failed",
            "error": str(exc),
            "kernel_collections": [str(path) for path in args.kernel_collection],
            "kernel_images": [str(path) for path in args.kernel_image],
            "contract_excerpts": [str(path) for path in args.contract_excerpt],
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
