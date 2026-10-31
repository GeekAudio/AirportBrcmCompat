#!/usr/bin/env python3
"""Run the real read-only driver-pin initializer against NICs in dependency ZIPs."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile


PROJECT = Path(__file__).resolve().parents[1]
MAX_ZIP_MEMBERS = 4096
MAX_MEMBER_SIZE = 32 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_SIZE = 64 * 1024 * 1024
MAX_ARCHIVE_FILE_SIZE = 64 * 1024 * 1024
MAX_MACHO_FILE_SIZE = 32 * 1024 * 1024
MAX_MAPPED_IMAGE_SIZE = 64 * 1024 * 1024

TARGETS = {
    "Kexts/AirPortBrcmNIC-Sonoma-Sequoia.kext/Contents/MacOS/AirPortBrcmNIC":
        ("sonoma-sequoia", "AirPortBrcmNIC-Sonoma-Sequoia.kext"),
    "Kexts/AirPortBrcmNIC-Tahoe.kext/Contents/MacOS/AirPortBrcmNIC":
        ("tahoe", "AirPortBrcmNIC-Tahoe.kext"),
}

EXPECTED_PIN_OFFSETS = {
    "set_hardware_address": 0x38B96,
    "get_hardware_address": 0x38B7A,
    "iovar": 0x3824A,
    "get_state": 0x3B9CE,
    "find_bss_cfg": 0x2E314,
    "assoc_in_progress": 0x110309,
    "set_associate": 0x42B8E,
    "set_auth_type": 0x438F8,
}
EXPECTED_CALLER_OFFSETS = {
    "auth_caller_return": 0x43231,
    "associate_caller_return": 0x59A6A,
}

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
CPU_SUBTYPE_X86_64_ALL = 3
MH_KEXT_BUNDLE = 11
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
S_ATTR_PURE_INSTRUCTIONS = 0x80000000


class VerificationError(ValueError):
    """Refuse an input archive or Mach-O that cannot be verified safely."""


@dataclass(frozen=True)
class MappedMachO:
    data: bytes
    macho_uuid: str
    image_vmaddr: int
    image_span: int
    text_vmaddr: int
    text_fileoff: int
    text_size: int
    text_file_size: int


@dataclass(frozen=True)
class DriverArtifact:
    role: str
    bundle: str
    member: str
    archive_name: str
    archive_sha256: str
    binary_sha256: str
    binary: bytes


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_member_name(name: str) -> None:
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        raise VerificationError(f"Unsafe ZIP member path: {name!r}")
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise VerificationError(f"Unsafe ZIP member path: {name!r}")
    if len(parts[0]) >= 2 and parts[0][1] == ":":
        raise VerificationError(f"Unsafe ZIP member path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name:
        raise VerificationError(f"Unsafe ZIP member path: {name!r}")


def _read_zip_members(path: Path) -> tuple[dict[str, bytes], str]:
    path = Path(path)
    if path.is_symlink():
        raise VerificationError("Dependency ZIP paths must not be symlinks")
    try:
        resolved = path.resolve(strict=True)
        if resolved.stat().st_size > MAX_ARCHIVE_FILE_SIZE:
            raise VerificationError("Dependency ZIP exceeds the compressed-size limit")
        with resolved.open("rb") as source:
            archive_bytes = source.read(MAX_ARCHIVE_FILE_SIZE + 1)
        if len(archive_bytes) > MAX_ARCHIVE_FILE_SIZE:
            raise VerificationError("Dependency ZIP exceeds the compressed-size limit")
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_MEMBERS:
                raise VerificationError("Dependency ZIP has too many members")
            names: set[str] = set()
            total_size = 0
            for info in infos:
                name = info.filename
                _validate_member_name(name)
                if name in names:
                    raise VerificationError(f"Duplicate ZIP member: {name}")
                names.add(name)
                if info.is_dir():
                    raise VerificationError(f"Directory ZIP member is not accepted: {name}")
                if info.flag_bits & 0x1:
                    raise VerificationError(f"Encrypted ZIP member is not accepted: {name}")
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise VerificationError(f"Unsupported ZIP compression method: {name}")
                if info.file_size > MAX_MEMBER_SIZE:
                    raise VerificationError(f"Oversized ZIP member: {name}")
                total_size += info.file_size
                if total_size > MAX_ARCHIVE_EXPANDED_SIZE:
                    raise VerificationError("Expanded dependency ZIP exceeds the size limit")
                mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if file_type == stat.S_IFLNK:
                    raise VerificationError(f"Symlink ZIP member is not accepted: {name}")
                if file_type not in (0, stat.S_IFREG):
                    raise VerificationError(f"Non-regular ZIP member is not accepted: {name}")

            members: dict[str, bytes] = {}
            for info in infos:
                if info.filename not in TARGETS:
                    continue
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise VerificationError(f"ZIP member size mismatch: {info.filename}")
                members[info.filename] = data
        return members, sha256(archive_bytes)
    except VerificationError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise VerificationError(f"Cannot read dependency ZIP: {path}") from exc


def _decode_name(raw: bytes) -> str:
    try:
        return raw.split(b"\0", 1)[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise VerificationError("Mach-O segment or section name is not ASCII") from exc


def map_thin_x86_64_macho(data: bytes) -> MappedMachO:
    """Map a thin Mach-O file into a zero-filled buffer by segment VM address."""
    if not isinstance(data, bytes) or len(data) < 32:
        raise VerificationError("Mach-O input is truncated")
    if len(data) > MAX_MACHO_FILE_SIZE:
        raise VerificationError("Mach-O file exceeds the size limit")
    magic, cpu, subtype, filetype, ncmds, sizeofcmds, _flags, _reserved = \
        struct.unpack_from("<IiiIIIII", data, 0)
    if (magic != MH_MAGIC_64 or cpu != CPU_TYPE_X86_64 or
            subtype != CPU_SUBTYPE_X86_64_ALL or filetype != MH_KEXT_BUNDLE):
        raise VerificationError("Expected a thin x86_64 MH_KEXT_BUNDLE Mach-O")
    commands_end = 32 + sizeofcmds
    if commands_end > len(data) or ncmds == 0 or ncmds > sizeofcmds // 8:
        raise VerificationError("Mach-O load commands exceed the file bounds")

    cursor = 32
    segments = []
    uuid_bytes = None
    text_sections = []
    for _ in range(ncmds):
        if cursor + 8 > commands_end:
            raise VerificationError("Truncated Mach-O load command")
        command, command_size = struct.unpack_from("<II", data, cursor)
        if (command_size < 8 or command_size % 8 or
                cursor + command_size > commands_end):
            raise VerificationError("Invalid Mach-O load command size")
        if command == LC_UUID:
            if command_size != 24 or uuid_bytes is not None:
                raise VerificationError("Invalid or duplicate Mach-O UUID command")
            uuid_bytes = data[cursor + 8:cursor + 24]
        elif command == LC_SEGMENT_64:
            if command_size < 72:
                raise VerificationError("Truncated LC_SEGMENT_64")
            (_cmd, _cmdsize, raw_name, vmaddr, vmsize, fileoff, filesize,
             _maxprot, _initprot, nsects, _segment_flags) = struct.unpack_from(
                "<II16sQQQQiiII", data, cursor)
            segment_name = _decode_name(raw_name)
            if (filesize > vmsize or vmaddr > 0xFFFFFFFFFFFFFFFF - vmsize or
                    fileoff > len(data) or filesize > len(data) - fileoff):
                raise VerificationError(f"Invalid segment bounds: {segment_name}")
            if nsects > (command_size - 72) // 80 or 72 + nsects * 80 != command_size:
                raise VerificationError(f"Invalid section table: {segment_name}")
            segments.append({"name": segment_name, "vmaddr": vmaddr,
                             "vmsize": vmsize, "fileoff": fileoff,
                             "filesize": filesize})
            for section_index in range(nsects):
                section_offset = cursor + 72 + section_index * 80
                (raw_section_name, raw_section_segment, address, size, section_fileoff,
                 _align, _reloff, _nreloc, section_flags, _reserved1, _reserved2,
                 _reserved3) = struct.unpack_from("<16s16sQQIIIIIIII", data,
                                                   section_offset)
                section_name = _decode_name(raw_section_name)
                section_segment = _decode_name(raw_section_segment)
                if (address < vmaddr or size > vmaddr + vmsize - address):
                    raise VerificationError(f"Section lies outside segment: {section_name}")
                section_type = section_flags & 0xFF
                zero_fill = section_type in (0x1, 0xC, 0x12)
                if not zero_fill and (section_fileoff < fileoff or
                                      section_fileoff > fileoff + filesize or
                                      size > fileoff + filesize - section_fileoff):
                    raise VerificationError(f"Section file range is outside segment: {section_name}")
                if section_name == "__text" and section_segment == "__TEXT":
                    text_sections.append({"address": address, "size": size,
                                          "fileoff": section_fileoff,
                                          "flags": section_flags})
        cursor += command_size
    if cursor != commands_end or uuid_bytes is None:
        raise VerificationError("Mach-O has an incomplete command table or no UUID")

    text_segments = [segment for segment in segments if segment["name"] == "__TEXT"]
    if len(text_segments) != 1 or len(text_sections) != 1:
        raise VerificationError("Mach-O must have one __TEXT segment and one __text section")
    text = text_segments[0]
    if text["fileoff"] != 0 or text["filesize"] < commands_end:
        raise VerificationError("Mach-O header is not mapped at the __TEXT base")
    section = text_sections[0]
    if (section["address"] - text["vmaddr"] != section["fileoff"] or
            not section["size"] or not section["flags"] & S_ATTR_PURE_INSTRUCTIONS):
        raise VerificationError("Mach-O __text file/VM mapping is not directly verifiable")

    image_base = text["vmaddr"]
    spans = []
    image_end = image_base
    for segment in segments:
        if segment["vmaddr"] < image_base:
            raise VerificationError("Segment precedes the __TEXT image base")
        start = segment["vmaddr"]
        end = start + segment["vmsize"]
        if end > start:
            spans.append((start, end, segment["name"]))
        image_end = max(image_end, end)
    spans.sort()
    for previous, current in zip(spans, spans[1:]):
        if previous[1] > current[0]:
            raise VerificationError(f"Overlapping Mach-O segments: {previous[2]}, {current[2]}")
    image_span = image_end - image_base
    if image_span > MAX_MAPPED_IMAGE_SIZE:
        raise VerificationError("Mapped Mach-O image exceeds the size limit")

    mapped = bytearray(image_span)
    for segment in segments:
        start = segment["vmaddr"] - image_base
        mapped[start:start + segment["filesize"]] = data[
            segment["fileoff"]:segment["fileoff"] + segment["filesize"]]
    uuid_hex = uuid_bytes.hex()
    canonical_uuid = "-".join((uuid_hex[0:8], uuid_hex[8:12], uuid_hex[12:16],
                               uuid_hex[16:20], uuid_hex[20:32])).upper()
    return MappedMachO(bytes(mapped), canonical_uuid, image_base, image_span,
                       text["vmaddr"], text["fileoff"], section["size"], text["filesize"])


def verify_chipmatch(data: bytes, mapped: MappedMachO) -> dict:
    """Inspect the device-table success path without executing driver code."""
    wanted = {b"_wlc_chipmatch", b"_wlc_devid"}
    found = {}
    symtab = None
    cursor = 32
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        kind, size = struct.unpack_from("<II", data, cursor)
        if kind == 2:  # LC_SYMTAB; the image mapper already checked commands.
            if symtab is not None or size != 24:
                raise VerificationError("Invalid chipmatch symbol table")
            symtab = struct.unpack_from("<IIII", data, cursor + 8)
        cursor += size
    if symtab is None:
        raise VerificationError("Missing chipmatch symbol table")
    symoff, count, stroff, strsize = symtab
    if (symoff > len(data) or count > (len(data)-symoff)//16 or
            stroff > len(data) or strsize > len(data)-stroff):
        raise VerificationError("Chipmatch symbols exceed file bounds")
    for index in range(count):
        nameoff, kind, section, _desc, value = struct.unpack_from("<IBBHQ", data, symoff + index*16)
        if kind & 0xe0 or (kind & 0x0e) != 0x0e or not section:
            continue
        if nameoff >= strsize:
            raise VerificationError("Invalid chipmatch symbol name")
        end = data.find(b"\0", stroff + nameoff, stroff + strsize)
        if end < 0:
            raise VerificationError("Unterminated chipmatch symbol name")
        name = data[stroff+nameoff:end]
        if name in wanted:
            if name in found:
                raise VerificationError("Duplicate chipmatch symbol")
            found[name] = value
    if set(found) != wanted:
        raise VerificationError("Missing chipmatch function or device table")

    def read(address, size):
        offset = address-mapped.image_vmaddr
        if offset < 0 or offset > len(mapped.data) or size > len(mapped.data)-offset:
            raise VerificationError("Chipmatch range exceeds mapped image")
        return mapped.data[offset:offset+size]

    function, table = found[b"_wlc_chipmatch"], found[b"_wlc_devid"]
    body_size = 0xc7
    if (function < mapped.text_vmaddr + 0x990 or
            function + body_size > mapped.text_vmaddr + 0x990 + mapped.text_size):
        raise VerificationError("Chipmatch function is outside code")
    body = read(function, body_size)
    prefix = bytes.fromhex(
        "554889e541574156535081ffe4140000755f31c0488d0d00000000"
        "663934080f84910000004883c002483dd400000075ea")
    normalized = bytearray(body[:len(prefix)])
    normalized[0x17:0x1b] = b"\0"*4
    success = bytes.fromhex("41b6014489f04883c4085b415e415f5dc3")
    if bytes(normalized) != prefix or body[0xb6:] != success:
        raise VerificationError("Unknown chipmatch table lookup or success path")
    displacement = struct.unpack_from("<i", body, 0x17)[0]
    if function + 0x1b + displacement != table:
        raise VerificationError("Chipmatch lookup does not use the resolved device table")
    table_bytes = read(table, 0xd4)
    devices = set(struct.unpack("<106H", table_bytes))
    required = ("43ba", "43a3", "43a0", "4357", "43b1", "43b2")
    if any(int(device, 16) not in devices for device in required):
        raise VerificationError("Modern NIC ID is absent from the driver's device table")
    return {"table_entries": 106, "table_sha256": sha256(table_bytes),
            "function_sha256": sha256(body),
            "accepted_pci_ids": ["14e4:"+device for device in required],
            "driver_function_invoked": False,
            "scope": "Vendor 14e4 and listed device IDs reach the checked chipmatch success return; firmware and RF functionality are not established."}


def _host_harness_source() -> str:
    return r'''#include "pinned_driver.hpp"
#include <stdint.h>
#include <stdio.h>
#include <fstream>
#include <iterator>
#include <vector>

template <typename T> static uintptr_t address(T function) {
    return reinterpret_cast<uintptr_t>(function);
}

int main(int argc, char **argv) {
    if (argc != 2) return 90;
    std::ifstream input(argv[1], std::ios::binary);
    std::vector<uint8_t> image((std::istreambuf_iterator<char>(input)), {});
    if (image.empty()) return 91;
    PrivateMAC::DriverPins pins;
    const auto status = PrivateMAC::initializeDriverPins(image.data(), image.size(), pins);
    const uintptr_t base = reinterpret_cast<uintptr_t>(image.data());
    printf("status=%d\n", static_cast<int>(status));
    printf("offsets=%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx\n",
        static_cast<unsigned long>(address(pins.setHardwareAddress) - base),
        static_cast<unsigned long>(address(pins.getHardwareAddress) - base),
        static_cast<unsigned long>(address(pins.iovar) - base),
        static_cast<unsigned long>(address(pins.getState) - base),
        static_cast<unsigned long>(address(pins.findBssCfg) - base),
        static_cast<unsigned long>(address(pins.assocInProgress) - base),
        static_cast<unsigned long>(address(pins.setAssociate) - base),
        static_cast<unsigned long>(address(pins.setAuthType) - base));
    printf("callers=%lx,%lx\n",
        static_cast<unsigned long>(pins.authCallerReturn - base),
        static_cast<unsigned long>(pins.associateCallerReturn - base));
    printf("nonnull=%u\n",
        unsigned(pins.setHardwareAddress != nullptr) +
        unsigned(pins.getHardwareAddress != nullptr) + unsigned(pins.iovar != nullptr) +
        unsigned(pins.getState != nullptr) + unsigned(pins.findBssCfg != nullptr) +
        unsigned(pins.assocInProgress != nullptr) + unsigned(pins.setAssociate != nullptr) +
        unsigned(pins.setAuthType != nullptr));
    return 0;
}
'''


def _parse_harness_result(stdout: str) -> dict:
    fields = {}
    for line in stdout.splitlines():
        if "=" not in line:
            raise VerificationError("Host pin harness returned malformed output")
        key, value = line.split("=", 1)
        if key in fields:
            raise VerificationError("Host pin harness returned duplicate fields")
        fields[key] = value
    try:
        status = int(fields["status"])
        pin_offsets = [int(value, 16) for value in fields["offsets"].split(",")]
        caller_offsets = [int(value, 16) for value in fields["callers"].split(",")]
        nonnull = int(fields["nonnull"])
    except (KeyError, ValueError) as exc:
        raise VerificationError("Host pin harness output is incomplete") from exc
    return {"status": status, "pin_offsets": pin_offsets,
            "caller_offsets": caller_offsets, "nonnull": nonnull}


def _compile_harness(temp_dir: Path) -> Path:
    compiler = shutil.which("clang++")
    if not compiler:
        raise VerificationError("clang++ is required for the host pin harness")
    source = temp_dir / "verify_driver_pins.cpp"
    executable = temp_dir / "verify_driver_pins"
    source.write_text(_host_harness_source())
    command = [compiler, "-std=c++14", "-Wall", "-Wextra", "-Werror",
               "-I", str(PROJECT / "src/private_mac_compat"), str(source),
               str(PROJECT / "src/private_mac_compat/pinned_driver.cpp"),
               "-o", str(executable)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise VerificationError(f"Could not build host pin harness: {detail}")
    return executable


def verify_dependencies(paths: list[Path]) -> dict:
    if not paths:
        raise VerificationError("Provide at least one --dependencies ZIP")
    resolved_paths = []
    for path in paths:
        candidate = Path(path)
        if candidate.is_symlink():
            raise VerificationError("Dependency ZIP paths must not be symlinks")
        resolved = candidate.resolve(strict=True)
        if resolved in resolved_paths:
            raise VerificationError("The same dependency ZIP was provided more than once")
        resolved_paths.append(resolved)

    artifacts: list[DriverArtifact] = []
    archive_records = []
    for path in resolved_paths:
        members, archive_hash = _read_zip_members(path)
        if not members:
            raise VerificationError(f"No supported AirPortBrcmNIC driver in {path.name}")
        archive_records.append({"name": path.name, "sha256": archive_hash})
        for member, data in sorted(members.items()):
            role, bundle = TARGETS[member]
            if not data:
                raise VerificationError(f"Empty NIC executable: {member}")
            artifacts.append(DriverArtifact(role, bundle, member, path.name,
                                            archive_hash, sha256(data), data))

    by_role: dict[str, list[DriverArtifact]] = {}
    for artifact in artifacts:
        by_role.setdefault(artifact.role, []).append(artifact)
    missing_roles = sorted(set(role for role, _ in TARGETS.values()) - set(by_role))
    if missing_roles:
        raise VerificationError(f"Missing modern NIC variant(s): {', '.join(missing_roles)}")
    for role, variants in by_role.items():
        hashes = {item.binary_sha256 for item in variants}
        if len(hashes) != 1:
            raise VerificationError(f"Conflicting {role} driver binaries in dependency ZIPs")

    unique_variants = []
    for role in sorted(by_role):
        unique_variants.append(by_role[role][0])

    compiler = shutil.which("clang++")
    if not compiler:
        raise VerificationError("clang++ is required for the host pin harness")
    variant_results = []
    with tempfile.TemporaryDirectory(prefix="verify-modern-driver-pins-") as temporary:
        temp_dir = Path(temporary)
        harness = _compile_harness(temp_dir)
        for artifact in unique_variants:
            mapped = map_thin_x86_64_macho(artifact.binary)
            chipmatch = verify_chipmatch(artifact.binary, mapped)
            mapped_path = temp_dir / f"{artifact.role}.mapped-image"
            mapped_path.write_bytes(mapped.data)
            result = subprocess.run([str(harness), str(mapped_path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)
            if result.returncode:
                detail = (result.stderr or result.stdout).strip()
                raise VerificationError(f"Host pin harness failed for {artifact.role}: {detail}")
            parsed = _parse_harness_result(result.stdout)
            expected_pins = list(EXPECTED_PIN_OFFSETS.values())
            expected_callers = list(EXPECTED_CALLER_OFFSETS.values())
            if (parsed["status"] != 0 or parsed["nonnull"] != len(expected_pins) or
                    parsed["pin_offsets"] != expected_pins or
                    parsed["caller_offsets"] != expected_callers):
                raise VerificationError(
                    f"initializeDriverPins did not accept the audited {artifact.role} image: "
                    f"status={parsed['status']}, pins={parsed['pin_offsets']}, "
                    f"callers={parsed['caller_offsets']}, nonnull={parsed['nonnull']}")
            variant_results.append({
                "role": artifact.role,
                "bundle": artifact.bundle,
                "member": artifact.member,
                "binary_sha256": artifact.binary_sha256,
                "macho_uuid": mapped.macho_uuid,
                "chipmatch": chipmatch,
                "mapped_image_span_bytes": mapped.image_span,
                "text_mapping": {
                    "image_vmaddr": hex(mapped.image_vmaddr),
                    "text_vmaddr": hex(mapped.text_vmaddr),
                    "text_fileoff": hex(mapped.text_fileoff),
                    "text_file_size": hex(mapped.text_file_size),
                    "text_section_size": hex(mapped.text_size),
                },
                "checked_source_zips": [
                    {"name": item.archive_name, "sha256": item.archive_sha256}
                    for item in by_role[artifact.role]
                ],
                "initialize_driver_pins_status": parsed["status"],
                "nonnull_pin_count": parsed["nonnull"],
                "pin_offsets": {
                    key: hex(value) for key, value in zip(EXPECTED_PIN_OFFSETS,
                                                          parsed["pin_offsets"])
                },
                "caller_offsets": {
                    key: hex(value) for key, value in zip(EXPECTED_CALLER_OFFSETS,
                                                          parsed["caller_offsets"])
                },
                "driver_function_pointers_invoked": False,
            })

    return {
        "schema": 1,
        "tool": "verify_modern_driver_pins",
        "scope": "offline host validation of the actual initializeDriverPins implementation",
        "inputs": archive_records,
        "required_variants_present": sorted(by_role),
        "variants": variant_results,
        "checks": {
            "all_required_variants_present": True,
            "all_pin_initializers_passed": True,
            "all_published_offsets_match_contract": True,
            "all_modern_ids_in_chipmatch_tables": True,
            "driver_function_pointers_invoked": False,
            "kernel_kext_loaded": False,
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependencies", type=Path, action="append", required=True,
                        help="dependency ZIP; repeat for each separate profile ZIP")
    parser.add_argument("--output-json", type=Path, required=True,
                        help="write the offline verification result to this JSON file")
    args = parser.parse_args(argv)
    try:
        report = verify_dependencies(args.dependencies)
        output = Path(args.output_json).absolute()
        if output.is_symlink():
            raise VerificationError("Output JSON path must not be a symlink")
        if output.resolve() in [Path(p).resolve() for p in args.dependencies]:
            raise VerificationError("Output JSON must not overwrite a dependency ZIP")
        output.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp",
                                              dir=output.parent)
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            os.chmod(temporary, 0o644)
            os.replace(temporary, output)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        print(f"Wrote {output}")
        print(f"Verified variants: {', '.join(report['required_variants_present'])}")
        print(f"ZIP inputs: {len(report['inputs'])}")
    except (OSError, subprocess.SubprocessError, VerificationError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
