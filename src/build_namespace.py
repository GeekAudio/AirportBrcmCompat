#!/usr/bin/env python3
"""Build a local, isolated legacy Skywalk experiment. Never installs or loads kexts.

Usage: python3 src/build_namespace.py --legacy-dir PATH --native-kernel-collection PATH
       --native-fileset-entry com.apple.iokit.IOSkywalkFamily
       --dependency-profile tahoe --output NEW_DIRECTORY
Requires macOS nm, codesign and exact OCLP dependency binaries pinned below.
An explicit native IOSkywalkFamily bundle or kernel-collection fileset entry is
used only as a symbol-collision sample; its provenance is recorded in the manifest.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path

OLD_ID = "com.apple.iokit.IOSkywalkFamily"
NEW_ID = "org.geekaudio.IOLegacyWFamilyKC"
INFO_SHA256 = {
    "IOSkywalkFamily.kext": "ca6a6329f2a69b6b656dcb6913531c904a28b9452cf267e055e1f8276a8a1bd3",
    "IO80211FamilyLegacy.kext": "e3db7231dce8d4bb5430785ccb6049ef3e329abbac4f6fcbc878a6a3a0792257",
    "AirPortBrcmNIC-Tahoe.kext": "545db395be05d1fa96c98e00fab1c8cacffa13e5f50ca832b6a5a79516d99514",
}
# Equal lengths preserve Itanium type-name lengths, section offsets and relocations.
# Bundle ID goes first, before its IOSkywalk substring is renamed.
RENAMES = (
    (OLD_ID.encode(), NEW_ID.encode()),
    (b"IOSkywalk", b"IOLegacyW"),
    (b"IOUserNetwork", b"IOLgcyNetwork"),
    (b"_IOSKFlagsToIOUNHWAssistFlags", b"_LGSKFlagsToLGUNHWAssistFlags"),
    (b"_IOUNHWAssistFlagsToIOSKFlags", b"_LGUNHWAssistFlagsToLGSKFlags"),
    (b"gIONetworkTxSubmit", b"gLGNetworkTxSubmit"),
)
COMMON_SAMPLES = (
    ("IOSkywalkFamily.kext", "IOLegacyWFamily.kext", "0484ecd97d1bdb8759aef72661c196cda4309697eea1945a4a3c4d5e6d7e5e5b"),
    ("IO80211FamilyLegacy.kext", "IO80211FamilyLegacy.kext", "ac2dc15b77f8eaf97b71b34c5d0e1b59f862bfeac618396449306e1837e73894"),
)
AIRPORT_BRCM_NIC_INFO_SHA256 = "545db395be05d1fa96c98e00fab1c8cacffa13e5f50ca832b6a5a79516d99514"
AIRPORT_BRCM_NIC_BUNDLE_ID = "com.apple.driver.AirPort.BrcmNIC"
AIRPORT_BRCM_NIC_VERSION = "1400.1.1"

DEPENDENCY_PROFILES = {
    "sonoma-sequoia": {
        "display_name": "Sonoma and Sequoia",
        "min_kernel": "23.0.0",
        "max_kernel": "24.99.99",
        "brcm_source": ("IO80211FamilyLegacy.kext", "Contents", "PlugIns",
                        "AirPortBrcmNIC.kext"),
        "brcm_bundle": "AirPortBrcmNIC-Sonoma-Sequoia.kext",
        "brcm_binary_sha256": "884e90b27cff151e432bb36275936f57b43e72419e95b51b3ac067d3f2ccd331",
        "brcm_info_sha256": AIRPORT_BRCM_NIC_INFO_SHA256,
        "asset_profile": "OCLP IO80211FamilyLegacy nested AirPortBrcmNIC",
    },
    "tahoe": {
        "display_name": "Tahoe",
        "min_kernel": "25.0.0",
        "max_kernel": "",
        "brcm_source": ("AirPortBrcmNIC-Tahoe.kext",),
        "brcm_bundle": "AirPortBrcmNIC-Tahoe.kext",
        "brcm_binary_sha256": "0b6cf936e594d1372960a60c8f17b6cbf68e3535a191574bd91498da49713775",
        "brcm_info_sha256": AIRPORT_BRCM_NIC_INFO_SHA256,
        "asset_profile": "OCLP standalone AirPortBrcmNIC-Tahoe",
    },
}
DEFAULT_PROFILE = "tahoe"

# The only private namespace imports which are not direct staged exports are
# three inherited C++ virtual slots. They are accepted only for the pinned
# provider, IO80211 consumer, and profile-specific AirPortBrcmNIC inputs after
# verifying each class-parent link and all four vtables at the recorded slots.
INHERITED_VTABLE_METHODS = (
    {
        "undefined_symbol": "__ZN26IOLegacyWEthernetInterface18getHardwareAddressEP12ether_addr_t",
        "parent_implementation_symbol": "__ZN26IOLegacyWEthernetInterface18getHardwareAddressEP10ether_addr",
        "slot": 334,
    },
    {
        "undefined_symbol": "__ZN26IOLegacyWEthernetInterface19setLinkLayerAddressEP12ether_addr_t",
        "parent_implementation_symbol": "__ZN26IOLegacyWEthernetInterface19setLinkLayerAddressEP10ether_addr",
        "slot": 336,
    },
    {
        "undefined_symbol": "__ZN26IOLegacyWEthernetInterface21setMulticastAddressesEPK12ether_addr_tj",
        "parent_implementation_symbol": "__ZN26IOLegacyWEthernetInterface21setMulticastAddressesEPK10ether_addrj",
        "slot": 338,
    },
)
PRIVATE_SYMBOL_MARKERS = (
    "IOLegacyW", "IOLgcyNetwork", "LGSKFlagsToLGUNHWAssistFlags",
    "LGUNHWAssistFlagsToLGSKFlags", "gLGNetworkTxSubmit",
)


@dataclass(frozen=True)
class Original:
    source: Path
    destination: str
    info: dict
    binary: Path
    raw: bytes
    info_sha256: str
    source_label: str


class BuildError(RuntimeError):
    pass


def run(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise BuildError(f"{args[0]} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dependency_profile(name: str | None = None) -> dict:
    selected = DEFAULT_PROFILE if name is None else name
    try:
        return dict(DEPENDENCY_PROFILES[selected])
    except KeyError as error:
        choices = ", ".join(DEPENDENCY_PROFILES)
        raise BuildError(f"Unknown dependency profile {selected!r}; choose {choices}") from error


def resolve_profile_brcm_source(legacy_dir: Path, profile_name: str | None = None) -> Path:
    profile = dependency_profile(profile_name)
    return Path(legacy_dir).joinpath(*profile["brcm_source"])


def pinned_bundle(legacy_dir: Path, relative_parts: tuple[str, ...], destination: str,
                  expected_binary_sha256: str, expected_info_sha256: str,
                  source_label: str, expected_bundle_id: str | None = None,
                  expected_version: str | None = None) -> Original:
    root = Path(legacy_dir).resolve()
    source = root.joinpath(*relative_parts)
    try:
        source.resolve().relative_to(root)
    except ValueError as error:
        raise BuildError("Pinned bundle path escapes the dependency directory") from error
    if source.is_symlink() or not source.is_dir():
        raise BuildError(f"Missing or symlink pinned bundle: {source_label}")
    if any(path.is_symlink() for path in source.rglob("*")):
        raise BuildError(f"Symlinks in source kext are not accepted: {source_label}")
    info, binary = executable(source)
    raw = binary.read_bytes()
    if digest(raw) != expected_binary_sha256:
        raise BuildError(f"Pinned binary hash mismatch: {source_label}")
    info_hash = digest((source / "Contents/Info.plist").read_bytes())
    if info_hash != expected_info_sha256:
        raise BuildError(f"Pinned metadata hash mismatch: {source_label}")
    if expected_bundle_id and info.get("CFBundleIdentifier") != expected_bundle_id:
        raise BuildError(f"Unexpected bundle identifier: {source_label}")
    if expected_version and info.get("CFBundleVersion") != expected_version:
        raise BuildError(f"Unexpected bundle version: {source_label}")
    macho(raw)
    return Original(source, destination, info, binary, raw, info_hash, source_label)


def native_sample(native_bundle: Path, label: str | None = None) -> tuple[dict, Path, bytes, dict]:
    native_bundle = Path(native_bundle)
    if native_bundle.is_symlink() or not native_bundle.is_dir():
        raise BuildError("Native Skywalk sample must be an explicit kext bundle directory")
    info, binary = executable(native_bundle)
    if info.get("CFBundleIdentifier") != OLD_ID:
        raise BuildError("Native sample is not com.apple.iokit.IOSkywalkFamily")
    raw = binary.read_bytes()
    macho(raw)
    metadata = {
        "sample_kind": "standalone-kext-bundle",
        "label": label or "explicit IOSkywalkFamily sample",
        "bundle_id": info.get("CFBundleIdentifier"),
        "bundle_version": info.get("CFBundleVersion"),
        "sdk_name": info.get("DTSDKName"),
        "info_sha256": digest((native_bundle / "Contents/Info.plist").read_bytes()),
        "executable_sha256": digest(raw),
    }
    return info, binary, raw, metadata


def kernel_collection_symbols(collection: Path, entry_id: str,
                              label: str | None = None) -> tuple[set[str], dict]:
    """Read one x86_64 MH_KEXT_BUNDLE's exported nlist symbols from an MH_FILESET.

    Kernel collections preserve child load-command file offsets in container
    coordinates. Parse those coordinates directly instead of manufacturing a
    standalone Mach-O whose header would no longer be byte-identical to the
    child recorded by the collection.
    """
    collection = Path(collection)
    if collection.is_symlink() or not collection.is_file():
        raise BuildError("Native kernel collection must be an explicit regular file")
    data = collection.read_bytes()
    if len(data) < 32:
        raise BuildError("Truncated native kernel collection")

    def header_at(offset: int, expected_filetype: int, description: str):
        if offset < 0 or offset + 32 > len(data):
            raise BuildError(f"{description} header outside kernel collection")
        magic, cpu, _, filetype, ncmds, cmdbytes, _, _ = struct.unpack_from("<8I", data, offset)
        if (magic, cpu, filetype) != (0xFEEDFACF, 0x1000007, expected_filetype):
            raise BuildError(f"Expected x86_64 {description} Mach-O")
        command_end = offset + 32 + cmdbytes
        if command_end > len(data) or ncmds > cmdbytes // 8:
            raise BuildError(f"Invalid {description} load-command bounds")
        return ncmds, command_end

    outer_count, outer_end = header_at(0, 0xC, "MH_FILESET")
    matches = []
    cursor = 32
    for _ in range(outer_count):
        if cursor + 8 > outer_end:
            raise BuildError("Truncated kernel-collection load command")
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmdsize < 8 or cmdsize % 8 or cursor + cmdsize > outer_end:
            raise BuildError("Invalid kernel-collection load-command size")
        if cmd == 0x80000035:  # LC_FILESET_ENTRY
            if cmdsize < 32:
                raise BuildError("Truncated LC_FILESET_ENTRY")
            _, fileoff = struct.unpack_from("<QQ", data, cursor + 8)
            name_offset = struct.unpack_from("<I", data, cursor + 24)[0]
            if name_offset < 32 or name_offset >= cmdsize:
                raise BuildError("Invalid fileset-entry identifier bounds")
            name_end = data.find(b"\0", cursor + name_offset, cursor + cmdsize)
            if name_end < 0:
                raise BuildError("Unterminated fileset-entry identifier")
            name = data[cursor + name_offset:name_end].decode("utf-8", errors="strict")
            if name == entry_id:
                matches.append(fileoff)
        cursor += cmdsize
    if cursor != outer_end:
        raise BuildError("Inconsistent kernel-collection load commands")
    if len(matches) != 1:
        reason = "not found" if not matches else "not unique"
        raise BuildError(f"Fileset entry {entry_id!r} {reason}")
    child_offset = matches[0]
    child_count, child_end = header_at(child_offset, 11, "MH_KEXT_BUNDLE fileset child")

    symtab = None
    uuid_bytes = None
    linkedit = None
    command = child_offset + 32
    for _ in range(child_count):
        if command + 8 > child_end:
            raise BuildError("Truncated fileset-child load command")
        cmd, cmdsize = struct.unpack_from("<II", data, command)
        if cmdsize < 8 or cmdsize % 8 or command + cmdsize > child_end:
            raise BuildError("Invalid fileset-child load-command size")
        if cmd == 0x19:  # LC_SEGMENT_64
            if cmdsize < 72:
                raise BuildError("Truncated fileset-child segment")
            name = data[command + 8:command + 24].split(b"\0", 1)[0].decode("ascii")
            fileoff, filesize = struct.unpack_from("<QQ", data, command + 40)
            if filesize and (fileoff < child_offset or fileoff + filesize > len(data)):
                raise BuildError("Fileset-child segment outside its kernel collection")
            if name == "__LINKEDIT":
                linkedit = (fileoff, fileoff + filesize)
        elif cmd == 2:  # LC_SYMTAB
            if cmdsize != 24 or symtab is not None:
                raise BuildError("Invalid or duplicate fileset-child symbol table")
            _, _, symoff, nsyms, stroff, strsize = struct.unpack_from("<6I", data, command)
            symtab = (symoff, nsyms, stroff, strsize)
        elif cmd == 0x1B:  # LC_UUID
            if cmdsize != 24 or uuid_bytes is not None:
                raise BuildError("Invalid or duplicate fileset-child UUID")
            uuid_bytes = data[command + 8:command + 24]
        command += cmdsize
    if command != child_end or symtab is None or uuid_bytes is None or linkedit is None:
        raise BuildError("Fileset child lacks a complete symbol table, UUID, or __LINKEDIT")

    symoff, nsyms, stroff, strsize = symtab
    sym_end = symoff + nsyms * 16
    str_end = stroff + strsize
    if (symoff < linkedit[0] or sym_end > linkedit[1] or
            stroff < linkedit[0] or str_end > linkedit[1] or str_end > len(data)):
        raise BuildError("Fileset-child symbol table outside __LINKEDIT")
    strings = data[stroff:str_end]
    exports = set()
    for index in range(nsyms):
        string_index, n_type, _, _, _ = struct.unpack_from("<IBBHQ", data, symoff + index * 16)
        # Mach-O nlist_64: ignore STAB/debug and undefined symbols, matching nm -gU.
        if n_type & 0xE0 or not (n_type & 0x01) or (n_type & 0x0E) in (0, 0x0C):
            continue
        if string_index == 0 or string_index >= len(strings):
            raise BuildError("Invalid fileset-child symbol string index")
        terminator = strings.find(b"\0", string_index)
        if terminator < 0:
            raise BuildError("Unterminated fileset-child symbol name")
        name = strings[string_index:terminator].decode("utf-8", errors="strict")
        if name:
            exports.add(name)
    if not exports:
        raise BuildError("Native fileset child has no defined external symbols")
    child_header = data[child_offset:child_offset + 32]
    child_commands = data[child_offset + 32:child_end]
    metadata = {
        "sample_kind": "kernel-collection-fileset-entry",
        "label": label or "explicit IOSkywalkFamily kernel-collection sample",
        "container_filename": collection.name,
        "container_size_bytes": len(data),
        "container_sha256": digest(data),
        "fileset_entry_id": entry_id,
        "fileset_entry_file_offset": child_offset,
        "macho_uuid": str(uuid.UUID(bytes=uuid_bytes)).upper(),
        "macho_header_sha256": digest(child_header),
        "macho_load_commands_sha256": digest(child_commands),
        "defined_external_symbol_count": len(exports),
    }
    return exports, metadata


def rename(data: bytes) -> bytes:
    for old, new in RENAMES:
        if len(old) != len(new):
            raise BuildError("Namespace replacements must have equal byte lengths")
        data = data.replace(old, new)
    return data


def rename_plist(value):
    if isinstance(value, str):
        return rename(value.encode()).decode()
    if isinstance(value, dict):
        pairs = [(rename_plist(k), rename_plist(v)) for k, v in value.items()]
        if len({k for k, _ in pairs}) != len(pairs):
            raise BuildError("Plist key collision after renaming")
        return dict(pairs)
    if isinstance(value, list):
        return [rename_plist(v) for v in value]
    return value


def macho(data: bytes) -> dict:
    """Strict parser for the pinned thin x86_64 MH_KEXT_BUNDLE samples."""
    if len(data) < 32:
        raise BuildError("Truncated Mach-O header")
    magic, cpu, _, filetype, ncmds, cmdbytes, _, _ = struct.unpack_from("<8I", data)
    if (magic, cpu, filetype) != (0xFEEDFACF, 0x1000007, 11):
        raise BuildError("Expected a thin x86_64 MH_KEXT_BUNDLE")
    end = 32 + cmdbytes
    if end > len(data) or ncmds > cmdbytes // 8:
        raise BuildError("Invalid load-command bounds")
    result = {"sections": [], "strtab": None, "signature": None}
    off = 32
    for _ in range(ncmds):
        if off + 8 > end:
            raise BuildError("Truncated load command")
        cmd, size = struct.unpack_from("<II", data, off)
        if size < 8 or size % 8 or off + size > end:
            raise BuildError("Invalid load command size")
        if cmd == 0x19:  # LC_SEGMENT_64
            if size < 72:
                raise BuildError("Truncated segment")
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            if 72 + nsects * 80 > size:
                raise BuildError("Truncated section table")
            for i in range(nsects):
                s = off + 72 + i * 80
                name = data[s:s + 16].split(b"\0")[0].decode("ascii")
                segment = data[s + 16:s + 32].split(b"\0")[0].decode("ascii")
                length = struct.unpack_from("<Q", data, s + 40)[0]
                position = struct.unpack_from("<I", data, s + 48)[0]
                flags = struct.unpack_from("<I", data, s + 64)[0]
                if flags & 0xFF in (1, 0xC, 0x12):  # zero-fill has no file payload
                    continue
                if length and (position < end or position + length > len(data)):
                    raise BuildError("Section outside file data")
                result["sections"].append({"name": name, "segment": segment,
                                           "start": position, "end": position + length,
                                           "instructions": bool(flags & 0x80000400)})
        elif cmd == 2:  # LC_SYMTAB
            if size != 24 or result["strtab"] is not None:
                raise BuildError("Invalid or duplicate symbol table")
            _, _, symoff, count, stroff, strsize = struct.unpack_from("<6I", data, off)
            if symoff + count * 16 > len(data) or stroff + strsize > len(data):
                raise BuildError("Symbol table outside file")
            result["strtab"] = (stroff, stroff + strsize)
        elif cmd == 0x1D:
            if size != 16:
                raise BuildError("Invalid signature command")
            pos, length = struct.unpack_from("<II", data, off + 8)
            if pos + length > len(data):
                raise BuildError("Signature outside file")
            result["signature"] = (pos, pos + length)
        off += size
    if off != end or result["strtab"] is None:
        raise BuildError("Missing symbol table or inconsistent load commands")
    return result


def macho_linkage(data: bytes) -> dict:
    """Read exact external symbols/relocations and section addresses.

    This is used only to validate three pinned C++ vtable inheritance cases;
    it does not rewrite Mach-O data or resolve arbitrary imports.
    """
    macho(data)  # Apply the main parser's strict x86_64 bundle validation.
    _, _, _, _, ncmds, cmdbytes, _, _ = struct.unpack_from("<8I", data)
    command_end = 32 + cmdbytes
    command = 32
    symtab = None
    dysymtab = None
    sections = []
    for _ in range(ncmds):
        if command + 8 > command_end:
            raise BuildError("Truncated linkage load command")
        cmd, size = struct.unpack_from("<II", data, command)
        if size < 8 or size % 8 or command + size > command_end:
            raise BuildError("Invalid linkage load command size")
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects = struct.unpack_from("<I", data, command + 64)[0]
            for index in range(nsects):
                section = command + 72 + index * 80
                name = data[section:section + 16].split(b"\0", 1)[0].decode("ascii")
                segment = data[section + 16:section + 32].split(b"\0", 1)[0].decode("ascii")
                address, length = struct.unpack_from("<QQ", data, section + 32)
                file_offset, _, reloc_offset, reloc_count, flags = struct.unpack_from(
                    "<5I", data, section + 48)
                if length and not (flags & 0xFF in (1, 0xC, 0x12)) and (
                        file_offset + length > len(data)):
                    raise BuildError("Linkage section outside Mach-O data")
                sections.append({"segment": segment, "name": name, "address": address,
                                 "size": length, "file_offset": file_offset,
                                 "reloc_offset": reloc_offset, "reloc_count": reloc_count,
                                 "flags": flags})
        elif cmd == 2:  # LC_SYMTAB
            if size != 24 or symtab is not None:
                raise BuildError("Invalid or duplicate linkage symbol table")
            symtab = struct.unpack_from("<6I", data, command)
        elif cmd == 0xB:  # LC_DYSYMTAB
            if size != 80 or dysymtab is not None:
                raise BuildError("Invalid or duplicate dynamic symbol table")
            dysymtab = struct.unpack_from("<18I", data, command + 8)
        command += size
    if command != command_end or symtab is None or dysymtab is None:
        raise BuildError("Mach-O lacks a complete external relocation table")

    _, _, symbol_offset, symbol_count, string_offset, string_size = symtab
    if (symbol_offset + symbol_count * 16 > len(data) or
            string_offset + string_size > len(data)):
        raise BuildError("Linkage symbol/string table outside Mach-O data")
    strings = data[string_offset:string_offset + string_size]
    symbol_names = []
    symbols_by_name = {}
    for index in range(symbol_count):
        string_index, n_type, section_index, description, value = struct.unpack_from(
            "<IBBHQ", data, symbol_offset + index * 16)
        if string_index == 0:
            name = ""
        elif string_index >= len(strings):
            raise BuildError("Invalid linkage symbol string index")
        else:
            end = strings.find(b"\0", string_index)
            if end < 0:
                raise BuildError("Unterminated linkage symbol name")
            name = strings[string_index:end].decode("utf-8", errors="strict")
        symbol_names.append(name)
        if not name or n_type & 0xE0:
            continue
        symbol_type = n_type & 0x0E
        symbols_by_name.setdefault(name, []).append({
            "defined": symbol_type not in (0, 0x0C),
            "external": bool(n_type & 0x01),
            "section_index": section_index,
            "description": description,
            "value": value,
        })

    ext_relocation_offset, ext_relocation_count = dysymtab[14], dysymtab[15]
    if ext_relocation_offset + ext_relocation_count * 8 > len(data):
        raise BuildError("External relocation table outside Mach-O data")
    external_relocations = []
    for index in range(ext_relocation_count):
        relocation = ext_relocation_offset + index * 8
        address, info = struct.unpack_from("<iI", data, relocation)
        symbol_index = info & 0x00FFFFFF
        pcrel = (info >> 24) & 1
        length = (info >> 25) & 0x3
        external = (info >> 27) & 1
        relocation_type = (info >> 28) & 0xF
        if not external:
            continue
        if symbol_index >= len(symbol_names) or not symbol_names[symbol_index]:
            raise BuildError("External relocation has an invalid symbol index")
        external_relocations.append({"address": address,
                                     "symbol": symbol_names[symbol_index],
                                     "pcrel": pcrel, "length": length,
                                     "type": relocation_type})
    return {"sections": sections, "symbols": symbols_by_name,
            "external_relocations": external_relocations}


def instruction_hashes(data: bytes) -> dict[str, str]:
    return {s["segment"] + "," + s["name"]: digest(data[s["start"]:s["end"]])
            for s in macho(data)["sections"] if s["instructions"]}


def patch_binary(data: bytes) -> tuple[bytes, dict]:
    layout = macho(data)
    if layout["signature"]:
        raise BuildError("Remove the copied binary's old signature before patching")
    allowed = [(layout["strtab"][0], layout["strtab"][1], "symbol strings")]
    for s in layout["sections"]:
        if not s["instructions"] and s["name"] in ("__cstring", "__data"):
            allowed.append((s["start"], s["end"], s["segment"] + "," + s["name"]))
    changed = []
    output = data
    for old, new in RENAMES:
        positions = []
        cursor = 0
        while True:
            pos = output.find(old, cursor)
            if pos < 0:
                break
            if not any(lo <= pos and pos + len(old) <= hi for lo, hi, _ in allowed):
                raise BuildError(f"Replacement outside approved string/data range: {old!r} at {pos:#x}")
            positions.append(pos)
            cursor = pos + len(old)
        output = output.replace(old, new)
        changed.append({"from": old.decode(), "to": new.decode(), "offsets": positions})
    if len(output) != len(data) or instruction_hashes(output) != instruction_hashes(data):
        raise BuildError("Namespace patch altered executable instructions or file length")
    return output, {"replacements": changed, "instruction_sha256": instruction_hashes(output)}


def symbols(binary: Path, undefined: bool = False) -> set[str]:
    output = run(["/usr/bin/nm", "-arch", "x86_64", "-uj" if undefined else "-gUj", str(binary)])
    values = set(output.splitlines())
    if not values:
        raise BuildError(f"Unexpected empty symbol set: {binary.name}")
    return values


def _defined_symbol_value(linkage: dict, name: str) -> int:
    records = [record for record in linkage["symbols"].get(name, ())
               if record["defined"] and record["external"]]
    values = {record["value"] for record in records}
    if len(values) != 1:
        raise BuildError(f"Expected one defined external symbol: {name}")
    return next(iter(values))


def _external_relocation(linkage: dict, address: int, expected_symbol: str):
    matches = [relocation for relocation in linkage["external_relocations"]
               if relocation["address"] == address]
    if (len(matches) != 1 or matches[0]["symbol"] != expected_symbol or
            matches[0]["pcrel"] != 0 or matches[0]["length"] != 3 or
            matches[0]["type"] != 0):
        raise BuildError(f"Unexpected vtable relocation at {address:#x}; expected {expected_symbol}")


def _read_const_pointer(data: bytes, linkage: dict, address: int) -> int:
    sections = [section for section in linkage["sections"]
                if section["segment"] == "__DATA" and section["name"] == "__const" and
                section["address"] <= address and address + 8 <= section["address"] + section["size"]]
    if len(sections) != 1:
        raise BuildError(f"Vtable slot is outside one __DATA,__const section: {address:#x}")
    section = sections[0]
    offset = section["file_offset"] + address - section["address"]
    if offset + 8 > len(data):
        raise BuildError("Vtable slot is outside Mach-O file data")
    return struct.unpack_from("<Q", data, offset)[0]


def _verify_metaclass_parent(data: bytes, linkage: dict, child_class: str,
                             parent_class: str):
    child_prefix = f"__ZN{len(child_class)}{child_class}"
    parent_meta = f"__ZN{len(parent_class)}{parent_class}10gMetaClassE"
    constructor = child_prefix + "9MetaClassC2Ev"
    start = _defined_symbol_value(linkage, constructor)
    text_sections = [section for section in linkage["sections"]
                     if section["segment"] == "__TEXT" and section["name"] == "__text" and
                     section["address"] <= start < section["address"] + section["size"]]
    if len(text_sections) != 1:
        raise BuildError(f"Metaclass constructor is outside __TEXT,__text: {constructor}")
    section = text_sections[0]
    function_offset = section["file_offset"] + start - section["address"]
    available = min(0x40, section["address"] + section["size"] - start)
    function = data[function_offset:function_offset + available]
    for index in range(max(0, len(function) - 6)):
        opcode = function[index:index + 3]
        if opcode not in (b"\x48\x8d\x15", b"\x48\x8b\x15"):
            continue
        displacement = struct.unpack_from("<i", function, index + 3)[0]
        target = start + index + 7 + displacement
        if opcode == b"\x48\x8d\x15":  # Local parent OSMetaClass pointer.
            parent_records = [record for record in linkage["symbols"].get(parent_meta, ())
                              if record["defined"] and record["external"]]
            if len(parent_records) == 1 and target == parent_records[0]["value"]:
                return
        else:  # External parent pointer loaded through its relocation slot.
            try:
                _external_relocation(linkage, target, parent_meta)
                return
            except BuildError:
                pass
    raise BuildError(f"Wrong or unverified superclass: {child_class} -> {parent_class}")


def verify_inherited_vtable_exceptions(provider_data: bytes, legacy_data: bytes,
                                       brcm_data: bytes, original_hashes: dict,
                                       expected_brcm_hash: str,
                                       brcm_bundle: str) -> list[dict]:
    """Prove the three narrowly allowed mismatched-signature inherited slots."""
    expected_hashes = {
        "provider": COMMON_SAMPLES[0][2],
        "legacy_consumer": COMMON_SAMPLES[1][2],
        "brcm_consumer": expected_brcm_hash,
    }
    if original_hashes != expected_hashes:
        raise BuildError("Inherited vtable exception is not allowed for these exact source hashes")

    provider = macho_linkage(provider_data)
    legacy = macho_linkage(legacy_data)
    brcm = macho_linkage(brcm_data)
    return _verify_inherited_vtable_layout(provider_data, provider, legacy_data,
                                           legacy, brcm_data, brcm, brcm_bundle)


def _verify_inherited_vtable_layout(provider_data: bytes, provider: dict,
                                    legacy_data: bytes, legacy: dict,
                                    brcm_data: bytes, brcm: dict,
                                    brcm_bundle: str) -> list[dict]:
    _verify_metaclass_parent(legacy_data, legacy, "IO80211SkywalkInterface",
                             "IOLegacyWEthernetInterface")
    _verify_metaclass_parent(legacy_data, legacy, "IO80211InfraInterface",
                             "IO80211SkywalkInterface")
    _verify_metaclass_parent(brcm_data, brcm, "AirPort_Brcm43xxLLSkywalkInterface",
                             "IO80211InfraInterface")

    vtables = (
        (provider_data, provider, "__ZTV26IOLegacyWEthernetInterface"),
        (legacy_data, legacy, "__ZTV23IO80211SkywalkInterface"),
        (legacy_data, legacy, "__ZTV21IO80211InfraInterface"),
        (brcm_data, brcm, "__ZTV34AirPort_Brcm43xxLLSkywalkInterface"),
    )
    evidence = []
    for method in INHERITED_VTABLE_METHODS:
        provider_impl = method["parent_implementation_symbol"]
        imported = method["undefined_symbol"]
        slot = method["slot"]
        provider_address = _defined_symbol_value(provider, provider_impl)
        for table_index, (image_data, linkage, table_name) in enumerate(vtables):
            table = _defined_symbol_value(linkage, table_name)
            slot_address = table + 16 + slot * 8
            if table_index == 0:
                if _read_const_pointer(image_data, linkage, slot_address) != provider_address:
                    raise BuildError(f"Provider implementation does not occupy vtable slot {slot}")
            elif table_index in (1, 2):
                _external_relocation(linkage, slot_address, provider_impl)
            else:
                _external_relocation(linkage, slot_address, imported)
        evidence.append({
            "consumer_bundle": brcm_bundle,
            "undefined_symbol": imported,
            "parent_implementation_symbol": provider_impl,
            "parent_class": "IOLegacyWEthernetInterface",
            "slot": slot,
            "class_path": ["AirPort_Brcm43xxLLSkywalkInterface",
                           "IO80211InfraInterface", "IO80211SkywalkInterface",
                           "IOLegacyWEthernetInterface"],
            "resolution": "kxld-inherited-vtable-slot",
        })
    return evidence


def private_import_resolution(defined_by_bundle: dict, undefined_by_bundle: dict,
                              inherited_exceptions: list[dict]) -> dict:
    """Reject every private-namespace import except verified direct or inherited slots."""
    is_private = lambda symbol: any(marker in symbol for marker in PRIVATE_SYMBOL_MARKERS)
    staged_definitions = set().union(*defined_by_bundle.values())
    private_imports = {bundle: {symbol for symbol in imported if is_private(symbol)}
                       for bundle, imported in undefined_by_bundle.items()}
    unresolved = set().union(*private_imports.values()) - staged_definitions
    allowed = {item["undefined_symbol"] for item in inherited_exceptions}
    if unresolved != allowed:
        unexpected = sorted(unresolved - allowed)
        absent = sorted(allowed - unresolved)
        raise BuildError("Private namespace import closure mismatch; "
                         f"unexpected unresolved={unexpected}, expected slots absent={absent}")
    if any(item["consumer_bundle"] not in private_imports or
           item["undefined_symbol"] not in private_imports[item["consumer_bundle"]]
           for item in inherited_exceptions):
        raise BuildError("Inherited vtable exception is not imported by its pinned consumer")
    return {
        "directly_resolved_import_count_by_bundle": {
            bundle: len(imports - unresolved) for bundle, imports in private_imports.items()
        },
        "direct_private_imports_not_in_staged_exports": sorted(unresolved),
        "inherited_vtable_exceptions": inherited_exceptions,
        "unresolved_after_inherited_slots": [],
    }


def executable(bundle: Path) -> tuple[dict, Path]:
    info = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
    name = info["CFBundleExecutable"]
    if not isinstance(name, str) or Path(name).name != name:
        raise BuildError("Invalid CFBundleExecutable")
    path = bundle / "Contents/MacOS" / name
    if path.is_symlink() or not path.is_file():
        raise BuildError("Missing executable or symlink input")
    return info, path


def copy_clean_bundle(source: Path, target: Path):
    """Copy bytes and permission bits, excluding signatures/plugins and all xattrs."""
    target.mkdir()
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        if any(part in ("PlugIns", "_CodeSignature") for part in relative.parts):
            continue
        if item.is_symlink():
            raise BuildError("Symlinks are not accepted in a copied bundle")
        destination = target / relative
        if item.is_dir():
            destination.mkdir(exist_ok=True)
        elif item.is_file():
            shutil.copyfile(item, destination)
            destination.chmod(item.stat().st_mode & 0o777)
        else:
            raise BuildError("Unsupported file type in source bundle")


def clear_staging_xattrs(target: Path):
    # Finder/cloud agents may add attributes to newly written workspace files.
    # This function is called only on the private temporary build copy.
    run(["/usr/bin/xattr", "-cr", str(target)])


def validate_output(path: Path, inputs: list[Path]):
    resolved = path.resolve()
    if path.exists():
        raise BuildError("Output must not already exist")
    forbidden = (Path("/System"), Path("/Library"), Path("/Volumes"), Path("/Applications"))
    if any(p == resolved or p in resolved.parents for p in forbidden + tuple(inputs)):
        raise BuildError("Output must be outside input, system and mounted-volume trees")
    if any(p.lower() in ("efi", "oc") or p.lower().endswith((".kext", ".dext")) for p in resolved.parts):
        raise BuildError("Output cannot be inside an EFI or extension bundle")


def build(legacy: Path, system: Path | None, output: Path,
          profile_name: str | None = None, native_skywalk_kext: Path | None = None,
          native_target_label: str | None = None,
          native_kernel_collection: Path | None = None,
          native_fileset_entry: str = OLD_ID,
          native_info_plist: Path | None = None) -> dict:
    profile_name = DEFAULT_PROFILE if profile_name is None else profile_name
    profile = dependency_profile(profile_name)
    legacy = Path(legacy).resolve()
    system = Path(system).resolve() if system is not None else None
    output = Path(output).resolve()
    if native_skywalk_kext is not None and native_kernel_collection is not None:
        raise BuildError("Choose one native kext bundle or kernel-collection sample")
    if native_info_plist is not None and native_kernel_collection is None:
        raise BuildError("--native-info-plist requires --native-kernel-collection")
    native_bundle = (Path(native_skywalk_kext).resolve() if native_skywalk_kext is not None
                     else (system / "IOSkywalkFamily.kext" if system is not None and
                           native_kernel_collection is None else None))
    native_collection = (Path(native_kernel_collection).resolve()
                         if native_kernel_collection is not None else None)
    if native_bundle is None and native_collection is None:
        raise BuildError("Pass --native-skywalk-kext or --native-kernel-collection")
    native_info_path = Path(native_info_plist).resolve() if native_info_plist is not None else None
    inputs = [legacy]
    if native_bundle is not None:
        inputs.append(native_bundle)
    if native_collection is not None:
        inputs.append(native_collection)
    if native_info_path is not None:
        inputs.append(native_info_path)
    if system is not None:
        inputs.append(system)
    validate_output(output, inputs)

    originals = []
    for name, dest, expected in COMMON_SAMPLES:
        originals.append(pinned_bundle(
            legacy, (name,), dest, expected, INFO_SHA256[name], name))
    brcm_relative = tuple(profile["brcm_source"])
    originals.append(pinned_bundle(
        legacy, brcm_relative, profile["brcm_bundle"],
        profile["brcm_binary_sha256"], profile["brcm_info_sha256"],
        profile["asset_profile"], AIRPORT_BRCM_NIC_BUNDLE_ID,
        AIRPORT_BRCM_NIC_VERSION))

    if native_collection is not None:
        native_defs, native_metadata = kernel_collection_symbols(
            native_collection, native_fileset_entry, native_target_label)
        if native_info_path is None and system is not None:
            candidate = system / "IOSkywalkFamily.kext" / "Contents" / "Info.plist"
            if candidate.is_file() and not candidate.is_symlink():
                native_info_path = candidate
        if native_info_path is not None:
            native_info_raw = native_info_path.read_bytes()
            native_info = plistlib.loads(native_info_raw)
            if native_info.get("CFBundleIdentifier") != native_fileset_entry:
                raise BuildError("Native Info.plist bundle ID does not match fileset entry")
            native_metadata.update({
                "bundle_id": native_info.get("CFBundleIdentifier"),
                "bundle_version": native_info.get("CFBundleVersion"),
                "sdk_name": native_info.get("DTSDKName"),
                "info_sha256": digest(native_info_raw),
            })
    else:
        native_info, native_bin, native_raw, native_metadata = native_sample(
            native_bundle, native_target_label)
        native_defs = symbols(native_bin)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Publish only after every static check passes. The temporary copy is ours.
    # Sign outside FileProvider/Documents: FinderInfo can be re-added after xattr -c.
    with tempfile.TemporaryDirectory(prefix="skywalk-build-") as temp:
        stage = Path(temp) / "package"
        kexts = stage / "Kexts"
        kexts.mkdir(parents=True)
        entries = []
        for original in originals:
            target = kexts / original.destination
            copy_clean_bundle(original.source, target)
            _, target_bin = executable(target)
            if target_bin.read_bytes() != original.raw:
                raise BuildError("Source executable changed while copying")
            if digest((target / "Contents/Info.plist").read_bytes()) != original.info_sha256:
                raise BuildError(f"Source metadata changed while copying: {original.source_label}")
            # Operates only on the staging copy, never on the pinned source.
            if macho(target_bin.read_bytes())["signature"]:
                run(["/usr/bin/codesign", "--remove-signature", str(target_bin)])
            patched, detail = patch_binary(target_bin.read_bytes())
            target_bin.write_bytes(patched)
            modified = rename_plist(original.info)
            if modified["CFBundleExecutable"] != target_bin.name:
                renamed_bin = target_bin.with_name(modified["CFBundleExecutable"])
                target_bin.rename(renamed_bin)
                target_bin = renamed_bin
            (target / "Contents/Info.plist").write_bytes(plistlib.dumps(modified, sort_keys=False))
            clear_staging_xattrs(target)
            run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(target)])
            run(["/usr/bin/codesign", "--verify", "--strict", str(target)])
            result_raw = target_bin.read_bytes()
            if instruction_hashes(result_raw) != instruction_hashes(original.raw):
                raise BuildError("Signing or patching changed instruction bytes")
            for undefined in (False, True):
                expected_syms = {rename(s.encode()).decode()
                                 for s in symbols(original.binary, undefined)}
                if symbols(target_bin, undefined) != expected_syms:
                    raise BuildError(f"Symbol rename mismatch: {original.destination}")
            entries.append({"bundle": original.destination,
                            "bundle_id": modified["CFBundleIdentifier"],
                            "source": original.source_label,
                            "source_sha256": digest(original.raw),
                            "output_sha256": digest(result_raw), **detail})
        _, private_bin = executable(kexts / COMMON_SAMPLES[0][1])
        private_defs = symbols(private_bin)
        collision = (private_defs & native_defs) - {"_kmod_info"}
        if collision:
            raise BuildError(f"Native Skywalk export collisions remain: {len(collision)}")
        _, legacy_bin = executable(kexts / COMMON_SAMPLES[1][1])
        _, brcm_bin = executable(kexts / profile["brcm_bundle"])
        original_provider = symbols(originals[0].binary)
        for original, modified_bin in [(originals[1], legacy_bin), (originals[2], brcm_bin)]:
            required = {rename(s.encode()).decode()
                        for s in symbols(original.binary, True) & original_provider}
            if not required <= private_defs or not required <= symbols(modified_bin, True):
                raise BuildError("Legacy consumer/provider dependency closure failed")
        for modified_bin in (legacy_bin, brcm_bin):
            overlap = (symbols(modified_bin) & native_defs) - {"_kmod_info"}
            if overlap:
                raise BuildError("Consumer conflicts with native Skywalk exports")
        output_binaries = {
            originals[0].destination: private_bin,
            originals[1].destination: legacy_bin,
            originals[2].destination: brcm_bin,
        }
        defined_by_bundle = {name: symbols(binary) for name, binary in output_binaries.items()}
        undefined_by_bundle = {name: symbols(binary, True) for name, binary in output_binaries.items()}
        original_hashes = {
            "provider": digest(originals[0].raw),
            "legacy_consumer": digest(originals[1].raw),
            "brcm_consumer": digest(originals[2].raw),
        }
        inherited_exceptions = verify_inherited_vtable_exceptions(
            private_bin.read_bytes(), legacy_bin.read_bytes(), brcm_bin.read_bytes(),
            original_hashes, profile["brcm_binary_sha256"], profile["brcm_bundle"])
        import_resolution = private_import_resolution(
            defined_by_bundle, undefined_by_bundle, inherited_exceptions)
        manifest = {"schema": 1, "prototype": "isolated-legacy-skywalk", "version": "0.1.0",
                    "status": "STATIC_PROFILE_CANDIDATE", "validation_scope": "offline",
                    "dependency_profile": {
                        "name": profile_name,
                        "min_kernel": profile["min_kernel"],
                        "max_kernel": profile["max_kernel"],
                        "brcm_bundle": profile["brcm_bundle"],
                        "brcm_source": "/".join(brcm_relative),
                        "brcm_source_sha256": profile["brcm_binary_sha256"],
                        "asset_profile": profile["asset_profile"],
                    },
                    "native_skywalk_sample": native_metadata,
                    "binaries": entries,
                    "private_import_resolution": {
                        "pinned_input_sha256": original_hashes,
                        **import_resolution,
                    },
                    "remaining_native_skywalk_export_collisions": [],
                    "checks": {"instruction_bytes_unchanged": True,
                               "exact_symbol_transform": True, "private_import_closure": True,
                               "adhoc_signature_verified": True}}
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        # Instructions rather than a full config: never copy a machine identity.
        fragment = {"Kernel": {"Add": [
            {"Arch": "x86_64", "BundlePath": original.destination,
             "Comment": f"Skywalk namespace isolation candidate ({profile_name})",
             "Enabled": True,
             "ExecutablePath": "Contents/MacOS/" + rename_plist(original.info)["CFBundleExecutable"],
             "PlistPath": "Contents/Info.plist", "MinKernel": profile["min_kernel"],
             "MaxKernel": profile["max_kernel"]}
            for original in originals], "Block": [
                {"Arch": "x86_64", "Comment": "Test-only: avoid legacy/native IO80211 class collisions",
                 "Enabled": True, "Identifier": "com.apple.iokit.IO80211Family",
                 "MinKernel": profile["min_kernel"], "MaxKernel": profile["max_kernel"],
                 "Strategy": "Exclude"}]}}
        (stage / "config.fragment.plist").write_bytes(plistlib.dumps(fragment, sort_keys=False))
        (stage / "TESTING.txt").write_text(
            "DEPENDENCY PROFILE CANDIDATE\n"
            "This package contains three Wi-Fi dependencies and requires a matching compatible AirportBrcmCompat core.\n"
            "Profile MinKernel/MaxKernel values select these dependencies; they do not establish support for every OS build or the whole OS.\n"
            "Keep native IOSkywalkFamily enabled. Block only native com.apple.iokit.IO80211Family for this selected profile.\n"
            "Merge config.fragment.plist into the existing configuration and retain unrelated entries.\n")
        for original in originals:
            if (original.binary.read_bytes() != original.raw or
                    digest((original.source / "Contents/Info.plist").read_bytes()) != original.info_sha256):
                raise BuildError("Source changed during build; refusing to publish")
        if native_collection is not None:
            if digest(native_collection.read_bytes()) != native_metadata["container_sha256"]:
                raise BuildError("Native kernel-collection sample changed during build")
        elif native_bin.read_bytes() != native_raw:
            raise BuildError("Native Skywalk sample changed during build")
        if output.suffix.lower() == ".zip":
            # ZIP entries contain ordinary file bytes/modes, never resource-fork xattrs.
            with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
                for item in sorted(stage.rglob("*")):
                    if item.is_file():
                        archive.write(item, item.relative_to(stage).as_posix())
        else:
            stage.rename(output)
            # A directory publication into FileProvider can gain Finder metadata.
            # Report that failure instead of publishing a false verified result.
            for original in originals:
                run(["/usr/bin/codesign", "--verify", "--strict",
                     str(output / "Kexts" / original.destination)])
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-dir", required=True, type=Path)
    parser.add_argument("--system-extensions", type=Path, default=Path("/System/Library/Extensions"))
    parser.add_argument("--native-skywalk-kext", type=Path,
                        help="explicit IOSkywalkFamily.kext sample for collision checks")
    parser.add_argument("--native-kernel-collection", type=Path,
                        help="explicit kernel collection containing the native fileset sample")
    parser.add_argument("--native-fileset-entry", default=OLD_ID,
                        help="exact LC_FILESET_ENTRY identifier to inspect")
    parser.add_argument("--native-info-plist", type=Path,
                        help="optional Info.plist matching the selected native fileset entry")
    parser.add_argument("--native-target-label",
                        help="optional label recorded with the native symbol sample metadata")
    parser.add_argument("--dependency-profile", choices=tuple(DEPENDENCY_PROFILES),
                        default=DEFAULT_PROFILE)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = build(args.legacy_dir, args.system_extensions, args.output,
                       args.dependency_profile, args.native_skywalk_kext,
                       args.native_target_label, args.native_kernel_collection,
                       args.native_fileset_entry, args.native_info_plist)
    except (BuildError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Build refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": result["status"], "bundles": len(result["binaries"]),
                      "output": str(args.output.resolve())}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
