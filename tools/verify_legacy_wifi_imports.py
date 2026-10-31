#!/usr/bin/env python3
"""Offline import and class-namespace audit for the OCLP ElCap Wi-Fi stack."""
from __future__ import annotations

import argparse
import json
import mmap
import pathlib
import plistlib
import re
import shutil
import struct
import subprocess
import sys


PROJECT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
sys.path.insert(0, str(PROJECT / "tools"))
import build_namespace  # noqa: E402
import verify_ifnet_kernel_contracts as kernel_reader  # noqa: E402


INHERITED_RESERVED_IMPORTS = {
    "__ZN19IONetworkController29_RESERVEDIONetworkController6Ev": 329,
    "__ZN19IONetworkController29_RESERVEDIONetworkController7Ev": 330,
    "__ZN20IOEthernetController30_RESERVEDIOEthernetController2Ev": 364,
    "__ZN20IOEthernetController30_RESERVEDIOEthernetController3Ev": 365,
    "__ZN20IOEthernetController30_RESERVEDIOEthernetController4Ev": 366,
    "__ZN20IOEthernetController30_RESERVEDIOEthernetController5Ev": 367,
    "__ZN20IOEthernetController30_RESERVEDIOEthernetController6Ev": 368,
    "__ZN20IOEthernetController30_RESERVEDIOEthernetController7Ev": 369,
    "__ZN20IOEthernetController30_RESERVEDIOEthernetController8Ev": 370,
    "__ZN20IOEthernetController30_RESERVEDIOEthernetController9Ev": 371,
}

INHERITED_CLASSES = {
    "IO80211ElCap": ("IO80211Controller", "IOEthernetController"),
    "AirPortBrcm4331": ("AirPort_Brcm4331", "IO80211Controller"),
    "AppleAirPortBrcm43224": ("AirPort_Brcm43224", "IO80211Controller"),
}

INHERITED_PARENT_METHODS = {
    329: "__ZN19IONetworkController20allocatePacketNoWaitEj",
    330: "__ZN19IONetworkController18setHardwareAssistsEjj",
    364: "__ZN20IOEthernetController21setAVBControllerStateE28IOEthernetControllerAVBState",
    365: "__ZN20IOEthernetController23transmitRealtimePacketsEjPPNS_19IOEthernetAVBPacketEjbPj",
    366: "__ZN20IOEthernetController20cleanupTransmitQueueEj",
    367: "__ZN20IOEthernetController29setRealtimeReceiveQueueFilterEjPNS_33IOEthernetAVBIngressFilterElementEj",
    368: "__ZN20IOEthernetController29getRealtimeReceiveQueueFilterEjPNS_33IOEthernetAVBIngressFilterElementEPj",
    369: "__ZN20IOEthernetController36setRealtimeReceiveQueuePacketHandlerEjPFvPvPNS_19IOEthernetAVBPacketEES0_",
    370: "__ZN20IOEthernetController36setRealtimeReceiveDestinationMACListEjP17IOEthernetAddressi",
    371: "__ZN20IOEthernetController22transmitTimeSyncPacketEPNS_19IOEthernetAVBPacketEy",
}


def parse_assignment(value: str) -> tuple[str, pathlib.Path]:
    label, separator, raw_path = value.partition("=")
    if not separator or not label or not raw_path:
        raise argparse.ArgumentTypeError("expected LABEL=PATH")
    return label, pathlib.Path(raw_path)


def _nm(nm: str, option: str, path: pathlib.Path) -> str:
    try:
        return subprocess.check_output([nm, option, str(path)], text=True, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as error:
        details = error.stderr.strip() if error.stderr else str(error)
        raise RuntimeError(f"nm {option} failed for {path}: {details}") from error


def defined_symbols(nm: str, path: pathlib.Path) -> set[str]:
    result = set()
    for line in _nm(nm, "-gU", path).splitlines():
        fields = line.split()
        if fields and not line.startswith("Symbols for "):
            result.add(fields[-1])
    return result


def parse_nm_mach(text: str) -> tuple[dict[str, set[str]], set[str], set[str]]:
    """Return definitions grouped by fileset image, plus strong and weak imports."""
    by_image: dict[str, set[str]] = {}
    strong_imports: set[str] = set()
    weak_imports: set[str] = set()
    image = ""
    undefined = re.compile(r"\(undefined\)\s+(?:(weak)\s+)?external\s+(\S+)")
    for line in text.splitlines():
        # Apple's nm prints a trailing space after the fileset image header.
        # Strip whitespace before matching so symbols remain grouped by kext.
        header = line.strip()
        if header.startswith("Symbols for ") and header.endswith(":"):
            image = header[len("Symbols for "):-1]
            by_image.setdefault(image, set())
            continue
        match = undefined.search(line)
        if match:
            (weak_imports if match.group(1) else strong_imports).add(match.group(2))
            continue
        fields = line.split()
        if image and "external" in fields:
            symbol = fields[-1]
            if symbol.startswith("_"):
                by_image[image].add(symbol)
    return by_image, strong_imports, weak_imports


def parse_nm_defined_addresses(text: str) -> dict[str, dict[int, set[str]]]:
    """Return defined external symbols by fileset image and link address."""
    by_image: dict[str, dict[int, set[str]]] = {}
    image = ""
    definition = re.compile(r"^\s*([0-9a-fA-F]+)\s+.*\bexternal\s+(\S+)")
    for line in text.splitlines():
        header = line.strip()
        if header.startswith("Symbols for ") and header.endswith(":"):
            image = header[len("Symbols for "):-1]
            by_image.setdefault(image, {})
            continue
        if not image or "(undefined)" in line:
            continue
        match = definition.match(line)
        if match:
            address = int(match.group(1), 16)
            by_image[image].setdefault(address, set()).add(match.group(2))
    return by_image


def _inner_member_layout(data: mmap.mmap, entry: dict, label: str) -> dict:
    """Parse a KC member's segment/section layout without assuming MH_EXECUTE."""
    parsed = kernel_reader.parse_header(data, entry["fileoff"], label)
    segments = []
    sections = []
    symtab = None
    for command, raw, _ in parsed["commands"]:
        if command == kernel_reader.LC_SEGMENT_64:
            segment, member_sections = kernel_reader.parse_segment(raw, label)
            segments.append(segment)
            sections.extend(member_sections)
        elif command == kernel_reader.LC_SYMTAB:
            if len(raw) != 24 or symtab is not None:
                raise ValueError(f"{label}: invalid/duplicate LC_SYMTAB")
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", raw, 8)
            symtab = {"symoff": symoff, "nsyms": nsyms,
                      "stroff": stroff, "strsize": strsize}
    if not segments or symtab is None:
        raise ValueError(f"{label}: missing segments or LC_SYMTAB")
    return {**{key: parsed[key] for key in ("header_offset", "ncmds", "sizeofcmds")},
            "segments": segments, "sections": sections, "symtab": symtab,
            "fileset_entry": entry}


def _verify_legacy_vtable_imports(name: str, bundle_data: dict) -> dict[str, int]:
    """Prove old reserved imports are only relocations in the expected class vtable."""
    class_name, parent_name = INHERITED_CLASSES[name]
    binary = pathlib.Path(bundle_data["binary"])
    raw = binary.read_bytes()
    linkage = build_namespace.macho_linkage(raw)
    build_namespace._verify_metaclass_parent(raw, linkage, class_name, parent_name)
    vtable_symbol = f"__ZTV{len(class_name)}{class_name}"
    vtable = build_namespace._defined_symbol_value(linkage, vtable_symbol)
    indices = {}
    for imported, expected_index in INHERITED_RESERVED_IMPORTS.items():
        matches = [item for item in linkage["external_relocations"]
                   if item["symbol"] == imported]
        if len(matches) != 1:
            raise ValueError(f"{name}: expected one external relocation for {imported}")
        relocation = matches[0]
        if (relocation["pcrel"] != 0 or relocation["length"] != 3 or
                relocation["type"] != 0 or relocation["address"] < vtable + 16):
            raise ValueError(f"{name}: {imported} is not an absolute vtable pointer relocation")
        sections = [section for section in linkage["sections"]
                    if section["segment"] in ("__DATA", "__DATA_CONST") and
                    section["name"] == "__const" and
                    section["address"] <= relocation["address"] and
                    relocation["address"] + 8 <= section["address"] + section["size"]]
        if len(sections) != 1:
            raise ValueError(f"{name}: {imported} relocation is outside one data const section")
        index, remainder = divmod(relocation["address"] - vtable - 16, 8)
        if remainder or index != expected_index:
            raise ValueError(f"{name}: unexpected inherited slot for {imported}")
        indices[imported] = index
    return indices


def verify_kxld_inherited_slots(kc_path: pathlib.Path, nm: str,
                                old_bundles: dict[str, dict]) -> dict:
    """Verify current parent vtable implementations for imports XNU KXLD can inherit."""
    old_slot_maps = {name: _verify_legacy_vtable_imports(name, data)
                     for name, data in old_bundles.items() if name in INHERITED_CLASSES}
    if set(old_slot_maps) != set(INHERITED_CLASSES):
        raise ValueError("legacy import audit requires all three old IO80211 bundles")
    if any(slot_map != old_slot_maps["IO80211ElCap"]
           for slot_map in old_slot_maps.values()):
        raise ValueError("old provider and driver vtable slot maps do not agree")

    with kc_path.open("rb") as stream:
        data = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            outer = kernel_reader.parse_header(data, 0, str(kc_path))
            entries = [kernel_reader.parse_fileset_entry(raw)
                       for command, raw, _ in outer["commands"]
                       if command == kernel_reader.LC_FILESET_ENTRY]
            kernel_entries = [entry for entry in entries if entry["id"] == "com.apple.kernel"]
            network_entries = [entry for entry in entries
                               if entry["id"] == "com.apple.iokit.IONetworkingFamily"]
            if len(kernel_entries) != 1 or len(network_entries) != 1:
                raise ValueError("BootKC lacks unique kernel/IONetworkingFamily entries")
            kernel = _inner_member_layout(data, kernel_entries[0], "com.apple.kernel")
            network = _inner_member_layout(data, network_entries[0],
                                           "com.apple.iokit.IONetworkingFamily")
            cache_bases = [segment["vmaddr"] for segment in kernel["segments"]
                           if segment["vmsize"]]
            if not cache_bases:
                raise ValueError("BootKC kernel has no mapped segments")
            cache_base = min(cache_bases)
            nm_images = parse_nm_defined_addresses(_nm(nm, "-m", kc_path))
            network_symbols = nm_images.get("com.apple.iokit.IONetworkingFamily", {})
            vtable_name = "__ZTV20IOEthernetController"
            vtable_addresses = [address for address, names in network_symbols.items()
                                if vtable_name in names]
            if len(vtable_addresses) != 1:
                raise ValueError("expected one IONetworkingFamily IOEthernetController vtable")
            vtable = vtable_addresses[0]
            table_sections = [section for section in network["sections"]
                              if section["segment"] in ("__DATA", "__DATA_CONST") and
                              section["name"] == "__const" and
                              section["addr"] <= vtable + 16 + 371 * 8 and
                              vtable + 16 + 372 * 8 <= section["addr"] + section["size"]]
            if len(table_sections) != 1:
                raise ValueError("IOEthernetController vtable exceeds one readable const section")
            section = table_sections[0]
            methods = {}
            for imported, slot in INHERITED_RESERVED_IMPORTS.items():
                location = vtable + 16 + slot * 8
                file_offset = section["fileoff"] + location - section["addr"]
                if file_offset < 0 or file_offset + 8 > len(data):
                    raise ValueError("parent vtable entry is outside KC bytes")
                encoded = struct.unpack_from("<Q", data, file_offset)[0]
                target = encoded & ((1 << 30) - 1)
                cache_level = (encoded >> 30) & 0x3
                if cache_level != 0 or (encoded >> 63):
                    raise ValueError("unexpected cache pointer encoding for inherited slot")
                address = cache_base + target
                names = network_symbols.get(address, set())
                candidates = sorted(name for name in names
                                    if name.startswith("__ZN19IONetworkController") or
                                    name.startswith("__ZN20IOEthernetController"))
                if (len(candidates) != 1 or "_RESERVED" in candidates[0] or
                        candidates[0] != INHERITED_PARENT_METHODS[slot]):
                    raise ValueError(f"KC parent slot {slot} is not the verified non-pad implementation")
                text_ranges = [(segment["vmaddr"], segment["vmaddr"] + segment["vmsize"])
                               for segment in network["segments"]
                               if segment["name"] == "__TEXT" and segment["initprot"] & 0x4]
                if not any(start <= address < end for start, end in text_ranges):
                    raise ValueError(f"KC parent slot {slot} target is outside executable text")
                methods[imported] = {"slot": slot, "symbol": candidates[0],
                                     "address": hex(address)}
            return {"verified": True, "parent_vtable": vtable_name,
                    "cache_base": hex(cache_base), "inherited_import_count": len(methods),
                    "classes": {name: {"class": INHERITED_CLASSES[name][0],
                                       "parent": INHERITED_CLASSES[name][1]}
                                for name in INHERITED_CLASSES},
                    "old_vtable_slots": old_slot_maps,
                    "resolved_methods": methods,
                    "resolution_rule": "XNU KXLD patches unresolved child vtable imports to the same non-pad parent vtable slot"}
        finally:
            data.close()


def kext_info(path: pathlib.Path) -> tuple[dict, pathlib.Path]:
    info_path = path / "Contents" / "Info.plist"
    if not info_path.is_file():
        raise ValueError(f"missing kext Info.plist: {info_path}")
    with info_path.open("rb") as stream:
        info = plistlib.load(stream)
    executable = info.get("CFBundleExecutable")
    if not executable:
        raise ValueError(f"missing CFBundleExecutable in {info_path}")
    binary = path / "Contents" / "MacOS" / executable
    if not binary.is_file():
        raise ValueError(f"missing kext executable: {binary}")
    return info, binary


def bundle(path: pathlib.Path, nm: str) -> dict:
    info, binary = kext_info(path)
    mach = _nm(nm, "-m", binary)
    _, strong, weak = parse_nm_mach(mach)
    return {
        "path": str(path),
        "binary": str(binary),
        "bundle_id": info.get("CFBundleIdentifier", ""),
        "version": info.get("CFBundleVersion", ""),
        "libraries": info.get("OSBundleLibraries", {}),
        "exports": defined_symbols(nm, binary),
        "strong_imports": strong,
        "weak_imports": weak,
    }


def binary_bundle(path: pathlib.Path, nm: str) -> dict:
    """Load a kext directory or an executable Mach-O path."""
    if path.is_dir():
        return bundle(path, nm)
    mach = _nm(nm, "-m", path)
    _, strong, weak = parse_nm_mach(mach)
    return {
        "path": str(path.parent),
        "binary": str(path),
        "bundle_id": "",
        "version": "",
        "libraries": {},
        "exports": defined_symbols(nm, path),
        "strong_imports": strong,
        "weak_imports": weak,
    }


def class_meta_symbols(symbols: set[str]) -> set[str]:
    return {symbol for symbol in symbols if symbol.endswith("10gMetaClassE")}


def class_name_from_meta_symbol(symbol: str) -> str:
    match = re.fullmatch(r"__ZN(\d+)(.+)10gMetaClassE", symbol)
    if not match or int(match.group(1)) != len(match.group(2)):
        raise ValueError(f"not a supported OSMetaClass symbol: {symbol}")
    return match.group(2)


def _class_name_from_constructor(raw, sections: list[dict], start: int,
                                 label: str) -> str:
    text = [section for section in sections
            if section["segment"] == "__TEXT" and section["name"] == "__text" and
            (section.get("addr", section.get("address")) <= start <
             section.get("addr", section.get("address")) + section["size"])]
    if len(text) != 1:
        raise ValueError(f"{label}: metaclass constructor outside one __TEXT,__text section")
    section = text[0]
    address_key = "addr" if "addr" in section else "address"
    file_key = "fileoff" if "fileoff" in section else "file_offset"
    section_start = section[address_key]
    function_offset = section[file_key] + start - section_start
    if function_offset < 0 or function_offset >= len(raw):
        raise ValueError(f"{label}: metaclass constructor exceeds file bounds")
    available = min(0x80, section_start + section["size"] - start)
    function = raw[function_offset:function_offset + available]
    names = []
    for index in range(max(0, len(function) - 6)):
        if function[index:index + 3] != b"\x48\x8d\x35":
            continue
        displacement = struct.unpack_from("<i", function, index + 3)[0]
        target = start + index + 7 + displacement
        strings = [candidate for candidate in sections
                   if candidate["addr" if "addr" in candidate else "address"] <= target <
                   candidate["addr" if "addr" in candidate else "address"] + candidate["size"]]
        if len(strings) != 1:
            continue
        string_section = strings[0]
        string_address_key = "addr" if "addr" in string_section else "address"
        string_file_key = "fileoff" if "fileoff" in string_section else "file_offset"
        string_offset = string_section[string_file_key] + target - string_section[string_address_key]
        string_limit = string_offset + string_section["size"] - (target - string_section[string_address_key])
        if string_offset < 0 or string_limit < string_offset or string_limit > len(raw):
            continue
        terminator = raw.find(b"\0", string_offset, string_limit)
        if terminator < 0:
            continue
        try:
            names.append(raw[string_offset:terminator].decode("ascii"))
        except UnicodeDecodeError:
            continue
    if not names:
        raise ValueError(f"{label}: no bounded RIP-relative metaclass name reference")
    # The first LEA into RSI is the x86_64 second-argument setup for
    # OSMetaClass(name, superclass, size) in these binaries. Later LEAs in the
    # same symbol may refer to logging strings after the constructor call.
    return names[0]


def _bundle_class_name(binary: pathlib.Path, class_name: str) -> str:
    binary = pathlib.Path(binary)
    raw = binary.read_bytes()
    linkage = build_namespace.macho_linkage(raw)
    constructor = f"__ZN{len(class_name)}{class_name}9MetaClassC2Ev"
    start = build_namespace._defined_symbol_value(linkage, constructor)
    return _class_name_from_constructor(raw, linkage["sections"], start, constructor)


def _bundle_meta_class_names(binary: pathlib.Path, symbols: set[str]) -> dict[str, str]:
    result = {}
    for symbol in sorted(class_meta_symbols(symbols)):
        class_name = class_name_from_meta_symbol(symbol)
        actual_name = _bundle_class_name(binary, class_name)
        if actual_name != class_name:
            raise ValueError(f"{binary}: gMetaClass {class_name} has constructor name {actual_name}")
        result[class_name] = actual_name
    return result


def _kc_class_names(data: mmap.mmap, entry: dict, module: str,
                    class_names: set[str]) -> dict[str, str]:
    layout = _inner_member_layout(data, entry, module)
    constructors = {class_name: f"__ZN{len(class_name)}{class_name}9MetaClassC2Ev"
                    for class_name in class_names}
    values, _ = kernel_reader.parse_symbols(data, layout, set(constructors.values()), module)
    return {class_name: _class_name_from_constructor(
                data, layout["sections"], values[symbol], symbol)
            for class_name, symbol in constructors.items() if symbol in values}


def _kc_member(path: pathlib.Path, module: str, class_names: set[str]) -> dict[str, str]:
    with path.open("rb") as stream:
        data = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            outer = kernel_reader.parse_header(data, 0, str(path))
            entries = [kernel_reader.parse_fileset_entry(raw)
                       for command, raw, _ in outer["commands"]
                       if command == kernel_reader.LC_FILESET_ENTRY]
            matches = [entry for entry in entries if entry["id"] == module]
            if len(matches) != 1:
                raise ValueError(f"{path}: expected one {module} fileset member")
            return _kc_class_names(data, matches[0], module, class_names)
        finally:
            data.close()


def _class_overlap_report(left: dict[str, str], right: dict[str, str]) -> dict:
    shared = sorted(left.keys() & right.keys())
    mismatches = [name for name in shared if left[name] != right[name]]
    if mismatches:
        raise ValueError(f"duplicate gMetaClass symbols have differing constructor names: {mismatches}")
    return {
        "potential_co_load_class_name_overlap": shared,
        "potential_co_load_class_name_overlap_count": len(shared),
        "constructor_class_names_verified": len(shared),
        "runtime_load_claim": False,
    }


def closure(bundle_data: dict, available: set[str],
            inherited_vtable_symbols: set[str] | None = None) -> dict:
    missing = bundle_data["strong_imports"] - available
    weak_missing = bundle_data["weak_imports"] - available
    inherited = missing & (inherited_vtable_symbols or set())
    return {
        "strong_import_count": len(bundle_data["strong_imports"]),
        "weak_import_count": len(bundle_data["weak_imports"]),
        "raw_nm_unresolved_strong": sorted(missing),
        "kxld_inherited_vtable_resolved": sorted(inherited),
        "unresolved_strong": sorted(missing - inherited),
        "unresolved_weak": sorted(weak_missing),
    }


def audit(legacy_root: pathlib.Path, collections: list[tuple[str, pathlib.Path]],
          modern_provider: pathlib.Path | None, modern_driver: pathlib.Path | None,
          nm: str) -> dict:
    legacy_root = legacy_root.resolve()
    paths = {
        "corecaptureElCap": legacy_root / "corecaptureElCap.kext",
        "IO80211ElCap": legacy_root / "IO80211ElCap.kext",
        "AirPortBrcm4331": legacy_root / "IO80211ElCap.kext/Contents/PlugIns/AirPortBrcm4331.kext",
        "AppleAirPortBrcm43224": legacy_root / "IO80211ElCap.kext/Contents/PlugIns/AppleAirPortBrcm43224.kext",
    }
    old = {name: bundle(path, nm) for name, path in paths.items()}
    old_class_metas = class_meta_symbols(old["IO80211ElCap"]["exports"])
    modern = binary_bundle(modern_provider, nm) if modern_provider else None
    modern_child = binary_bundle(modern_driver, nm) if modern_driver else None

    result = {
        "legacy_bundles": {
            name: {key: value for key, value in data.items()
                   if key not in {"exports", "strong_imports", "weak_imports"}}
            for name, data in old.items()
        },
        "namespace": {},
        "kernel_collections": [],
    }
    if modern:
        modern_meta_overlap = old_class_metas & class_meta_symbols(modern["exports"])
        result["namespace"]["elcap_vs_modern_provider_duplicate_meta_symbols"] = sorted(
            modern_meta_overlap)
        result["namespace"]["elcap_vs_modern_provider_duplicate_meta_count"] = len(
            modern_meta_overlap)
        old_class_names = _bundle_meta_class_names(
            old["IO80211ElCap"]["binary"], modern_meta_overlap)
        modern_class_names = _bundle_meta_class_names(
            modern["binary"], modern_meta_overlap)
        result["namespace"]["elcap_vs_modern_provider"] = _class_overlap_report(
            old_class_names, modern_class_names)
    if modern_child:
        old_driver_metas = class_meta_symbols(
            old["AirPortBrcm4331"]["exports"] | old["AppleAirPortBrcm43224"]["exports"])
        result["namespace"]["elcap_drivers_vs_modern_driver_duplicate_meta_symbols"] = sorted(
            old_driver_metas & class_meta_symbols(modern_child["exports"]))
        driver_overlap = old_driver_metas & class_meta_symbols(modern_child["exports"])
        old_driver_class_names = {}
        for child_name in ("AirPortBrcm4331", "AppleAirPortBrcm43224"):
            child_overlap = class_meta_symbols(old[child_name]["exports"]) & driver_overlap
            old_driver_class_names.update(_bundle_meta_class_names(
                old[child_name]["binary"], child_overlap))
        modern_driver_class_names = _bundle_meta_class_names(
            modern_child["binary"], driver_overlap)
        result["namespace"]["elcap_drivers_vs_modern_driver"] = _class_overlap_report(
            old_driver_class_names, modern_driver_class_names)

    for label, kc_path in collections:
        kc_path = kc_path.resolve()
        kxld_inherited = verify_kxld_inherited_slots(kc_path, nm, old)
        inherited_symbols = set(kxld_inherited["resolved_methods"])
        mach = _nm(nm, "-m", kc_path)
        images, kc_strong, kc_weak = parse_nm_mach(mach)
        kc_exports = set().union(*images.values()) if images else defined_symbols(nm, kc_path)
        native_wireless = images.get("com.apple.iokit.IO80211Family", set())
        native_wireless_metas = class_meta_symbols(native_wireless)
        native_wireless_overlap = old_class_metas & native_wireless_metas
        old_native_wireless_names = _bundle_meta_class_names(
            old["IO80211ElCap"]["binary"], native_wireless_overlap)
        native_wireless_names = _kc_member(
            kc_path, "com.apple.iokit.IO80211Family", set(old_native_wireless_names))
        old_corecapture_metas = class_meta_symbols(old["corecaptureElCap"]["exports"])
        native_corecapture_metas = class_meta_symbols(
            images.get("com.apple.driver.corecapture", set()))
        corecapture_overlap = old_corecapture_metas & native_corecapture_metas
        old_native_corecapture_names = _bundle_meta_class_names(
            old["corecaptureElCap"]["binary"], corecapture_overlap)
        native_corecapture_names = _kc_member(
            kc_path, "com.apple.driver.corecapture", set(old_native_corecapture_names))
        skywalk_metas = class_meta_symbols(
            images.get("com.apple.iokit.IOSkywalkFamily", set()))
        skywalk_overlap = old_class_metas & skywalk_metas
        old_skywalk_names = _bundle_meta_class_names(
            old["IO80211ElCap"]["binary"], skywalk_overlap)
        skywalk_names = _kc_member(kc_path, "com.apple.iokit.IOSkywalkFamily",
                                   set(old_skywalk_names)) if old_skywalk_names else {}
        cc = old["corecaptureElCap"]
        provider = old["IO80211ElCap"]
        children = [old["AirPortBrcm4331"], old["AppleAirPortBrcm43224"]]
        provider_available = kc_exports | cc["exports"]
        child_available = provider_available | provider["exports"]
        provider_old_corecapture_only = sorted(
            provider["strong_imports"] & cc["exports"] - kc_exports)
        results = {
            "label": label,
            "kernel_collection": str(kc_path),
            "exported_symbol_count": len(kc_exports),
            "native_io80211family_class_meta_overlap": sorted(old_class_metas & native_wireless_metas),
            "native_io80211family_class_meta_overlap_count": len(old_class_metas & native_wireless_metas),
            "potential_co_load_classes": {
                "IO80211ElCap_vs_native_IO80211Family": _class_overlap_report(
                    old_native_wireless_names, native_wireless_names),
                "corecaptureElCap_vs_native_corecapture": _class_overlap_report(
                    old_native_corecapture_names, native_corecapture_names),
                "IO80211ElCap_vs_IOSkywalkFamily": _class_overlap_report(
                    old_skywalk_names, skywalk_names),
            },
            "imports": {
                "corecaptureElCap": closure(cc, kc_exports),
                "IO80211ElCap": closure(provider, provider_available, inherited_symbols),
                "AirPortBrcm4331": closure(children[0], child_available, inherited_symbols),
                "AppleAirPortBrcm43224": closure(children[1], child_available, inherited_symbols),
            },
            "provider_symbols_satisfied_only_by_bundled_corecaptureElCap":
                provider_old_corecapture_only,
            "kxld_inherited_vtable": kxld_inherited,
            "old_networking_reserved_symbols_present": sorted(
                symbol for symbol in kc_exports
                if symbol.startswith("__ZN19IONetworkController29_RESERVEDIONetworkController") or
                   symbol.startswith("__ZN20IOEthernetController30_RESERVEDIOEthernetController")),
            "newer_ethernet_reserved_symbols_present": sorted(
                symbol for symbol in kc_exports
                if symbol.startswith("__ZN20IOEthernetController31_RESERVEDIOEthernetController")),
        }
        result["kernel_collections"].append(results)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-root", type=pathlib.Path, required=True,
                        help="directory containing extracted IO80211ElCap.kext and corecaptureElCap.kext")
    parser.add_argument("--kernel-collection", type=parse_assignment, action="append", default=[],
                        metavar="LABEL=PATH", help="official BootKC sample; repeat for each OS")
    parser.add_argument("--modern-provider", type=pathlib.Path,
                        help="modern IO80211FamilyLegacy kext directory or executable")
    parser.add_argument("--modern-driver", type=pathlib.Path,
                        help="modern AirPortBrcmNIC kext directory or executable")
    parser.add_argument("--nm", default=shutil.which("nm") or "nm", help="nm executable")
    parser.add_argument("--output", type=pathlib.Path, help="write JSON to this path instead of stdout")
    args = parser.parse_args(argv)
    if not args.kernel_collection:
        parser.error("at least one --kernel-collection is required")
    try:
        result = audit(args.legacy_root,args.kernel_collection,args.modern_provider,
                       args.modern_driver,args.nm)
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))
    encoded = json.dumps(result,indent=2,sort_keys=True)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(encoded)
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
