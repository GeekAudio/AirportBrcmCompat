"""Build a pinned, EFI-only package for the OCLP El Capitan Wi-Fi stack.

The helper keeps upstream kext identifiers and C++ symbols intact. It changes
only exact NUL-terminated corecapture class-name literals in file-backed Mach-O
string sections, then signs the staged bundles ad hoc for strict verification.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile


IO80211_SHA256 = "7fcf956d36d3c1f35fc16c2c6570b4b004224369497971dadb38ccba794e6327"
CORECAPTURE_SHA256 = "59dbbd272c3a796219ddfa43df5349731e2dd068047136b69109c64c6657a47f"
IO80211_URL = (
    "https://github.com/dortania/OpenCore-Legacy-Patcher/raw/refs/heads/main/"
    "payloads/Kexts/Wifi/IO80211ElCap-v2.0.1.zip"
)
CORECAPTURE_URL = (
    "https://github.com/dortania/OpenCore-Legacy-Patcher/raw/refs/heads/main/"
    "payloads/Kexts/Wifi/corecaptureElCap-v1.0.2.zip"
)

PROVIDER = "IO80211ElCap.kext"
CORECAPTURE = "corecaptureElCap.kext"
CORE_BUNDLE = "AirportBrcmCompat.kext"
CORE_EXECUTABLE = "Contents/MacOS/AirportBrcmCompat"
CORECAPTURE_EXECUTABLE = "Contents/MacOS/corecaptureElCap"
CORECAPTURE_BINARY = CORECAPTURE + "/" + CORECAPTURE_EXECUTABLE
DRIVER_4331 = PROVIDER + "/Contents/PlugIns/AirPortBrcm4331.kext"
DRIVER_43224 = PROVIDER + "/Contents/PlugIns/AppleAirPortBrcm43224.kext"
EXCLUDED_ATHEROS = PROVIDER + "/Contents/PlugIns/AirPortAtheros40.kext"
PROVIDER_EXECUTABLE = PROVIDER + "/Contents/MacOS/IO80211ElCap"
DRIVER_4331_EXECUTABLE = DRIVER_4331 + "/Contents/MacOS/AirPortBrcm4331"
DRIVER_43224_EXECUTABLE = DRIVER_43224 + "/Contents/MacOS/AppleAirPortBrcm43224"

TARGET_KERNEL_LABELS = frozenset(f"Darwin{major}" for major in range(21, 26))

EXPECTED_CLASS_NAMES = (
    "CCCapture", "CCDataPipe", "CCDataPipeBlob", "CCDataSession",
    "CCDataStream", "CCIOReporterDataStream", "CCIOReporterHub",
    "CCIOReporterLogStream", "CCLogPipe", "CCLogPipeUserClient",
    "CCLogStream", "CCPipe", "CCPipeUserClient", "CCStream",
)
CORECAPTURE_REQUIRED_IMPORTS = (
    "__ZN22CCIOReporterDataStream35getIOReporterRawDataForSubscriptionEy",
    "__ZN22CCIOReporterDataStream41getIOReporterInterestArrayForSubscriptionEy",
)

TARGET_PCI_IDS = {
    "AirPortBrcm4331.kext": ("pci14e4,432b",),
    "AppleAirPortBrcm43224.kext": (
        # Explicit Apple vendor alias retained by the pinned OCLP donor's
        # Broadcom 802.11 PCI personality. This is intentionally the only
        # non-14e4 match admitted by the dependency builder.
        "pci106b,4e",
        "pci14e4,4311", "pci14e4,4312", "pci14e4,4313",
        "pci14e4,4318", "pci14e4,4319", "pci14e4,431a",
        "pci14e4,4320", "pci14e4,4324", "pci14e4,4325",
        "pci14e4,4328", "pci14e4,432c", "pci14e4,432d",
    ),
}

PROFILES = {"legacy-darwin21plus": ("21.0.0", "")}
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_MEMBER_BYTES = 12 * 1024 * 1024
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
N_STAB = 0xE0
N_TYPE = 0x0E
N_UNDF = 0x00
SECTION_TYPE = 0xFF
S_CSTRING_LITERALS = 0x2


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _bounded_slice(data: bytes, start: int, size: int, label: str) -> bytes:
    if start < 0 or size < 0 or start > len(data) or size > len(data) - start:
        raise ValueError(f"{label} exceeds the input image")
    return data[start:start + size]


def parse_macho64(data: bytes, label: str) -> dict:
    """Parse only bounded x86_64 Mach-O load commands, sections and symbols."""
    if len(data) < 32:
        raise ValueError(f"{label}: truncated Mach-O header")
    magic, cputype = struct.unpack_from("<II", data, 0)
    if magic != MH_MAGIC_64 or cputype != CPU_TYPE_X86_64:
        raise ValueError(f"{label}: expected a little-endian x86_64 Mach-O")
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    if ncmds > 100_000 or sizeofcmds > 64 * 1024 * 1024:
        raise ValueError(f"{label}: unreasonable Mach-O load-command bounds")
    command_end = 32 + sizeofcmds
    _bounded_slice(data, 32, sizeofcmds, f"{label} load commands")
    cursor = 32
    sections: list[dict] = []
    symtab = None
    for index in range(ncmds):
        if cursor > command_end or command_end - cursor < 8:
            raise ValueError(f"{label}: truncated load command {index}")
        command, command_size = struct.unpack_from("<II", data, cursor)
        if (command_size < 8 or command_size % 8 or
                command_size > command_end - cursor):
            raise ValueError(f"{label}: invalid load-command size")
        raw = data[cursor:cursor + command_size]
        if command == LC_SEGMENT_64:
            if command_size < 72:
                raise ValueError(f"{label}: truncated LC_SEGMENT_64")
            segment = raw[8:24].split(b"\0", 1)[0].decode("ascii")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", raw, 24)
            nsects = struct.unpack_from("<I", raw, 64)[0]
            if 72 + nsects * 80 != command_size:
                raise ValueError(f"{label}: invalid section count in {segment}")
            if fileoff > len(data) or filesize > len(data) - fileoff:
                raise ValueError(f"{label}: segment {segment} exceeds file bounds")
            for section_index in range(nsects):
                offset = 72 + section_index * 80
                name = raw[offset:offset + 16].split(b"\0", 1)[0].decode("ascii")
                section_segment = raw[offset + 16:offset + 32].split(b"\0", 1)[0].decode("ascii")
                address, size = struct.unpack_from("<QQ", raw, offset + 32)
                section_fileoff, flags = struct.unpack_from("<II", raw, offset + 48)[0], \
                    struct.unpack_from("<I", raw, offset + 64)[0]
                if section_segment != segment:
                    raise ValueError(f"{label}: section {name} has a mismatched segment")
                section_type = flags & SECTION_TYPE
                item = {"segment": segment, "name": name, "addr": address,
                        "size": size, "fileoff": section_fileoff, "flags": flags}
                if size and section_type not in (0x1, 0xC, 0x12):
                    _bounded_slice(data, section_fileoff, size,
                                   f"{label} section {segment},{name}")
                sections.append(item)
        elif command == LC_SYMTAB:
            if command_size != 24 or symtab is not None:
                raise ValueError(f"{label}: invalid or duplicate LC_SYMTAB")
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", raw, 8)
            if nsyms > 20_000_000 or strsize > 512 * 1024 * 1024:
                raise ValueError(f"{label}: unreasonable symbol-table bounds")
            _bounded_slice(data, symoff, nsyms * 16, f"{label} symbol table")
            _bounded_slice(data, stroff, strsize, f"{label} symbol strings")
            symtab = {"symoff": symoff, "nsyms": nsyms,
                      "stroff": stroff, "strsize": strsize}
        cursor += command_size
    if cursor != command_end or not sections or symtab is None:
        raise ValueError(f"{label}: invalid load-command end, missing sections or symbols")
    return {"sections": sections, "symtab": symtab}


def defined_symbol_values(data: bytes, image: dict, wanted: set[str], label: str) -> dict[str, int]:
    """Return unique defined nlist_64 addresses for the requested symbols."""
    symtab = image["symtab"]
    strings = _bounded_slice(data, symtab["stroff"], symtab["strsize"],
                             f"{label} symbol strings")
    found: dict[str, set[int]] = {name: set() for name in wanted}
    for index in range(symtab["nsyms"]):
        offset = symtab["symoff"] + index * 16
        string_index, n_type, _section, _desc, value = struct.unpack_from("<IBBHQ", data, offset)
        if (n_type & N_STAB) or (n_type & N_TYPE) == N_UNDF or not string_index:
            continue
        if string_index >= len(strings):
            continue
        end = strings.find(b"\0", string_index)
        if end < 0:
            continue
        try:
            name = strings[string_index:end].decode("ascii")
        except UnicodeDecodeError:
            continue
        if name in found:
            found[name].add(value)
    ambiguous = sorted(name for name, values in found.items() if len(values) > 1)
    missing = sorted(name for name, values in found.items() if not values)
    if ambiguous or missing:
        raise ValueError(f"{label}: ambiguous/missing symbols: {ambiguous + missing}")
    return {name: next(iter(values)) for name, values in found.items()}


def macho_symbol_names(data: bytes, image: dict) -> set[str]:
    """Return all bounded nlist names so byte patches cannot alter C++ imports."""
    symtab = image["symtab"]
    strings = _bounded_slice(data, symtab["stroff"], symtab["strsize"],
                             "Mach-O symbol strings")
    result = set()
    for index in range(symtab["nsyms"]):
        offset = symtab["symoff"] + index * 16
        string_index = struct.unpack_from("<I", data, offset)[0]
        if not string_index or string_index >= len(strings):
            continue
        end = strings.find(b"\0", string_index)
        if end < 0:
            continue
        try:
            result.add(strings[string_index:end].decode("ascii"))
        except UnicodeDecodeError:
            continue
    return result


def macho_symbol_kinds(data: bytes, image: dict) -> tuple[set[str], set[str]]:
    """Return bounded defined/undefined external symbols from one Mach-O image."""
    symtab = image["symtab"]
    strings = _bounded_slice(data, symtab["stroff"], symtab["strsize"],
                             "Mach-O symbol strings")
    defined, undefined = set(), set()
    for index in range(symtab["nsyms"]):
        offset = symtab["symoff"] + index * 16
        string_index, n_type, _section, _desc, _value = struct.unpack_from(
            "<IBBHQ", data, offset)
        if (n_type & N_STAB) or not string_index or string_index >= len(strings):
            continue
        end = strings.find(b"\0", string_index)
        if end < 0:
            continue
        try:
            name = strings[string_index:end].decode("ascii")
        except UnicodeDecodeError:
            continue
        if not name or not (n_type & 0x01):
            continue
        if (n_type & N_TYPE) == N_UNDF:
            undefined.add(name)
        else:
            defined.add(name)
    return defined, undefined


def macho_meta_class_names(data: bytes, image: dict) -> set[str]:
    result = set()
    for symbol in macho_symbol_names(data, image):
        match = re.fullmatch(r"__ZN(\d+)(.+)10gMetaClassE", symbol)
        if match and int(match.group(1)) == len(match.group(2)):
            result.add(match.group(2))
    return result


def file_backed_section_hashes(data: bytes, image: dict) -> dict[str, dict]:
    result = {}
    for section in image["sections"]:
        if not section["size"] or section["flags"] & SECTION_TYPE in (0x1, 0xC, 0x12):
            continue
        key = f"{section['segment']},{section['name']}"
        if key in result:
            index = 2
            while f"{key}#{index}" in result:
                index += 1
            key = f"{key}#{index}"
        payload = _bounded_slice(data, section["fileoff"], section["size"], key)
        result[key] = {"size": section["size"], "sha256": sha256(payload)}
    return dict(sorted(result.items()))


def constructor_class_name(data: bytes, image: dict, name: str, label: str) -> tuple[str, int]:
    """Decode the MetaClass constructor's first RIP-relative RSI string literal."""
    symbol = f"__ZN{len(name)}{name}9MetaClassC2Ev"
    start = defined_symbol_values(data, image, {symbol}, label)[symbol]
    text = [section for section in image["sections"]
            if section["segment"] == "__TEXT" and section["name"] == "__text" and
            section["addr"] <= start < section["addr"] + section["size"]]
    if len(text) != 1:
        raise ValueError(f"{label}: constructor is outside one __TEXT,__text section")
    section = text[0]
    offset = section["fileoff"] + start - section["addr"]
    length = min(0x80, section["size"] - (start - section["addr"]))
    code = _bounded_slice(data, offset, length, f"{label} constructor bytes")
    for index in range(max(0, len(code) - 6)):
        if code[index:index + 3] != b"\x48\x8d\x35":
            continue
        displacement = struct.unpack_from("<i", code, index + 3)[0]
        target = start + index + 7 + displacement
        candidates = [item for item in image["sections"]
                      if item["segment"] == "__TEXT" and
                      item["flags"] & SECTION_TYPE == S_CSTRING_LITERALS and
                      item["addr"] <= target < item["addr"] + item["size"]]
        if len(candidates) != 1:
            continue
        literal_section = candidates[0]
        literal_offset = literal_section["fileoff"] + target - literal_section["addr"]
        available = literal_section["size"] - (target - literal_section["addr"])
        literal = _bounded_slice(data, literal_offset, available, f"{label} class string")
        end = literal.find(b"\0")
        if end < 0:
            continue
        try:
            return literal[:end].decode("ascii"), literal_offset
        except UnicodeDecodeError:
            continue
    raise ValueError(f"{label}: no bounded class-name LEA in MetaClass constructor")


def cstring_offsets(data: bytes, image: dict, value: bytes, label: str) -> list[int]:
    """Find exact NUL-terminated literals only in mapped C-string sections."""
    pattern = value + b"\0"
    offsets = []
    for section in image["sections"]:
        if (section["segment"] != "__TEXT" or
                section["flags"] & SECTION_TYPE != S_CSTRING_LITERALS):
            continue
        block = _bounded_slice(data, section["fileoff"], section["size"],
                               f"{label} {section['name']}")
        cursor = 0
        while True:
            found = block.find(pattern, cursor)
            if found < 0:
                break
            offsets.append(section["fileoff"] + found)
            cursor = found + 1
    return offsets


def namespace_class_names(existing_names: set[str], prefix_order: str = "XQZV") -> tuple[str, dict[str, str]]:
    """Pick one same-length leading-byte namespace prefix with no collisions."""
    if not prefix_order or len(set(prefix_order)) != len(prefix_order):
        raise ValueError("namespace prefixes must be unique nonempty bytes")
    for prefix in prefix_order:
        mapping = {name: prefix + name[1:] for name in EXPECTED_CLASS_NAMES}
        values = list(mapping.values())
        if (len(set(values)) != len(values) or any(len(a) != len(b) for a, b in mapping.items()) or
                any(name in existing_names for name in values) or
                any(name in EXPECTED_CLASS_NAMES for name in values)):
            continue
        return prefix, mapping
    raise ValueError("could not find a collision-free same-length class namespace")


def meta_class_names_from_nm(text: str) -> set[str]:
    names = set()
    pattern = re.compile(r"__ZN(\d+)(.+)10gMetaClassE$")
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        match = pattern.fullmatch(fields[-1])
        if match and int(match.group(1)) == len(match.group(2)):
            names.add(match.group(2))
    return names


def kernel_collection_classes(path: Path, nm: str = "nm") -> set[str]:
    try:
        output = subprocess.check_output([nm, "-m", str(path)], text=True,
                                         stderr=subprocess.PIPE, timeout=300)
    except subprocess.CalledProcessError as error:
        message = error.stderr.strip() if error.stderr else str(error)
        raise ValueError(f"nm failed for kernel collection {path}: {message}") from error
    return meta_class_names_from_nm(output)


def _read_pinned_archive(path: Path, expected_hash: str, label: str) -> bytes:
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"{label} exceeds the pinned input size limit")
    data = path.read_bytes()
    if sha256(data) != expected_hash:
        raise ValueError(f"{label} SHA-256 does not match the pinned OCLP asset")
    return data


def _safe_archive_members(archive: zipfile.ZipFile, root_bundle: str) -> list[zipfile.ZipInfo]:
    selected = []
    seen = set()
    total = 0
    for info in archive.infolist():
        name = PurePosixPath(info.filename)
        if (name.is_absolute() or ".." in name.parts or "\\" in info.filename or
                not name.parts):
            raise ValueError("upstream ZIP contains an unsafe path")
        if info.filename.startswith("__MACOSX/") or name.parts[0] != root_bundle:
            continue
        normalized = name.as_posix().rstrip("/")
        if normalized in seen:
            raise ValueError("upstream ZIP contains duplicate paths")
        seen.add(normalized)
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise ValueError("upstream ZIP contains a symlink")
        if not info.is_dir():
            if info.file_size > MAX_MEMBER_BYTES:
                raise ValueError("upstream ZIP member exceeds the size limit")
            total += info.file_size
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("upstream ZIP expanded size exceeds the limit")
        selected.append(info)
    return selected


def _extract_selected_archive(archive_bytes: bytes, target: Path, root_bundle: str,
                              excluded_prefixes: tuple[str, ...] = ()) -> None:
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        for info in _safe_archive_members(archive, root_bundle):
            relative = PurePosixPath(info.filename)
            if any(relative.as_posix().startswith(prefix) for prefix in excluded_prefixes):
                continue
            destination = target.joinpath(*relative.parts)
            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            payload = archive.read(info)
            if len(payload) != info.file_size:
                raise ValueError("upstream ZIP member length changed while extracting")
            destination.write_bytes(payload)
            mode = (info.external_attr >> 16) & 0o777
            if mode:
                os.chmod(destination, mode)


def _bundle_info(path: Path) -> tuple[dict, Path]:
    info_path = path / "Contents" / "Info.plist"
    if not info_path.is_file():
        raise ValueError(f"missing bundle Info.plist: {path}")
    info = plistlib.loads(info_path.read_bytes())
    executable = info.get("CFBundleExecutable")
    if not isinstance(executable, str) or not executable:
        raise ValueError(f"missing CFBundleExecutable: {path}")
    binary = path / "Contents" / "MacOS" / executable
    if not binary.is_file():
        raise ValueError(f"missing executable: {binary}")
    return info, binary


def _validated_source_tree(stage: Path) -> dict[str, Path]:
    expected = {
        PROVIDER: ("com.apple.iokit.IO80211ElCap", "1110.26", "IO80211ElCap"),
        CORECAPTURE: ("com.apple.driver.corecaptureElCap", "1.0.4", "corecaptureElCap"),
        DRIVER_4331: ("com.apple.driver.AirPort.Brcm4331", "800.20.24", "AirPortBrcm4331"),
        DRIVER_43224: ("com.apple.driver.AirPortBrcm43224", "700.36.24", "AppleAirPortBrcm43224"),
    }
    binaries = {}
    for relative, (bundle_id, version, executable) in expected.items():
        info, binary = _bundle_info(stage / relative)
        if (info.get("CFBundleIdentifier") != bundle_id or
                info.get("CFBundleVersion") != version or
                info.get("CFBundleExecutable") != executable):
            raise ValueError(f"unexpected OCLP bundle metadata: {relative}")
        binaries[relative] = binary

    core_info, _ = _bundle_info(stage / CORECAPTURE)
    provider_info, _ = _bundle_info(stage / PROVIDER)
    if provider_info.get("OSBundleLibraries", {}).get(core_info.get("CFBundleIdentifier")) is None:
        raise ValueError("IO80211ElCap does not retain its corecaptureElCap dependency")
    for driver_path in (DRIVER_4331, DRIVER_43224):
        driver_info, _ = _bundle_info(stage / driver_path)
        if driver_info.get("OSBundleLibraries", {}).get(provider_info.get("CFBundleIdentifier")) is None:
            raise ValueError(f"{driver_path} does not retain its IO80211ElCap dependency")

    core_data = binaries[CORECAPTURE].read_bytes()
    provider_data = binaries[PROVIDER].read_bytes()
    core_defined, _core_undefined = macho_symbol_kinds(
        core_data, parse_macho64(core_data, "corecaptureElCap"))
    _provider_defined, provider_undefined = macho_symbol_kinds(
        provider_data, parse_macho64(provider_data, "IO80211ElCap"))
    for symbol in CORECAPTURE_REQUIRED_IMPORTS:
        if symbol not in core_defined or symbol not in provider_undefined:
            raise ValueError(f"legacy provider/corecapture C++ dependency is not closed: {symbol}")

    personality_specs = {
        DRIVER_4331: ("AirPortBrcm4331.kext", "AirPort_Brcm4331"),
        DRIVER_43224: ("AppleAirPortBrcm43224.kext", "AirPort_Brcm43224"),
    }
    for bundle, (relative, expected_class) in personality_specs.items():
        expected_ids = set(TARGET_PCI_IDS[relative])
        info, _binary = _bundle_info(stage / bundle)
        personalities = info.get("IOKitPersonalities")
        if not isinstance(personalities, dict) or "Broadcom 802.11 PCI" not in personalities:
            raise ValueError(f"missing Broadcom PCI personality in {bundle}")
        personality = personalities["Broadcom 802.11 PCI"]
        ids = personality.get("IONameMatch")
        if (personality.get("IOClass") != expected_class or
                personality.get("IOProviderClass") != "IOPCIDevice" or
                not isinstance(ids, list) or not expected_ids.issubset(set(ids))):
            raise ValueError(f"unexpected Broadcom PCI personality in {bundle}")
    return binaries


def _patch_corecapture_namespace(stage: Path, binaries: dict[str, Path],
                                 collision_names: set[str]) -> dict:
    core_binary = binaries[CORECAPTURE]
    core_data = core_binary.read_bytes()
    core_image = parse_macho64(core_data, str(core_binary))
    names = set(collision_names)
    for binary in binaries.values():
        data = binary.read_bytes()
        image = parse_macho64(data, str(binary))
        names |= macho_meta_class_names(data, image)
    prefix, mapping = namespace_class_names(names)
    patches: dict[str, list[tuple[int, bytes]]] = {key: [] for key in binaries}

    for class_name in EXPECTED_CLASS_NAMES:
        patch_count_before = sum(len(entries) for entries in patches.values())
        actual_name, constructor_offset = constructor_class_name(
            core_data, core_image, class_name, str(core_binary))
        if actual_name != class_name:
            raise ValueError(f"unexpected corecapture constructor name for {class_name}")
        for bundle_relative, binary in binaries.items():
            data = binary.read_bytes()
            image = parse_macho64(data, str(binary))
            occurrences = cstring_offsets(data, image, class_name.encode("ascii"), str(binary))
            if bundle_relative == CORECAPTURE and constructor_offset not in occurrences:
                raise ValueError(f"class constructor literal is not a mapped C string: {class_name}")
            for offset in occurrences:
                patches[bundle_relative].append((offset, mapping[class_name].encode("ascii")))
        if sum(len(entries) for entries in patches.values()) == patch_count_before:
            raise ValueError(f"no mapped NUL-terminated literal found for {class_name}")

    changed = {}
    section_hashes_before_signing = {}
    for bundle_relative, entries in patches.items():
        binary = binaries[bundle_relative]
        original = binary.read_bytes()
        original_image = parse_macho64(original, str(binary))
        original_symbols = macho_symbol_names(original, original_image)
        mutable = bytearray(original)
        seen = set()
        for offset, replacement in sorted(entries):
            if offset in seen:
                raise ValueError(f"duplicate class literal patch offset in {bundle_relative}")
            seen.add(offset)
            old = bytes(mutable[offset:offset + len(replacement)])
            expected_old = next(old_name.encode("ascii")
                                for old_name, new_name in mapping.items()
                                if new_name.encode("ascii") == replacement)
            if old != expected_old or mutable[offset + len(old)] != 0:
                raise ValueError(f"class literal changed before patching in {bundle_relative}")
            if len(old) != len(replacement):
                raise ValueError("namespace patch must preserve literal length")
            mutable[offset:offset + len(replacement)] = replacement
        binary.write_bytes(mutable)
        if len(mutable) != len(original):
            raise ValueError("namespace patch changed Mach-O size")
        patched_bytes = bytes(mutable)
        patched_image = parse_macho64(patched_bytes, str(binary))
        if macho_symbol_names(patched_bytes, patched_image) != original_symbols:
            raise ValueError(f"class namespace patch changed C++ symbols in {bundle_relative}")
        section_hashes_before_signing[bundle_relative] = file_backed_section_hashes(
            patched_bytes, patched_image)
        if entries:
            changed[bundle_relative] = {
                "original_sha256": sha256(original),
                "patched_sha256": sha256(patched_bytes),
                "literal_replacements": len(entries),
            }

    # Verify all constructors now register under the new unique names, while
    # exports and imports remain byte-for-byte the same symbol strings.
    renamed_core = core_binary.read_bytes()
    renamed_image = parse_macho64(renamed_core, str(core_binary))
    for old_name, new_name in mapping.items():
        actual, _offset = constructor_class_name(renamed_core, renamed_image,
                                                  old_name, str(core_binary))
        if actual != new_name:
            raise ValueError(f"namespace verification failed for {old_name}")
    return {"prefix": prefix, "mapping": mapping, "patched_binaries": changed,
            "section_hashes_before_signing": section_hashes_before_signing}


def _restrict_personality(path: Path, expected_pci_ids: tuple[str, ...]) -> None:
    if (not expected_pci_ids or len(set(expected_pci_ids)) != len(expected_pci_ids) or
            any(not re.fullmatch(r"pci14e4,[0-9a-f]{4}", item) and
                item != "pci106b,4e"
                for item in expected_pci_ids)):
        raise ValueError("expected PCI IDs must be unique Broadcom IDs or the pinned Apple alias")
    info, _binary = _bundle_info(path)
    personality = info["IOKitPersonalities"]["Broadcom 802.11 PCI"]
    personality["IONameMatch"] = list(expected_pci_ids)
    info_path = path / "Contents" / "Info.plist"
    info_path.write_bytes(plistlib.dumps(info, sort_keys=False))


def _sign_bundle(bundle: Path) -> None:
    subprocess.run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(bundle)],
                   check=True, capture_output=True)


def _verify_bundle(bundle: Path) -> None:
    subprocess.run(["codesign", "--verify", "--strict", str(bundle)],
                   check=True, capture_output=True)


def _sign_and_verify(stage: Path) -> None:
    # Sign inner kext bundles before the provider that contains them.
    binaries = _validated_source_tree(stage)
    section_hashes = {
        relative: file_backed_section_hashes(
            binary.read_bytes(), parse_macho64(binary.read_bytes(), str(binary)))
        for relative, binary in binaries.items()
    }
    for relative in (DRIVER_4331, DRIVER_43224, PROVIDER, CORECAPTURE):
        _sign_bundle(stage / relative)
    for relative in (DRIVER_4331, DRIVER_43224, PROVIDER, CORECAPTURE):
        _verify_bundle(stage / relative)
    for relative, binary in binaries.items():
        signed = binary.read_bytes()
        actual = file_backed_section_hashes(signed, parse_macho64(signed, str(binary)))
        if actual != section_hashes[relative]:
            raise ValueError(f"ad-hoc signing changed a file-backed Mach-O section in {relative}")


def _write_config_fragment(stage: Path, profile: str) -> dict:
    minimum, maximum = PROFILES[profile]
    add_specs = [
        (CORE_BUNDLE, CORE_EXECUTABLE,
         "AirportBrcmCompat core; bundle ID org.geekaudio.AirportBrcmCompat; distributed separately"),
        (CORECAPTURE, CORECAPTURE_EXECUTABLE, "OCLP El Capitan corecapture dependency"),
        (PROVIDER, "Contents/MacOS/IO80211ElCap", "OCLP El Capitan 802.11 provider"),
        (DRIVER_4331, "Contents/MacOS/AirPortBrcm4331", "OCLP AirPortBrcm4331 legacy PCI ID 432b"),
        (DRIVER_43224, "Contents/MacOS/AppleAirPortBrcm43224", "OCLP AppleAirPortBrcm43224 PCI ID set; no hardware claim"),
    ]
    add = []
    for bundle_path, executable, comment in add_specs:
        add.append({"Arch": "x86_64", "BundlePath": bundle_path,
                    "Comment": comment, "Enabled": True,
                    "ExecutablePath": executable, "PlistPath": "Contents/Info.plist",
                    "MinKernel": minimum, "MaxKernel": maximum})
    blocked = [
        ("com.apple.iokit.IO80211Family", "Exclude", "Replace native IO80211 classes with the legacy provider"),
        ("com.apple.iokit.IO80211FamilyLegacy", "Disable", "Mutually exclusive modern IO80211 provider"),
        ("com.apple.driver.AirPort.BrcmNIC", "Disable", "Mutually exclusive modern Broadcom NIC driver"),
    ]
    block = [{"Arch": "x86_64", "Comment": comment, "Enabled": True,
              "Identifier": identifier, "MinKernel": minimum,
              "MaxKernel": maximum, "Strategy": strategy}
             for identifier, strategy, comment in blocked]
    config = {"Kernel": {"Add": add, "Block": block}}
    (stage / "config-legacy-wifi.fragment.plist").write_bytes(
        plistlib.dumps(config, sort_keys=False))
    return config


def _validate_kernel_collection_samples(
        kernel_collections: list[tuple[str, Path]]) -> list[tuple[str, Path]]:
    if not kernel_collections:
        raise ValueError("supply at least one user-selected target BootKernelCollection sample")

    normalized = []
    labels = set()
    for label, raw_path in kernel_collections:
        if label not in TARGET_KERNEL_LABELS:
            raise ValueError("target BootKC labels must be unique Darwin21 through Darwin25")
        if label in labels:
            raise ValueError(f"duplicate target BootKC label: {label}")
        path = Path(raw_path)
        if not path.is_file():
            raise ValueError(f"BootKernelCollection does not exist: {path}")
        labels.add(label)
        normalized.append((label, path))
    return normalized


def _write_notice(stage: Path, archive_hashes: dict[str, str]) -> None:
    text = (
        "Legacy Wi-Fi dependency provenance\n"
        "\n"
        "This package is derived from the OCLP El Capitan Apple kernel-extension "
        "binaries. Fourteen same-length corecapture class-name literals are namespaced; "
        "the two Broadcom PCI personalities are narrowed to their selected IDs; the "
        "staged bundles are ad-hoc signed for strict integrity verification. These "
        "binaries are not AirportBrcmCompat source and are not covered by this "
        "repository's BSD-3-Clause license.\n"
        "\n"
        f"IO80211ElCap v2.0.1 source: {IO80211_URL}\n"
        f"IO80211ElCap source ZIP SHA-256: {archive_hashes['IO80211ElCap']}\n"
        f"corecaptureElCap v1.0.2 source: {CORECAPTURE_URL}\n"
        f"corecaptureElCap source ZIP SHA-256: {archive_hashes['corecaptureElCap']}\n"
        "\n"
        "The generated OpenCore fragment is a dedicated EFI legacy-Wi-Fi profile. It "
        "blocks the native and modern wireless-provider routes for this profile and "
        "must replace, not accompany, the modern IO80211FamilyLegacy profile. Offline "
        "validation covers pinned source archives, class-name collision samples, "
        "unchanged C++ symbol/dependency closure, code signatures, and ZIP contents.\n"
    )
    (stage / "NOTICE-legacy-wifi.txt").write_text(text)


def _zip_tree(stage: Path) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as package:
        for path in sorted(stage.rglob("*"), key=lambda item: item.relative_to(stage).as_posix()):
            relative = path.relative_to(stage).as_posix()
            mode = stat.S_IMODE(path.stat().st_mode)
            info = zipfile.ZipInfo(relative + "/" if path.is_dir() else relative)
            info.create_system = 3
            info.date_time = (1980, 1, 1, 0, 0, 0)
            if path.is_dir():
                info.external_attr = (stat.S_IFDIR | mode) << 16 | 0x10
                info.compress_type = zipfile.ZIP_STORED
                package.writestr(info, b"")
            else:
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                package.writestr(info, path.read_bytes())
    return output.getvalue()


def _extract_package(package_bytes: bytes, destination: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(package_bytes)) as package:
        seen = set()
        for info in package.infolist():
            name = PurePosixPath(info.filename)
            if name.is_absolute() or ".." in name.parts or "\\" in info.filename:
                raise ValueError("generated ZIP contains an unsafe path")
            if info.filename in seen:
                raise ValueError("generated ZIP contains duplicate paths")
            seen.add(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError("generated ZIP contains a symlink")
            target = destination.joinpath(*name.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = package.read(info)
            if len(payload) != info.file_size:
                raise ValueError("generated ZIP member length changed")
            target.write_bytes(payload)
            permissions = (info.external_attr >> 16) & 0o777
            if permissions:
                os.chmod(target, permissions)


def _verify_package_tree(stage: Path, config: dict, namespace: dict) -> None:
    for relative in (CORECAPTURE, PROVIDER, DRIVER_4331, DRIVER_43224):
        if not (stage / relative).is_dir():
            raise ValueError(f"package is missing {relative}")
        _verify_bundle(stage / relative)
    if (stage / EXCLUDED_ATHEROS).exists():
        raise ValueError("package unexpectedly contains the Atheros plugin")
    expected_bundle_ids = {
        CORECAPTURE: "com.apple.driver.corecaptureElCap",
        PROVIDER: "com.apple.iokit.IO80211ElCap",
        DRIVER_4331: "com.apple.driver.AirPort.Brcm4331",
        DRIVER_43224: "com.apple.driver.AirPortBrcm43224",
    }
    for relative, expected_id in expected_bundle_ids.items():
        info, _binary = _bundle_info(stage / relative)
        if info.get("CFBundleIdentifier") != expected_id:
            raise ValueError(f"bundle identifier changed unexpectedly: {relative}")
    for relative, target_key in ((DRIVER_4331, "AirPortBrcm4331.kext"),
                                 (DRIVER_43224, "AppleAirPortBrcm43224.kext")):
        info, _binary = _bundle_info(stage / relative)
        ids = info.get("IOKitPersonalities", {}).get("Broadcom 802.11 PCI", {}).get("IONameMatch")
        if ids != list(TARGET_PCI_IDS[target_key]):
            raise ValueError(f"PCI matching is not restricted to its verified target in {relative}")
    plugins = sorted(path.name for path in (stage / PROVIDER / "Contents/PlugIns").iterdir()
                     if path.is_dir())
    if plugins != sorted((Path(DRIVER_4331).name, Path(DRIVER_43224).name)):
        raise ValueError("legacy provider has an unexpected plugin set")
    expected_add = [CORE_BUNDLE, CORECAPTURE, PROVIDER, DRIVER_4331, DRIVER_43224]
    actual_add = [entry["BundlePath"] for entry in config["Kernel"]["Add"]]
    if actual_add != expected_add:
        raise ValueError("legacy profile has an unexpected or reordered Add list")
    core_entry = config["Kernel"]["Add"][0]
    if (core_entry.get("ExecutablePath") != CORE_EXECUTABLE or
            core_entry.get("PlistPath") != "Contents/Info.plist"):
        raise ValueError("legacy profile does not load the matching AirportBrcmCompat core first")
    block_ids = {entry["Identifier"] for entry in config["Kernel"]["Block"]}
    if not {"com.apple.iokit.IO80211Family", "com.apple.iokit.IO80211FamilyLegacy",
            "com.apple.driver.AirPort.BrcmNIC"}.issubset(block_ids):
        raise ValueError("legacy profile does not exclude competing wireless providers")
    if len(namespace["mapping"]) != len(EXPECTED_CLASS_NAMES):
        raise ValueError("legacy corecapture namespace mapping is incomplete")


def prepare(io80211_archive: Path, corecapture_archive: Path, output: Path,
            kernel_collections: list[tuple[str, Path]],
            profile: str = "legacy-darwin21plus", nm: str = "nm") -> dict:
    io80211_archive = Path(io80211_archive)
    corecapture_archive = Path(corecapture_archive)
    output = Path(output)
    if profile not in PROFILES:
        raise ValueError("unknown legacy dependency profile")
    if output.exists() or output.is_symlink():
        raise ValueError("output already exists")
    if output.suffix.lower() != ".zip":
        raise ValueError("output must be a .zip package path")
    kernel_collections = _validate_kernel_collection_samples(kernel_collections)

    io80211_bytes = _read_pinned_archive(io80211_archive, IO80211_SHA256,
                                         "IO80211ElCap v2.0.1")
    corecapture_bytes = _read_pinned_archive(corecapture_archive, CORECAPTURE_SHA256,
                                             "corecaptureElCap v1.0.2")
    if not shutil.which("codesign"):
        raise ValueError("codesign is required to sign the modified EFI dependency bundles")
    kc_classes = set()
    kc_inputs = []
    for label, path in kernel_collections:
        classes = kernel_collection_classes(path, nm)
        if not classes:
            raise ValueError(f"BootKernelCollection has no visible gMetaClass symbols: {path}")
        missing_corecapture_names = set(EXPECTED_CLASS_NAMES) - classes
        if missing_corecapture_names:
            raise ValueError(f"{label} does not contain the expected native class names: "
                             f"{sorted(missing_corecapture_names)}")
        kc_classes |= classes
        kc_inputs.append({"label": label, "path": str(path.resolve()),
                          "sha256": sha256_file(path),
                          "visible_meta_class_count": len(classes)})

    source_hashes = {"IO80211ElCap": sha256(io80211_bytes),
                     "corecaptureElCap": sha256(corecapture_bytes)}
    with tempfile.TemporaryDirectory(prefix="legacy-wifi-dependencies-") as temporary:
        stage = Path(temporary) / "stage"
        stage.mkdir()
        _extract_selected_archive(io80211_bytes, stage, PROVIDER,
                                  (EXCLUDED_ATHEROS,))
        _extract_selected_archive(corecapture_bytes, stage, CORECAPTURE)
        binaries = _validated_source_tree(stage)
        namespace = _patch_corecapture_namespace(stage, binaries, kc_classes)

        _restrict_personality(stage / DRIVER_4331, TARGET_PCI_IDS["AirPortBrcm4331.kext"])
        _restrict_personality(stage / DRIVER_43224,
                              TARGET_PCI_IDS["AppleAirPortBrcm43224.kext"])
        config = _write_config_fragment(stage, profile)
        _write_notice(stage, source_hashes)
        _sign_and_verify(stage)

        manifest = {
            "schema": 1,
            "status": "EFI_LEGACY_WIFI_DEPENDENCY_OFFLINE_CHECKED",
            "dependency_profile": profile,
            "minimum_kernel": PROFILES[profile][0],
            "maximum_kernel": PROFILES[profile][1],
            "input_sources": {
                "IO80211ElCap": {"version": "2.0.1", "url": IO80211_URL,
                                 "sha256": source_hashes["IO80211ElCap"]},
                "corecaptureElCap": {"version": "1.0.2", "url": CORECAPTURE_URL,
                                     "sha256": source_hashes["corecaptureElCap"]},
            },
            "kernel_collection_collision_samples": kc_inputs,
            "corecapture_class_namespace": namespace,
            "preserved_bundle_ids": {
                "corecaptureElCap": "com.apple.driver.corecaptureElCap",
                "IO80211ElCap": "com.apple.iokit.IO80211ElCap",
                "AirPortBrcm4331": "com.apple.driver.AirPort.Brcm4331",
                "AppleAirPortBrcm43224": "com.apple.driver.AirPortBrcm43224",
            },
            "personality_pci_ids": {
                bundle: list(ids) for bundle, ids in TARGET_PCI_IDS.items()
            },
            "personality_pci_id_basis": (
                "OCLP legacy table plus pci106b,4e explicitly present in the pinned "
                "AppleAirPortBrcm43224 donor personality; "
                "PCI ID matching is not hardware validation"
            ),
            "hardware_validation": False,
            "bundles": [CORECAPTURE, PROVIDER, DRIVER_4331, DRIVER_43224],
            "excluded_bundle": EXCLUDED_ATHEROS,
            "profile_blocks": [
                "com.apple.iokit.IO80211Family",
                "com.apple.iokit.IO80211FamilyLegacy",
                "com.apple.driver.AirPort.BrcmNIC",
            ],
            "exclusive_wifi_profile": True,
            "must_not_merge_with_modern_wifi_adds": True,
            "corecapture_cpp_imports_preserved": list(CORECAPTURE_REQUIRED_IMPORTS),
            "binary_hashes": {
                relative: {"sha256": sha256(binary.read_bytes()),
                           "size": binary.stat().st_size}
                for relative, binary in sorted(binaries.items())
            },
            "license_scope": "upstream Apple/OCLP binaries are not covered by BSD-3-Clause",
            "validation_scope": [
                "pinned OCLP input ZIP hashes",
                "bounded Mach-O class literal and symbol checks",
                "class-name collision checks against the supplied BootKCs",
                "strict ad-hoc code-signature verification",
                "configuration and ZIP extraction round-trip",
            ],
        }
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        _verify_package_tree(stage, config, namespace)
        package_bytes = _zip_tree(stage)

        fresh = Path(temporary) / "fresh-extract"
        fresh.mkdir()
        _extract_package(package_bytes, fresh)
        fresh_config = plistlib.loads((fresh / "config-legacy-wifi.fragment.plist").read_bytes())
        fresh_manifest = json.loads((fresh / "manifest.json").read_text())
        _verify_package_tree(fresh, fresh_config, fresh_manifest["corecapture_class_namespace"])
        if fresh_manifest != manifest:
            raise ValueError("package manifest changed during ZIP round-trip")
        for executable in (CORECAPTURE_BINARY, PROVIDER_EXECUTABLE,
                           DRIVER_4331_EXECUTABLE, DRIVER_43224_EXECUTABLE):
            if (fresh / executable).stat().st_mode & 0o111 == 0:
                raise ValueError(f"ZIP did not preserve executable mode for {executable}")

    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(package_bytes)
    except FileExistsError as error:
        raise ValueError("output already exists") from error
    except Exception:
        if output.exists():
            output.unlink()
        raise
    return manifest
