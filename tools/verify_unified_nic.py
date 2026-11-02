#!/usr/bin/env python3
"""Offline proof checks for using the pinned Tahoe NIC image as one shared candidate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile


PROJECT = Path(__file__).resolve().parents[1]
TOOLS = PROJECT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import verify_modern_driver_pins as pins  # noqa: E402


SONOMA_MEMBER = (
    "Kexts/AirPortBrcmNIC-Sonoma-Sequoia.kext/Contents/MacOS/AirPortBrcmNIC"
)
TAHOE_MEMBER = "Kexts/AirPortBrcmNIC-Tahoe.kext/Contents/MacOS/AirPortBrcmNIC"
EXPECTED_BINARY_SHA256 = {
    "sonoma": "c43b8c5443c14d029c86459ea60502ede731bb94acb8de201fc210c99080f0d0",
    "tahoe": "999c1a5b6a0d18baba2050520c1d429b49edfd99bfc8d71299b639334f263982",
}
EXPECTED_UUID = "E4678FEB-1DC1-35CC-9306-48021083D04A"

# Half-open file-offset ranges. The first is the Tahoe DMA shim inserted over
# an existing code area; the remaining four are its call-site branches.
CODE_CHANGE_RANGES = (
    ("dma_shim", 0x1AFFF, 0x1B4D6),
    ("dma_detach_hook", 0x2C1AE8, 0x2C1AED),
    ("tx_dma_hook", 0x2C2612, 0x2C261A),
    ("rx_dma_hook", 0x2C3D78, 0x2C3D82),
    ("rx_complete_hook", 0x2C4286, 0x2C428E),
)

HOOKS = (
    ("dma_detach_hook", 0x2C1AE8, 5, 0x1B47C, 0),
    ("tx_dma_hook", 0x2C2612, 8, 0x1B17F, 3),
    ("rx_dma_hook", 0x2C3D78, 10, 0x1B2B7, 5),
    ("rx_complete_hook", 0x2C4286, 8, 0x1B2EA, 3),
)

REJOIN_BRANCHES = (
    ("tx_dma_rejoin", 0x1B2B2, 0x2C261A),
    ("rx_dma_rejoin", 0x1B2E5, 0x2C3D82),
    ("rx_complete_rejoin", 0x1B356, 0x2C428E),
)

# Calls present in the pinned Tahoe shim. Targets written as names must resolve
# to one unambiguous, defined symbol in the same AirPortBrcmNIC image.
SHIM_CALLS = (
    (0x1B0A3, "_osl_malloc"),
    (0x1B12D, "_osl_dma_alloc_consistent"),
    (0x1B1A4, "_bcm_decode_anqp_nai_realm_print"),
    (0x1B1E7, "_osl_pktdata"),
    (0x1B1FB, "_osl_pktlen"),
    (0x1B250, "_osl_pktnext"),
    (0x1B2D6, "_bcm_decode_anqp_nai_realm_print"),
    (0x1B312, "_bcm_decode_anqp_nai_realm_print"),
    (0x1B32B, "_osl_pktdata"),
    (0x1B3FC, "_osl_dma_free_consistent"),
    (0x1B423, "_osl_mfree"),
    (0x1B4A6, 0x1B35B),
    (0x1B4B6, 0x1B35B),
    # The original DMA map calls remain immediately before the patched sites.
    (0x2C260D, "_osl_dma_map"),
    (0x2C3D73, "_osl_dma_map"),
)

LC_SYMTAB = 0x2
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
N_STAB = 0xE0
N_TYPE = 0x0E
N_UNDF = 0x00
N_SECT = 0x0E
N_EXT = 0x01


class VerificationError(ValueError):
    """Raised when an input differs from the pinned, statically checked image."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _import_digest(items) -> str:
    serialized = "\n".join(
        "\t".join(str(part) for part in item) for item in sorted(items)
    ).encode("ascii")
    return _sha256(serialized)


def _read_artifact(path: Path, member: str, role: str) -> dict:
    path = Path(path)
    members, archive_sha = pins._read_zip_members(path)
    if set(members) != {member}:
        raise VerificationError(
            f"{path.name} must contain exactly its {role} NIC executable"
        )
    binary = members[member]
    binary_sha = _sha256(binary)
    if binary_sha != EXPECTED_BINARY_SHA256[role]:
        raise VerificationError(
            f"{role} NIC binary is not the hash-pinned image: {binary_sha}"
        )

    contents = member.split("/MacOS/", 1)[0]
    metadata_names = {
        "Info.plist": contents + "/Info.plist",
        "version.plist": contents + "/version.plist",
        "CodeResources": contents + "/_CodeSignature/CodeResources",
    }
    try:
        with zipfile.ZipFile(path) as archive:
            metadata = {key: archive.read(name) for key, name in metadata_names.items()}
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise VerificationError(f"{role} NIC bundle metadata is incomplete") from exc

    try:
        import plistlib

        info = plistlib.loads(metadata["Info.plist"])
    except Exception as exc:
        raise VerificationError(f"{role} NIC Info.plist is invalid") from exc
    return {
        "role": role,
        "path": path.resolve(strict=True),
        "archive_name": path.name,
        "archive_sha256": archive_sha,
        "member": member,
        "binary": binary,
        "binary_sha256": binary_sha,
        "metadata": metadata,
        "info": info,
    }


def _load_commands(data: bytes) -> tuple[list[bytes], tuple[int, int], tuple[int, int, int, int], dict]:
    if len(data) < 32:
        raise VerificationError("Mach-O header is truncated")
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    end = 32 + sizeofcmds
    if end > len(data) or ncmds == 0 or ncmds > sizeofcmds // 8:
        raise VerificationError("Mach-O load command table is out of bounds")

    commands = []
    signature = None
    symtab = None
    sections = {}
    section_index = 1
    cursor = 32
    for _ in range(ncmds):
        if cursor + 8 > end:
            raise VerificationError("Truncated Mach-O load command")
        command, size = struct.unpack_from("<II", data, cursor)
        if size < 8 or size % 8 or cursor + size > end:
            raise VerificationError("Invalid Mach-O load command size")
        chunk = data[cursor:cursor + size]
        commands.append(chunk)
        if command == LC_CODE_SIGNATURE:
            if signature is not None or size != 16:
                raise VerificationError("Invalid or duplicate LC_CODE_SIGNATURE")
            signature = struct.unpack_from("<II", chunk, 8)
        elif command == LC_SYMTAB:
            if symtab is not None or size != 24:
                raise VerificationError("Invalid or duplicate LC_SYMTAB")
            symtab = struct.unpack_from("<IIII", chunk, 8)
        elif command == LC_SEGMENT_64:
            if size < 72:
                raise VerificationError("Truncated LC_SEGMENT_64")
            nsects = struct.unpack_from("<I", chunk, 64)[0]
            if 72 + nsects * 80 != size:
                raise VerificationError("Invalid LC_SEGMENT_64 section table")
            for index in range(nsects):
                offset = 72 + index * 80
                section_raw, segment_raw = struct.unpack_from("<16s16s", chunk, offset)
                section_name = section_raw.split(b"\0", 1)[0].decode("ascii")
                segment_name = segment_raw.split(b"\0", 1)[0].decode("ascii")
                sections[section_index] = (segment_name, section_name)
                section_index += 1
        cursor += size
    if cursor != end or signature is None or symtab is None:
        raise VerificationError("Mach-O command table is incomplete")
    sigoff, sigsize = signature
    if sigoff > len(data) or sigsize > len(data) - sigoff:
        raise VerificationError("LC_CODE_SIGNATURE exceeds Mach-O file bounds")
    return commands, signature, symtab, sections


def _parse_symbols(data: bytes, symtab, section_names: dict) -> dict:
    symoff, count, stroff, strsize = symtab
    if (symoff > len(data) or count > (len(data) - symoff) // 16 or
            stroff > len(data) or strsize > len(data) - stroff):
        raise VerificationError("Mach-O symbol table is out of bounds")

    imports = set()
    vtables = {}
    defined = {}
    for index in range(count):
        nameoff, n_type, n_sect, n_desc, value = struct.unpack_from(
            "<IBBHQ", data, symoff + index * 16
        )
        if n_type & N_STAB:
            continue
        if nameoff >= strsize:
            raise VerificationError("Invalid Mach-O symbol name offset")
        terminator = data.find(b"\0", stroff + nameoff, stroff + strsize)
        if terminator < 0:
            raise VerificationError("Unterminated Mach-O symbol name")
        try:
            name = data[stroff + nameoff:terminator].decode("ascii")
        except UnicodeDecodeError as exc:
            raise VerificationError("Mach-O symbol name is not ASCII") from exc
        if not name:
            continue

        kind = n_type & N_TYPE
        if kind == N_UNDF and n_type & N_EXT:
            imports.add((name, n_type, n_sect, n_desc, value))
        elif kind == N_SECT and n_sect:
            symbol = (name, n_type, n_sect, n_desc, value,
                      section_names.get(n_sect, ("?", "?")))
            defined.setdefault(name, []).append(symbol)
            if name.startswith("__ZTV"):
                if name in vtables:
                    raise VerificationError(f"Duplicate vtable symbol: {name}")
                vtables[name] = symbol[1:]
    return {"imports": imports, "vtables": vtables, "defined": defined}


def _defined_address(symbols: dict, name: str) -> int:
    matches = symbols["defined"].get(name, [])
    addresses = {entry[4] for entry in matches}
    if len(addresses) != 1:
        raise VerificationError(f"Expected one unambiguous definition of {name}")
    return next(iter(addresses))


def decode_rel32_target(code: bytes, offset: int, opcode: int) -> int:
    """Decode one x86-64 near branch at an image-relative address."""
    if offset < 0 or offset + 5 > len(code) or code[offset] != opcode:
        raise VerificationError(f"Expected relative branch opcode at {offset:#x}")
    displacement = struct.unpack_from("<i", code, offset + 1)[0]
    return offset + 5 + displacement


def _assert_text_address(address: int, mapped) -> None:
    start = mapped.text_vmaddr
    end = start + mapped.text_size
    if address < start or address >= end:
        raise VerificationError(f"Control-flow target {address:#x} is outside __text")


def _check_delta(base: bytes, candidate: bytes, signature: tuple[int, int],
                 code_ranges=CODE_CHANGE_RANGES) -> dict:
    if len(base) != len(candidate):
        raise VerificationError("The two pinned NIC images have different file sizes")
    sig_start, sig_size = signature
    sig_end = sig_start + sig_size
    ranges = [(name, start, end) for name, start, end in code_ranges]
    if any(start < 0 or end <= start or end > len(base) for _, start, end in ranges):
        raise VerificationError("A declared code-change range is outside the image")
    if any(start < sig_end and sig_start < end for _, start, end in ranges):
        raise VerificationError("A code-change range overlaps the signature blob")

    counts = {name: 0 for name, _, _ in ranges}
    signature_changes = 0
    changed = 0
    for offset, (left, right) in enumerate(zip(base, candidate)):
        if left == right:
            continue
        changed += 1
        matching = [name for name, start, end in ranges if start <= offset < end]
        if matching:
            counts[matching[0]] += 1
        elif sig_start <= offset < sig_end:
            signature_changes += 1
        else:
            raise VerificationError(f"Unexpected NIC binary difference at {offset:#x}")
    if any(count == 0 for count in counts.values()):
        missing = ", ".join(name for name, count in counts.items() if count == 0)
        raise VerificationError(f"A declared DMA shim/hook region has no changed bytes: {missing}")
    if signature_changes == 0:
        raise VerificationError("The code signature did not change with the patched image")
    return {
        "changed_byte_count": changed,
        "code_region_changed_bytes": counts,
        "signature_changed_byte_count": signature_changes,
        "unlisted_changes": 0,
    }


def _check_hook_targets(mapped, symbols) -> list[dict]:
    code = mapped.data
    results = []
    for name, site, length, target, padding in HOOKS:
        actual = decode_rel32_target(code, site, 0xE9)
        _assert_text_address(actual, mapped)
        if actual != target:
            raise VerificationError(f"{name} targets {actual:#x}, expected {target:#x}")
        if any(byte != 0x90 for byte in code[site + 5:site + length]):
            raise VerificationError(f"{name} has unexpected trailing patch bytes")
        if length - 5 != padding:
            raise VerificationError(f"Internal padding contract is inconsistent for {name}")
        results.append({"name": name, "site": hex(site), "target": hex(actual),
                        "target_in_text": True, "nop_padding_bytes": padding})

    for name, site, target in REJOIN_BRANCHES:
        actual = decode_rel32_target(code, site, 0xE9)
        _assert_text_address(actual, mapped)
        if actual != target:
            raise VerificationError(f"{name} targets {actual:#x}, expected {target:#x}")
        results.append({"name": name, "site": hex(site), "target": hex(actual),
                        "target_in_text": True})

    calls = []
    for site, expected in SHIM_CALLS:
        actual = decode_rel32_target(code, site, 0xE8)
        _assert_text_address(actual, mapped)
        expected_address = (_defined_address(symbols, expected)
                            if isinstance(expected, str) else expected)
        if actual != expected_address:
            label = expected if isinstance(expected, str) else hex(expected)
            raise VerificationError(
                f"Call at {site:#x} targets {actual:#x}, expected {label} ({expected_address:#x})"
            )
        calls.append({"site": hex(site), "target": hex(actual),
                      "symbol": expected if isinstance(expected, str) else None})

    return [{"branches": results, "calls": calls}]


def verify(sonoma_zip: Path, tahoe_zip: Path) -> dict:
    """Compare pinned Sonoma and Tahoe NIC images; invoke no driver code."""
    sonoma = _read_artifact(Path(sonoma_zip), SONOMA_MEMBER, "sonoma")
    tahoe = _read_artifact(Path(tahoe_zip), TAHOE_MEMBER, "tahoe")
    if sonoma["path"] == tahoe["path"]:
        raise VerificationError("Sonoma and Tahoe inputs must be separate ZIP files")

    sonoma_mapped = pins.map_thin_x86_64_macho(sonoma["binary"])
    tahoe_mapped = pins.map_thin_x86_64_macho(tahoe["binary"])
    if sonoma_mapped.macho_uuid != EXPECTED_UUID or tahoe_mapped.macho_uuid != EXPECTED_UUID:
        raise VerificationError("A pinned NIC image has an unexpected LC_UUID")
    if (sonoma_mapped.image_vmaddr != 0 or tahoe_mapped.image_vmaddr != 0 or
            sonoma_mapped.text_fileoff != 0 or tahoe_mapped.text_fileoff != 0):
        raise VerificationError("Pinned NIC image no longer has the audited __TEXT mapping")
    map_fields = ("image_span", "text_vmaddr", "text_fileoff", "text_size", "text_file_size")
    if any(getattr(sonoma_mapped, field) != getattr(tahoe_mapped, field)
           for field in map_fields):
        raise VerificationError("The pinned NIC images have different text mappings")

    sonoma_commands, sonoma_signature, sonoma_symtab, sonoma_sections = _load_commands(
        sonoma["binary"]
    )
    tahoe_commands, tahoe_signature, tahoe_symtab, tahoe_sections = _load_commands(
        tahoe["binary"]
    )
    if sonoma_commands != tahoe_commands:
        raise VerificationError("Mach-O load commands differ between pinned NIC images")
    if sonoma_signature != tahoe_signature:
        raise VerificationError("LC_CODE_SIGNATURE ranges differ between pinned NIC images")

    sonoma_symbols = _parse_symbols(sonoma["binary"], sonoma_symtab, sonoma_sections)
    tahoe_symbols = _parse_symbols(tahoe["binary"], tahoe_symtab, tahoe_sections)
    if sonoma_symbols["imports"] != tahoe_symbols["imports"]:
        raise VerificationError("Undefined native symbol imports differ between NIC images")
    if sonoma_symbols["vtables"] != tahoe_symbols["vtables"]:
        raise VerificationError("C++ vtable symbols or locations differ between NIC images")

    key_symbols = (
        "_bcm_decode_anqp_nai_realm_print", "_osl_dma_alloc_consistent",
        "_osl_dma_free_consistent", "_osl_dma_map", "_osl_malloc",
        "_osl_mfree", "_osl_pktdata", "_osl_pktlen", "_osl_pktnext",
    )
    stable_symbols = {}
    for name in key_symbols:
        sonoma_address = _defined_address(sonoma_symbols, name)
        tahoe_address = _defined_address(tahoe_symbols, name)
        if sonoma_address != tahoe_address:
            raise VerificationError(f"Key NIC helper moved between images: {name}")
        _assert_text_address(tahoe_address, tahoe_mapped)
        stable_symbols[name] = hex(tahoe_address)

    if sonoma["metadata"]["Info.plist"] != tahoe["metadata"]["Info.plist"]:
        raise VerificationError("NIC Info.plist matching metadata differs")
    if sonoma["metadata"]["version.plist"] != tahoe["metadata"]["version.plist"]:
        raise VerificationError("NIC version.plist differs")

    chipmatch_sonoma = pins.verify_chipmatch(sonoma["binary"], sonoma_mapped)
    chipmatch_tahoe = pins.verify_chipmatch(tahoe["binary"], tahoe_mapped)
    if chipmatch_sonoma != chipmatch_tahoe:
        raise VerificationError("Device table or checked chipmatch path differs")

    delta = _check_delta(sonoma["binary"], tahoe["binary"], tahoe_signature)
    control_flow = _check_hook_targets(tahoe_mapped, tahoe_symbols)

    info = tahoe["info"]
    personalities = info.get("IOKitPersonalities", {})
    pci_matches = []
    for personality in personalities.values():
        if isinstance(personality, dict):
            pci_matches.extend(personality.get("IONameMatch", []))

    imports_digest = _import_digest(sonoma_symbols["imports"])
    vtables_digest = _import_digest(
        (name,) + tuple(value) for name, value in sonoma_symbols["vtables"].items()
    )
    return {
        "schema": 1,
        "tool": "verify_unified_nic",
        "scope": (
            "Offline comparison of the hash-pinned Sonoma and Tahoe NIC images. "
            "The Tahoe image is a packaging candidate for one shared NIC bundle; "
            "this report does not establish runtime compatibility."
        ),
        "inputs": [
            {"role": item["role"], "name": item["archive_name"],
             "sha256": item["archive_sha256"], "member": item["member"],
             "binary_sha256": item["binary_sha256"]}
            for item in (sonoma, tahoe)
        ],
        "candidate": {
            "source": "pinned Tahoe AirPortBrcmNIC image",
            "binary_sha256": tahoe["binary_sha256"],
            "bundle_identifier": info.get("CFBundleIdentifier"),
            "bundle_version": info.get("CFBundleVersion"),
            "pci_personality_matches": sorted(set(pci_matches)),
            "chipmatch_table_ids": chipmatch_tahoe["accepted_pci_ids"],
            "kext_loaded": False,
        },
        "static_evidence": {
            "macho_uuid": tahoe_mapped.macho_uuid,
            "binary_size": len(tahoe["binary"]),
            "text_mapping": {
                "image_vmaddr": hex(tahoe_mapped.image_vmaddr),
                "text_vmaddr": hex(tahoe_mapped.text_vmaddr),
                "text_fileoff": hex(tahoe_mapped.text_fileoff),
                "text_section_size": hex(tahoe_mapped.text_size),
                "text_segment_file_size": hex(tahoe_mapped.text_file_size),
            },
            "load_commands_identical": True,
            "load_commands_sha256": _sha256(b"".join(tahoe_commands)),
            "native_undefined_symbols_identical": True,
            "native_undefined_symbol_count": len(tahoe_symbols["imports"]),
            "native_undefined_symbols_sha256": imports_digest,
            "cxx_vtable_symbols_identical": True,
            "cxx_vtable_symbol_count": len(tahoe_symbols["vtables"]),
            "cxx_vtable_symbols_sha256": vtables_digest,
            "stable_helper_symbols": stable_symbols,
            "matching_info_plist_identical": True,
            "chipmatch_table_identical": True,
            "chipmatch_table_sha256": chipmatch_tahoe["table_sha256"],
            "binary_delta": delta,
            "hook_and_rejoin_targets": control_flow[0]["branches"],
            "shim_call_targets": control_flow[0]["calls"],
            "code_signature_blob": {
                "offset": hex(tahoe_signature[0]),
                "size": tahoe_signature[1],
                "signature_verified": False,
            },
        },
        "not_established": [
            "DMA allocation lifetime, concurrent teardown, or failure-path correctness",
            "The Tahoe DMA shim behaving correctly on Sonoma or Sequoia hardware",
            "Boot, association, packet transmission, private MAC, AirDrop, sleep, or wake",
            "Code-signature acceptance or kext loading by any macOS release",
            "Support for PCI IDs beyond the checked personality and chipmatch tables",
        ],
        "runtime_tested": False,
        "driver_functions_invoked": False,
        "kernel_kext_loaded": False,
    }


def main(argv=None) -> int:
    import argparse
    import os
    import tempfile

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sonoma", type=Path, required=True,
                        help="hash-pinned Sonoma/Sequoia dependency ZIP")
    parser.add_argument("--tahoe", type=Path, required=True,
                        help="hash-pinned Tahoe dependency ZIP")
    parser.add_argument("--output-json", type=Path,
                        help="write the verification JSON to this path")
    args = parser.parse_args(argv)
    try:
        report = verify(args.sonoma, args.tahoe)
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output_json is None:
            sys.stdout.write(encoded)
        else:
            output = Path(args.output_json).absolute()
            if output.is_symlink() or output.resolve() in {
                    Path(args.sonoma).resolve(), Path(args.tahoe).resolve()}:
                raise VerificationError("Output JSON must be a new, non-input file")
            output.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(prefix="." + output.name + ".",
                                             suffix=".tmp", dir=output.parent)
            os.close(fd)
            temporary = Path(temp_name)
            try:
                temporary.write_text(encoded)
                os.chmod(temporary, 0o644)
                os.replace(temporary, output)
            except Exception:
                temporary.unlink(missing_ok=True)
                raise
    except (OSError, pins.VerificationError, VerificationError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
