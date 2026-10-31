#!/usr/bin/env python3
"""Build a local, isolated legacy Skywalk experiment. Never installs or loads kexts.

Usage: python3 src/build_namespace.py --legacy-dir PATH --system-extensions PATH
       --output NEW_DIRECTORY
Requires macOS nm, codesign and three exact local legacy binaries listed below.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

OLD_ID = "com.apple.iokit.IOSkywalkFamily"
NEW_ID = "org.geekaudio.IOLegacyWFamilyKC"
NATIVE_SHA256 = "58521fe8367163a44e176372c5b1ff38ee9c8d1257b427badf2ab1865547aa17"
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
SAMPLES = (
    ("IOSkywalkFamily.kext", "IOLegacyWFamily.kext", "0484ecd97d1bdb8759aef72661c196cda4309697eea1945a4a3c4d5e6d7e5e5b"),
    ("IO80211FamilyLegacy.kext", "IO80211FamilyLegacy.kext", "ac2dc15b77f8eaf97b71b34c5d0e1b59f862bfeac618396449306e1837e73894"),
    ("AirPortBrcmNIC-Tahoe.kext", "AirPortBrcmNIC-Tahoe.kext", "0b6cf936e594d1372960a60c8f17b6cbf68e3535a191574bd91498da49713775"),
)


class BuildError(RuntimeError):
    pass


def run(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise BuildError(f"{args[0]} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def build(legacy: Path, system: Path, output: Path) -> dict:
    legacy, system, output = legacy.resolve(), system.resolve(), output.resolve()
    validate_output(output, [legacy, system])
    originals = []
    for name, dest, expected in SAMPLES:
        source = legacy / name
        if any(p.is_symlink() for p in source.rglob("*")):
            raise BuildError("Symlinks in source kext are not accepted")
        info, binary = executable(source)
        raw = binary.read_bytes()
        if digest(raw) != expected:
            raise BuildError(f"Pinned binary hash mismatch: {name}")
        if digest((source / "Contents/Info.plist").read_bytes()) != INFO_SHA256[name]:
            raise BuildError(f"Pinned metadata hash mismatch: {name}")
        macho(raw)
        originals.append((source, dest, info, binary, raw))
    native = system / "IOSkywalkFamily.kext"
    native_info, native_bin = executable(native)
    native_defs = symbols(native_bin)
    native_raw = native_bin.read_bytes()
    if native_info.get("DTSDKName") != "macosx26.7.internal" or digest(native_raw) != NATIVE_SHA256:
        raise BuildError("This prototype is restricted to the audited Tahoe 26.7 Skywalk")
    output.parent.mkdir(parents=True, exist_ok=True)
    # Publish only after every static check passes. The temporary copy is ours.
    # Sign outside FileProvider/Documents: FinderInfo can be re-added after xattr -c.
    with tempfile.TemporaryDirectory(prefix="skywalk-build-") as temp:
        stage = Path(temp) / "package"
        kexts = stage / "Kexts"
        kexts.mkdir(parents=True)
        entries = []
        for source, dest, info, original_bin, raw in originals:
            target = kexts / dest
            copy_clean_bundle(source, target)
            _, target_bin = executable(target)
            if target_bin.read_bytes() != raw:
                raise BuildError("Source executable changed while copying")
            if digest((target / "Contents/Info.plist").read_bytes()) != INFO_SHA256[source.name]:
                raise BuildError("Source metadata changed while copying")
            # Operates only on the staging copy, never on the pinned source.
            if macho(target_bin.read_bytes())["signature"]:
                run(["/usr/bin/codesign", "--remove-signature", str(target_bin)])
            patched, detail = patch_binary(target_bin.read_bytes())
            target_bin.write_bytes(patched)
            modified = rename_plist(info)
            if modified["CFBundleExecutable"] != target_bin.name:
                renamed_bin = target_bin.with_name(modified["CFBundleExecutable"])
                target_bin.rename(renamed_bin)
                target_bin = renamed_bin
            (target / "Contents/Info.plist").write_bytes(plistlib.dumps(modified, sort_keys=False))
            clear_staging_xattrs(target)
            run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(target)])
            run(["/usr/bin/codesign", "--verify", "--strict", str(target)])
            result_raw = target_bin.read_bytes()
            if instruction_hashes(result_raw) != instruction_hashes(raw):
                raise BuildError("Signing or patching changed instruction bytes")
            for undefined in (False, True):
                expected_syms = {rename(s.encode()).decode() for s in symbols(original_bin, undefined)}
                if symbols(target_bin, undefined) != expected_syms:
                    raise BuildError(f"Symbol rename mismatch: {dest}")
            entries.append({"bundle": dest, "bundle_id": modified["CFBundleIdentifier"],
                            "source_sha256": digest(raw), "output_sha256": digest(result_raw),
                            **detail})
        _, private_bin = executable(kexts / SAMPLES[0][1])
        private_defs = symbols(private_bin)
        collision = (private_defs & native_defs) - {"_kmod_info"}
        if collision:
            raise BuildError(f"Native Skywalk export collisions remain: {len(collision)}")
        _, legacy_bin = executable(kexts / SAMPLES[1][1])
        _, brcm_bin = executable(kexts / SAMPLES[2][1])
        original_provider = symbols(originals[0][3])
        for source, modified_bin in [(originals[1][3], legacy_bin), (originals[2][3], brcm_bin)]:
            required = {rename(s.encode()).decode() for s in symbols(source, True) & original_provider}
            if not required <= private_defs or not required <= symbols(modified_bin, True):
                raise BuildError("Legacy consumer/provider dependency closure failed")
        for modified_bin in (legacy_bin, brcm_bin):
            overlap = (symbols(modified_bin) & native_defs) - {"_kmod_info"}
            if overlap:
                raise BuildError("Consumer conflicts with native Skywalk exports")
        manifest = {"schema": 1, "prototype": "isolated-legacy-skywalk", "version": "0.1.0",
                    "status": "STATIC_CHECKS_PASSED_RUNTIME_UNTESTED",
                    "root_patch_free": False, "airdrop_verified": False,
                    "native_skywalk_sha256": digest(native_raw), "binaries": entries,
                    "remaining_native_skywalk_export_collisions": [],
                    "checks": {"instruction_bytes_unchanged": True,
                               "exact_symbol_transform": True, "private_import_closure": True,
                               "adhoc_signature_verified": True},
                    "runtime_requirements": ["native IO80211Family excluded to avoid duplicate legacy classes",
                                             "existing wireless userspace retained for this first experiment",
                                             "working fallback EFI and independent test boot required"]}
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        # Instructions rather than a full config: never copy a machine identity.
        fragment = {"Kernel": {"Add": [
            {"Arch": "x86_64", "BundlePath": dest,
             "Comment": "Skywalk namespace isolation prototype - runtime untested",
             "Enabled": True, "ExecutablePath": "Contents/MacOS/" + rename_plist(info)["CFBundleExecutable"],
             "PlistPath": "Contents/Info.plist", "MinKernel": "25.6.0", "MaxKernel": "25.6.0"}
            for _, dest, info, _, _ in originals], "Block": [
                {"Arch": "x86_64", "Comment": "Test-only: avoid legacy/native IO80211 class collisions",
                 "Enabled": True, "Identifier": "com.apple.iokit.IO80211Family",
                 "MinKernel": "25.6.0", "MaxKernel": "25.6.0", "Strategy": "Exclude"}]}}
        (stage / "config.fragment.plist").write_bytes(plistlib.dumps(fragment, sort_keys=False))
        (stage / "TESTING.txt").write_text(
            "EXPERIMENTAL - NOT A ROOT-PATCH-FREE WIFI DRIVER\n"
            "Offline namespace isolation only; no live EFI/system changes were made.\n"
            "Use a separate test EFI copied from a verified working baseline.\n"
            "Disable the old IOSkywalkFamily Add and its system IOSkywalkFamily Block.\n"
            "Replace the two legacy wireless Add entries with these staged copies.\n"
            "Add IOLegacyWFamily before IO80211FamilyLegacy and AirPortBrcmNIC-Tahoe.\n"
            "Exclude native IO80211Family; keep the original, native IOSkywalkFamily.\n"
            "Do not remove wireless userspace root patches for this first experiment.\n"
            "Do not alter existing SIP/AMFI, SMBIOS, ACPI, boot-args or unrelated kexts.\n"
            "Ad-hoc signing does not satisfy normal Apple kext signing policy.\n"
            "Run matching-version ocvalidate on the complete test config before boot.\n"
            "Do not live-unload or live-replace either Skywalk implementation.\n"
            "After test boot, collect loaded bundle IDs, interface presence, kernel logs,\n"
            "then test network traffic, sleep/wake and actual bidirectional AirDrop.\n"
            "Rollback: boot the untouched original EFI.\n")
        for source, _, _, binary, raw in originals:
            if binary.read_bytes() != raw or digest((source / "Contents/Info.plist").read_bytes()) != INFO_SHA256[source.name]:
                raise BuildError("Source changed during build; refusing to publish")
        if digest(native_bin.read_bytes()) != NATIVE_SHA256:
            raise BuildError("Native Skywalk changed during build")
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
            for _, dest, _, _, _ in originals:
                run(["/usr/bin/codesign", "--verify", "--strict", str(output / "Kexts" / dest)])
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-dir", required=True, type=Path)
    parser.add_argument("--system-extensions", type=Path, default=Path("/System/Library/Extensions"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = build(args.legacy_dir, args.system_extensions, args.output)
    except (BuildError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Build refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": result["status"], "bundles": len(result["binaries"]),
                      "output": str(args.output.resolve())}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
