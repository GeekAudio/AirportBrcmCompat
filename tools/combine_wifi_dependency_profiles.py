#!/usr/bin/env python3
"""Combine pinned Sonoma, Sequoia, and Tahoe Wi-Fi dependency profiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import shutil
import stat
import subprocess
import tempfile
import zipfile
import uuid


PROJECT = Path(__file__).resolve().parents[1]
MAX_MEMBER_SIZE = 12 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_SIZE = 24 * 1024 * 1024

COMMON_INPUTS = {
    "provider": {
        "bundle": "IOLegacyWFamily.kext",
        "source_sha256": "0484ecd97d1bdb8759aef72661c196cda4309697eea1945a4a3c4d5e6d7e5e5b",
        "output_sha256": "301375974eb60d246d454e6ce8e806b98ecdbe15025c4d9adf9cb2530daf236d",
        "bundle_id": "org.geekaudio.IOLegacyWFamilyKC",
        "executable": "IOLegacyWFamily",
    },
    "legacy_consumer": {
        "bundle": "IO80211FamilyLegacy.kext",
        "source_sha256": "ac2dc15b77f8eaf97b71b34c5d0e1b59f862bfeac618396449306e1837e73894",
        "output_sha256": "919a0b05ef73bade44545164292d5b5ca17ef44d04756b73dae8757fc57d5487",
        "bundle_id": "com.apple.iokit.IO80211FamilyLegacy",
        "executable": "IO80211FamilyLegacy",
    },
}

PROFILES = {
    "sonoma-sequoia": {
        "archive_filename": "sonoma14-dependencies.zip",
        "min_kernel": "23.0.0",
        "max_kernel": "24.99.99",
        "bundle": "AirPortBrcmNIC-Sonoma-Sequoia.kext",
        "source": "OCLP IO80211FamilyLegacy nested AirPortBrcmNIC",
        "source_path": "IO80211FamilyLegacy.kext/Contents/PlugIns/AirPortBrcmNIC.kext",
        "source_sha256": "884e90b27cff151e432bb36275936f57b43e72419e95b51b3ac067d3f2ccd331",
        "output_sha256": "c43b8c5443c14d029c86459ea60502ede731bb94acb8de201fc210c99080f0d0",
        "profile_name": "sonoma-sequoia",
    },
    "tahoe": {
        "archive_filename": "tahoe26-dependencies.zip",
        "min_kernel": "25.0.0",
        "max_kernel": "",
        "bundle": "AirPortBrcmNIC-Tahoe.kext",
        "source": "OCLP standalone AirPortBrcmNIC-Tahoe",
        "source_path": "AirPortBrcmNIC-Tahoe.kext",
        "source_sha256": "0b6cf936e594d1372960a60c8f17b6cbf68e3535a191574bd91498da49713775",
        "output_sha256": "999c1a5b6a0d18baba2050520c1d429b49edfd99bfc8d71299b639334f263982",
        "profile_name": "tahoe",
    },
}

# These native sample identities are derived from the retained kernel-collection
# files and validation/compatibility-contracts.json. The sample label inside an
# input manifest is descriptive only; identify the sample by its pinned KC hash.
NATIVE_SAMPLE_IDENTITIES = {
    "sonoma": {
        "system": "Sonoma",
        "version": "14.8.9",
        "build": "23J631",
        "container_sha256": "3f5dcde57f2d0ce27b9c9abf3d1e3d2c36b33cea9ae0a7eb36bf9c4282ed8cd2",
        "sample_fields": {
            "bundle_id": "com.apple.iokit.IOSkywalkFamily",
            "bundle_version": "1.0",
            "container_filename": "sonoma14__AssetData__boot__System__Library__KernelCollections__BootKernelExtensions.kc",
            "container_size_bytes": 62783488,
            "defined_external_symbol_count": 1935,
            "fileset_entry_file_offset": 41254912,
            "fileset_entry_id": "com.apple.iokit.IOSkywalkFamily",
            "info_sha256": "ece6b3b542111e41b2c2b9707b760e34b6c4306cec7e9b051dfebce3ac85ce25",
            "macho_header_sha256": "ffe50914f8e77853685d56c3db7b80c3b4d214e06b7b97e4a8d709b02cfe03a3",
            "macho_load_commands_sha256": "8b5769575cc91aefc06aaaec9f06680ea7082a1c2d419afa7fc919676a8a0cf6",
            "macho_uuid": "9F5908B5-BA4B-37E3-AC31-62E1D45F1589",
            "sample_kind": "kernel-collection-fileset-entry",
            "sdk_name": "macosx14.8.internal",
        },
    },
    "sequoia": {
        "system": "Sequoia",
        "version": "15.8.2",
        "build": "24H232",
        "container_sha256": "ddd9016e225a61ebfd4f04b02a00937262f26690c57a928613e08506978c81be",
        "sample_fields": {
            "bundle_id": "com.apple.iokit.IOSkywalkFamily",
            "bundle_version": "1.0",
            "container_filename": "sequoia15__AssetData__boot__System__Library__KernelCollections__BootKernelExtensions.kc",
            "container_size_bytes": 66125824,
            "defined_external_symbol_count": 2157,
            "fileset_entry_file_offset": 42422272,
            "fileset_entry_id": "com.apple.iokit.IOSkywalkFamily",
            "info_sha256": "b5be21185a517cba29cf43c3628bd1ed390b10b16a52b45f5bd4e87fa08cb7f8",
            "macho_header_sha256": "ffe50914f8e77853685d56c3db7b80c3b4d214e06b7b97e4a8d709b02cfe03a3",
            "macho_load_commands_sha256": "17fabd51173ab3bfac9bc335a6f43670788a5cf81178fe9a854de1c481b830b6",
            "macho_uuid": "70DFAA8E-E369-3417-B6FD-B19FB6D5D49B",
            "sample_kind": "kernel-collection-fileset-entry",
            "sdk_name": "macosx15.8.internal",
        },
    },
    "tahoe": {
        "system": "Tahoe",
        "version": "26.7.2",
        "build": "25G332",
        "container_sha256": "96c12f421a8e99580b5015dfd39877df38ecde9b9e056b8ccd28f15847bca35c",
        "sample_fields": {
            "bundle_id": "com.apple.iokit.IOSkywalkFamily",
            "bundle_version": "1.0",
            "container_filename": "BootKernelExtensions.kc",
            "container_size_bytes": 67600384,
            "defined_external_symbol_count": 2195,
            "fileset_entry_file_offset": 44040192,
            "fileset_entry_id": "com.apple.iokit.IOSkywalkFamily",
            "info_sha256": "c6f591e047ce09df4a9f59d2b15c3a0dd835ddb83023eb8d6fa35f8c58aa6ea0",
            "macho_header_sha256": "ffe50914f8e77853685d56c3db7b80c3b4d214e06b7b97e4a8d709b02cfe03a3",
            "macho_load_commands_sha256": "368199b38a78cd97c0760848c54b8bb17b6da8bbc9b207d7b75a509095a45d9d",
            "macho_uuid": "A6EDB8DB-175B-3A49-8919-5769FCDB6BED",
            "sample_kind": "kernel-collection-fileset-entry",
            "sdk_name": "macosx26.7.internal",
        },
    },
}

NIC_COMMON_FILES = (
    "Contents/Info.plist",
    "Contents/_CodeSignature/CodeResources",
    "Contents/version.plist",
)
TESTING_SHA256 = "8a00058c03f291369eb0b87939d203ea8ea15486f5fcf64fb1d3fa3b3c75e291"
EXPECTED_MEMBER_SHA256 = {
    "Kexts/IOLegacyWFamily.kext/Contents/Info.plist":
        "2bf91d8d51638b3855df26c706d2db8b7a78b6f2c6b142ac059b2b8a14826bae",
    "Kexts/IOLegacyWFamily.kext/Contents/MacOS/IOLegacyWFamily":
        "301375974eb60d246d454e6ce8e806b98ecdbe15025c4d9adf9cb2530daf236d",
    "Kexts/IOLegacyWFamily.kext/Contents/_CodeSignature/CodeResources":
        "6686de10a28a2fe11b36cbb86dcbacc827cfc4ea116b4dabf1845e5aee629e9b",
    "Kexts/IO80211FamilyLegacy.kext/Contents/Info.plist":
        "1656e35cc3f51bcd775b9fb54689199bf6d657c82fe48f49f7c11d51f6521c25",
    "Kexts/IO80211FamilyLegacy.kext/Contents/MacOS/IO80211FamilyLegacy":
        "919a0b05ef73bade44545164292d5b5ca17ef44d04756b73dae8757fc57d5487",
    "Kexts/IO80211FamilyLegacy.kext/Contents/_CodeSignature/CodeResources":
        "6686de10a28a2fe11b36cbb86dcbacc827cfc4ea116b4dabf1845e5aee629e9b",
}
COMMON_RELATIVE_FILES = {
    "IOLegacyWFamily.kext": (
        "Contents/Info.plist",
        "Contents/MacOS/IOLegacyWFamily",
        "Contents/_CodeSignature/CodeResources",
    ),
    "IO80211FamilyLegacy.kext": (
        "Contents/Info.plist",
        "Contents/MacOS/IO80211FamilyLegacy",
        "Contents/_CodeSignature/CodeResources",
    ),
}


class CombineError(ValueError):
    """Refuse a profile archive that is not the exact reviewed input."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _expected_input_files(profile: dict) -> set[str]:
    files = {"manifest.json", "config.fragment.plist", "TESTING.txt"}
    for bundle, relative_paths in COMMON_RELATIVE_FILES.items():
        files.update(f"Kexts/{bundle}/{relative}" for relative in relative_paths)
    nic = profile["bundle"]
    files.update(f"Kexts/{nic}/{relative}" for relative in NIC_COMMON_FILES)
    files.add(f"Kexts/{nic}/Contents/MacOS/AirPortBrcmNIC")
    return files


def _validate_member_name(name: str) -> None:
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        raise CombineError(f"Unsafe ZIP member path: {name!r}")
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise CombineError(f"Unsafe ZIP member path: {name!r}")
    if len(parts[0]) >= 2 and parts[0][1] == ":":
        raise CombineError(f"Unsafe ZIP member path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name:
        raise CombineError(f"Unsafe ZIP member path: {name!r}")


def _preflight_zip(archive: zipfile.ZipFile, profile: dict) -> dict[str, bytes]:
    infos = archive.infolist()
    names: set[str] = set()
    total_size = 0
    for info in infos:
        name = info.filename
        _validate_member_name(name)
        if name in names:
            raise CombineError(f"Duplicate ZIP member: {name}")
        names.add(name)
        if info.is_dir():
            raise CombineError(f"Directory entries are not accepted: {name}")
        if info.flag_bits & 0x1:
            raise CombineError(f"Encrypted ZIP member is not accepted: {name}")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise CombineError(f"Unsupported ZIP compression method: {name}")
        if info.file_size > MAX_MEMBER_SIZE:
            raise CombineError(f"Oversized ZIP member: {name}")
        total_size += info.file_size
        if total_size > MAX_ARCHIVE_EXPANDED_SIZE:
            raise CombineError("Expanded ZIP exceeds the size limit")

        mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if file_type == stat.S_IFLNK:
            raise CombineError(f"Symlink ZIP member is not accepted: {name}")
        if file_type not in (0, stat.S_IFREG):
            raise CombineError(f"Non-regular ZIP member is not accepted: {name}")

    expected = _expected_input_files(profile)
    if names != expected:
        missing = sorted(expected - names)
        extra = sorted(names - expected)
        raise CombineError(f"Unexpected ZIP member set; missing={missing}, extra={extra}")

    files = {}
    for info in infos:
        data = archive.read(info)
        if len(data) != info.file_size:
            raise CombineError(f"ZIP member size mismatch: {info.filename}")
        files[info.filename] = data
    return files


def _expected_profile_manifest(profile_key: str, profile: dict) -> dict:
    return {
        "name": profile["profile_name"],
        "min_kernel": profile["min_kernel"],
        "max_kernel": profile["max_kernel"],
        "brcm_bundle": profile["bundle"],
        "brcm_source": profile["source_path"],
        "brcm_source_sha256": profile["source_sha256"],
        "asset_profile": profile["source"],
    }


def _verify_source_config(config_bytes: bytes, profile: dict) -> None:
    try:
        config = plistlib.loads(config_bytes)
    except Exception as exc:
        raise CombineError("Input config.fragment.plist is invalid") from exc
    kernel = config.get("Kernel") if isinstance(config, dict) else None
    if not isinstance(kernel, dict) or set(kernel) != {"Add", "Block"}:
        raise CombineError("Input config has an unexpected Kernel section")
    additions = kernel["Add"]
    if not isinstance(additions, list) or len(additions) != 3:
        raise CombineError("Input config must have exactly three Wi-Fi kext entries")
    expected_bundles = [COMMON_INPUTS["provider"]["bundle"],
                        COMMON_INPUTS["legacy_consumer"]["bundle"], profile["bundle"]]
    for entry, bundle in zip(additions, expected_bundles):
        if not isinstance(entry, dict):
            raise CombineError("Invalid Kernel/Add entry")
        executable = ("AirPortBrcmNIC" if bundle == profile["bundle"] else
                      next(item["executable"] for item in COMMON_INPUTS.values()
                           if item["bundle"] == bundle))
        expected = {
            "Arch": "x86_64",
            "BundlePath": bundle,
            "Comment": f"Skywalk namespace isolation candidate ({profile['profile_name']})",
            "Enabled": True,
            "ExecutablePath": f"Contents/MacOS/{executable}",
            "PlistPath": "Contents/Info.plist",
            "MinKernel": profile["min_kernel"],
            "MaxKernel": profile["max_kernel"],
        }
        if entry != expected:
            raise CombineError(f"Input Kernel/Add entry differs from pinned profile: {bundle}")
    blocks = kernel["Block"]
    expected_block = {
        "Arch": "x86_64",
        "Comment": "Test-only: avoid legacy/native IO80211 class collisions",
        "Enabled": True,
        "Identifier": "com.apple.iokit.IO80211Family",
        "MinKernel": profile["min_kernel"],
        "MaxKernel": profile["max_kernel"],
        "Strategy": "Exclude",
    }
    if blocks != [expected_block]:
        raise CombineError("Input native IO80211Family block differs from pinned profile")


def _profile_binary_map(manifest: dict) -> dict[str, dict]:
    binaries = manifest.get("binaries")
    if not isinstance(binaries, list):
        raise CombineError("Input manifest has no binary records")
    result = {}
    for item in binaries:
        if not isinstance(item, dict) or not isinstance(item.get("bundle"), str):
            raise CombineError("Invalid input manifest binary record")
        if item["bundle"] in result:
            raise CombineError("Duplicate binary record in input manifest")
        result[item["bundle"]] = item
    return result


def _validate_bundle(bundle: str, files: dict[str, bytes], expected: dict) -> dict:
    prefix = f"Kexts/{bundle}/Contents/"
    try:
        info = plistlib.loads(files[prefix + "Info.plist"])
    except Exception as exc:
        raise CombineError(f"Invalid Info.plist for {bundle}") from exc
    if (not isinstance(info, dict) or
            info.get("CFBundleIdentifier") != expected["bundle_id"] or
            info.get("CFBundleExecutable") != expected["executable"]):
        raise CombineError(f"Unexpected bundle identity or executable in {bundle}")
    executable_path = prefix + "MacOS/" + expected["executable"]
    executable = files[executable_path]
    if sha256(executable) != expected["output_sha256"]:
        raise CombineError(f"Executable hash mismatch in {bundle}")
    return {"bundle": bundle, "bundle_id": expected["bundle_id"],
            "executable": expected["executable"],
            "executable_sha256": sha256(executable)}


def _validate_native_sample(manifest: dict) -> dict:
    sample = manifest.get("native_skywalk_sample")
    if not isinstance(sample, dict):
        raise CombineError("Input manifest has no native Skywalk sample metadata")
    expected_keys = {
        "bundle_id", "bundle_version", "container_filename", "container_sha256",
        "container_size_bytes", "defined_external_symbol_count",
        "fileset_entry_file_offset", "fileset_entry_id", "info_sha256", "label",
        "macho_header_sha256", "macho_load_commands_sha256", "macho_uuid",
        "sample_kind", "sdk_name",
    }
    if set(sample) != expected_keys:
        raise CombineError("Native Skywalk sample metadata fields differ from the pinned schema")
    if sample.get("sample_kind") != "kernel-collection-fileset-entry":
        raise CombineError("Native Skywalk sample is not a kernel collection fileset entry")
    if sample.get("fileset_entry_id") != "com.apple.iokit.IOSkywalkFamily":
        raise CombineError("Native Skywalk sample names a different fileset entry")
    for key in ("label", "container_filename"):
        value = sample.get(key)
        if not isinstance(value, str) or not value.strip():
            raise CombineError(f"Native Skywalk sample has invalid {key}")
    if PurePosixPath(sample["container_filename"]).name != sample["container_filename"]:
        raise CombineError("Native Skywalk container filename must be a basename")
    for key in ("container_size_bytes", "fileset_entry_file_offset", "defined_external_symbol_count"):
        value = sample.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise CombineError(f"Native Skywalk sample has invalid {key}")
    if sample["container_size_bytes"] == 0 or sample["defined_external_symbol_count"] == 0:
        raise CombineError("Native Skywalk sample has empty container or export metadata")
    if sample["fileset_entry_file_offset"] >= sample["container_size_bytes"]:
        raise CombineError("Native Skywalk fileset entry offset exceeds its container")
    if sample.get("bundle_id") != "com.apple.iokit.IOSkywalkFamily":
        raise CombineError("Native Skywalk sample Info.plist identity differs")
    for required_string in ("bundle_version", "sdk_name"):
        if not isinstance(sample.get(required_string), str) or not sample[required_string]:
            raise CombineError(f"Native Skywalk sample has invalid {required_string}")
    for key in ("container_sha256", "macho_header_sha256", "macho_load_commands_sha256"):
        value = sample.get(key)
        if (not isinstance(value, str) or len(value) != 64 or
                any(ch not in "0123456789abcdef" for ch in value.lower())):
            raise CombineError(f"Native Skywalk sample has invalid {key}")
    value = sample.get("info_sha256")
    if (not isinstance(value, str) or len(value) != 64 or
            any(ch not in "0123456789abcdef" for ch in value.lower())):
        raise CombineError("Native Skywalk sample has invalid info_sha256")
    value = sample.get("macho_uuid")
    try:
        parsed_uuid = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise CombineError("Native Skywalk sample has invalid Mach-O UUID") from exc
    if str(parsed_uuid).upper() != value.upper():
        raise CombineError("Native Skywalk sample Mach-O UUID is not canonical")
    return sample


def _verify_native_sample_identity(sample_key: str, sample: dict) -> dict:
    expected = NATIVE_SAMPLE_IDENTITIES[sample_key]
    if sample.get("container_sha256") != expected["container_sha256"]:
        raise CombineError(
            f"Native Skywalk sample hash does not match the pinned {expected['system']} sample")
    for key, value in expected["sample_fields"].items():
        if sample.get(key) != value:
            raise CombineError(
                f"Native Skywalk {expected['system']} sample metadata differs: {key}")
    return {key: expected[key] for key in ("system", "version", "build", "container_sha256")}


def _verify_manifest(profile_key: str, sample_key: str, profile: dict,
                     files: dict[str, bytes]) -> tuple[dict, dict[str, dict], dict]:
    manifest_raw = files["manifest.json"]
    if sha256(files["TESTING.txt"]) != TESTING_SHA256:
        raise CombineError(f"{profile_key} TESTING.txt differs from the reviewed input")
    try:
        manifest = json.loads(manifest_raw)
    except Exception as exc:
        raise CombineError("Input manifest.json is invalid") from exc
    if not isinstance(manifest, dict):
        raise CombineError("Input manifest.json must contain an object")
    if (manifest.get("schema") != 1 or manifest.get("prototype") != "isolated-legacy-skywalk" or
            manifest.get("version") != "0.1.0" or
            manifest.get("status") != "STATIC_PROFILE_CANDIDATE" or
            manifest.get("validation_scope") != "offline"):
        raise CombineError("Input manifest schema/profile status differs from the reviewed source")
    if manifest.get("dependency_profile") != _expected_profile_manifest(profile_key, profile):
        raise CombineError(f"{profile_key} dependency profile is not the pinned original")
    sample = _validate_native_sample(manifest)
    sample_identity = _verify_native_sample_identity(sample_key, sample)
    if manifest.get("remaining_native_skywalk_export_collisions") != []:
        raise CombineError("Input profile reports native export collisions")
    checks = manifest.get("checks")
    if (not isinstance(checks, dict) or set(checks) != {
            "instruction_bytes_unchanged", "exact_symbol_transform",
            "private_import_closure", "adhoc_signature_verified"} or
            any(value is not True for value in checks.values())):
        raise CombineError("Input profile checks are missing or false")

    resolution = manifest.get("private_import_resolution")
    if not isinstance(resolution, dict):
        raise CombineError("Input manifest private import resolution is invalid")
    pins = resolution.get("pinned_input_sha256")
    expected_pins = {
        "provider": COMMON_INPUTS["provider"]["source_sha256"],
        "legacy_consumer": COMMON_INPUTS["legacy_consumer"]["source_sha256"],
        "brcm_consumer": profile["source_sha256"],
    }
    if pins != expected_pins:
        raise CombineError("Input manifest pinned source hashes differ")
    if resolution.get("unresolved_after_inherited_slots") != []:
        raise CombineError("Input profile has unresolved private imports")

    binary_map = _profile_binary_map(manifest)
    expected_records = {
        COMMON_INPUTS["provider"]["bundle"]: COMMON_INPUTS["provider"],
        COMMON_INPUTS["legacy_consumer"]["bundle"]: COMMON_INPUTS["legacy_consumer"],
        profile["bundle"]: {"bundle": profile["bundle"],
                             "source_sha256": profile["source_sha256"],
                             "output_sha256": profile["output_sha256"],
                             "bundle_id": "com.apple.driver.AirPort.BrcmNIC",
                             "executable": "AirPortBrcmNIC"},
    }
    if set(binary_map) != set(expected_records):
        raise CombineError("Input manifest does not describe exactly the three Wi-Fi bundles")
    inventory = {}
    for bundle, expected in expected_records.items():
        record = binary_map[bundle]
        if (record.get("bundle_id") != expected["bundle_id"] or
                record.get("source_sha256") != expected["source_sha256"] or
                record.get("output_sha256") != expected["output_sha256"]):
            raise CombineError(f"Pinned manifest binary record differs: {bundle}")
        checked = _validate_bundle(bundle, files, expected)
        if record.get("source") != (profile["source"] if bundle == profile["bundle"] else
                                     "IOSkywalkFamily.kext" if bundle == "IOLegacyWFamily.kext" else
                                     "IO80211FamilyLegacy.kext"):
            raise CombineError(f"Pinned manifest source label differs: {bundle}")
        inventory[bundle] = checked
    nic_prefix = f"Kexts/{profile['bundle']}/Contents/"
    nic_member_hashes = {
        nic_prefix + "Info.plist": "9e3abd92fca600317ee9df158e8025752b3ff3ba9c984945be74a804b6d24783",
        nic_prefix + "MacOS/AirPortBrcmNIC": profile["output_sha256"],
        nic_prefix + "_CodeSignature/CodeResources": "71f08f6b787d6691df97fe1a0ad0670ba8d1e37d022422074b4bcd4cfcd84bc5",
        nic_prefix + "version.plist": "8e2d967e744d35653ff29269a81cffc2b0aaf5b8ce65aef0886b5e60c798b0e1",
    }
    for name, expected_hash in {**EXPECTED_MEMBER_SHA256, **nic_member_hashes}.items():
        if sha256(files[name]) != expected_hash:
            raise CombineError(f"Pinned kext member hash mismatch: {name}")
    _verify_source_config(files["config.fragment.plist"], profile)
    return manifest, inventory, sample_identity


def _compare_common_payloads(sonoma_files: dict[str, bytes], tahoe_files: dict[str, bytes]) -> dict:
    compared = {}
    for bundle, relative_paths in COMMON_RELATIVE_FILES.items():
        for relative in relative_paths:
            name = f"Kexts/{bundle}/{relative}"
            left = sonoma_files[name]
            right = tahoe_files[name]
            if left != right:
                raise CombineError(f"Common dependency differs byte-for-byte: {name}")
            compared[name] = sha256(left)
    return compared


def _compare_sonoma_sequoia_payloads(sonoma_files: dict[str, bytes],
                                      sequoia_files: dict[str, bytes]) -> dict:
    compared = _compare_common_payloads(sonoma_files, sequoia_files)
    nic_bundle = PROFILES["sonoma-sequoia"]["bundle"]
    prefix = f"Kexts/{nic_bundle}/"
    nic_members = sorted(name for name in sonoma_files if name.startswith(prefix))
    if not nic_members or nic_members != sorted(
            name for name in sequoia_files if name.startswith(prefix)):
        raise CombineError("Sonoma and Sequoia NIC payload member sets differ")
    for name in nic_members:
        if sonoma_files[name] != sequoia_files[name]:
            raise CombineError(f"Sonoma and Sequoia NIC payload differs byte-for-byte: {name}")
        compared[name] = sha256(sonoma_files[name])
    return compared


def _sample_manifest_record(sample: dict, identity: dict) -> dict:
    record = dict(sample)
    record["input_manifest_label"] = sample["label"]
    record["label"] = f"{identity['system']} {identity['version']} ({identity['build']})"
    record["verified_system"] = identity["system"]
    record["verified_version"] = identity["version"]
    record["verified_build"] = identity["build"]
    record["verified_by_container_sha256"] = identity["container_sha256"]
    return record


def _combined_config() -> dict:
    def add(bundle: str, executable: str, minimum: str, maximum: str, comment: str) -> dict:
        return {"Arch": "x86_64", "BundlePath": bundle, "Comment": comment,
                "Enabled": True, "ExecutablePath": f"Contents/MacOS/{executable}",
                "PlistPath": "Contents/Info.plist", "MinKernel": minimum,
                "MaxKernel": maximum}

    common_min, common_max = "23.0.0", ""
    provider = COMMON_INPUTS["provider"]
    legacy = COMMON_INPUTS["legacy_consumer"]
    sonoma = PROFILES["sonoma-sequoia"]
    tahoe = PROFILES["tahoe"]
    return {"Kernel": {
        "Add": [
            add("AirportBrcmCompat.kext", "AirportBrcmCompat", "23.0.0", "",
                "AirportBrcmCompat core (distributed separately)"),
            add(provider["bundle"], provider["executable"], common_min, common_max,
                provider["bundle"]),
            add(legacy["bundle"], legacy["executable"], common_min, common_max,
                legacy["bundle"]),
            add(sonoma["bundle"], "AirPortBrcmNIC", sonoma["min_kernel"], sonoma["max_kernel"],
                f"Wi-Fi dependency ({sonoma['profile_name']})"),
            add(tahoe["bundle"], "AirPortBrcmNIC", tahoe["min_kernel"], tahoe["max_kernel"],
                f"Wi-Fi dependency ({tahoe['profile_name']})"),
        ],
        "Block": [{
            "Arch": "x86_64", "Comment": "Wireless compatibility",
            "Enabled": True, "Identifier": "com.apple.iokit.IO80211Family",
            "MinKernel": "23.0.0", "MaxKernel": "", "Strategy": "Exclude",
        }],
        "Quirks": {"DisableLinkeditJettison": True},
    }}


def _zip_write(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    archive.writestr(info, data)


def _verify_codesign(bundle_path: Path) -> None:
    result = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(bundle_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise CombineError(f"Strict codesign verification failed for {bundle_path.name}: {detail}")


def _write_tree(root: Path, files: dict[str, bytes]) -> None:
    for name, data in files.items():
        _validate_member_name(name)
        destination = root.joinpath(*name.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)


def _verify_staged_signatures(root: Path, bundles: list[str]) -> None:
    for bundle in bundles:
        _verify_codesign(root / "Kexts" / bundle)


def _read_pinned_profile(path: Path, profile_key: str,
                         sample_key: str) -> tuple[dict[str, bytes], dict, dict, dict]:
    profile = PROFILES[profile_key]
    try:
        with zipfile.ZipFile(path) as archive:
            files = _preflight_zip(archive, profile)
    except (zipfile.BadZipFile, OSError) as exc:
        raise CombineError(f"Cannot read {profile_key} profile ZIP: {path}") from exc
    _verify_source_config(files["config.fragment.plist"], profile)
    manifest, inventory, sample_identity = _verify_manifest(
        profile_key, sample_key, profile, files)
    return files, manifest, inventory, sample_identity


def combine(sonoma_path: Path, sequoia_path: Path, tahoe_path: Path,
            output_path: Path) -> dict:
    input_paths = (Path(sonoma_path), Path(sequoia_path), Path(tahoe_path))
    if any(path.is_symlink() for path in input_paths):
        raise CombineError("Input ZIP paths must not be symlinks")
    sonoma_path = Path(sonoma_path).resolve(strict=True)
    sequoia_path = Path(sequoia_path).resolve(strict=True)
    tahoe_path = Path(tahoe_path).resolve(strict=True)
    output_path = Path(output_path).absolute()
    resolved_inputs = (sonoma_path, sequoia_path, tahoe_path)
    if len(set(resolved_inputs)) != len(resolved_inputs):
        raise CombineError("Sonoma, Sequoia, and Tahoe inputs must be different ZIP files")
    if output_path.exists() or output_path.is_symlink():
        raise CombineError("Output already exists")
    if output_path.resolve() in resolved_inputs:
        raise CombineError("Output must not overwrite an input ZIP")
    if not shutil.which("/usr/bin/codesign"):
        raise CombineError("macOS /usr/bin/codesign is required")

    sonoma_files, sonoma_manifest, sonoma_inventory, sonoma_identity = _read_pinned_profile(
        sonoma_path, "sonoma-sequoia", "sonoma")
    sequoia_files, sequoia_manifest, sequoia_inventory, sequoia_identity = _read_pinned_profile(
        sequoia_path, "sonoma-sequoia", "sequoia")
    tahoe_files, tahoe_manifest, tahoe_inventory, tahoe_identity = _read_pinned_profile(
        tahoe_path, "tahoe", "tahoe")
    sonoma_sequoia_hashes = _compare_sonoma_sequoia_payloads(
        sonoma_files, sequoia_files)
    common_hashes = _compare_common_payloads(sonoma_files, tahoe_files)

    combined_kexts: dict[str, bytes] = {}
    for source_files, profile in ((sonoma_files, PROFILES["sonoma-sequoia"]),
                                  (tahoe_files, PROFILES["tahoe"])):
        for name, data in source_files.items():
            if not name.startswith("Kexts/"):
                continue
            bundle = name.split("/", 2)[1]
            if bundle in COMMON_RELATIVE_FILES:
                combined_kexts[name] = data
            elif bundle == profile["bundle"]:
                combined_kexts[name] = data
            else:
                raise CombineError(f"Unexpected kext bundle during combine: {bundle}")

    expected_bundle_names = ["IOLegacyWFamily.kext", "IO80211FamilyLegacy.kext",
                             PROFILES["sonoma-sequoia"]["bundle"],
                             PROFILES["tahoe"]["bundle"]]
    output_manifest = {
        "schema": 2,
        "prototype": "combined-cross-version-wifi-dependencies",
        "version": "0.1.0",
        "status": "STATIC_PROFILE_CANDIDATE",
        "validation_scope": "offline",
        "profiles": [
            {"name": role, "dependency_profile": key,
             "min_kernel": PROFILES[key]["min_kernel"],
             "max_kernel": PROFILES[key]["max_kernel"],
             "nic_bundle": PROFILES[key]["bundle"],
             "source_zip_sha256": sha256(path.read_bytes()),
             "source_manifest_sha256": sha256(files["manifest.json"]),
             "native_skywalk_sample": _sample_manifest_record(
                 manifest["native_skywalk_sample"], identity),
             "binary_inventory": inventory}
            for role, key, path, files, manifest, inventory, identity in (
                ("sonoma", "sonoma-sequoia", sonoma_path, sonoma_files,
                 sonoma_manifest, sonoma_inventory, sonoma_identity),
                ("sequoia", "sonoma-sequoia", sequoia_path, sequoia_files,
                 sequoia_manifest, sequoia_inventory, sequoia_identity),
                ("tahoe", "tahoe", tahoe_path, tahoe_files,
                 tahoe_manifest, tahoe_inventory, tahoe_identity))
        ],
        "common_dependency_member_sha256": common_hashes,
        "sonoma_sequoia_payload_member_sha256": sonoma_sequoia_hashes,
        "bundles": expected_bundle_names,
        "checks": {
            "input_manifests_pinned": True,
            "native_sample_hashes_pinned": True,
            "sonoma_sequoia_common_and_nic_payloads_byte_identical": True,
            "common_dependencies_byte_identical": True,
            "strict_codesign_verified": True,
            "wifi_only_kexts": True,
            "kernel_ranges_verified": True,
        },
        "kext_member_sha256": {
            name: sha256(data) for name, data in sorted(combined_kexts.items())
        },
    }
    output_config = plistlib.dumps(_combined_config(), sort_keys=False)
    output_manifest_bytes = (json.dumps(output_manifest, indent=2, sort_keys=True) + "\n").encode()
    package_files = {
        **combined_kexts,
        "TESTING.txt": (
            "CROSS-VERSION WI-FI DEPENDENCY PROFILE CANDIDATE\n"
            "This archive contains four Wi-Fi dependencies. AirportBrcmCompat.kext is distributed separately.\n"
            "Merge config.fragment.plist into the existing OpenCore configuration and retain unrelated entries.\n"
        ).encode(),
        "config.fragment.plist": output_config,
        "manifest.json": output_manifest_bytes,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{output_path.name}.", suffix=".tmp",
                                          dir=output_path.parent)
    os.close(fd)
    temporary_path = Path(temporary_name)
    try:
        with tempfile.TemporaryDirectory(prefix="combine-wifi-profile-") as staging:
            stage = Path(staging)
            _write_tree(stage, package_files)
            _verify_staged_signatures(stage, expected_bundle_names)
            with zipfile.ZipFile(temporary_path, "w", compression=zipfile.ZIP_DEFLATED,
                                 compresslevel=9) as archive:
                for name in sorted(package_files):
                    _zip_write(archive, name, package_files[name])

        # Re-open the finished archive, compare all payload bytes, and verify signatures
        # again from the exact bytes consumers will extract.
        with zipfile.ZipFile(temporary_path) as archive:
            output_files = _preflight_output_zip(archive, set(package_files))
        if output_files != package_files:
            raise CombineError("Output ZIP content differs from the validated staging files")
        with tempfile.TemporaryDirectory(prefix="verify-combined-wifi-") as verify_dir:
            verify_root = Path(verify_dir)
            _write_tree(verify_root, output_files)
            _verify_staged_signatures(verify_root, expected_bundle_names)
        os.chmod(temporary_path, 0o644)
        try:
            os.link(temporary_path, output_path)
        except FileExistsError as exc:
            raise CombineError("Output already exists") from exc
        temporary_path.unlink()
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    return output_manifest


def _preflight_output_zip(archive: zipfile.ZipFile, expected: set[str]) -> dict[str, bytes]:
    files = {}
    names = set()
    for info in archive.infolist():
        _validate_member_name(info.filename)
        if info.filename in names:
            raise CombineError(f"Duplicate output ZIP member: {info.filename}")
        names.add(info.filename)
        mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if info.is_dir() or file_type not in (0, stat.S_IFREG) or file_type == stat.S_IFLNK:
            raise CombineError(f"Unexpected output ZIP member type: {info.filename}")
        if info.flag_bits & 0x1 or info.file_size > MAX_MEMBER_SIZE:
            raise CombineError(f"Unsafe output ZIP member: {info.filename}")
        files[info.filename] = archive.read(info)
    if names != expected:
        raise CombineError("Output ZIP member set differs from the expected Wi-Fi allowlist")
    return files


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sonoma-sequoia", type=Path,
                        default=PROJECT / "build/compatibility-profiles" /
                        PROFILES["sonoma-sequoia"]["archive_filename"])
    parser.add_argument("--sequoia", type=Path, required=True,
                        help="independent Sequoia input profile; must match Sonoma payloads")
    parser.add_argument("--tahoe", type=Path,
                        default=PROJECT / "build/compatibility-profiles" /
                        PROFILES["tahoe"]["archive_filename"])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        manifest = combine(args.sonoma_sequoia, args.sequoia, args.tahoe, args.output)
    except (CombineError, OSError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    print(f"Wrote {args.output}")
    print(f"Wi-Fi kext bundles: {', '.join(manifest['bundles'])}")
    print(f"Output SHA-256: {sha256(args.output.read_bytes())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
