#!/usr/bin/env python3
"""Preview or install a hash-verified Broadcom Wi-Fi package into a chosen OC copy."""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import shutil
import stat
import sys
import tempfile
import zipfile

from brcmctl import CORE, LEGACY, NIC, PROVIDER, applies, configure, load_plist, preflight, version

FRAGMENT = "config.plist"
BUNDLES = {
    "AirportBrcmCompat.kext": CORE,
    "IOLegacyWFamily.kext": PROVIDER,
    "IO80211FamilyLegacy.kext": LEGACY,
    "AirPortBrcmNIC.kext": NIC,
    "AirPortBrcmNIC_Injector.kext": "as.lvs1974.AirportBrcmNICInjector",
    "AirportBrcmFixup.kext": "as.lvs1974.AirportBrcmFixup",
    "Lilu.kext": "as.vit9696.Lilu",
}
OLD_NAMES = {
    "AirPortBrcmNIC-Sonoma-Sequoia.kext": NIC,
    "AirPortBrcmNIC-Tahoe.kext": NIC,
}
OWNED_BUNDLES = set(BUNDLES) - {"Lilu.kext"}
REQUIRED_BUNDLES = set(BUNDLES)
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024


class InstallError(ValueError):
    pass


class ArchiveContents(dict[str, bytes]):
    def __init__(self, archive_sha256: str):
        super().__init__()
        self.archive_sha256 = archive_sha256


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or ".." in path.parts or "\\" in value or
            ":" in (path.parts[0] if path.parts else "") or "\x00" in value):
        raise InstallError("Unsafe relative path")
    return path


def read_archive(path: Path, expected_sha256: str) -> dict[str, bytes]:
    if len(expected_sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in expected_sha256):
        raise InstallError("--sha256 must be a 64-character SHA-256")
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARCHIVE:
        raise InstallError("Archive must be a regular file within the size limit")
    raw = path.read_bytes()
    if sha(raw) != expected_sha256.lower():
        raise InstallError("Archive SHA-256 does not match --sha256")
    result = ArchiveContents(sha(raw))
    canonical_names = set()
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for item in archive.infolist():
                name = item.filename.rstrip("/") if item.is_dir() else item.filename
                relative = safe_relative(name)
                mode = item.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise InstallError("ZIP contains a link or special file")
                if item.is_dir():
                    continue
                canonical = relative.as_posix()
                if name in result or canonical in canonical_names or canonical.casefold() in {
                        existing.casefold() for existing in canonical_names}:
                    raise InstallError("ZIP contains duplicate paths")
                if item.file_size > MAX_MEMBER:
                    raise InstallError("ZIP member exceeds the size limit")
                total += item.file_size
                if total > MAX_EXPANDED:
                    raise InstallError("Expanded ZIP exceeds the size limit")
                if item.file_size and item.compress_size == 0:
                    raise InstallError("ZIP member has an invalid compression size")
                if item.compress_size and item.file_size > item.compress_size * 2000:
                    raise InstallError("ZIP compression ratio is excessive")
                canonical_names.add(canonical)
                result[name] = archive.read(item)
    except (zipfile.BadZipFile, RuntimeError) as error:
        raise InstallError("Could not read installation ZIP") from error
    if not result:
        raise InstallError("Installation ZIP is empty")
    return result


def validate_bundles(files: dict[str, bytes]) -> dict[str, dict]:
    root_files = {}
    infos = {}
    for name, data in files.items():
        relative = safe_relative(name)
        if len(relative.parts) < 3 or relative.parts[0] != "Kexts" or not relative.parts[1].endswith(".kext"):
            continue
        bundle_name = relative.parts[1]
        if bundle_name not in BUNDLES:
            raise InstallError("ZIP contains an unexpected kext: " + bundle_name)
        if "PlugIns" in relative.parts[2:]:
            raise InstallError("Package kexts must be flat, not nested inside another kext")
        inner = PurePosixPath(*relative.parts[2:]).as_posix()
        root_files.setdefault(bundle_name, {})[inner] = data
    if not set(files) <= {FRAGMENT} | {
            "Kexts/" + bundle + "/" + name
            for bundle, members in root_files.items() for name in members}:
        raise InstallError("ZIP may contain only Kexts/*.kext and config.plist")
    if FRAGMENT not in files:
        raise InstallError("ZIP has no config.plist fragment")
    if set(root_files) != REQUIRED_BUNDLES:
        missing = sorted(REQUIRED_BUNDLES-set(root_files))
        unexpected = sorted(set(root_files)-REQUIRED_BUNDLES)
        raise InstallError("ZIP must contain the complete flat kext set; missing="+
                           ",".join(missing)+" unexpected="+",".join(unexpected))
    if OLD_NAMES.keys() & root_files.keys():
        raise InstallError("System-specific AirPortBrcmNIC bundles are not allowed")
    for bundle_name, members in root_files.items():
        if "Contents/Info.plist" not in members:
            raise InstallError("Kext has no Contents/Info.plist: " + bundle_name)
        try:
            info = plistlib.loads(members["Contents/Info.plist"])
        except (plistlib.InvalidFileException, ValueError) as error:
            raise InstallError("Invalid kext Info.plist: " + bundle_name) from error
        if not isinstance(info, dict) or info.get("CFBundleIdentifier") != BUNDLES[bundle_name]:
            raise InstallError("Unexpected bundle identifier: " + bundle_name)
        libraries = info.get("OSBundleLibraries", {})
        if (not isinstance(libraries, dict) or
                any(not isinstance(key, str) or not isinstance(value, (str, int))
                    for key, value in libraries.items())):
            raise InstallError("Invalid OSBundleLibraries in " + bundle_name)
        executable = info.get("CFBundleExecutable")
        if executable:
            if not isinstance(executable, str) or "/" in executable or executable in (".", ".."):
                raise InstallError("Unsafe CFBundleExecutable: " + bundle_name)
            executable_path = "Contents/MacOS/" + executable
            if executable_path not in members:
                raise InstallError("Kext executable is missing: " + bundle_name)
        infos[bundle_name] = info
    if infos["AirportBrcmCompat.kext"].get("CFBundleExecutable") != "AirportBrcmCompat":
        raise InstallError("Unexpected AirportBrcmCompat executable")
    return infos


def validate_fragment(raw: bytes, infos: dict[str, dict]) -> dict:
    if len(raw) > 8 * 1024 * 1024:
        raise InstallError("Configuration fragment exceeds the size limit")
    try:
        fragment = plistlib.loads(raw)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise InstallError("Invalid config.plist fragment") from error
    if not isinstance(fragment, dict) or set(fragment) != {"Kernel"}:
        raise InstallError("Fragment must contain only Kernel settings")
    kernel = fragment["Kernel"]
    if not isinstance(kernel, dict) or set(kernel) - {"Add", "Block", "Quirks"}:
        raise InstallError("Fragment contains unsupported OpenCore settings")
    adds = kernel.get("Add")
    if not isinstance(adds, list) or not adds:
        raise InstallError("Fragment must list kext load order")
    if not all(isinstance(entry, dict) for entry in adds):
        raise InstallError("Kernel/Add entries must be dictionaries")
    paths = []
    ids = []
    for entry in adds:
        path = entry.get("BundlePath")
        if not isinstance(path, str):
            raise InstallError("Kernel/Add entry has no BundlePath")
        safe_relative(path)
        if "/" in path or path not in BUNDLES or path not in infos:
            raise InstallError("Every package kext must be a separate Kexts/*.kext bundle")
        if entry.get("MaxKernel") not in (None, ""):
            raise InstallError("Unified kext entries cannot have a maximum OS version")
        if entry.get("MinKernel") != "23.0.0":
            raise InstallError("Unified kext entries must start at Darwin 23.0.0")
        if entry.get("Arch") not in ("x86_64", "Any"):
            raise InstallError("Unexpected kext architecture")
        executable = infos[path].get("CFBundleExecutable")
        expected_executable = "Contents/MacOS/" + executable if executable else ""
        if entry.get("ExecutablePath", "") != expected_executable:
            raise InstallError("OpenCore executable path disagrees with the kext bundle")
        if entry.get("PlistPath") != "Contents/Info.plist":
            raise InstallError("Unexpected OpenCore plist path")
        if entry.get("Enabled") is not True:
            raise InstallError("Every Wi-Fi kext entry must be enabled")
        if entry.get("Identifier") not in (None, infos[path]["CFBundleIdentifier"]):
            raise InstallError("OpenCore identifier disagrees with the kext bundle")
        paths.append(path)
        ids.append(infos[path]["CFBundleIdentifier"])
    if len(paths) != len(set(paths)) or len(ids) != len(set(ids)):
        raise InstallError("Fragment contains duplicate kext paths or identifiers")
    expected_ids = set(BUNDLES.values())
    if not expected_ids.issubset(ids):
        raise InstallError("Fragment does not load every package kext")
    unlisted = set(infos) - set(paths)
    if unlisted - {"Lilu.kext"}:
        raise InstallError("Every Wi-Fi kext must have a matching Kernel/Add entry")
    blocks = kernel.get("Block")
    if not isinstance(blocks, list) or len(blocks) != 1 or not isinstance(blocks[0], dict):
        raise InstallError("Fragment must contain only the Wi-Fi compatibility block")
    block = blocks[0]
    if (block.get("Identifier") != "com.apple.iokit.IO80211Family" or
            block.get("Strategy") != "Exclude" or block.get("Enabled") is not True or
            block.get("MinKernel") != "23.0.0" or block.get("MaxKernel") not in (None, "") or
            block.get("Arch") not in ("x86_64", "Any")):
        raise InstallError("Fragment contains an unexpected or OS-limited kernel block")
    quirks = kernel.get("Quirks")
    if quirks != {"DisableLinkeditJettison": True}:
        raise InstallError("Fragment may only enable DisableLinkeditJettison")
    indexed = {infos[entry["BundlePath"]]["CFBundleIdentifier"]: index
               for index, entry in enumerate(adds)}
    for index, entry in enumerate(adds):
        info = infos[entry["BundlePath"]]
        for dependency in info.get("OSBundleLibraries", {}):
            if dependency in indexed and indexed[dependency] >= index:
                raise InstallError("A kext must follow its bundled dependency: " + dependency)
            if dependency not in indexed and dependency != "as.vit9696.Lilu" and not dependency.startswith(
                    ("com.apple.kpi.", "com.apple.iokit.", "com.apple.driver.", "com.apple.kec.")):
                raise InstallError("Package is missing a declared kext dependency: " + dependency)
    return fragment


def inspect_oc(oc_dir: Path):
    oc = Path(oc_dir)
    if oc.is_symlink() or not oc.is_dir():
        raise InstallError("--oc-dir must be an existing OpenCore directory")
    oc = oc.resolve()
    kexts = oc / "Kexts"
    config_path = oc / "config.plist"
    if kexts.is_symlink() or not kexts.is_dir():
        raise InstallError("OC/Kexts must be an existing real directory")
    if config_path.is_symlink() or not config_path.is_file():
        raise InstallError("OC/config.plist must be a regular file")
    raw = config_path.read_bytes()
    if len(raw) > 8 * 1024 * 1024:
        raise InstallError("OC/config.plist exceeds the size limit")
    config = load_plist(config_path)
    if (not isinstance(config.get("Kernel", {}).get("Add", []), list) or
            not all(isinstance(entry, dict) for entry in config.get("Kernel", {}).get("Add", []))):
        raise InstallError("Kernel/Add must be an array")
    return oc, kexts.resolve(), config, raw


def tree_hash(path: Path) -> str:
    if path.is_file():
        return sha(path.read_bytes())
    records = []
    for item in sorted(path.rglob("*"), key=lambda p: p.relative_to(path).as_posix()):
        if item.is_symlink():
            records.append((item.relative_to(path).as_posix(), "link", os.readlink(item)))
        elif item.is_file():
            records.append((item.relative_to(path).as_posix(), "file", sha(item.read_bytes())))
        elif item.is_dir():
            records.append((item.relative_to(path).as_posix(), "dir", ""))
    return sha(json.dumps(records, separators=(",", ":")).encode())


def inspect_existing(bundle: Path) -> tuple[dict, str]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise InstallError("Expected a real existing kext: " + bundle.name)
    if any(path.is_symlink() for path in bundle.rglob("*")):
        raise InstallError("Refusing to alter a kext containing symlinks: " + bundle.name)
    info_path = bundle / "Contents/Info.plist"
    if info_path.is_symlink() or not info_path.is_file():
        raise InstallError("Existing kext has no Info.plist: " + bundle.name)
    return load_plist(info_path), tree_hash(bundle)


def known_old_entries(config: dict, kexts: Path):
    paths = {name: BUNDLES[name] for name in OWNED_BUNDLES}
    paths.update(OLD_NAMES)
    remove_entries = []
    remove_paths = []
    for entry in config.get("Kernel", {}).get("Add", []):
        path = entry.get("BundlePath")
        if path in OLD_NAMES:
            expected_id = OLD_NAMES[path]
        elif path in OWNED_BUNDLES:
            expected_id = BUNDLES[path]
        else:
            continue
        bundle = kexts / path
        if not bundle.exists():
            raise InstallError("Known kext entry has no bundle to verify: " + path)
        info, _ = inspect_existing(bundle)
        if info.get("CFBundleIdentifier") != expected_id:
            raise InstallError("Known kext path has an unexpected identifier: " + path)
        remove_entries.append(entry)
        if bundle not in remove_paths:
            remove_paths.append(bundle)
    for name, identifier in paths.items():
        bundle = kexts / name
        if (bundle.exists() or bundle.is_symlink()) and bundle not in remove_paths:
            info, _ = inspect_existing(bundle)
            if info.get("CFBundleIdentifier") != identifier:
                raise InstallError("Known kext path has an unexpected identifier: " + name)
            # A known component at its canonical path is safe to replace after backup.
            remove_paths.append(bundle)
    return remove_entries, remove_paths


def find_external_lilu(config: dict, fragment: dict, infos: dict[str, dict],
                       kexts: Path, darwin: str) -> tuple[dict, tuple[dict, Path] | None]:
    required_versions = [info.get("OSBundleLibraries", {}).get("as.vit9696.Lilu")
                         for info in infos.values()]
    required_versions = [value for value in required_versions if value]
    if not required_versions:
        return fragment, None
    required_version = max(version(str(value)) for value in required_versions)
    external = []
    for entry in config.get("Kernel", {}).get("Add", []):
        path = entry.get("BundlePath", "")
        if path in OWNED_BUNDLES or path in OLD_NAMES:
            continue
        try:
            relative = safe_relative(path)
        except InstallError:
            continue
        bundle = kexts.joinpath(*relative.parts)
        try:
            plist_relative = safe_relative(entry.get("PlistPath", "Contents/Info.plist"))
        except (InstallError, TypeError):
            continue
        info_path = bundle.joinpath(*plist_relative.parts)
        if not info_path.resolve().is_relative_to(bundle.resolve()):
            raise InstallError("Existing component plist escapes its bundle")
        if any(part.is_symlink() for part in (bundle, *bundle.parents) if part != kexts.parent) or \
                any(part.is_symlink() for part in (info_path, *info_path.parents) if part != kexts.parent):
            raise InstallError("Existing Lilu path contains a symlink")
        if info_path.is_file() and not info_path.is_symlink():
            info = load_plist(info_path)
            if info.get("CFBundleIdentifier") == "as.vit9696.Lilu":
                if entry.get("Arch", "Any") not in ("Any", "x86_64", ""):
                    raise InstallError("Existing Lilu does not support the target architecture")
                if not applies(entry, version(darwin)):
                    raise InstallError("Existing Lilu is not enabled for the requested system")
                minimum = entry.get("MinKernel", "")
                maximum = entry.get("MaxKernel", "")
                if minimum and version(minimum) > version("23.0.0") or maximum:
                    raise InstallError("Existing Lilu must cover Darwin 23 and later without a version ceiling")
                external.append((entry, info, bundle))
    if len(external) > 1:
        raise InstallError("Multiple external Lilu entries are active")
    bundled = [entry for entry in fragment["Kernel"]["Add"]
               if entry.get("BundlePath") == "Lilu.kext"]
    if external:
        info = external[0][1]
        try:
            found_version = version(str(info.get("CFBundleVersion", "0")))
        except ValueError as error:
            raise InstallError("Existing Lilu has an unrecognized version") from error
        if found_version < required_version:
            raise InstallError("Existing Lilu is older than the version required by the package")
        if len(bundled) > 1:
            raise InstallError("Package has duplicate Lilu entries")
        result = copy.deepcopy(fragment)
        if bundled:
            result["Kernel"]["Add"] = [entry for entry in result["Kernel"]["Add"]
                                       if entry.get("BundlePath") != "Lilu.kext"]
        return result, (external[0][0], external[0][2])
    if not bundled:
        raise InstallError("No suitable Lilu is configured and the package has no Lilu kext")
    info = infos.get("Lilu.kext", {})
    try:
        bundled_version = version(str(info.get("CFBundleVersion", "0")))
    except ValueError as error:
        raise InstallError("Packaged Lilu has an unrecognized version") from error
    if bundled_version < required_version:
        raise InstallError("Packaged Lilu is older than the version required by the package")
    return fragment, None


def candidate_config(config: dict, fragment: dict, remove_entries: list[dict]) -> dict:
    result = copy.deepcopy(config)
    # These entries were matched to known on-disk bundle paths and verified by
    # bundle identifier in known_old_entries. BundlePath is the stable key; a
    # JSON round trip would reject valid plist values such as bytes and dates.
    removed = {entry.get("BundlePath") for entry in remove_entries}
    result.setdefault("Kernel", {}).setdefault("Add", [])[:] = [
        entry for entry in result["Kernel"]["Add"] if entry.get("BundlePath") not in removed]
    return configure(result, fragment)


def write_staged_payload(bundle_files: dict[str, bytes], destination: Path) -> None:
    for relative, data in bundle_files.items():
        staged = destination.joinpath(*safe_relative(relative).parts)
        staged.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        for directory in (staged.parent, *staged.parent.parents):
            if directory == destination or destination in directory.parents:
                os.chmod(directory, 0o755)
            if directory == destination:
                break
        staged.write_bytes(data)
        parts = PurePosixPath(relative).parts
        mode = 0o755 if len(parts) >= 3 and parts[-3:-1] == ("Contents", "MacOS") else 0o644
        os.chmod(staged, mode)


def check_staged(bundle_files: dict[str, bytes], config: dict, external_lilu: tuple[dict, Path] | None,
                 darwin: str, external_lilu_hash: str | None = None) -> dict:
    with tempfile.TemporaryDirectory(prefix="brcm-install-check-") as temporary:
        oc = Path(temporary) / "OC"
        kexts = oc / "Kexts"
        kexts.mkdir(parents=True)
        staged_files = {name: data for name, data in bundle_files.items()
                        if not external_lilu or name.split("/", 1)[0] != "Lilu.kext"}
        write_staged_payload(staged_files, kexts)
        entries = config.get("Kernel", {}).get("Add", [])
        filtered = []
        package_names = {member.split("/", 1)[0] for member in bundle_files}
        for entry in entries:
            name = entry.get("BundlePath", "")
            if name in OWNED_BUNDLES or (name == "Lilu.kext" and external_lilu is None and
                                         name in package_names):
                filtered.append(entry)
            elif external_lilu and name == external_lilu[0].get("BundlePath"):
                source = external_lilu[1]
                destination = kexts.joinpath(*safe_relative(name).parts)
                shutil.copytree(source, destination)
                if external_lilu_hash and tree_hash(destination) != external_lilu_hash:
                    raise InstallError("External Lilu changed while the install was being checked")
                filtered.append(entry)
        staged = copy.deepcopy(config)
        staged.setdefault("Kernel", {})["Add"] = filtered
        (oc / "config.plist").write_bytes(plistlib.dumps(staged))
        report = preflight(oc, darwin)
        report["scope"] = "staged AirportBrcmCompat kext group and declared runtime dependency"
        return report


def ensure_no_collisions(config: dict, kexts: Path, infos: dict[str, dict],
                         replacing: set[str], darwin: str,
                         external_lilu: tuple[dict, Path] | None = None) -> None:
    wanted = {info["CFBundleIdentifier"] for info in infos.values()}
    collisions = {}
    for entry in config.get("Kernel", {}).get("Add", []):
        if not applies(entry, version(darwin)):
            continue
        path = entry.get("BundlePath", "")
        if path in replacing:
            continue
        if external_lilu and path == external_lilu[0].get("BundlePath"):
            continue
        try:
            relative = safe_relative(path)
        except InstallError:
            continue
        bundle = kexts.joinpath(*relative.parts)
        info_path = bundle / entry.get("PlistPath", "Contents/Info.plist")
        if info_path.is_file() and not info_path.is_symlink():
            identifier = load_plist(info_path).get("CFBundleIdentifier")
            if identifier in wanted:
                collisions.setdefault(identifier, []).append(path)
    if collisions:
        text = "; ".join(identifier + " at " + ", ".join(paths)
                         for identifier, paths in sorted(collisions.items()))
        raise InstallError("Duplicate component identifiers would be loaded: " + text)


def plan(archive: Path, expected_sha256: str, oc_dir: Path, darwin: str) -> dict:
    version(darwin)
    files = read_archive(archive, expected_sha256)
    bundle_files = {name[len("Kexts/"):]: data for name, data in files.items()
                    if name.startswith("Kexts/")}
    infos = validate_bundles(files)
    fragment = validate_fragment(files[FRAGMENT], infos)
    oc, kexts, config, original = inspect_oc(oc_dir)
    remove_entries, remove_paths = known_old_entries(config, kexts)
    replacing = {path.relative_to(kexts).as_posix() for path in remove_paths}
    fragment, external_lilu = find_external_lilu(config, fragment, infos, kexts, darwin)
    ensure_no_collisions(config, kexts, infos, replacing, darwin, external_lilu)
    bundled_lilu = kexts / "Lilu.kext"
    packaged_lilu = any(name.startswith("Lilu.kext/") for name in bundle_files)
    if packaged_lilu and external_lilu is not None:
        # The existing compatible library stays exactly where it is; package bytes
        # remain verified as part of the archive but are not copied over it.
        bundle_files = {name: data for name, data in bundle_files.items()
                        if name.split("/", 1)[0] != "Lilu.kext"}
    elif packaged_lilu and (bundled_lilu.exists() or bundled_lilu.is_symlink()):
        raise InstallError("An unconfigured Lilu.kext already occupies the package install path")
    elif external_lilu is None and not packaged_lilu:
        raise InstallError("A suitable Lilu is required by the package but is not available")
    candidate = candidate_config(config, fragment, remove_entries)
    external_lilu_hash = tree_hash(external_lilu[1]) if external_lilu else None
    staged = check_staged(bundle_files, candidate, external_lilu, darwin, external_lilu_hash)
    if external_lilu and tree_hash(external_lilu[1]) != external_lilu_hash:
        raise InstallError("External Lilu changed during preflight; rerun the installer")
    if not staged.get("passed"):
        raise InstallError("Staged configuration failed preflight: " + "; ".join(staged["errors"]))
    snapshots = {"config.plist": sha(original)}
    incoming_bundle_names = {name.split("/", 1)[0] for name in bundle_files}
    targets = {oc / "Kexts" / name for name in OWNED_BUNDLES | set(OLD_NAMES)}
    if "Lilu.kext" in incoming_bundle_names:
        targets.add(oc / "Kexts" / "Lilu.kext")
    for target in targets:
        snapshots[str(target.relative_to(oc))] = tree_hash(target) if target.exists() or target.is_symlink() else "<missing>"
    if external_lilu:
        relative = str(external_lilu[1].relative_to(oc))
        snapshots[relative] = external_lilu_hash
    return {"oc": oc, "kexts": kexts, "darwin": darwin,
            "archive_sha256": files.archive_sha256,
            "config": candidate, "config_bytes": plistlib.dumps(candidate, sort_keys=False),
            "bundles": bundle_files, "archive_members": files, "remove_paths": remove_paths,
            "snapshots": snapshots, "external_lilu_hash": external_lilu_hash,
            "external_lilu": external_lilu,
            "external_lilu_used": external_lilu is not None, "preflight": staged}


def backup_location(oc: Path, value: Path) -> Path:
    path = Path(value).expanduser()
    if path.exists() or path.is_symlink():
        raise InstallError("--backup-dir must be a new directory")
    candidate = path.parent.resolve() / path.name
    if candidate == oc or candidate in oc.parents or oc in candidate.parents:
        raise InstallError("Backup directory must be outside the OpenCore directory")
    if oc.parent.name.upper() == "EFI":
        efi = oc.parent
        if candidate == efi or efi in candidate.parents:
            raise InstallError("Backup directory must be outside EFI")
    if not candidate.parent.is_dir():
        raise InstallError("Backup directory parent must already exist")
    return candidate


def copy_tree(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, symlinks=True)


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    temporary = path.with_name(path.name + ".brcm-install-tmp")
    if temporary.exists() or temporary.is_symlink():
        raise InstallError("Temporary config path already exists")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        original_stat = path.stat()
        try:
            os.chown(temporary, original_stat.st_uid, original_stat.st_gid)
        except (AttributeError, PermissionError, OSError):
            current_stat = temporary.stat()
            if (current_stat.st_uid, current_stat.st_gid) != (original_stat.st_uid, original_stat.st_gid):
                raise InstallError("Cannot preserve config.plist ownership")
        shutil.copystat(path, temporary, follow_symlinks=False)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def current_snapshot(oc: Path, snapshots: dict[str, str]) -> dict[str, str]:
    current = {"config.plist": sha((oc / "config.plist").read_bytes())}
    for name in snapshots:
        if name == "config.plist":
            continue
        path = oc.joinpath(*safe_relative(name).parts)
        current[name] = tree_hash(path) if path.exists() or path.is_symlink() else "<missing>"
    return current


def rollback(oc: Path, backup: Path, saved: set[str], config_mode: int,
            added_lilu: bool) -> None:
    kexts = oc / "Kexts"
    extras = {"Lilu.kext"} if added_lilu or "Lilu.kext" in saved else set()
    for name in OWNED_BUNDLES | set(OLD_NAMES) | extras:
        target = kexts / name
        if target.exists():
            shutil.rmtree(target)
    for name in saved:
        copy_tree(backup / "Kexts" / name, kexts / name)
    atomic_write(oc / "config.plist", (backup / "config.plist").read_bytes(), config_mode)


def apply(plan_result: dict, backup_dir: Path) -> dict:
    oc, kexts = plan_result["oc"], plan_result["kexts"]
    backup = backup_location(oc, backup_dir)
    expected = plan_result["snapshots"]
    if current_snapshot(oc, expected) != expected:
        raise InstallError("EFI files changed after preflight; rerun the installer")
    backup.mkdir(mode=0o700)
    saved = set()
    mutating = False
    config_mode = stat.S_IMODE((oc / "config.plist").stat().st_mode)
    incoming_bundle_names = {name.split("/", 1)[0] for name in plan_result["bundles"]}
    staging = None
    try:
        shutil.copy2(oc / "config.plist", backup / "config.plist")
        (backup / "Kexts").mkdir()
        backup_names = OWNED_BUNDLES | set(OLD_NAMES) | (
            {"Lilu.kext"} if "Lilu.kext" in incoming_bundle_names else set())
        for name in sorted(backup_names):
            source = kexts / name
            if source.exists():
                copy_tree(source, backup / "Kexts" / name)
                saved.add(name)
        (backup / "backup.json").write_text(json.dumps({
            "scope": "OpenCore config and recognized Broadcom bundles",
            "config_sha256": sha((backup / "config.plist").read_bytes()),
            "bundles": {name: tree_hash(backup / "Kexts" / name) for name in sorted(saved)}
        }, indent=2) + "\n")
        if current_snapshot(oc, expected) != expected:
            raise InstallError("EFI files changed while the backup was being created")
        staging = Path(tempfile.mkdtemp(prefix=".airportbrcmcompat-stage-", dir=kexts))
        write_staged_payload(plan_result["bundles"], staging)
        for relative, data in plan_result["bundles"].items():
            staged = staging / relative
            if not staged.is_file() or staged.read_bytes() != data:
                raise InstallError("Could not stage the verified kext payload: " + relative)
        if current_snapshot(oc, expected) != expected:
            raise InstallError("EFI files changed while the install payload was being staged")
        mutating = True
        for name in OWNED_BUNDLES | set(OLD_NAMES):
            target = kexts / name
            if target.exists() or target.is_symlink():
                shutil.rmtree(target)
        for name in sorted(incoming_bundle_names):
            os.replace(staging / name, kexts / name)
        atomic_write(oc / "config.plist", plan_result["config_bytes"], config_mode)
        for relative, expected_data in plan_result["bundles"].items():
            installed = kexts / relative
            if not installed.is_file() or installed.is_symlink() or installed.read_bytes() != expected_data:
                raise InstallError("Installed kext content differs from the verified archive: " + relative)
        if (oc / "config.plist").read_bytes() != plan_result["config_bytes"]:
            raise InstallError("Installed config differs from the preflighted configuration")
        checked = check_staged(plan_result["bundles"], plan_result["config"],
                               plan_result["external_lilu"], plan_result["darwin"],
                               plan_result["external_lilu_hash"])
        if not checked.get("passed"):
            raise InstallError("Installed OpenCore copy failed preflight: " + "; ".join(checked["errors"]))
        shutil.rmtree(staging)
        staging = None
        return {"applied": True, "backup": str(backup), "preflight": checked,
                "external_lilu_used": plan_result["external_lilu_used"]}
    except Exception as install_error:
        cleanup_error = None
        try:
            if staging and staging.exists():
                shutil.rmtree(staging)
        except Exception as error:
            cleanup_error = error
        if mutating:
            try:
                rollback(oc, backup, saved, config_mode,
                         "Lilu.kext" in incoming_bundle_names and not plan_result["external_lilu_used"])
            except Exception as error:
                raise InstallError("Install failed; rollback needs manual attention and backup remains at " +
                                   str(backup) + ": " + str(error))
        if cleanup_error:
            raise InstallError("Install failed; temporary staging cleanup failed" +
                               (" and backup remains at " + str(backup) if mutating else "") +
                               ": " + str(cleanup_error)) from install_error
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--oc-dir", type=Path, required=True,
                        help="Existing OpenCore directory; the installer does not search or mount EFI")
    parser.add_argument("--darwin", required=True)
    parser.add_argument("--apply", action="store_true", help="Write to the supplied OpenCore directory")
    parser.add_argument("--backup-dir", type=Path, help="New backup directory outside EFI; required with --apply")
    args = parser.parse_args(argv)
    try:
        if args.apply and args.backup_dir is None:
            raise InstallError("--backup-dir is required with --apply")
        result = plan(args.archive, args.sha256, args.oc_dir, args.darwin)
        if args.apply:
            output = apply(result, args.backup_dir)
            output = {"scope": "explicit OpenCore directory only", **output}
        else:
            output = {"scope": "dry run; no files changed",
                      "archive_sha256": result["archive_sha256"], "darwin": result["darwin"],
                      "install": ["Kexts/" + name for name in sorted(
                          {member.split("/", 1)[0] for member in result["bundles"]})],
                      "remove": sorted(path.name for path in result["remove_paths"]),
                      "external_lilu_used": result["external_lilu_used"],
                      "preflight": result["preflight"]}
        print(json.dumps(output, indent=2))
        return 0
    except (OSError, InstallError, ValueError, KeyError, TypeError,
            plistlib.InvalidFileException, zipfile.BadZipFile) as error:
        print("install: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
