#!/usr/bin/env python3
"""Package the optional NIC injector from a hash-pinned upstream release ZIP.

The command only creates an EFI/OpenCore dependency ZIP. It never installs or
loads the kexts. PCI matching entries are candidates, not hardware test results.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile


ARCHIVE_SHA256 = '2432c8a62445ad2cdadcc59b73928f01f8bf42bcd3f4386e49bc63a1c91db06f'
UPSTREAM = 'https://github.com/acidanthera/AirportBrcmFixup/releases/tag/2.2.1'
ROOT = Path(__file__).resolve().parents[1]
CORE = 'AirportBrcmFixup.kext'
INJECTOR = CORE + '/Contents/PlugIns/AirPortBrcmNIC_Injector.kext'
EXECUTABLE = CORE + '/Contents/MacOS/AirportBrcmFixup'
BASE_IDS = ('43ba', '43a3', '43a0')
ADDITIONAL_IDS = ('4331', '4353', '4357', '43b1', '43b2')
MATCH_IDS = ('4331', '4353', '4357', '43ba', '43a3', '43a0', '43b1', '43b2')
PROFILES = {'sonoma-sequoia': ('23.0.0', '24.99.99'), 'tahoe': ('25.0.0', ''),
            'automatic': ('23.0.0', '')}


def _check_id_policy():
    if (len(set(MATCH_IDS)) != 8 or len(set(ADDITIONAL_IDS)) != 5 or
            set(BASE_IDS) & set(ADDITIONAL_IDS) or
            set(BASE_IDS) | set(ADDITIONAL_IDS) != set(MATCH_IDS)):
        raise ValueError('Inconsistent base/additional Broadcom PCI ID policy')


def _macho_section_hashes(binary):
    """Return file-backed Mach-O section hashes, excluding code-sign blobs."""
    if len(binary) < 32:
        raise ValueError('Truncated upstream executable')
    magic, cputype = struct.unpack_from('<Ii', binary, 0)
    if magic != 0xFEEDFACF or cputype != 0x01000007:
        raise ValueError('Expected a 64-bit x86_64 Mach-O executable')
    ncmds, sizeofcmds = struct.unpack_from('<II', binary, 16)
    commands_end = 32 + sizeofcmds
    if ncmds > 100000 or commands_end > len(binary):
        raise ValueError('Invalid Mach-O load-command bounds')
    cursor = 32
    found = {}
    for _ in range(ncmds):
        if cursor + 8 > commands_end:
            raise ValueError('Truncated Mach-O load command')
        cmd, cmdsize = struct.unpack_from('<II', binary, cursor)
        if cmdsize < 8 or cmdsize % 8 or cursor + cmdsize > commands_end:
            raise ValueError('Invalid Mach-O load-command size')
        if cmd == 0x19:  # LC_SEGMENT_64
            if cmdsize < 72:
                raise ValueError('Truncated LC_SEGMENT_64')
            segment_name = binary[cursor + 8:cursor + 24].split(b'\0', 1)[0].decode('ascii')
            nsects = struct.unpack_from('<I', binary, cursor + 64)[0]
            if 72 + nsects * 80 != cmdsize:
                raise ValueError('Invalid Mach-O section table size')
            for index in range(nsects):
                start = cursor + 72 + index * 80
                section_name = binary[start:start + 16].split(b'\0', 1)[0].decode('ascii')
                section_segment = binary[start + 16:start + 32].split(b'\0', 1)[0].decode('ascii')
                address, size = struct.unpack_from('<QQ', binary, start + 32)
                fileoff = struct.unpack_from('<I', binary, start + 48)[0]
                flags = struct.unpack_from('<I', binary, start + 64)[0]
                if section_segment != segment_name:
                    raise ValueError('Mach-O section/segment name mismatch')
                section_type = flags & 0xFF
                if section_type in (0x1, 0xC, 0x12) or size == 0:  # zero-fill sections
                    continue
                if fileoff > len(binary) or size > len(binary) - fileoff:
                    raise ValueError('Mach-O section exceeds executable bytes')
                key = f'{segment_name},{section_name}'
                if key in found:
                    key += f'#{index}'
                found[key] = {'size': size, 'sha256': hashlib.sha256(binary[fileoff:fileoff + size]).hexdigest()}
        cursor += cmdsize
    if cursor != commands_end or not found:
        raise ValueError('Invalid or empty Mach-O section table')
    return dict(sorted(found.items()))


def _check_executable_sections(upstream_binary, signed_binary):
    original = _macho_section_hashes(upstream_binary)
    signed = _macho_section_hashes(signed_binary)
    if original != signed:
        raise ValueError('Ad-hoc signing changed upstream Mach-O section bytes')
    return original


def _verify_codesign(bundle):
    subprocess.run(['codesign', '--verify', '--strict', str(bundle)],
                   check=True, capture_output=True)


def _sign_bundles(root):
    for bundle in (root / INJECTOR, root / CORE):
        subprocess.run(['codesign', '--force', '--sign', '-', '--timestamp=none', str(bundle)],
                       check=True, capture_output=True)
    for bundle in (root / INJECTOR, root / CORE):
        _verify_codesign(bundle)


def _verify_tree(root):
    core = root / CORE
    injector = root / INJECTOR
    if not core.is_dir() or not injector.is_dir():
        raise ValueError('Prepared package is missing a required kext bundle')
    if any('4360' in path.name for path in (core / 'Contents' / 'PlugIns').iterdir()):
        raise ValueError('Unexpected non-NIC plugin in prepared package')
    _verify_codesign(injector)
    _verify_codesign(core)


def _write_zip(root):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        paths = sorted(root.rglob('*'), key=lambda path: path.relative_to(root).as_posix())
        for path in paths:
            relative = path.relative_to(root).as_posix()
            mode = stat.S_IMODE(path.stat().st_mode)
            if path.is_dir():
                info = zipfile.ZipInfo(relative + '/')
                info.create_system = 3
                info.external_attr = (stat.S_IFDIR | mode) << 16 | 0x10
                info.compress_type = zipfile.ZIP_STORED
                package.writestr(info, b'')
            else:
                info = zipfile.ZipInfo(relative)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                package.writestr(info, path.read_bytes())
    return output.getvalue()


def _extract_package(package_bytes, root):
    with zipfile.ZipFile(io.BytesIO(package_bytes)) as package:
        for item in package.infolist():
            name = PurePosixPath(item.filename)
            if name.is_absolute() or '..' in name.parts or '\\' in item.filename:
                raise ValueError('Prepared ZIP contains an unsafe path')
            destination = root.joinpath(*name.parts)
            if item.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                mode = (item.external_attr >> 16) & 0o777
                if mode:
                    os.chmod(destination, mode)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(package.read(item))
            mode = (item.external_attr >> 16) & 0o777
            if mode:
                os.chmod(destination, mode)


def prepare(archive, output, profile):
    archive, output = Path(archive), Path(output)
    if profile not in PROFILES:
        raise ValueError('Unknown dependency profile')
    if output.exists() or output.is_symlink():
        raise ValueError('Output already exists')
    if output.suffix.lower() != '.zip':
        raise ValueError('Output must be a .zip package path')
    _check_id_policy()
    archive_bytes = archive.read_bytes()
    if hashlib.sha256(archive_bytes).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('Expected the official AirportBrcmFixup 2.2.1 RELEASE archive')

    with tempfile.TemporaryDirectory(prefix='airport-broadcom-', dir='/private/tmp') as temp:
        stage = Path(temp) / 'stage'
        stage.mkdir()
        upstream_binary = None
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as source:
            for item in source.infolist():
                name = PurePosixPath(item.filename)
                if name.is_absolute() or '..' in name.parts or '\\' in item.filename:
                    raise ValueError('Archive path escapes its root')
                if not name.parts or name.parts[0] != CORE or item.is_dir():
                    continue
                # Only the NIC injector is appropriate here. The 4360 injector
                # targets a different hardware driver and is never packaged.
                if '/Contents/PlugIns/' in item.filename and not item.filename.startswith(INJECTOR + '/'):
                    continue
                if ((item.external_attr >> 16) & 0o170000) == 0o120000:
                    raise ValueError('Symlink in dependency archive')
                destination = stage.joinpath(*name.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                payload = source.read(item)
                destination.write_bytes(payload)
                mode = (item.external_attr >> 16) & 0o777
                if mode:
                    os.chmod(destination, mode)
                if item.filename == EXECUTABLE:
                    upstream_binary = payload
        if upstream_binary is None:
            raise ValueError('Upstream release lacks the expected core executable')

        core_info_path = stage / CORE / 'Contents/Info.plist'
        injector_info_path = stage / INJECTOR / 'Contents/Info.plist'
        core_info = plistlib.loads(core_info_path.read_bytes())
        injector_info = plistlib.loads(injector_info_path.read_bytes())
        if (core_info.get('CFBundleIdentifier') != 'as.lvs1974.AirportBrcmFixup' or
                core_info.get('CFBundleVersion') != '2.2.1' or
                core_info.get('CFBundleExecutable') != 'AirportBrcmFixup'):
            raise ValueError('Unexpected upstream core metadata')
        personality = injector_info.get('IOKitPersonalities', {}).get('Airport_BrcmNIC', {})
        injector_ids = personality.get('IONameMatch', [])
        expected_ids = {'pci14e4,' + value for value in MATCH_IDS}
        if (injector_info.get('CFBundleIdentifier') != 'as.lvs1974.AirportBrcmNICInjector' or
                personality.get('CFBundleIdentifier') != 'com.apple.driver.AirPort.BrcmNIC' or
                personality.get('IOClass') != 'AirPort_BrcmNIC' or
                not isinstance(injector_ids, list) or len(injector_ids) != 8 or
                set(injector_ids) != expected_ids):
            raise ValueError('Unexpected NIC injector matching')

        minimum, maximum = PROFILES[profile]
        entries = []
        for bundle, executable in ((CORE, 'Contents/MacOS/AirportBrcmFixup'), (INJECTOR, '')):
            entries.append({'Arch': 'x86_64', 'BundlePath': bundle,
                            'Comment': 'Optional additional Broadcom card matching candidate',
                            'Enabled': True, 'ExecutablePath': executable,
                            'PlistPath': 'Contents/Info.plist', 'MinKernel': minimum,
                            'MaxKernel': maximum})
        (stage / 'config.additional-cards.plist').write_bytes(
            plistlib.dumps({'Kernel': {'Add': entries}}, sort_keys=False))
        shutil.copyfile(ROOT / 'LICENSES/AirportBrcmFixup-LICENSE.txt', stage / 'LICENSE-AirportBrcmFixup.txt')

        _sign_bundles(stage)
        signed_binary = (stage / EXECUTABLE).read_bytes()
        unchanged_sections = _check_executable_sections(upstream_binary, signed_binary)
        manifest = {'schema': 1, 'status': 'ADDITIONAL_CARD_MATCHING_CANDIDATE',
                    'upstream': UPSTREAM, 'version': '2.2.1', 'archive_sha256': ARCHIVE_SHA256,
                    'dependency_profile': profile,
                    'base_pci_ids': ['14e4:' + value for value in BASE_IDS],
                    'additional_pci_ids': ['14e4:' + value for value in ADDITIONAL_IDS],
                    'injector_match_pci_ids': ['14e4:' + value for value in MATCH_IDS],
                    'bundles': [CORE, INJECTOR], 'minimum_kernel': minimum, 'maximum_kernel': maximum,
                    'requires_matching_wifi_dependency_profile': True,
                    'binary_integrity': {
                        'upstream_executable_sha256': hashlib.sha256(upstream_binary).hexdigest(),
                        'signed_executable_sha256': hashlib.sha256(signed_binary).hexdigest(),
                        'file_backed_section_sha256': unchanged_sections,
                        'note': 'Ad-hoc signing adds Mach-O signature metadata; every original file-backed section is unchanged.'
                    },
                    'files_sha256': {p.relative_to(stage).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in sorted(stage.rglob('*')) if p.is_file()}}
        (stage / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')

        _verify_tree(stage)
        package_bytes = _write_zip(stage)
        # Validate the actual delivery bytes after a fresh extraction, including
        # ZIP permission bits and both nested and parent code signatures.
        verify_root = Path(temp) / 'fresh-extract'
        verify_root.mkdir()
        _extract_package(package_bytes, verify_root)
        _verify_tree(verify_root)
        if (verify_root / EXECUTABLE).stat().st_mode & 0o111 == 0:
            raise ValueError('ZIP did not preserve the core executable permission')
        verified_manifest = json.loads((verify_root / 'manifest.json').read_text())
        if verified_manifest != manifest:
            raise ValueError('Prepared package manifest did not survive ZIP round-trip')

    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open('xb') as stream:
            stream.write(package_bytes)
    except FileExistsError as exc:
        raise ValueError('Output already exists') from exc
    except Exception:
        if output.exists():
            output.unlink()
        raise
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new .zip package path')
    parser.add_argument('--dependency-profile', choices=PROFILES, required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.archive, args.output, args.dependency_profile)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        parser.exit(1, f'prepare_broadcom_injector: {error}\n')
    print(json.dumps({'output': str(args.output.resolve()), 'status': result['status']}))


if __name__ == '__main__':
    main()
