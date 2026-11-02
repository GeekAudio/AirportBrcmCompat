#!/usr/bin/env python3
"""Build one flat Wi-Fi dependency set from the three pinned offline inputs.

Historical profiles remain test fixtures, not installation choices. The sole
NIC is the complete DMA-compatible image, never a partly patched live driver.
"""
import argparse
import json
from pathlib import Path
import plistlib
import tempfile
import zipfile

import combine_wifi_dependency_profiles as profiles


def configuration():
    result = profiles._combined_config()
    adds = result['Kernel']['Add']
    result['Kernel']['Add'] = [entry for entry in adds
                              if not entry['BundlePath'].startswith('AirPortBrcmNIC-')]
    result['Kernel']['Add'].append({
        'Arch': 'x86_64', 'BundlePath': 'AirPortBrcmNIC.kext',
        'Comment': 'Broadcom Wi-Fi', 'Enabled': True,
        'ExecutablePath': 'Contents/MacOS/AirPortBrcmNIC',
        'PlistPath': 'Contents/Info.plist', 'MinKernel': '23.0.0', 'MaxKernel': ''})
    return result


def unify(sonoma, sequoia, tahoe, output):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('Use a new output archive')
    # The original validator pins every input member, checks all three sample
    # identities, common-payload equality, import closure and signatures.
    with tempfile.TemporaryDirectory(prefix='brcm-unified-') as temporary:
        stage = Path(temporary)
        combined = stage/'profiles.zip'
        historical = profiles.combine(sonoma, sequoia, tahoe, combined)
        from verify_unified_nic import verify
        nic_check = verify(Path(sonoma), Path(tahoe))
        with zipfile.ZipFile(combined) as archive:
            files = {}
            for name in archive.namelist():
                if not name.startswith('Kexts/') or 'AirPortBrcmNIC-Sonoma-Sequoia.kext/' in name:
                    continue
                target = name.replace('AirPortBrcmNIC-Tahoe.kext/', 'AirPortBrcmNIC.kext/')
                files[target] = archive.read(name)
        bundles = ['IOLegacyWFamily.kext', 'IO80211FamilyLegacy.kext', 'AirPortBrcmNIC.kext']
        profiles._write_tree(stage/'verify', files)
        profiles._verify_staged_signatures(stage/'verify', bundles)
        manifest = {
            'schema': 3, 'layout': 'flat-unified-wifi', 'validation_scope': 'offline',
            'runtime_validated': False, 'minimum_darwin': '23.0.0', 'maximum_darwin': None,
            'bundles': bundles, 'nic_variants': 1,
            'selection': 'One complete DMA-compatible NIC image on every supported system',
            'historical_input_validation': historical, 'unified_nic': nic_check,
            'kext_member_sha256': {name: profiles.sha256(data) for name, data in sorted(files.items())},
        }
        files['config.fragment.plist'] = plistlib.dumps(configuration(), sort_keys=False)
        files['manifest.json'] = (json.dumps(manifest, indent=2)+'\n').encode()
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, 'x', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(files.items()):
                profiles._zip_write(archive, name, data)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('sonoma', 'sequoia', 'tahoe', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    result = unify(args.sonoma, args.sequoia, args.tahoe, args.output)
    print(json.dumps({'output': str(args.output), 'bundles': result['bundles'], 'scope': 'offline'}))


if __name__ == '__main__':
    main()
