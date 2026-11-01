#!/usr/bin/env python3
"""Create a complete, versioned distribution from validated offline inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import zipfile

from brcmctl import probe

ROOT=Path(__file__).resolve().parents[1]
sha=lambda data:hashlib.sha256(data).hexdigest()


def release_filenames(version):
    # GitHub renders the asset list in filename order.
    return {'RELEASE':f'01-AirportBrcmCompat-{version}-RELEASE.zip',
            'dependencies':f'02-AirportBrcmCompat-{version}-WiFi-Pack.zip',
            'additional_cards':f'03-AirportBrcmCompat-{version}-BCM43225-BCM4352.zip',
            'DEBUG':f'04-AirportBrcmCompat-{version}-DEBUG.zip',
            'checksums':'05-SHA256SUMS.txt',
            'validation':'06-VALIDATION.json',
            'licenses':'07-LICENSES.md'}


def read_files(path):
    files={};total=0
    with zipfile.ZipFile(path) as source:
        names=set()
        for member in source.infolist():
            name=member.filename;relative=PurePosixPath(name)
            if (name in names or relative.is_absolute() or '..' in relative.parts or
                    '\\' in name or (member.external_attr>>16)&0o170000==0o120000):
                raise ValueError('Unsafe or duplicate distribution member')
            names.add(name)
            if member.is_dir():continue
            total+=member.file_size
            if total>40*1024*1024:raise ValueError('Distribution input exceeds size limit')
            files[name]=source.read(member)
    return files


def test_result(data):
    match=re.search(r'Ran (\d+) tests in ([\d.]+)s\s+OK\s*$',data)
    if not match or int(match[1])==0:raise ValueError('A successful zero-skip test log is required')
    return {'passed':int(match[1]),'seconds':float(match[2]),'skipped':0,'log_sha256':sha(data.encode())}


def write_zip(path,files):
    with zipfile.ZipFile(path,'x',zipfile.ZIP_DEFLATED,compresslevel=9) as output:
        for name,data in sorted(files.items()):
            info=zipfile.ZipInfo(name);info.create_system=3;info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=(0o100755 if '/Contents/MacOS/' in name else 0o100644)<<16
            output.writestr(info,data)


def installation_files(files,bundles,fragments=()):
    for bundle in bundles:
        if bundle+'/Contents/Info.plist' not in files:
            raise ValueError('Missing installation bundle: '+bundle)
    if any(name not in files for name in fragments):
        raise ValueError('Missing installation configuration fragment')
    return {name:data for name,data in files.items()
            if name in fragments or any(name.startswith(bundle+'/') for bundle in bundles)}


def verify_signatures(files):
    with tempfile.TemporaryDirectory(prefix='brcm-distribution-',dir='/private/tmp') as temporary:
        root=Path(temporary)
        for name,data in files.items():
            if '.kext/' not in name:continue
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            if '/Contents/MacOS/' in name:path.chmod(0o755)
        for bundle in root.rglob('*.kext'):
            subprocess.run(['codesign','--verify','--strict',str(bundle)],check=True,capture_output=True)


def package(args):
    version=json.loads((ROOT/'release-metadata.json').read_text())['version']
    names=release_filenames(version)
    result=test_result(args.test_log.read_text())
    expected=json.loads((ROOT/'release-metadata.json').read_text())['checks']['offline_tests_passed']
    if result['passed']!=expected:raise ValueError('Test count differs from the source validation record')
    if args.output.exists():raise ValueError('Use a new distribution directory')
    cores=[];core_manifests={}
    for flavor,path in [('RELEASE',args.release_core),('DEBUG',args.debug_core)]:
        probe(path);files=read_files(path);manifest=json.loads(files['build-manifest.json'])
        if (manifest['version']!=version or manifest['build_flavor']!=flavor or
                not manifest.get('release_ready') or manifest.get('channel')!='release'):
            raise ValueError('Expected a matching release core')
        for name,digest in manifest['sources'].items():
            relative=PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts or sha((ROOT/name).read_bytes())!=digest:
                raise ValueError('Core source hash mismatch')
        payload=installation_files(files,('AirportBrcmCompat.kext',))
        verify_signatures(payload)
        cores.append((names[flavor],payload))
        core_manifests[flavor]=manifest
    files=read_files(args.dependencies);manifest=json.loads(files['manifest.json'])
    for name,digest in manifest['kext_member_sha256'].items():
        if sha(files[name])!=digest:raise ValueError('Dependency member hash mismatch')
    for flavor in ('RELEASE','DEBUG'):
        name=f'Examples/config-WiFi-{flavor}.example.plist'
        files[name]=(ROOT/name).read_bytes()
    files=installation_files(files,tuple('Kexts/'+name+'.kext' for name in
        ('IOLegacyWFamily','IO80211FamilyLegacy','AirPortBrcmNIC-Sonoma-Sequoia','AirPortBrcmNIC-Tahoe')),
        tuple(f'Examples/config-WiFi-{flavor}.example.plist' for flavor in ('RELEASE','DEBUG')))
    verify_signatures(files)
    optional=read_files(args.additional_cards);optional_manifest=json.loads(optional['manifest.json'])
    for name,digest in optional_manifest['files_sha256'].items():
        if sha(optional[name])!=digest:raise ValueError('Optional component hash mismatch')
    if len(optional_manifest['injector_match_pci_ids'])!=6 or len(optional_manifest['additional_pci_ids'])!=3:
        raise ValueError('Optional matching exceeds the modern NIC scope')
    optional=installation_files(optional,('AirportBrcmFixup.kext',),('config.additional-cards.plist',))
    verify_signatures(optional)
    # Complete all input checks before creating the published artifact set.
    args.output.mkdir(parents=True)
    for name,data in cores:write_zip(args.output/name,data)
    write_zip(args.output/names['dependencies'],files)
    write_zip(args.output/names['additional_cards'],optional)
    # Binary redistribution notices accompany the downloads as a separate
    # release attachment, keeping installation ZIPs limited to EFI payloads.
    notices=[ROOT/'NOTICE.md',ROOT/'LICENSE',*sorted((ROOT/'LICENSES').glob('*.txt'))]
    (args.output/names['licenses']).write_text('# Distribution notices and licenses\n\n'+
        '\n\n'.join('## '+str(path.relative_to(ROOT))+'\n\n'+path.read_text() for path in notices)+'\n')
    commit=os.environ.get('GITHUB_SHA') or subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    validation={'version':version,'source_commit':commit,'scope':'offline','tests':result,
                'fixture_lock_sha256':sha((ROOT/'tests/fixtures.lock.json').read_bytes()),
                'source_checksum_manifest_sha256':sha((ROOT/'SHA256SUMS.txt').read_bytes()),
                'packaging':'EFI bundles and configuration fragments only',
                'input_manifests':{'cores':core_manifests,'dependencies':manifest,'additional_cards':optional_manifest},
                'artifacts':{p.name:{'sha256':sha(p.read_bytes()),'bytes':p.stat().st_size}
                             for p in sorted(args.output.glob('*.zip'))}}
    (args.output/names['validation']).write_text(json.dumps(validation,indent=2)+'\n')
    (args.output/names['checksums']).write_text(''.join(sha(p.read_bytes())+'  '+p.name+'\n'
        for p in sorted(args.output.iterdir()) if p.is_file() and p.name!=names['checksums']))
    return validation


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('release-core','debug-core','dependencies','additional-cards','test-log','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();result=package(args)
    print(json.dumps({'output':str(args.output),'source_commit':result['source_commit'],'artifacts':len(result['artifacts'])}))


if __name__=='__main__':main()
