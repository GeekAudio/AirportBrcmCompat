#!/usr/bin/env python3
"""Create a complete, versioned distribution from validated offline inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import struct
import subprocess
import tempfile
import zipfile

from brcmctl import probe
from release_inventory import inventory, lineage

ROOT=Path(__file__).resolve().parents[1]
sha=lambda data:hashlib.sha256(data).hexdigest()


def release_filenames(version):
    # GitHub renders the asset list in filename order.
    return {'RELEASE':f'01-AirportBrcmCompat-{version}-RELEASE.zip',
            'DEBUG':f'02-AirportBrcmCompat-{version}-DEBUG.zip',
            'checksums':'metadata/SHA256SUMS.txt',
            'validation':'metadata/VALIDATION.json',
            'licenses':'metadata/LICENSES.md'}


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


def flat_additional_cards(files):
    """Keep upstream functionality while removing the nested bundle layout."""
    source='AirportBrcmFixup.kext/Contents/PlugIns/AirPortBrcmNIC_Injector.kext/'
    result={}
    for name,data in files.items():
        if name.startswith(source):
            result['Kexts/AirPortBrcmNIC_Injector.kext/'+name[len(source):]]=data
        elif name.startswith('AirportBrcmFixup.kext/'):
            if '/PlugIns/' in name:raise ValueError('Unexpected additional-card plugin')
            result['Kexts/'+name]=data
    # Removing an embedded resource changes the parent's resource envelope.
    # Re-sign only that envelope and confirm every executable section is intact.
    from prepare_broadcom_injector import _check_executable_sections
    binary='Kexts/AirportBrcmFixup.kext/Contents/MacOS/AirportBrcmFixup'
    original=result[binary]
    with tempfile.TemporaryDirectory(prefix='brcm-flat-fixup-') as temporary:
        root=Path(temporary)
        for name,data in result.items():
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            if '/Contents/MacOS/' in name:path.chmod(0o755)
        subprocess.run(['codesign','--force','--sign','-','--timestamp=none',
                        str(root/'Kexts/AirportBrcmFixup.kext')],check=True,capture_output=True)
        result={p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*') if p.is_file()}
    _check_executable_sections(original,result[binary])
    return result


def runtime_files(path):
    from verify_lilu_release_compatibility import RELEASES
    spec=RELEASES['1.7.2']
    if sha(path.read_bytes())!=spec['asset_sha256']:
        raise ValueError('Runtime library archive does not match its pinned release')
    source=read_files(path)
    selected=installation_files(source,('Lilu.kext',))
    from prepare_broadcom_injector import _check_executable_sections
    binary='Lilu.kext/Contents/MacOS/Lilu'
    fat=selected[binary]
    # The pinned universal upstream image includes an obsolete i386 slice
    # which current codesign cannot sign. Preserve its x86_64 slice exactly.
    if fat[:4]!=bytes.fromhex('cafebabe'):raise ValueError('Unexpected runtime Mach-O container')
    count=struct.unpack_from('>I',fat,4)[0]
    if count>16 or 8+20*count>len(fat):raise ValueError('Invalid runtime architecture table')
    slices=[]
    for index in range(count):
        cpu,subcpu,offset,size,align=struct.unpack_from('>5I',fat,8+20*index)
        if offset>len(fat) or size>len(fat)-offset:raise ValueError('Invalid runtime slice bounds')
        if cpu==0x1000007:slices.append(fat[offset:offset+size])
    if len(slices)!=1:raise ValueError('Expected one x86_64 runtime slice')
    original=selected[binary]=slices[0]
    info_path='Lilu.kext/Contents/Info.plist'
    info=plistlib.loads(selected[info_path])
    info['OSBundleLibraries']=info.pop('OSBundleLibraries_x86_64')
    selected[info_path]=plistlib.dumps(info,sort_keys=False)
    with tempfile.TemporaryDirectory(prefix='brcm-runtime-') as temporary:
        root=Path(temporary)
        for name,data in selected.items():
            target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
            if '/Contents/MacOS/' in name:target.chmod(0o755)
        subprocess.run(['codesign','--force','--sign','-','--timestamp=none',str(root/'Lilu.kext')],
                       check=True,capture_output=True)
        selected={p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*') if p.is_file()}
    _check_executable_sections(original,selected[binary])
    return {'Kexts/'+name:data for name,data in selected.items()}


def install_configuration(files,flavor):
    """One dependency order and one version range for every supported OS."""
    order=('Lilu','AirportBrcmCompat','AirportBrcmFixup','IOLegacyWFamily',
           'IO80211FamilyLegacy','AirPortBrcmNIC_Injector','AirPortBrcmNIC')
    adds=[];identifiers=set()
    for name in order:
        bundle=name+'.kext'
        info=plistlib.loads(files['Kexts/'+bundle+'/Contents/Info.plist'])
        identifier=info['CFBundleIdentifier']
        if identifier in identifiers:raise ValueError('Duplicate installation bundle identifier')
        identifiers.add(identifier)
        executable=info.get('CFBundleExecutable')
        adds.append({'Arch':'x86_64','BundlePath':bundle,'Comment':name,'Enabled':True,
                     'ExecutablePath':'Contents/MacOS/'+executable if executable else '',
                     'PlistPath':'Contents/Info.plist','MinKernel':'23.0.0','MaxKernel':''})
    result={'Kernel':{'Add':adds,'Block':[{
        'Arch':'x86_64','Comment':'Wireless compatibility','Enabled':True,
        'Identifier':'com.apple.iokit.IO80211Family','MinKernel':'23.0.0',
        'MaxKernel':'','Strategy':'Exclude'}], 'Quirks':{'DisableLinkeditJettison':True}}}
    return result


def validate_installation(files):
    if any('/PlugIns/' in name for name in files):
        raise ValueError('Unified distribution must not contain embedded kexts')
    if any('AirPortBrcmNIC-' in name for name in files):
        raise ValueError('OS-specific NIC variants are forbidden in the installation set')
    from brcmctl import preflight
    with tempfile.TemporaryDirectory(prefix='brcm-install-check-') as temporary:
        root=Path(temporary)
        for name,data in files.items():
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        for darwin in ('23.0.0','23.99.99','24.0.0','24.99.99','25.0.0','25.99.99','26.0.0','99.0.0'):
            report=preflight(root,darwin)
            if not report['passed']:raise ValueError('Unified configuration failed: '+str(report['errors']))
    verify_signatures(files)


def package(args):
    version=json.loads((ROOT/'release-metadata.json').read_text())['version']
    names=release_filenames(version)
    result=test_result(args.test_log.read_text())
    expected=json.loads((ROOT/'release-metadata.json').read_text())['checks']['offline_tests_passed']
    if result['passed']!=expected:raise ValueError('Test count differs from the source validation record')
    if args.output.exists():raise ValueError('Use a new distribution directory')
    cores=[];core_manifests={};core_sources={}
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
        core_sources[flavor]={'manifest':manifest,'archive_sha256':sha(path.read_bytes()),
            'manifest_sha256':sha(files['build-manifest.json']),
            'binary':payload['AirportBrcmCompat.kext/Contents/MacOS/AirportBrcmCompat']}
    files=read_files(args.dependencies);manifest=json.loads(files['manifest.json'])
    from unify_wifi_dependencies import unify
    with tempfile.TemporaryDirectory(prefix='brcm-dependency-recheck-') as temporary:
        reference=Path(temporary)/'reference.zip'
        fixtures=ROOT/'build/compatibility-profiles'
        expected=unify(fixtures/'sonoma14-dependencies.zip',fixtures/'sequoia15-dependencies.zip',
                       fixtures/'tahoe26-dependencies.zip',reference)
        if manifest!=expected or files!=read_files(reference):
            raise ValueError('Unified dependency artifact differs from freshly verified pinned inputs')
    for name,digest in manifest['kext_member_sha256'].items():
        if sha(files[name])!=digest:raise ValueError('Dependency member hash mismatch')
    if manifest.get('layout')!='flat-unified-wifi' or manifest.get('nic_variants')!=1:
        raise ValueError('Expected one unified dependency set')
    files=installation_files(files,tuple('Kexts/'+name+'.kext' for name in
        ('IOLegacyWFamily','IO80211FamilyLegacy','AirPortBrcmNIC')))
    verify_signatures(files)
    optional=read_files(args.additional_cards);optional_manifest=json.loads(optional['manifest.json'])
    for name,digest in optional_manifest['files_sha256'].items():
        if sha(optional[name])!=digest:raise ValueError('Optional component hash mismatch')
    if len(optional_manifest['injector_match_pci_ids'])!=6 or len(optional_manifest['additional_pci_ids'])!=3:
        raise ValueError('Optional matching exceeds the modern NIC scope')
    optional=installation_files(optional,('AirportBrcmFixup.kext',),('config.additional-cards.plist',))
    verify_signatures(optional)
    common={**files,**flat_additional_cards(optional),**runtime_files(args.runtime)}
    completed=[]
    for flavor,(name,core) in zip(('RELEASE','DEBUG'),cores):
        payload={**common,**{'Kexts/'+key:data for key,data in core.items()}}
        payload['config.plist']=plistlib.dumps(install_configuration(payload,flavor),sort_keys=False)
        validate_installation(payload)
        completed.append((name,payload))
    # Complete all input checks before creating the published artifact set.
    args.output.mkdir(parents=True)
    for name,data in completed:write_zip(args.output/name,data)
    (args.output/'metadata').mkdir()
    # These records are published in source/Release text, not additional assets.
    notices=[ROOT/'NOTICE.md',ROOT/'LICENSE',*sorted((ROOT/'LICENSES').glob('*.txt'))]
    (args.output/names['licenses']).write_text('# Distribution notices and licenses\n\n'+
        '\n\n'.join('## '+str(path.relative_to(ROOT))+'\n\n'+path.read_text() for path in notices)+'\n')
    commit=os.environ.get('GITHUB_SHA') or subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    actual_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if commit!=actual_commit:raise ValueError('Packaging commit differs from the checked-out source')
    tag=json.loads((ROOT/'release-metadata.json').read_text())['release_tag']
    validation={'schema':2,'version':version,'source_commit':commit,'source_commit_role':'repackaging',
                'lineage':lineage(ROOT,tag,core_sources,commit),'scope':'offline','tests':result,
                'fixture_lock_sha256':sha((ROOT/'tests/fixtures.lock.json').read_bytes()),
                'source_checksum_manifest_sha256':sha((ROOT/'SHA256SUMS.txt').read_bytes()),
                'packaging':'Two complete ZIPs; flat common kext set and one configuration fragment',
                'layout':'flat-unified-wifi','runtime_validated':False,
                'input_manifests':{'cores':core_manifests,'dependencies':manifest,'additional_cards':optional_manifest},
                'artifacts':{p.name:{'sha256':sha(p.read_bytes()),'bytes':p.stat().st_size,**inventory(read_files(p))}
                             for p in sorted(args.output.glob('*.zip'))}}
    (args.output/names['validation']).write_text(json.dumps(validation,indent=2)+'\n')
    (args.output/names['checksums']).write_text(''.join(sha(p.read_bytes())+'  '+p.relative_to(args.output).as_posix()+'\n'
        for p in sorted(args.output.rglob('*')) if p.is_file() and p!=args.output/names['checksums']))
    return validation


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('release-core','debug-core','dependencies','additional-cards','runtime','test-log','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();result=package(args)
    print(json.dumps({'output':str(args.output),'source_commit':result['source_commit'],'artifacts':len(result['artifacts'])}))


if __name__=='__main__':main()
