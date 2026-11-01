"""Describe installation payloads and check selected downloads against a release inventory."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import struct
import subprocess
import uuid
import zipfile

sha=lambda data:hashlib.sha256(data).hexdigest()


def relative(name):
    path=PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError('Unsafe inventory path')
    return path


def inventory(files):
    members={};bundles=[]
    for name,data in sorted(files.items()):
        relative(name)
        install=None
        if '.kext/' in name:install=name if name.startswith('Kexts/') else 'Kexts/'+name
        members[name]={'sha256':sha(data),'bytes':len(data),'install_path':install,
                       'action':'copy' if install else 'merge_configuration'}
        if name.endswith('.kext/Contents/Info.plist'):
            info=plistlib.loads(data);base=name[:-len('Contents/Info.plist')]
            executable=info.get('CFBundleExecutable')
            bundle={'bundle_path':base.removeprefix('Kexts/').rstrip('/'),
                    'identifier':info['CFBundleIdentifier'],'version':info['CFBundleVersion']}
            if executable:
                path=base+'Contents/MacOS/'+executable
                bundle['executable_sha256']=sha(files[path])
            if info.get('AirportBrcmBuildFlavor'):bundle['build_flavor']=info['AirportBrcmBuildFlavor']
            bundles.append(bundle)
    return {'members':members,'bundles':bundles}


def macho_uuid(data):
    if len(data)<32 or struct.unpack_from('<I',data)[0]!=0xfeedfacf:raise ValueError('Expected a Mach-O 64 core')
    ncmds,command_bytes=struct.unpack_from('<II',data,16);offset=32;end=32+command_bytes;found=[]
    if end>len(data) or ncmds>command_bytes//8:raise ValueError('Invalid Mach-O load commands')
    for _ in range(ncmds):
        if offset+8>end:raise ValueError('Truncated Mach-O load command')
        kind,size=struct.unpack_from('<II',data,offset)
        if size<8 or size>end-offset:raise ValueError('Invalid Mach-O command size')
        if kind==0x1b:
            if size!=24:raise ValueError('Invalid UUID command')
            found.append(str(uuid.UUID(bytes=data[offset+8:offset+24])).upper())
        offset+=size
    if offset!=end or len(found)!=1:raise ValueError('Expected exactly one core UUID')
    return found[0]


def lineage(root,tag,cores,packaging_commit):
    result=subprocess.run(['git','rev-parse','--verify','refs/tags/'+tag+'^{commit}'],cwd=root,
                          text=True,capture_output=True)
    commit=result.stdout.strip() if result.returncode==0 else None
    details={};cache={}
    for flavor,source in cores.items():
        manifest=source['manifest'];mismatches=[]
        for name,digest in manifest['sources'].items():
            relative(name)
            if not commit:continue
            key=(commit,name)
            if key not in cache:
                data=subprocess.run(['git','show',commit+':'+name],cwd=root,capture_output=True)
                cache[key]=sha(data.stdout) if data.returncode==0 else None
            if cache[key]!=digest:mismatches.append(name)
        details[flavor]={'binary_sha256':sha(source['binary']),'macho_uuid':macho_uuid(source['binary']),
                        'input_build_zip_sha256':source['archive_sha256'],
                        'build_manifest_sha256':source['manifest_sha256'],
                        'builder_recorded_source_commit':manifest.get('source_commit'),
                        'source_identity_basis':'per-file SHA-256, not an inferred build time',
                        'source_files_checked':len(manifest['sources']),
                        'source_files_match_tag':None if not commit else not mismatches,
                        'mismatched_source_paths':mismatches}
    return {'release':{'tag':tag,'tag_commit':commit,'tag_resolved':commit is not None},
            'core_builds':details,'repackaging':{'source_commit':packaging_commit,
                'working_tree_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip())}}


def verify(directory,checksums='05-SHA256SUMS.txt',validation='06-VALIDATION.json',assets=None):
    root=Path(directory).resolve()
    def read(name):
        path=root.joinpath(*relative(name).parts)
        if not path.resolve().is_relative_to(root):raise ValueError('Inventory file escapes download directory')
        if path.stat().st_size>40*1024*1024:raise ValueError('Inventory input exceeds size limit')
        return path.read_bytes()
    hashes={}
    for line in read(checksums).decode().splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  (.+)',line)
        if not match or match[2] in hashes:raise ValueError('Invalid or duplicate checksum entry')
        relative(match[2]);hashes[match[2]]=match[1]
    data=read(validation)
    if hashes.get(validation)!=sha(data):raise ValueError('Validation manifest checksum mismatch')
    manifest=json.loads(data);records=manifest['artifacts']
    selected=list(dict.fromkeys(assets)) if assets else [name for name in records if (root/name).is_file()]
    if not selected:raise ValueError('No installation ZIP selected or present')
    verified=[]
    for name in selected:
        if name not in records:raise ValueError('Unknown installation ZIP: '+name)
        record=records[name];data=read(name)
        if len(data)!=record['bytes'] or sha(data)!=record['sha256'] or hashes.get(name)!=sha(data):raise ValueError('Installation ZIP checksum mismatch: '+name)
        with zipfile.ZipFile(io.BytesIO(data)) as package:
            names=package.namelist()
            if len(names)!=len(set(names)) or set(names)!=set(record['members']):raise ValueError('Installation ZIP member list mismatch')
            if sum(m.file_size for m in package.infolist())>40*1024*1024:raise ValueError('Expanded ZIP exceeds size limit')
            for member in names:
                relative(member);payload=package.read(member);expected=record['members'][member]
                if len(payload)!=expected['bytes'] or sha(payload)!=expected['sha256']:raise ValueError('Installation member mismatch: '+member)
            for bundle in record['bundles']:
                if bundle['identifier']=='org.geekaudio.AirportBrcmCompat':
                    core=manifest['lineage']['core_builds'][bundle['build_flavor']]
                    binary=package.read('AirportBrcmCompat.kext/Contents/MacOS/AirportBrcmCompat')
                    if sha(binary)!=core['binary_sha256'] or macho_uuid(binary)!=core['macho_uuid']:
                        raise ValueError('Core build lineage does not match the selected ZIP')
        verified.append({'name':name,'members_checked':len(record['members']),'bundles':record['bundles']})
    return {'schema':1,'scope':'selected download integrity, not author identity or hardware validation',
            'passed':True,'verified':verified,'not_checked':sorted(set(records)-set(selected)),
            'complete_distribution':set(selected)==set(records),'release':manifest['lineage']['release'],
            'core_builds':manifest['lineage']['core_builds'],'repackaging':manifest['lineage']['repackaging']}
