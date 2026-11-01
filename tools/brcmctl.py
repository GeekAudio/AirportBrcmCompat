#!/usr/bin/env python3
"""Offline Broadcom package/configuration tools; operates on supplied copies."""
import argparse
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import sys
import zipfile

CORE='org.geekaudio.AirportBrcmCompat'
PROVIDER='org.geekaudio.IOLegacyWFamilyKC'
LEGACY='com.apple.iokit.IO80211FamilyLegacy'
NIC='com.apple.driver.AirPort.BrcmNIC'
REQUIRED=(CORE,PROVIDER,LEGACY,NIC)
sha=lambda value:hashlib.sha256(value).hexdigest()


def load_plist(path):
    data=Path(path).read_bytes()
    if len(data)>8*1024*1024:raise ValueError('Plist exceeds size limit')
    value=plistlib.loads(data)
    if not isinstance(value,dict):raise ValueError('Plist root must be a dictionary')
    return value


def version(value):
    if not isinstance(value,str) or not re.fullmatch(r'\d+(?:\.\d+){0,2}',value):
        raise ValueError('Darwin versions must contain one to three numeric components')
    parts=tuple(map(int,value.split('.')))
    return parts+(0,)*(3-len(parts))


def applies(entry,target):
    if not entry.get('Enabled',False):return False
    if entry.get('Arch','Any') not in ('Any','x86_64',''):return False
    return (not entry.get('MinKernel') or target>=version(entry['MinKernel'])) and (
        not entry.get('MaxKernel') or target<=version(entry['MaxKernel']))


def contained(base,name):
    path=PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError('Unsafe relative kext path')
    base=Path(base).resolve();result=base.joinpath(*path.parts)
    if not result.resolve().is_relative_to(base):raise ValueError('Kext path escapes its directory')
    return result


def configure(config,fragment):
    result=copy.deepcopy(config);kernel=result.setdefault('Kernel',{})
    patch=fragment.get('Kernel',{})
    if set(patch)-{'Add','Block','Quirks'}:raise ValueError('Unexpected fragment section')
    adds=kernel.get('Add',[]);incoming=patch.get('Add',[])
    for entries in (adds,incoming):
        names=[item.get('BundlePath') for item in entries]
        if not all(names) or len(names)!=len(set(names)):raise ValueError('Duplicate or missing BundlePath')
    paths={item['BundlePath'] for item in incoming}
    # Existing unrelated entries keep their order. The matched group follows
    # the fragment's dependency order after any preexisting runtime framework.
    kernel['Add']=[entry for entry in adds if entry['BundlePath'] not in paths]+copy.deepcopy(incoming)
    blocks=kernel.setdefault('Block',[])
    for item in patch.get('Block',[]):
        key=lambda entry:tuple(entry.get(name,'') for name in ('Identifier','MinKernel','MaxKernel'))
        blocks[:]=[entry for entry in blocks if key(entry)!=key(item)]
        blocks.append(copy.deepcopy(item))
    kernel.setdefault('Quirks',{}).update(copy.deepcopy(patch.get('Quirks',{})))
    return result


def preflight(oc_dir,darwin):
    oc=Path(oc_dir);config=load_plist(oc/'config.plist');target=version(darwin)
    errors=[];components=[];ids={};kernel=config.get('Kernel',{})
    for index,entry in enumerate(kernel.get('Add',[])):
        if not applies(entry,target):continue
        name=entry.get('BundlePath','')
        try:
            bundle=contained(oc/'Kexts',name)
            info=load_plist(contained(bundle,entry.get('PlistPath','Contents/Info.plist')))
            executable=entry.get('ExecutablePath','')
            if info.get('CFBundleExecutable') and not executable:raise ValueError('ExecutablePath is missing')
            if executable and not contained(bundle,executable).is_file():raise ValueError('Executable is missing')
            identifier=info.get('CFBundleIdentifier')
            if not isinstance(identifier,str):raise ValueError('Bundle identifier is missing')
            item={'bundle':name,'identifier':identifier,'version':info.get('CFBundleVersion',''),
                  'index':index,'libraries':info.get('OSBundleLibraries',{})}
            if executable:item['executable_sha256']=sha(contained(bundle,executable).read_bytes())
            components.append(item);ids.setdefault(identifier,[]).append(item)
        except (OSError,ValueError,plistlib.InvalidFileException) as error:
            errors.append(name+': '+str(error))
    for identifier in REQUIRED:
        if len(ids.get(identifier,[]))!=1:errors.append('Expected one active component: '+identifier)
    for component in components:
        if component['identifier'] not in REQUIRED:continue
        for dependency in component['libraries']:
            if dependency in ids:
                if len(ids[dependency])!=1 or ids[dependency][0]['index']>=component['index']:
                    errors.append('Dependency must load first: '+dependency+' -> '+component['identifier'])
            elif dependency in REQUIRED or not dependency.startswith(
                    ('com.apple.kpi.','com.apple.iokit.','com.apple.driver.')):
                errors.append('Missing EFI dependency: '+dependency)
    blocks=[entry for entry in kernel.get('Block',[]) if applies(entry,target)]
    if any(entry.get('Identifier')=='com.apple.iokit.IOSkywalkFamily' for entry in blocks):
        errors.append('Native IOSkywalkFamily is blocked')
    if not any(entry.get('Identifier')=='com.apple.iokit.IO80211Family' and
               entry.get('Strategy')=='Exclude' for entry in blocks):
        errors.append('Expected IO80211Family Exclude block')
    if kernel.get('Quirks',{}).get('DisableLinkeditJettison') is not True:
        errors.append('DisableLinkeditJettison must be enabled')
    # The collection deliberately omits NVRAM, SMBIOS, network names/addresses
    # and raw config contents. Hashes and driver metadata are sufficient here.
    return {'schema':1,'scope':'offline EFI file and configuration checks','darwin':darwin,
            'config_sha256':sha((oc/'config.plist').read_bytes()),'components':components,
            'errors':errors,'passed':not errors}


def probe(archive,expected_sha=None):
    data=Path(archive).read_bytes()
    if len(data)>20*1024*1024:raise ValueError('Core ZIP exceeds size limit')
    digest=sha(data)
    if expected_sha and digest!=expected_sha.lower():raise ValueError('Core ZIP SHA-256 mismatch')
    with zipfile.ZipFile(archive) as package:
        names=package.namelist()
        if len(names)!=len(set(names)):raise ValueError('Duplicate ZIP members')
        manifest=json.loads(package.read('build-manifest.json'))
        files={**manifest['files'],**manifest.get('distribution_files',{})}
        if not files:raise ValueError('Empty build manifest')
        for name,expected in files.items():
            member=package.getinfo(name)
            if member.file_size>20*1024*1024 or sha(package.read(name))!=expected:
                raise ValueError('Manifest hash mismatch: '+name)
    return {'schema':1,'scope':'offline core archive integrity','archive_sha256':digest,
            'version':manifest['version'],'flavor':manifest['build_flavor'],
            'files_verified':len(files),'expected_sha256_checked':bool(expected_sha),'passed':True}


def write_new(path,data):
    path=Path(path)
    with path.open('xb') as output:output.write(data)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    merge=sub.add_parser('configure',help='Merge a fragment into a new config copy')
    for name in ('config','fragment','output'):merge.add_argument('--'+name,type=Path,required=True)
    for command in ('preflight','collect'):
        cli=sub.add_parser(command,help='Check an EFI copy'+(' and save a privacy-filtered summary' if command=='collect' else ''))
        cli.add_argument('--oc-dir',type=Path,required=True);cli.add_argument('--darwin',required=True)
        if command=='collect':cli.add_argument('--output',type=Path,required=True)
    check=sub.add_parser('probe',help='Check a core ZIP against its manifest and optional published hash')
    check.add_argument('--core',type=Path,required=True);check.add_argument('--sha256')
    args=parser.parse_args(argv)
    try:
        if args.command=='configure':
            result=configure(load_plist(args.config),load_plist(args.fragment))
            write_new(args.output,plistlib.dumps(result,sort_keys=False))
            print(json.dumps({'output':str(args.output),'source_modified':False}));return 0
        result=probe(args.core,args.sha256) if args.command=='probe' else preflight(args.oc_dir,args.darwin)
        payload=(json.dumps(result,indent=2)+'\n').encode()
        if args.command=='collect':write_new(args.output,payload)
        print(payload.decode(),end='');return 0 if result['passed'] else 1
    except (OSError,ValueError,KeyError,TypeError,plistlib.InvalidFileException,zipfile.BadZipFile) as error:
        print('brcmctl: '+str(error),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
