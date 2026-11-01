"""Read-only checks for a supplied Intel kernel collection, without OS allowlists.

The result covers the host-side contracts of the public-KPI fallback only.
Loader bindings, wireless-image pins, requests and hardware remain live gates.
"""
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

import verify_ifnet_kernel_contracts as macho

ROOT=Path(__file__).resolve().parents[1]
MAX_COLLECTION=1024*1024*1024
MAX_MAPPED_IMAGE=64*1024*1024
NETWORK_ID='com.apple.iokit.IONetworkingFamily'
NETWORK_SYMBOLS=(
    '__ZN18IONetworkInterface15initIfnetParamsEP17ifnet_init_params',
    '__ZN18IONetworkInterface8if_ioctlEP7__ifnetmPv',
    '__ZN18IONetworkInterface9if_outputEP7__ifnetP6__mbuf',
    '__ZN18IONetworkInterface14if_set_bpf_tapEP7__ifnetjPFiS1_P6__mbufE',
    '__ZN18IONetworkInterface9if_detachEP7__ifnet',
)
KERNEL_SYMBOLS={'__mh_execute_header','_version','_osrelease','_ifnet_ioctl',
                '_ifnet_softc','__ZNK9IOService10isInactiveEv'}
SOURCES=('src/private_mac_compat/ifnet_kpi_contract.hpp',
         'src/private_mac_compat/network_callback_contract.hpp',
         'tools/upgrade_contract_probe.cpp','tools/upgrade_check.py')


def network_image(data):
    outer=macho.parse_header(data,0,'BootKC')
    entries=[macho.parse_fileset_entry(raw) for kind,raw,_ in outer['commands']
             if kind==macho.LC_FILESET_ENTRY]
    matches=[entry for entry in entries if entry['id']==NETWORK_ID]
    if len(matches)!=1:
        raise ValueError('Expected exactly one IONetworkingFamily fileset member')
    entry=matches[0];header=macho.parse_header(data,entry['fileoff'],NETWORK_ID)
    if header['filetype']!=11:raise ValueError('IONetworkingFamily must be MH_KEXT_BUNDLE')
    segments=[];sections=[];symtab=None;uuid=None
    for kind,raw,_ in header['commands']:
        if kind==macho.LC_SEGMENT_64:
            segment,parts=macho.parse_segment(raw,NETWORK_ID)
            if segment['filesize']>segment['vmsize']:
                raise ValueError('Networking segment file size exceeds virtual size')
            macho.checked_slice(data,segment['fileoff'],segment['filesize'],NETWORK_ID)
            segments.append(segment);sections.extend(parts)
        elif kind==macho.LC_SYMTAB:
            if len(raw)!=24 or symtab is not None:raise ValueError('Invalid networking symbol table')
            symoff,nsyms,stroff,strsize=struct.unpack_from('<IIII',raw,8)
            if nsyms>1_000_000 or strsize>64*1024*1024:
                raise ValueError('Networking symbol table exceeds limits')
            symtab=dict(symoff=symoff,nsyms=nsyms,stroff=stroff,strsize=strsize)
        elif kind==macho.LC_UUID:
            if len(raw)!=24 or uuid is not None or not any(raw[8:24]):
                raise ValueError('Invalid networking UUID')
            uuid=raw[8:24].hex()
    if symtab is None or uuid is None:raise ValueError('Missing networking symbols or UUID')
    image={'header_offset':entry['fileoff'],'fileset_entry':entry,'symtab':symtab,
           'segments':segments,'sections':sections,'uuid':uuid}
    symbols,_=macho.parse_symbols(data,image,set(NETWORK_SYMBOLS),NETWORK_ID)
    if set(symbols)!=set(NETWORK_SYMBOLS):raise ValueError('Missing networking callback symbols')
    base=entry['vmaddr'];header_size=32+header['sizeofcmds']
    headers=[segment for segment in segments if segment['name']=='__TEXT' and
             segment['vmaddr']==base and segment['fileoff']==entry['fileoff'] and
             segment['filesize']>=header_size and segment['initprot']&1]
    if len(headers)!=1:raise ValueError('Networking header mapping is ambiguous')
    spans=[];size=0
    for segment in segments:
        if not segment['vmsize']:continue
        offset=segment['vmaddr']-base;end=offset+segment['vmsize']
        if offset<0 or end>MAX_MAPPED_IMAGE:
            raise ValueError('Networking virtual mapping exceeds limits')
        if any(offset<right and left<end for left,right in spans):
            raise ValueError('Overlapping networking virtual segments')
        spans.append((offset,end));size=max(size,end)
    mapped=bytearray(size)
    for segment in segments:
        if not segment['filesize']:continue
        offset=segment['vmaddr']-base
        mapped[offset:offset+segment['filesize']]=macho.checked_slice(
            data,segment['fileoff'],segment['filesize'],NETWORK_ID)
    if mapped[:header_size]!=data[entry['fileoff']:entry['fileoff']+header_size]:
        raise ValueError('Networking mapped header differs from member header')
    return image,symbols,bytes(mapped)


def kernel_release(data,image,symbols):
    raw=macho.read_vm_range(data,image,symbols['_version'],256,False,'kernel version')
    value=raw.split(b'\0',1)[0]
    match=re.match(rb'Darwin Kernel Version (\d+\.\d+\.\d+):',value)
    if not match:raise ValueError('Cannot read actual Darwin version from the kernel symbol')
    release=match[1].decode('ascii')
    if '_osrelease' in symbols:
        other=macho.read_vm_range(data,image,symbols['_osrelease'],32,False,'osrelease')
        if other.split(b'\0',1)[0]!=match[1]:raise ValueError('Kernel version symbols disagree')
    return release


def read_sample(path,target):
    path=Path(path)
    with path.open('rb') as stream:
        size=os.fstat(stream.fileno()).st_size
        if not 32<=size<=MAX_COLLECTION:raise ValueError('Kernel collection size is outside limits')
        with mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as data:
            digest=hashlib.sha256(data).hexdigest()
            outer,kernel=macho.parse_bootkc(data,'target')
            if not any(kernel['uuid_bytes']) or not any(bytes.fromhex(outer['uuid'])):
                raise ValueError('Kernel collection UUID is zero')
            kernel['fileset_entry']=outer['kernel_entry']
            symbols,_=macho.parse_symbols(data,kernel,KERNEL_SYMBOLS,'kernel')
            required=KERNEL_SYMBOLS-{'_osrelease'}
            if not required.issubset(symbols):raise ValueError('Required kernel symbols are missing')
            if symbols['__mh_execute_header']!=outer['kernel_entry']['vmaddr']:
                raise ValueError('Kernel symbol and fileset header mapping differ')
            actual=kernel_release(data,kernel,symbols)
            if tuple(map(int,actual.split('.')))!=target:
                raise ValueError('Sample Darwin '+actual+' does not match requested target')
            prefix=macho.read_vm_range(data,kernel,symbols['_ifnet_ioctl'],48,True,'public ioctl')
            for name in ('_ifnet_softc','__ZNK9IOService10isInactiveEv'):
                macho.read_vm_range(data,kernel,symbols[name],1,True,name)
            network,callbacks,mapped=network_image(data)
            args=[network['fileset_entry']['vmaddr'],callbacks[NETWORK_SYMBOLS[0]],
                  callbacks[NETWORK_SYMBOLS[1]],symbols['_ifnet_softc'],
                  symbols['__ZNK9IOService10isInactiveEv'],
                  *[callbacks[name] for name in NETWORK_SYMBOLS[2:]]]
            return {'collection_sha256':digest,'collection_bytes':size,
                    'architecture':'x86_64','actual_darwin':actual,
                    'kernel_uuid':kernel['uuid'],'networking_uuid':network['uuid']},prefix,mapped,args


def run_probe(prefix,mapped,args):
    compiler=shutil.which('clang++')
    if not compiler:raise ValueError('clang++ is required for production contract checks')
    with tempfile.TemporaryDirectory(prefix='brcm-upgrade-contract-') as temporary:
        root=Path(temporary);public=root/'prefix';network=root/'network';binary=root/'probe'
        public.write_bytes(prefix);network.write_bytes(mapped)
        built=subprocess.run([compiler,'-std=c++14','-Wall','-Wextra','-Werror',
                              '-I',str(ROOT),str(ROOT/SOURCES[2]),'-o',str(binary)],
                             capture_output=True,text=True,timeout=60)
        if built.returncode:raise ValueError('Contract probe compilation failed: '+built.stderr)
        result=subprocess.run([str(binary),str(public),str(network),*[format(n,'x') for n in args]],
                              capture_output=True,text=True,timeout=10)
        if result.returncode:raise ValueError('Contract probe could not inspect the supplied bytes')
        return json.loads(result.stdout)


def assess(configuration,target,kernel_collection=None):
    result={'schema':1,'scope':'offline upgrade preparation; host public-KPI fallback contracts only',
            'configuration':configuration,'target_darwin':'.'.join(map(str,target)),
            'sample_status':'not_supplied','sample':None,'host_contracts':None,
            'runtime_validated':False,'ready_for_hardware_test':False,'passed':False,
            'core_contract_binding':'helpers from this checkout; installed core equivalence not established',
            'remaining_live_gates':['loader-bound public KPI imports','wireless image and vtable pins',
                                    'request and event formats','boot and card binding','association and traffic',
                                    'private address','bidirectional AirDrop','sleep and wake'],
            'production_sources':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
                                  for name in SOURCES},'errors':[]}
    if target<(23,0,0):result['errors'].append('Minimum target is Darwin 23')
    if not configuration['passed']:result['errors'].append('EFI file/configuration checks failed')
    if kernel_collection is None:
        result['errors'].append('Target Intel BootKC sample is required; configuration alone is insufficient')
        return result
    try:
        sample,prefix,mapped,args=read_sample(kernel_collection,target)
        result['sample']=sample
        result['host_contracts']=run_probe(prefix,mapped,args)
        result['sample_status']='host_contracts_passed' if result['host_contracts']['passed'] else 'host_contracts_rejected'
        if not result['host_contracts']['passed']:
            result['errors'].append('Public-KPI fallback contracts rejected; other routes were not evaluated')
    except (OSError,ValueError,macho.VerificationError,struct.error,subprocess.TimeoutExpired) as error:
        result['sample_status']='rejected';result['errors'].append(str(error))
    result['passed']=not result['errors']
    result['ready_for_hardware_test']=result['passed']
    return result
