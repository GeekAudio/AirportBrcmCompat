#!/usr/bin/env python3
"""Build a kext package; an unqualified build selects the automatic 1.1.0 candidate. Never install/load it."""
import argparse
import hashlib
import json
import os
import plistlib
import struct
from pathlib import Path
import subprocess
import tempfile
import zipfile

PROJECT=Path(__file__).resolve().parents[1]
SDK_ENV='AIRPORT_BRCM_MAC_KERNEL_SDK'
LILU_ENV='AIRPORT_BRCM_LILU_RESOURCES'
NAME='AirportBrcmCompat'
IDENTIFIER='org.geekaudio.'+NAME
VERSION='1.1.0'
LILU_RUNTIME_MINIMUM='1.7.1'
LIBRARIES={'as.vit9696.Lilu':LILU_RUNTIME_MINIMUM,'com.apple.kpi.bsd':'19.0.0','com.apple.kpi.iokit':'19.0.0',
           'com.apple.kpi.libkern':'19.0.0','com.apple.kpi.mach':'19.0.0',
           'com.apple.kpi.unsupported':'19.0.0','com.apple.iokit.IONetworkingFamily':'3.4'}

def automatic_compatibility_info_metadata(baseline_trace, control_windows):
    return {
        'AirportBrcmDevelopmentStatus':'AutomaticABICandidate-1.1.0',
        'AirportBrcmAutomaticCompatibility':1,
        'AirportBrcmKernelIdentityPolicy':'ABIContractProbesFailClosed',
        'AirportBrcmMinimumDarwinKernelVersion':'25.0.0',
        'AirportBrcmRequestSchemaPolicy':'StrictFailClosed',
        'AirportBrcmStrictRequestSchemas':['scan-multiple-set86-v1','sae-password-carrier-subset-v1'],
        'AirportBrcmBaselineTraceConfigured':1 if baseline_trace else 0,
        'AirportBrcmControlRxWindowsConfigured':1 if control_windows else 0,
    }

def automatic_compatibility_manifest_metadata(baseline_trace, control_windows):
    return {
        'candidate':'AutomaticABICompatibility-1.1.0',
        'purpose':'Automatic kernel ABI-probe compatibility candidate with strict request schemas',
        'compatibility_policy':{
            'kernel_admission':'All required ABI contract probes must pass; an unknown UUID alone never admits compatibility.',
            'probe_policy':'Probe the active kernel contract, then retain independent exact checks for each wireless dependency image.',
            'failure_behavior':'Kernel probe failures prevent compatibility admission; requests outside the strict schemas are not adapted.',
            'minimum_darwin_kernel_version':'25.0.0',
            'request_schema_policy':'strict-fail-closed',
            'strict_request_schemas':['scan-multiple-set86-v1','sae-password-carrier-subset-v1'],
            'wireless_dependency_images':'Existing per-image UUID, layout, instruction and call-target pins remain required.',
        },
        'release_ready':False,
        'runtime_validated':False,
        'minimum_darwin_kernel_version':'25.0.0',
        'baseline_trace_schema':2 if baseline_trace else None,
        'scan_multiple_native_size':0x14e8,
        'scan_multiple_legacy_size':0x14e0,
        'scan_multiple_nonzero_min_timestamp':'refuse',
        'sae_subset':{'selected_upper':4096,'cipher':10,'password_length_min':8,'password_length_max':63,
                      'pmk_length':32,'allowed_auth_masks':[0,4,0x40000004],
                      'selected_auth_preserved':True},
        'control_rx_windows_policy':({'schema':1,'bank_limit':4,'bank_reuse':False,'reset_allowed':False,
                                      'max_seconds':120,'sample_limit':256,'sampling':'per-subtype time-thinned',
                                      'clock':'mach_absolute_time_ns_excludes_sleep','source_alias':'window-keyed SipHash24 six-byte input',
                                      'control_rx_only':True} if control_windows else None),
        'compiled_features':{
            'automatic_kernel_abi_probe_gate':True,
            'wifi_private_mac_bridge':True,
            'native_control_endpoint':True,
            'scan_multiple_set86_adapter':True,
            'sae_password_carrier_subset':True,
            'awdl_event_pipeline_and_routes':True,
            'baseline_control_rx_trace':bool(baseline_trace),
            'control_rx_observation_windows':bool(control_windows),
        },
        'native_empty_query_policy':'Selectors1/5/7 accept a nonnull unused inline input pointer when length is exactly0; pointer is never read. All descriptor/scalar/async/output constraints remain.',
        'native_ool_input_policy':'Borrowed synchronous MIG input descriptor: balanced prepare/complete around one owned snapshot read, outside the old WorkLoop/gate; no descriptor release or retained mapping.',
        'bounded_closing_policy':'Retain at most8 authorized Closing records until reboot; no automatic record removal or late old-table dispatch; subsequent admission may be refused.',
        'linked_inactive_cores':['Strict message55 recovery codec: no proven observer source'],
        'validation_scope':'offline'
    }

def apply_automatic_compatibility_manifest(base, baseline_trace, control_windows):
    """Replace stale historical summary fields with the compiled 1.1.0 feature set."""
    base.update(automatic_compatibility_manifest_metadata(baseline_trace,control_windows))
    base['ready_for_install']=False
    for key in ('awdl_backend_active','native_control_runtime_validated','native_control_only',
                'active_behavior','remaining','colocated_scope_policy','association_policy_survey',
                'dhcp_device_type_policy','original_driver_dependencies'):
        base.pop(key,None)
    return base

def validate_automatic_compatibility_metadata(info, manifest):
    expected_info=automatic_compatibility_info_metadata(
        bool(info.get('AirportBrcmBaselineTraceConfigured')),
        bool(info.get('AirportBrcmControlRxWindowsConfigured')))
    if any(info.get(key)!=value for key,value in expected_info.items()):
        raise ValueError('Automatic compatibility Info.plist policy mismatch')
    if manifest.get('minimum_darwin_kernel_version')!='25.0.0' or \
       manifest.get('runtime_validated') is not False or \
       manifest.get('release_ready') is not False or \
       manifest.get('ready_for_install') is not False:
        raise ValueError('Automatic compatibility cannot claim a wider OS range or runtime validation')
    expected_manifest=automatic_compatibility_manifest_metadata(
        bool(manifest.get('compiled_features',{}).get('baseline_control_rx_trace')),
        bool(manifest.get('compiled_features',{}).get('control_rx_observation_windows')))
    if any(manifest.get(key)!=value for key,value in expected_manifest.items()):
        raise ValueError('Automatic compatibility manifest policy mismatch')
    if ('AirportBrcmSupportedBuilds' in info or 'AirportBrcmKernelProfiles' in info or
        'AirportBrcmMaximumDarwinKernelVersion' in info or
        any(key in manifest for key in ('supported_build','supported_builds','kernel_profiles',
                                        'maximum_darwin_kernel_version'))):
        raise ValueError('Automatic compatibility metadata cannot contain a build allowlist or maximum OS version')
    historical=('awdl_backend_active','native_control_runtime_validated','native_control_only',
                'active_behavior','remaining','colocated_scope_policy','association_policy_survey',
                'dhcp_device_type_policy','original_driver_dependencies')
    if any(key in manifest for key in historical):
        raise ValueError('Automatic compatibility manifest contains a stale historical summary')
    if 'No event capability advertised' in manifest.get('native_empty_query_policy',''):
        raise ValueError('Automatic compatibility manifest contradicts its compiled event features')
    return True

def bundle_info():
    return {'CFBundleDevelopmentRegion':'en','CFBundleExecutable':NAME,'CFBundleIdentifier':IDENTIFIER,
            'CFBundleInfoDictionaryVersion':'6.0','CFBundleName':NAME,'CFBundlePackageType':'KEXT',
            'CFBundleShortVersionString':'1.0' if VERSION=='1.0.0' else VERSION,
            'CFBundleVersion':VERSION,'OSBundleRequired':'Root',
            'OSBundleLibraries':dict(LIBRARIES),'AirportBrcmDevelopmentStatus':'StaticReview-1.1.0',
            'IOKitPersonalities':{IDENTIFIER:{'CFBundleIdentifier':IDENTIFIER,'IOClass':NAME,
                'IOMatchCategory':NAME,'IOProviderClass':'IOResources','IOResourceMatch':'IOKit'}}}

def inspect_linked_metadata(executable):
    """Read the actual x86_64 MH_KEXT_BUNDLE, not a manifest claim or nm count."""
    data=Path(executable).read_bytes()
    if len(data)<32 or struct.unpack_from('<I',data)[0]!=0xfeedfacf:
        raise ValueError('Expected a little-endian 64-bit Mach-O')
    _,cpu,_,filetype,ncmds,cmdbytes,_,_=struct.unpack_from('<8I',data)
    if cpu!=0x01000007 or filetype!=11 or 32+cmdbytes>len(data):
        raise ValueError('Expected a complete x86_64 MH_KEXT_BUNDLE')
    segments=[];symtab=None;offset=32
    for _ in range(ncmds):
        if offset+8>32+cmdbytes:raise ValueError('Truncated Mach-O commands')
        command,size=struct.unpack_from('<II',data,offset)
        if size<8 or offset+size>32+cmdbytes:raise ValueError('Invalid Mach-O command')
        if command==0x19:
            if size<72:raise ValueError('Truncated segment')
            address,_,fileoffset,filesize=struct.unpack_from('<4Q',data,offset+24)
            if fileoffset+filesize>len(data):raise ValueError('Truncated segment data')
            segments.append((address,fileoffset,filesize))
        elif command==2:
            if size<24 or symtab is not None:raise ValueError('Invalid symbol table command')
            symtab=struct.unpack_from('<4I',data,offset+8)
        offset+=size
    if offset!=32+cmdbytes or symtab is None:raise ValueError('Missing Mach-O metadata')
    symoff,count,stroff,strsize=symtab
    if symoff+count*16>len(data) or stroff+strsize>len(data):raise ValueError('Truncated symbol table')
    strings=data[stroff:stroff+strsize];symbols={}
    for index in range(count):
        strindex,kind,section,_,value=struct.unpack_from('<IBBHQ',data,symoff+index*16)
        if kind&0xe0:continue
        if strindex>=len(strings):raise ValueError('Invalid symbol string offset')
        end=strings.find(b'\0',strindex)
        if end<0:raise ValueError('Unterminated symbol')
        name=strings[strindex:end].decode('utf-8')
        if kind&0x0e==0x0e and section: symbols.setdefault(name,[]).append(value)
    def single(name):
        values=symbols.get(name,[])
        if len(values)!=1:raise ValueError('Expected exactly one defined '+name)
        return values[0]
    def at(address,size):
        matches=[data[fo+address-vm:fo+address-vm+size] for vm,fo,fs in segments
                 if vm<=address and address+size<=vm+fs]
        if len(matches)!=1:raise ValueError('Metadata address not uniquely file backed')
        return matches[0]
    def text(raw):
        end=raw.find(b'\0')
        if end<0:raise ValueError('Unterminated kmod string')
        return raw[:end].decode('ascii')
    # mach/kmod.h: kmod_info_64_v1 is pack(4), size196, name@16,
    # version@80, start@180 and stop@188. Not the host Python ABI.
    kmod=at(single('_kmod_info'),196)
    if struct.unpack_from('<I',kmod,8)[0]!=1:raise ValueError('Unsupported kmod_info layout')
    identifier,version=text(kmod[16:80]),text(kmod[80:144])
    start,stop=struct.unpack_from('<QQ',kmod,180)
    if start!=single('_'+NAME+'_kern_start') or stop!=single('_'+NAME+'_kern_stop'):
        raise ValueError('kmod bootstrap pointers disagree with product entry points')
    if struct.unpack('<Q',at(single('__realmain'),8))[0]!=start or \
       struct.unpack('<Q',at(single('__antimain'),8))[0]!=stop:
        raise ValueError('Lilu bootstrap pointers disagree with kmod_info')
    expected={'_'+NAME+'_kern_start','_'+NAME+'_kern_stop'}
    if {s for s in symbols if s.endswith(('_kern_start','_kern_stop'))}!=expected:
        raise ValueError('Multiple or stale product bootstrap entry points')
    single('__ZN'+str(len(NAME))+NAME+'10gMetaClassE')
    single('__ZTV'+str(len(NAME))+NAME)
    if any('SkywalkLegacyCore' in symbol for symbol in symbols):
        raise ValueError('Stale compatibility core namespace remains linked')
    return {'identifier':identifier,'version':version,'kmod_info_count':1,
            'bootstrap':NAME,'observer_class':NAME}

def validate_bundle_metadata(bundle):
    bundle=Path(bundle)
    if bundle.name!=NAME+'.kext':raise ValueError('Unexpected product bundle name')
    info=plistlib.loads((bundle/'Contents/Info.plist').read_bytes())
    expected=bundle_info()
    for key in ['CFBundleExecutable','CFBundleIdentifier','CFBundleName','CFBundlePackageType',
                'CFBundleVersion','CFBundleShortVersionString','OSBundleLibraries','IOKitPersonalities']:
        if info.get(key)!=expected[key]:raise ValueError('Product metadata mismatch: '+key)
    executables=list((bundle/'Contents/MacOS').iterdir())
    if len(executables)!=1 or executables[0].name!=NAME or not executables[0].is_file():
        raise ValueError('Expected exactly one product executable')
    if (bundle/'Contents/PlugIns').exists():raise ValueError('Nested compatibility executables are forbidden')
    actual=inspect_linked_metadata(executables[0])
    if actual['identifier']!=info['CFBundleIdentifier'] or actual['version']!=info['CFBundleVersion']:
        raise ValueError('Compiled kmod identity/version disagrees with Info.plist')
    return actual

def run(arguments):
    r=subprocess.run([str(a) for a in arguments],capture_output=True,text=True,timeout=90)
    if r.returncode:raise RuntimeError(r.stderr.strip() or r.stdout.strip())
    return r.stdout

def resolve_toolchain_paths(args, project=PROJECT, environ=None):
    """Resolve external SDK and Lilu headers without embedding workstation paths."""
    env=os.environ if environ is None else environ
    sdk_value=args.mackernelsdk or env.get(SDK_ENV)
    lilu_value=args.lilu_resources or env.get(LILU_ENV)
    sdk=Path(sdk_value).expanduser() if sdk_value else project/'vendor/MacKernelSDK'
    lilu=Path(lilu_value).expanduser() if lilu_value else project/'vendor/LiluResources'
    sdk=sdk.resolve()
    lilu=lilu.resolve()
    required_sdk=('Headers','Library/universal/libkmod.a',
                  'Library/universal/libkmodc++.a')
    missing=[path for path in required_sdk if not (sdk/path).exists()]
    if missing:
        raise ValueError('MacKernelSDK path is incomplete; missing '+', '.join(missing))
    required_lilu=('Headers/kern_api.hpp','Headers/kern_mach.hpp',
                   'Headers/kern_patcher.hpp','Headers/plugin_start.hpp')
    missing=[path for path in required_lilu if not (lilu/path).is_file()]
    if missing:
        raise ValueError('Lilu Resources path is incomplete; missing '+', '.join(missing))
    return sdk,lilu

def build_parser():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mackernelsdk',type=Path,
                        help=f'MacKernelSDK root (or ${SDK_ENV}; default: vendor/MacKernelSDK)')
    parser.add_argument('--lilu-resources',type=Path,
                        help=f'Lilu headers/resources (or ${LILU_ENV}; default: vendor/LiluResources)')
    parser.add_argument('--event-pipe-components-review',action='store_true',
                        help='Compile/link the real event components for offline review; no event routing or installation')
    parser.add_argument('--event-pipe-routes-review',action='store_true',
                        help='Compile/link experimental routes for offline review; router capability remains disabled')
    parser.add_argument('--automatic-compatibility',action='store_true',
                        help='Build the 1.1.0 candidate with automatic ABI probes, scan-multiple and strict SAE compatibility (the default mode)')
    parser.add_argument('--baseline-trace',action='store_true',
                        help='Include optional schema-2 numeric control-RX trace; requires automatic compatibility mode')
    parser.add_argument('--control-rx-windows',action='store_true',
                        help='Include optional root-armed control-RX windows; requires automatic mode and --baseline-trace')
    parser.add_argument('--build-flavor',choices=('RELEASE','DEBUG'),default='RELEASE',
                        help='Real compiler DEBUG macro for the diagnostic flavor; never installs a build')
    return parser

def configure_build_mode(args):
    """Resolve CLI modes before touching toolchains or building an artifact."""
    review = args.event_pipe_components_review or args.event_pipe_routes_review
    automatic = args.automatic_compatibility
    if not automatic and not review and not args.baseline_trace and not args.control_rx_windows:
        # Keep an unqualified build on the current candidate path. Historical
        # component review modes remain explicit and cannot silently shadow it.
        automatic = True

    if automatic:
        if review:
            raise ValueError('Automatic compatibility is a standalone candidate mode')
        if args.control_rx_windows and not args.baseline_trace:
            raise ValueError('Control RX windows require --baseline-trace')
        args.automatic_compatibility = True
        args.event_pipe_routes_review = True
        args.event_pipe_components_review = True
        return {'mode':'automatic-compatibility','version':'1.1.0','ready_for_install':False}

    if args.baseline_trace or args.control_rx_windows:
        raise ValueError('--baseline-trace and --control-rx-windows require --automatic-compatibility')
    args.event_pipe_components_review = args.event_pipe_components_review or args.event_pipe_routes_review
    return {'mode':'component-review','version':'1.1.0','ready_for_install':False}

def compatibility_compile_defines(args):
    """Return feature macros selected by the resolved candidate mode."""
    defines=[]
    if args.automatic_compatibility:
        defines += ['-DAIRPORT_BRCM_SCAN_MULTIPLE=1','-DAIRPORT_BRCM_SAE_COMPAT=1']
    if args.baseline_trace:
        defines.append('-DAIRPORT_BRCM_BASELINE_TRACE=1')
    if args.control_rx_windows:
        defines.append('-DAIRPORT_BRCM_BASELINE_WINDOW=1')
    return defines

def main():
    global VERSION
    parser=build_parser()
    args=parser.parse_args();output=args.output.absolute()
    try:
        build_mode=configure_build_mode(args)
    except ValueError as error:
        parser.error(str(error))
    VERSION=build_mode['version']
    if output.exists() or output.suffix.lower()!='.zip' or any(
        p in output.parts for p in ('EFI','OC')):
        raise ValueError('Use a new ZIP path outside EFI/OC')
    try:
        SDK,LILU=resolve_toolchain_paths(args)
    except ValueError as error:
        parser.error(str(error))
    source=PROJECT/'src'
    cpp=[source/'scan_kernel'/p for p in ['plugin.cpp','lifecycle.cpp','kernel_identity.cpp']]
    cpp += [source/'unified_kernel'/p for p in ['module.cpp','compat_core.cpp']]
    # Explicit production sources only. Offline mocks never enter the kext.
    cpp += [source/'private_mac_compat'/p for p in ['station_backend.cpp','bsd_lease.cpp',
                                                   'pinned_driver.cpp','private_bridge.cpp']]
    cpp += [source/'awdl_kernel'/p for p in ['driver_version_backend.cpp','version_external_method.cpp',
                                            'client_registry.cpp','scoped_reset.cpp','native_control_bridge.cpp']]
    c=[source/'awdl_compat'/p for p in ['event_ring.c','awdl_message_codec.c']]
    if args.event_pipe_components_review:
        cpp += [source/'awdl_kernel'/p for p in ['event_memory.cpp','async_notification_owner.cpp',
            'legacy_post_observer.cpp','event_pipe_session.cpp','event_pipe_worker.cpp']]
        if args.event_pipe_routes_review:
            cpp.append(source/'awdl_kernel'/'event_pipe_router.cpp')
        c += [source/'awdl_compat'/p for p in ['message48_subset_codec.c','message55_recovery_codec.c']]
    if args.baseline_trace:
        cpp.append(source/'awdl_kernel'/'baseline_trace.cpp')
    common=['-arch','x86_64','-mkernel','-fno-builtin','-fno-common','-fno-stack-protector',
            '-fno-asynchronous-unwind-tables','-mno-red-zone','-mno-sse','-mno-sse2',
            '-nostdinc','-isystem',SDK/'Headers','-DKERNEL=1','-DKERNEL_PRIVATE=1',
            '-mmacosx-version-min=10.15','-O2','-Wall','-Wextra','-Werror',
            '-Wno-unused-parameter','-Wno-unknown-warning-option','-Wno-ignored-attributes']
    if args.build_flavor=='DEBUG':
        common.append('-DDEBUG=1')
    common += compatibility_compile_defines(args)
    with tempfile.TemporaryDirectory(prefix='airport-brcm-review-') as temporary:
        work=Path(temporary);bundle=work/(NAME+'.kext')
        executable=bundle/'Contents/MacOS'/NAME;executable.parent.mkdir(parents=True)
        objects=[]
        for index,path in enumerate(cpp+c):
            obj=work/(str(index)+'.o')
            flags=(['xcrun','clang++','-std=c++14','-fapple-kext','-fno-exceptions','-fno-rtti',
                    '-nostdinc++','-I',LILU,'-DPRODUCT_NAME='+NAME,'-DMODULE_VERSION='+VERSION,
                    '-DBUNDLE_IDENTIFIER='+IDENTIFIER,
                    '-DAIRPORT_BRCM_PRIVATE_MAC=1',
                    '-DAIRPORT_BRCM_NATIVE_CONTROL=1',
                    *(['-DAIRPORT_BRCM_EVENT_PIPE=1'] if args.event_pipe_routes_review else []),
                    *(['-DAIRPORT_BRCM_EVENT_PIPE_CANDIDATE=1'] if args.automatic_compatibility else []),
                    '-DLILU_CUSTOM_KMOD_INIT=1','-DLILU_CUSTOM_IOKIT_INIT=1',
                    '-Wno-stdlibcxx-not-found'] if path.suffix=='.cpp' else ['xcrun','clang','-std=c11'])
            run(flags+common+['-c',path,'-o',obj]);objects.append(obj)
        run(['xcrun','ld','-arch','x86_64','-kext','-static','-undefined','dynamic_lookup',
             '-no_fixup_chains','-o',executable,*objects,'-L',SDK/'Library/universal','-lkmodc++','-lkmod'])
        info=bundle_info()
        info['AirportBrcmBuildFlavor']=args.build_flavor
        if args.automatic_compatibility:
            info.update(automatic_compatibility_info_metadata(args.baseline_trace,args.control_rx_windows))
        elif args.event_pipe_components_review:
            info['AirportBrcmDevelopmentStatus']=('EventPipe-Routes-CapabilityDisabled-Review'
                if args.event_pipe_routes_review else 'EventPipe-Components-Unwired-Review')
        (bundle/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        run(['/usr/bin/codesign','--force','--sign','-',bundle]);run(['/usr/bin/codesign','--verify','--strict',bundle])
        metadata=validate_bundle_metadata(bundle)
        symbols=run(['xcrun','nm',executable]).splitlines()
        kmod=[line for line in symbols if line.split()[-1:] == ['_kmod_info']]
        if len(kmod)!=1:raise ValueError('Unified executable must have exactly one kmod_info')
        required=['awcm_translate','awc_ring_publish','applyPrivateAddress','checkStationState',
                  'admitPrimaryAssociation','BSDLease5Scope5enter','StationSession4open',
                  'wrappedPerform','wrappedDriverAssociate','wrappedAuth']
        if any(not any(needle in line for line in symbols) for needle in required):
            raise ValueError('A required compatibility core was not linked')
        if any('awcf_mock_' in line for line in symbols):raise ValueError('Offline facade mock must never be linked')
        headers=[p for directory in ['scan_kernel','private_mac_compat','awdl_compat','awdl_kernel','unified_kernel']
                 for p in (source/directory).glob('*') if p.suffix in ('.h','.hpp') and p.name!='facade_mock.h']
        manifest={'schema':1,'identifier':IDENTIFIER,'version':VERSION,
                  'build_flavor':args.build_flavor,'compiler_debug_macro':args.build_flavor=='DEBUG',
                  'minimum_darwin_kernel_version':'25.0.0',
                  'one_self_developed_kext':True,'executable_count':1,
                  'kmod_info_count':1,'ready_for_install':build_mode['ready_for_install'],'installed':False,
                  'purpose':'static review only',
                  'runtime_validated':False,
                  'metadata_review':metadata,
                  'sources':{str(p.relative_to(PROJECT)):hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in sorted(set(cpp+c+headers))},
                  'nm_undefined':run(['xcrun','nm','-u',executable]).splitlines(),
                  'files':{str(p.relative_to(work)):hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in bundle.rglob('*') if p.is_file()}}
        if args.event_pipe_components_review and not args.automatic_compatibility:
            manifest.update({
                'purpose':'offline actual-SDK event component compile/link review; no event routes installed',
                'event_pipe_components_linked':True,'event_pipe_routes_installed':False,
                'event_pipe_routes_compiled':args.event_pipe_routes_review,
                'ready_for_install':False,
                'linked_inactive_cores':['bounded native event ring, descriptor owner, async-right owner, '
                    'real legacy post observer, resident event session/worker, strict46/47/48 codecs; '
                    'strict message55 recovery codec has no proven observer source'],
                'remaining':'Real IOUC selector/map/lifecycle routing and same-connection pipe reinitialization '
                    'are not installed. No event capability, AirDrop transfer or runtime safety claim.'})
        if args.automatic_compatibility:
            apply_automatic_compatibility_manifest(manifest,args.baseline_trace,args.control_rx_windows)
            validate_automatic_compatibility_metadata(info,manifest)
        output.parent.mkdir(parents=True,exist_ok=True)
        with zipfile.ZipFile(output,'x',zipfile.ZIP_DEFLATED) as archive:
            for p in sorted(bundle.rglob('*')):
                if p.is_file():archive.write(p,str(p.relative_to(work)))
            archive.writestr('build-manifest.json',json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'output':str(output),'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
                      'single_kext':True,'ready_for_install':build_mode['ready_for_install'],
                      'runtime_validated':False}))

if __name__=='__main__':main()
