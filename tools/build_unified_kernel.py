#!/usr/bin/env python3
"""Build one compatibility kext for review or an explicit experimental test; never install/load it."""
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
VERSION='0.1.12'
LIBRARIES={'as.vit9696.Lilu':'1.7.3','com.apple.kpi.bsd':'19.0.0','com.apple.kpi.iokit':'19.0.0',
           'com.apple.kpi.libkern':'19.0.0','com.apple.kpi.mach':'19.0.0',
           'com.apple.kpi.unsupported':'19.0.0','com.apple.iokit.IONetworkingFamily':'3.4'}
DUAL_PROFILE_KERNELS=(
    {'build':'25G241','kernel_uuid':'1291D44A-C0CD-3AC7-A9E4-CA2749B33959'},
    {'build':'25G332','kernel_uuid':'28267FD5-3E1E-3686-8A1C-E73E2466FCFB'},
)

def dual_profile_info_metadata(baseline_trace, scan_multiple=False, sae=False, control_windows=False):
    profiles=';'.join(item['build']+':'+item['kernel_uuid'] for item in DUAL_PROFILE_KERNELS)
    return {
        'AirportBrcmDevelopmentStatus':('Test023-ControlRX-Windows-DualProfile-Candidate' if control_windows else
                                       'Test022-SAE-Subset-DualProfile-Candidate' if sae else
                                       'Test021-HotspotScan-DualProfile-Candidate' if scan_multiple else
                                       'Test020-DualProfile-Candidate'),
        'AirportBrcmDualProfileMode':1,
        'AirportBrcmSupportedBuilds':','.join(item['build'] for item in DUAL_PROFILE_KERNELS),
        'AirportBrcmKernelProfiles':profiles,
        'AirportBrcmBaselineTrace':'25G332-only' if baseline_trace else 'Disabled',
        'AirportBrcmBaselineTraceConfigured':1 if baseline_trace else 0,
        'AirportBrcmScanMultipleCompatConfigured':1 if scan_multiple else 0,
        'AirportBrcmSaeCompatConfigured':1 if sae else 0,
        'AirportBrcmControlRxWindowsConfigured':1 if control_windows else 0,
    }

def dual_profile_manifest_metadata(baseline_trace, scan_multiple=False, sae=False, control_windows=False):
    return {
        'candidate':('Test023-ControlRX-Windows-DualProfile' if control_windows else
                     'Test022-SAE-Subset-DualProfile' if sae else
                     'Test021-HotspotScan-DualProfile' if scan_multiple else 'Test020-DualProfile'),
        'purpose':'Exact 25G241 and 25G332 build/inner-kernel UUID compatibility candidate',
        'supported_builds':[item['build'] for item in DUAL_PROFILE_KERNELS],
        'kernel_profiles':[dict(item) for item in DUAL_PROFILE_KERNELS],
        'release_ready':False,
        'runtime_validated':False,
        'baseline_trace_enabled':bool(baseline_trace),
        'baseline_trace_schema':2 if baseline_trace else None,
        'baseline_trace_profile':'25G332-only' if baseline_trace else None,
        'scan_multiple_compat_enabled':bool(scan_multiple),
        'scan_multiple_native_size':0x14e8 if scan_multiple else None,
        'scan_multiple_legacy_size':0x14e0 if scan_multiple else None,
        'scan_multiple_nonzero_min_timestamp':'refuse' if scan_multiple else None,
        'sae_compat_enabled':bool(sae),
        'sae_subset':({'selected_upper':4096,'cipher':10,'password_length_min':8,'password_length_max':63,
                       'pmk_length':32,'allowed_auth_masks':[0,4,0x40000004],
                       'selected_auth_preserved':True,'runtime_sae_validated':False} if sae else None),
        'control_rx_windows':({'schema':1,'bank_limit':4,'bank_reuse':False,'reset_allowed':False,
                               'max_seconds':120,'sample_limit':256,'sampling':'per-subtype time-thinned',
                               'clock':'mach_absolute_time_ns_excludes_sleep','source_alias':'window-keyed SipHash24 six-byte input',
                               'control_rx_only':True,'runtime_validated':False} if control_windows else None),
        'remaining':'Each exact build/UUID pair still requires separate boot and functional regression; HTTP, AirDrop peer visibility and bidirectional transfer remain unverified.'
    }

def bundle_info():
    return {'CFBundleDevelopmentRegion':'en','CFBundleExecutable':NAME,'CFBundleIdentifier':IDENTIFIER,
            'CFBundleInfoDictionaryVersion':'6.0','CFBundleName':NAME,'CFBundlePackageType':'KEXT',
            'CFBundleShortVersionString':'1.0' if VERSION=='1.0.0' else VERSION,
            'CFBundleVersion':VERSION,'OSBundleRequired':'Root',
            'OSBundleLibraries':dict(LIBRARIES),'AirportBrcmDevelopmentStatus':'NativeControl-Test014-EmptyQueryFix-EventPipeDisabled',
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
    parser.add_argument('--test-candidate',action='store_true',
                        help='Mark the exact package as an experimental Test014 candidate, not a validated release')
    parser.add_argument('--event-pipe-components-review',action='store_true',
                        help='Compile/link the real event components for offline review; no event routing or installation')
    parser.add_argument('--event-pipe-routes-review',action='store_true',
                        help='Compile/link experimental routes for offline review; router capability remains disabled')
    parser.add_argument('--event-pipe-test-candidate',action='store_true',
                        help='Build experimental Test018 bounded legacy channel-flags support; runtime install pins decide capability, never install/load here')
    parser.add_argument('--release-version',choices=('1.0.0',),
                        help='Rebuild the accepted Test018 feature set with release version metadata')
    parser.add_argument('--baseline-25g332',action='store_true',
                        help='Build the exact 25G332 Broadcom control-RX diagnostic profile; never install here')
    parser.add_argument('--dual-profile-test-candidate',action='store_true',
                        help='Build Test020 candidate gated by the exact 25G241/build-UUID or 25G332/build-UUID pair')
    parser.add_argument('--baseline-trace',action='store_true',
                        help='Include schema-2 numeric control-RX trace; dual-profile builds collect it only on 25G332')
    parser.add_argument('--hotspot-scan-compat',action='store_true',
                        help='Explicit Test021 SET86 adapter; requires the dual-profile candidate and refuses nonzero minimum timestamps')
    parser.add_argument('--sae-compat',action='store_true',
                        help='Explicit Test022 narrow SAE password-carrier candidate; requires dual-profile and hotspot-scan compatibility')
    parser.add_argument('--control-rx-windows',action='store_true',
                        help='Explicit Test023 root-armed immutable control-RX windows; requires dual-profile, baseline-trace and hotspot-scan compatibility')
    parser.add_argument('--build-flavor',choices=('RELEASE','DEBUG'),default='RELEASE',
                        help='Real compiler DEBUG macro for the diagnostic flavor; never installs a build')
    return parser

def main():
    global VERSION
    parser=build_parser()
    args=parser.parse_args();output=args.output.absolute()
    if args.hotspot_scan_compat and not args.dual_profile_test_candidate:
        raise ValueError('Hotspot scan compatibility requires the explicit dual-profile candidate')
    if args.sae_compat and not (args.dual_profile_test_candidate and args.hotspot_scan_compat):
        raise ValueError('SAE subset requires the explicit dual-profile and hotspot-scan candidate')
    if args.control_rx_windows and not (args.dual_profile_test_candidate and args.baseline_trace and args.hotspot_scan_compat):
        raise ValueError('Control RX windows require dual-profile, baseline-trace and hotspot-scan compatibility')
    if args.dual_profile_test_candidate:
        if (args.baseline_25g332 or args.test_candidate or args.event_pipe_components_review or
            args.event_pipe_routes_review or args.event_pipe_test_candidate or args.release_version):
            raise ValueError('Dual-profile Test020 is its own explicit candidate mode')
        args.event_pipe_test_candidate=True
    if args.baseline_trace and not (args.baseline_25g332 or args.dual_profile_test_candidate):
        raise ValueError('Baseline trace is supported only by an explicit 25G332 or dual-profile candidate')
    if args.baseline_25g332 and (not args.event_pipe_test_candidate or args.release_version):
        raise ValueError('25G332 baseline requires the explicit event candidate and excludes release metadata')
    if args.release_version and not args.event_pipe_test_candidate:
        raise ValueError('Release metadata requires the accepted Test018 feature set')
    if args.event_pipe_test_candidate and (args.test_candidate or args.event_pipe_components_review or args.event_pipe_routes_review):
        raise ValueError('Select one explicit candidate or review mode')
    if args.event_pipe_test_candidate:
        VERSION='0.1.16';args.event_pipe_routes_review=True
    if args.release_version:
        VERSION=args.release_version
    if args.baseline_25g332:
        VERSION='1.0.1'
        args.baseline_trace=True
    if args.dual_profile_test_candidate:
        VERSION='1.0.1'
    args.event_pipe_components_review=args.event_pipe_components_review or args.event_pipe_routes_review
    if args.test_candidate and args.event_pipe_components_review:
        raise ValueError('Unwired component review cannot be marked ready for installation')
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
    if args.baseline_25g332:
        common.append('-DAIRPORT_BRCM_BASELINE_25G332=1')
    if args.dual_profile_test_candidate:
        common.append('-DAIRPORT_BRCM_DUAL_PROFILE_25G241_25G332=1')
    if args.baseline_trace:
        common.append('-DAIRPORT_BRCM_BASELINE_TRACE=1')
    if args.hotspot_scan_compat:
        common.append('-DAIRPORT_BRCM_SCAN_MULTIPLE=1')
    if args.sae_compat:
        common.append('-DAIRPORT_BRCM_SAE_COMPAT=1')
    if args.control_rx_windows:
        common.append('-DAIRPORT_BRCM_BASELINE_WINDOW=1')
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
                    *(['-DAIRPORT_BRCM_EVENT_PIPE_CANDIDATE=1'] if args.event_pipe_test_candidate else []),
                    '-DLILU_CUSTOM_KMOD_INIT=1','-DLILU_CUSTOM_IOKIT_INIT=1',
                    '-Wno-stdlibcxx-not-found'] if path.suffix=='.cpp' else ['xcrun','clang','-std=c11'])
            run(flags+common+['-c',path,'-o',obj]);objects.append(obj)
        run(['xcrun','ld','-arch','x86_64','-kext','-static','-undefined','dynamic_lookup',
             '-no_fixup_chains','-o',executable,*objects,'-L',SDK/'Library/universal','-lkmodc++','-lkmod'])
        info=bundle_info()
        info['AirportBrcmBuildFlavor']=args.build_flavor
        if args.event_pipe_test_candidate:
            info['AirportBrcmDevelopmentStatus']='NativeEventPipe-Test018-ChannelFlags-Experimental'
            if args.baseline_25g332:
                info['AirportBrcmDevelopmentStatus']='25G332-Baseline019-ControlRX-Diagnostics'
                info['AirportBrcmBaselineBuild']='25G332-Baseline019'
            elif args.dual_profile_test_candidate:
                info.update(dual_profile_info_metadata(args.baseline_trace,args.hotspot_scan_compat,args.sae_compat,args.control_rx_windows))
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
                  'supported_build':'25G332' if args.baseline_25g332 else '25G241',
                  'supported_kernel':'25.6.0','one_self_developed_kext':True,'executable_count':1,
                  'kmod_info_count':1,'ready_for_install':args.test_candidate,'installed':False,
                  'purpose':'experimental Test014 zero-length native query input repair boot test' if args.test_candidate else 'static review only',
                  'runtime_validated':False,'awdl_backend_active':False,
                  'metadata_review':metadata,
                  'active_behavior':'Preserved Test011 Wi-Fi/private-MAC bridge plus real old AsyncUC native type0 control endpoint, real GET43 and strict selector1/5/7=false. No event-pipe capability advertised.',
                  'native_control_runtime_validated':False,
                  'native_control_only':True,
                  'native_empty_query_policy':'Selectors1/5/7 accept a nonnull unused inline input pointer when length is exactly0; pointer is never read. All descriptor/scalar/async/output constraints remain. No event capability advertised.',
                  'native_ool_input_policy':'Borrowed synchronous MIG input descriptor: balanced prepare/complete around one owned snapshot read, outside the old WorkLoop/gate; no descriptor release or retained mapping.',
                  'bounded_closing_policy':'Retain at most8 authorized Closing records until reboot; no automatic record removal or late old-table dispatch; subsequent admission may be refused. Experimental control validation only.',
                  'linked_inactive_cores':['AWDL bounded event ring and proven message46/47 codecs'],
                  'remaining':'native control runtime admission/GET43/close and Wi-Fi/Handoff regression validation; actual event source, pipe, notifications and AirDrop transfer remain incomplete',
                  'colocated_scope_policy':'Unsupported network-group event suppression and current-scope GET387; scoped hint retained and only a strict idle/disconnected private join may use legacy default link events. No roaming equivalence claimed.',
                  'association_policy_survey':'Only bounded policy enums/counts/lengths. No MAC/BSSID/SSID/scope text/key/IE contents. Does not change admission.',
                  'dhcp_device_type_policy':'Known native469 bit40 is an allow request, not MAC validity. Kept in the scoped plan; legacy GET552 remains unsupported and IPConfiguration uses its proven conservative false fallback. Full allow=true behavior is not implemented.',
                  'original_driver_dependencies':'preserved separately; no legacy binary or Lilu merged into this executable',
                  'sources':{str(p.relative_to(PROJECT)):hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in sorted(set(cpp+c+headers))},
                  'nm_undefined':run(['xcrun','nm','-u',executable]).splitlines(),
                  'files':{str(p.relative_to(work)):hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in bundle.rglob('*') if p.is_file()}}
        if args.event_pipe_components_review:
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
        if args.event_pipe_test_candidate:
            manifest.update({
                'purpose':'experimental Test018 bounded legacy channel-flags support after Test017 actual bit10 rejections',
                'ready_for_install':True,'native_control_only':False,
                'event_pipe_candidate_enabled':True,
                'mapped_image_policy':'KC file offsets are container metadata; instruction access uses the bounded mapped base and fixed VM-relative offsets. UUID, text extents, code and exact external-call target pins remain mandatory.',
                'install_diagnostics':'Pointer-free progress for router/observer preparation, image and external-call pins, memory method range/guard/route; failures keep selector5 false.',
                'codec_diagnostics':'Pointer-free received/rejected/committed counters by message46/47/48/other, codec error enum and message48 rejection bitmaps. No MAC/SSID/peer/body/metadata values. Last fields select the newest allocated resident Session with the respective observation, not a cross-worker timestamp. Diagnostics do not decide admission; channel subset is described separately. Lifecycle unchanged.',
                'channel_flags_policy':'Exactly one legacy band0x8/0x10 and one width0x1/0x2/0x4/0x400 (10/20/40/80MHz), optional DFS0x100, extension0x200 only with40MHz. Twenty finite structural combinations of producer-written bits, not a regulatory or RF-support claim. No widthless/160MHz/80+80/new native flags. All other metadata/frame/version/TLV/ownership/lifecycle checks remain.',
                'active_behavior':'Preserved Wi-Fi/private-address bridge and zero-input query fix; '
                    'conditionally installed real46/47/strict48 observer, native ring mappings, '
                    'zero-argument async notification and resident thread-call consumer.',
                'event_pipe_capability_policy':'True only after real control/reset, observer and '
                    'pinned kernel memory route installation plus prepared nonretiring router. '
                    'Partial setup keeps selector5 false. Initialization/subscription is a separate runtime test.',
                'event_pipe_reinitialization':'Same active UC gets at most8 fresh resident Sessions; '
                    'old Closed Session/MD/pages/right/worker are never reused. Reopen requires '
                    'real registry/owner/GET43/pins, old typed worker stopped+SessionClosed and '
                    'observer drain. Failed unbound creation may fail closed until reboot.',
                'linked_inactive_cores':['Strict message55 recovery codec: no proven observer source'],
                'remaining':'Real boot, IOUC init/map/subscribe, captured native events/notifications, '
                    'same-connection reinit and Wi-Fi/private-address/Handoff regression; '
                    'bidirectional AirDrop file transfer and full body/data-plane coverage remain unverified.'})
        if args.baseline_25g332:
            manifest.update(candidate='25G332-Baseline019',
                purpose='Exact macOS26.7.2 compatibility and bounded Broadcom control-RX baseline boot test',
                release_ready=False,runtime_validated=False,
                diagnostic_scope='Owned message48 receive snapshots only; numeric PSF/MIF and address-equality summaries. No raw addresses, payloads, hostnames, synthetic events or new RF commands.',
                kernel_identity='28267FD5-3E1E-3686-8A1C-E73E2466FCFB',
                remaining='Boot/load, Wi-Fi, native event consumer, actual peer transfer and diagnostic values remain untested on this profile.')
        if args.dual_profile_test_candidate:
            manifest.pop('supported_build',None)
            manifest.update(dual_profile_manifest_metadata(args.baseline_trace,args.hotspot_scan_compat,args.sae_compat,args.control_rx_windows))
        output.parent.mkdir(parents=True,exist_ok=True)
        with zipfile.ZipFile(output,'x',zipfile.ZIP_DEFLATED) as archive:
            for p in sorted(bundle.rglob('*')):
                if p.is_file():archive.write(p,str(p.relative_to(work)))
            archive.writestr('build-manifest.json',json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'output':str(output),'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
                      'single_kext':True,'ready_for_install':args.test_candidate or args.event_pipe_test_candidate,
                      'runtime_validated':False}))

if __name__=='__main__':main()
