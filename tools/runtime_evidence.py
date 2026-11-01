#!/usr/bin/env python3
"""Check and render hardware-test records; never executes hardware tests."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from release_inventory import relative

ROOT=Path(__file__).resolve().parents[1]
SYSTEMS={14:('Sonoma',23),15:('Sequoia',24),26:('Tahoe',25)}
IDS=('14e4:43ba','14e4:43a3','14e4:43a0','14e4:4357','14e4:43b1','14e4:43b2')
CHECKS=('boot','association','private_address','airdrop_to_peer','airdrop_from_peer','sleep_wake')
STATES=('not_run','pass','fail','blocked')
SHA=re.compile(r'[0-9a-f]{64}')


def require(value,message):
    if not value:raise ValueError(message)


def observation(check,value):
    flags={'boot':('cold_boot','loaded_core_hash_matches','expected_nic_bound','no_panic'),
           'association':('associated','dhcp_acquired','traffic_returned'),
           'private_address':('driver_bsd_ioreg_agree','ap_observed_private_address','locally_administered_unicast'),
           'airdrop_to_peer':('receiver_received','receiver_hash_verified'),
           'airdrop_from_peer':('receiver_received','receiver_hash_verified'),
           'sleep_wake':('post_wake_associated','post_wake_traffic','private_state_consistent','no_panic')}
    require(all(value.get(key) is True for key in flags[check]),check+': missing endpoint observations')
    if check=='association':require(value.get('security') in ('WPA2','WPA3','WPA2/WPA3'), 'Record the tested authentication mode')
    if check=='private_address':require(value.get('mode') in ('fixed','rotating'),'Record the tested private-address mode')
    if check.startswith('airdrop_'):
        require(type(value.get('bytes')) is int and value['bytes']>0,'Record the received file size')
        require(SHA.fullmatch(value.get('source_sha256','')) is not None and
                value.get('received_sha256')==value['source_sha256'],'Receiver hash must match the sent file')
    if check=='sleep_wake':
        sleeps=value.get('sleep_seconds',[])
        require(isinstance(sleeps,list) and len(sleeps)>=3 and
                all(type(v) is int and v>0 for v in sleeps),'Record at least three bounded sleep cycles')


def check_matrix(matrix,evidence_root,require_complete=False):
    require(matrix.get('schema')==1,'Unsupported runtime-matrix schema')
    require(matrix.get('target_release') and isinstance(matrix.get('core_builds'),dict),'Missing target core identity')
    require(set(matrix['core_builds'])=={'RELEASE','DEBUG'} and
            all(SHA.fullmatch(v) for v in matrix['core_builds'].values()),'Invalid target core hashes')
    expected={(major,pci) for major in SYSTEMS for pci in IDS};seen=set();run_ids=set();qualified=0;run_count=0
    rows=[];root=Path(evidence_root).resolve()
    for cell in matrix['cells']:
        key=(cell['macos_major'],cell['pci_id'])
        require(key in expected and key not in seen,'Unknown or duplicate system/PCI cell');seen.add(key)
        good=[]
        for run in cell['runs']:
            run_count+=1
            require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}',run['id']) is not None and run['id'] not in run_ids,'Invalid or duplicate run ID')
            run_ids.add(run['id']);major,darwin=cell['macos_major'],SYSTEMS[cell['macos_major']][1]
            require(run['pci_id']==cell['pci_id'],'Run PCI ID differs from matrix cell')
            require(re.fullmatch(str(major)+r'\.\d+(?:\.\d+)?',run['macos_version']) is not None,'Record an exact macOS version')
            require(re.fullmatch(str(darwin)+r'[A-Z]\d+[a-z]?',run['system_build']) is not None,'Build does not match the target system generation')
            require(bool(run.get('boot_session_alias')),'Record the boot session alias')
            core=run['core'];require(core['version']==matrix['target_release'],'Historical core cannot qualify this release')
            require(core['flavor'] in matrix['core_builds'] and core['binary_sha256']==matrix['core_builds'][core['flavor']], 'Core hash differs from the target release')
            require(set(run['checks'])==set(CHECKS),'Expected all six capability results')
            evidence={}
            for item in run.get('evidence',[]):
                require(item['id'] not in evidence,'Duplicate evidence ID')
                require(item.get('kind')=='hardware_capture','Offline/synthetic inputs cannot qualify runtime results')
                require(SHA.fullmatch(item['sha256']) is not None,'Invalid evidence hash')
                path=root.joinpath(*relative(item['path']).parts)
                require(path.resolve().is_relative_to(root),'Evidence path escapes its root')
                require(path.is_file() and 0<path.stat().st_size<=8*1024*1024,'Missing/oversized evidence file')
                payload=path.read_bytes()
                require(hashlib.sha256(payload).hexdigest()==item['sha256'],'Evidence hash mismatch')
                envelope=json.loads(payload)
                require(not any(envelope.get(flag) is True for flag in ('synthetic','simulated','test_fixture')),
                        'Synthetic evidence cannot qualify hardware records')
                binding={'pci_id':run['pci_id'],'system_build':run['system_build'],
                         'core_binary_sha256':core['binary_sha256'],'boot_session_alias':run['boot_session_alias']}
                require(envelope.get('kind')=='hardware_capture' and envelope.get('binding')==binding,
                        'Evidence belongs to another card, build, core or boot session')
                evidence[item['id']]=item
            any_tested=False
            for name,result in run['checks'].items():
                require(result['status'] in STATES,'Unknown runtime result')
                refs=result.get('evidence',[])
                require(isinstance(refs,list) and all(ref in evidence for ref in refs),'Unknown evidence reference')
                if result['status']!='not_run':
                    any_tested=True;require(bool(refs),'A tested result requires evidence')
                if result['status']=='pass':observation(name,result.get('observations',{}))
            if any_tested:
                require(run.get('review',{}).get('method')=='manual_hardware_evidence' and
                        re.fullmatch(r'\d{4}-\d{2}-\d{2}',run['review'].get('reviewed_on','')) is not None,'Hardware evidence needs an explicit review record')
            if all(run['checks'][name]['status']=='pass' for name in CHECKS):good.append(run['id'])
        # Never combine successful features from different sessions/builds.
        if good:qualified+=1
        rows.append({'macos_major':key[0],'pci_id':key[1],'runs':len(cell['runs']),'qualifying_runs':good})
    require(seen==expected,'Matrix must cover all 18 system/PCI combinations')
    report={'schema':1,'scope':'record structure and retained evidence integrity; no hardware re-execution',
            'target_release':matrix['target_release'],'cells':18,'recorded_runs':run_count,
            'qualified_cells':qualified,'complete':qualified==18,'rows':rows}
    if require_complete:require(report['complete'],'Runtime matrix incomplete: '+str(qualified)+'/18 qualified cells')
    return report


def render(matrix):
    lines=['# 实机验证矩阵 / Hardware validation matrix','',
           '目标版本 / Target release: **'+matrix['target_release']+'**。每项结论只属于记录中的具体系统构建、PCI ID、核心哈希和启动会话。',
           'A result applies only to its recorded OS build, PCI ID, core hash and boot session. Offline tests are separate.',
           '', '“—”为未测试。不同会话的单项通过不会合并成整组通过。历史结果不计入当前版本。',
           '“—” means not tested. Results from separate runs are never combined into a complete pass.', '',
           '| 系统 / OS | PCI ID | 构建 / Build | 启动 / Boot | 关联 / Join | 私人地址 / Private | AirDrop → | AirDrop ← | 睡眠 / Sleep |',
           '| --- | --- | --- | --- | --- | --- | --- | --- | --- |']
    symbols={'not_run':'—','pass':'PASS','fail':'FAIL','blocked':'BLOCKED'}
    for cell in matrix['cells']:
        system=SYSTEMS[cell['macos_major']][0]+' '+str(cell['macos_major'])
        if not cell['runs']:lines.append('| '+system+' | `'+cell['pci_id']+'` | — | '+' | '.join(['—']*6)+' |')
        for run in cell['runs']:
            lines.append('| '+system+' | `'+cell['pci_id']+'` | '+run['macos_version']+' / '+run['system_build']+' / '+run['id']+' | '+
                         ' | '.join(symbols[run['checks'][key]['status']] for key in CHECKS)+' |')
    lines+=['','记录方法与异常恢复 / Procedures: [RUNTIME-VALIDATION.md](../docs/RUNTIME-VALIDATION.md).','',
            '历史参考另列于 JSON 的 historical_references，未迁移为当前版本通过项。',
            'Historical references remain separate and do not qualify the current release.','']
    return '\n'.join(lines)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix',type=Path,default=ROOT/'validation/runtime-matrix.json')
    parser.add_argument('--evidence-root',type=Path,default=ROOT/'validation/runtime-evidence')
    parser.add_argument('--require-complete',action='store_true')
    parser.add_argument('--render',type=Path)
    args=parser.parse_args()
    try:
        matrix=json.loads(args.matrix.read_text());report=check_matrix(matrix,args.evidence_root,args.require_complete)
        if args.render:args.render.write_text(render(matrix))
        print(json.dumps(report,indent=2));return 0
    except (OSError,ValueError,KeyError,TypeError) as error:
        print('runtime_evidence: '+str(error));return 1


if __name__=='__main__':raise SystemExit(main())
