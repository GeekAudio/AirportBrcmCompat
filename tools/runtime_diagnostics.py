"""Interpret saved, numeric driver snapshots without changing driver state."""
import plistlib
from pathlib import Path

STAGES=('ScanRoute','CapabilitiesRoute','CopyInRoute','AssociationRoute',
        'PrivateDriverRoute','PrivateAuthRoute','PrivateBSDRoute','PrivateReady',
        'PrivateIfnetMode','PrivatePublicIoctlRoute','PrivateInterfaceIoctlRoute',
        'PrivateGateReason','PrivateGateField','PrivateGatePhase',
        'PrivateApplyStage','PrivateApplyResult','PrivateBackendStatus',
        'FirstPrivateApplied','PrivatePostResult','PrivateQuarantined','PrivateEntry')
APPLY_STAGES=('None','Quarantined','Reentrant','InvalidAPI','PrivateRequest','AddressShape',
              'Authorization','RegistryUnlocked','ControllerGate','Unassociated','PolicySource',
              'SetFirmware','VerifyDriverCache','SetPrimaryBSD','VerifyPrimaryBSD',
              'PublishCurrentIOMAC','VerifyCurrentIOMAC','ScopeCopy','AssociationResult')


def diagnose(path):
    data=Path(path).read_bytes()
    if len(data)>8*1024*1024:raise ValueError('IORegistry snapshot exceeds size limit')
    root=plistlib.loads(data);pending=[root];found=[];visited=0
    while pending:
        value=pending.pop();visited+=1
        if visited>100000:raise ValueError('IORegistry snapshot has too many nodes')
        if isinstance(value,dict):
            if 'ScanCompatDiagnostics' in value:found.append(value['ScanCompatDiagnostics'])
            pending.extend(value.values())
        elif isinstance(value,list):pending.extend(value)
    if len(found)!=1 or not isinstance(found[0],dict):
        raise ValueError('Expected exactly one ScanCompatDiagnostics snapshot')
    snapshot=found[0]
    if snapshot.get('Schema')!=1:raise ValueError('Unsupported diagnostic schema')
    stages={}
    for name in STAGES:
        if name not in snapshot:continue
        item=snapshot[name]
        if not isinstance(item,dict) or type(item.get('Reached')) is not bool or type(item.get('Code')) is not int:
            raise ValueError('Invalid stage: '+name)
        code=item['Code']
        if not -1<=code<=0xffffffff:raise ValueError('Invalid stage code')
        if code>=0x80000000:code-=0x100000000
        if item['Reached']!=(code!=-1):raise ValueError('Reached/code sentinel mismatch: '+name)
        stages[name]={'reached':item['Reached'],'code':code}
    def code(name):
        item=stages.get(name,{})
        return item.get('code') if item.get('reached') else None
    def group(names):
        values=[code(name) for name in names]
        if all(v is None for v in values):return 'not_observed'
        if all(v==0 for v in values):return 'installed'
        if any(v==0 for v in values) and any(v is not None and v!=0 for v in values):return 'partial'
        if any(v is not None and v!=0 for v in values):return 'refused'
        return 'incomplete'
    private=['PrivateDriverRoute','PrivateAuthRoute','PrivateBSDRoute']
    if code('PrivateIfnetMode')==1:private+=['PrivatePublicIoctlRoute','PrivateInterfaceIoctlRoute']
    ready=code('PrivateReady')
    quarantined=code('PrivateQuarantined')
    warnings=[]
    private_routes=group(private)
    if ready==0 and private_routes!='installed':warnings.append('PrivateReady contradicts the supplied route stages')
    if ready==0 and code('PrivateIfnetMode') not in (0,1):warnings.append('PrivateReady lacks a known ifnet mode')
    apply_stage=code('PrivateApplyStage')
    return {'schema':1,'scope':'saved numeric diagnostics; no hardware success or recovery inferred',
            'stages':stages,'scan_routes':group(('ScanRoute','CapabilitiesRoute')),
            'association_routes':group(('CopyInRoute','AssociationRoute')),
            'private_routes':private_routes,'private_hooks_ready':None if ready is None else ready==0,
            'private_quarantined':None if quarantined is None else quarantined==1,
            'private_apply_stage':APPLY_STAGES[apply_stage] if apply_stage is not None and 0<=apply_stage<len(APPLY_STAGES) else None,
            'primary_association_admission':'blocked_by_quarantine' if quarantined==1 else 'not_proven_by_snapshot',
            'recovery_policy':('restart_with_known_good_files; quarantine_is_not_cleared_by_retry'
                               if quarantined==1 else 'no_recovery_inference'),
            'recovery_observed':None,'warnings':warnings,'passed':not warnings}
