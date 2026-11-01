import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import runtime_evidence as tool


class RuntimeEvidenceTests(unittest.TestCase):
    def matrix(self):return json.loads((ROOT/'validation/runtime-matrix.json').read_text())

    def session(self,matrix,root):
        core={'version':matrix['target_release'],'flavor':'RELEASE','binary_sha256':matrix['core_builds']['RELEASE']}
        run={'id':'synthetic-unit-fixture','pci_id':'14e4:43ba','macos_version':'14.0','system_build':'23A344',
             'boot_session_alias':'unit-fixture','core':core,'review':{'method':'manual_hardware_evidence','reviewed_on':'2026-11-01'},
             'checks':{name:{'status':'not_run','evidence':[],'observations':{}} for name in tool.CHECKS}}
        envelope={'kind':'hardware_capture','binding':{'pci_id':run['pci_id'],'system_build':run['system_build'],
            'core_binary_sha256':core['binary_sha256'],'boot_session_alias':run['boot_session_alias']}}
        data=json.dumps(envelope).encode();(root/'capture.json').write_bytes(data)
        run['evidence']=[{'id':'capture','kind':'hardware_capture','path':'capture.json','sha256':hashlib.sha256(data).hexdigest()}]
        matrix['cells'][0]['runs'].append(run);return run

    def test_repository_has_eighteen_pending_cells_without_historical_promotion(self):
        matrix=self.matrix();result=tool.check_matrix(matrix,ROOT/'validation/runtime-evidence')
        self.assertEqual(result['cells'],18);self.assertEqual(result['qualified_cells'],0)
        self.assertFalse(result['complete']);self.assertEqual(result['recorded_runs'],0)
        self.assertTrue(all(not r['qualifies_target_release'] for r in matrix['historical_references']))

    def test_complete_gate_and_duplicate_cells_reject(self):
        matrix=self.matrix()
        with self.assertRaisesRegex(ValueError,'incomplete'):tool.check_matrix(matrix,ROOT,True)
        matrix['cells'][-1]=copy.deepcopy(matrix['cells'][0])
        with self.assertRaisesRegex(ValueError,'duplicate'):tool.check_matrix(matrix,ROOT)

    def test_pass_requires_endpoint_evidence_not_sender_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);matrix=self.matrix();run=self.session(matrix,root)
            run['checks']['airdrop_to_peer']={'status':'pass','evidence':['capture'],'observations':{'sender_completed':True}}
            with self.assertRaisesRegex(ValueError,'endpoint'):tool.check_matrix(matrix,root)

    def test_wrong_core_build_binding_and_synthetic_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);matrix=self.matrix();run=self.session(matrix,root)
            run['core']['version']='1.0.1'
            with self.assertRaisesRegex(ValueError,'Historical'):tool.check_matrix(matrix,root)
            run['core']['version']=matrix['target_release'];run['system_build']='25G332'
            with self.assertRaisesRegex(ValueError,'generation'):tool.check_matrix(matrix,root)
            run['system_build']='23A344';run['pci_id']='14e4:43a3'
            with self.assertRaisesRegex(ValueError,'PCI'):tool.check_matrix(matrix,root)
            run['pci_id']='14e4:43ba';run['evidence'][0]['kind']='offline_fixture'
            with self.assertRaisesRegex(ValueError,'synthetic'):tool.check_matrix(matrix,root)

    def test_capture_hash_session_binding_and_path_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);matrix=self.matrix();run=self.session(matrix,root)
            run['boot_session_alias']='other-boot'
            with self.assertRaisesRegex(ValueError,'another card'):tool.check_matrix(matrix,root)
            run['boot_session_alias']='unit-fixture';run['evidence'][0]['path']='../outside'
            with self.assertRaisesRegex(ValueError,'Unsafe'):tool.check_matrix(matrix,root)
            run['evidence'][0]['path']='capture.json';(root/'capture.json').write_text('changed')
            with self.assertRaisesRegex(ValueError,'hash mismatch'):tool.check_matrix(matrix,root)

    def test_sleep_and_private_pass_need_observations(self):
        with self.assertRaises(ValueError):tool.observation('private_address',{'driver_bsd_ioreg_agree':True})
        with self.assertRaises(ValueError):tool.observation('sleep_wake',{'sleep_seconds':[1]})
        with self.assertRaises(ValueError):tool.observation('airdrop_from_peer',{'receiver_received':True,'receiver_hash_verified':True,'bytes':32,'source_sha256':'a'*64,'received_sha256':'b'*64})

    def test_independent_run_results_are_not_combined(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);matrix=self.matrix();run=self.session(matrix,root)
            run['checks']['boot']={'status':'pass','evidence':['capture'],'observations':{
                'cold_boot':True,'loaded_core_hash_matches':True,'expected_nic_bound':True,'no_panic':True}}
            other=copy.deepcopy(run);other['id']='second-unit-fixture';other['checks']['boot']['status']='not_run'
            other['checks']['association']={'status':'pass','evidence':['capture'],'observations':{
                'associated':True,'dhcp_acquired':True,'traffic_returned':True,'security':'WPA2'}}
            matrix['cells'][0]['runs'].append(other)
            result=tool.check_matrix(matrix,root);self.assertEqual(result['qualified_cells'],0)
