import importlib.util
from pathlib import Path
import plistlib
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('runtime_diagnostics',ROOT/'tools/runtime_diagnostics.py')
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)


class RuntimeDiagnosticsTests(unittest.TestCase):
    def report(self,stages,extra=None):
        snapshot={'Schema':1,**{name:{'Reached':code is not None,'Code':0xffffffff if code is None else code} for name,code in stages.items()}}
        if extra:snapshot.update(extra)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'ioreg.plist'
            path.write_bytes(plistlib.dumps([{'private_address':'do-not-export','ScanCompatDiagnostics':snapshot}]))
            return tool.diagnose(path)

    def test_partial_scan_is_not_complete_association(self):
        result=self.report({'ScanRoute':0,'CapabilitiesRoute':1})
        self.assertEqual(result['scan_routes'],'partial')
        self.assertEqual(result['association_routes'],'not_observed')

    def test_unknown_is_not_success(self):
        result=self.report({'ScanRoute':0,'CapabilitiesRoute':None,'PrivateQuarantined':None})
        self.assertEqual(result['scan_routes'],'incomplete');self.assertIsNone(result['private_quarantined'])

    def test_quarantine_does_not_infer_recovery_or_export_identity(self):
        result=self.report({'PrivateQuarantined':1,'PrivateApplyStage':13,'PrivateApplyResult':5})
        self.assertTrue(result['private_quarantined']);self.assertIsNone(result['recovery_observed'])
        self.assertNotIn('do-not-export',str(result))

    def test_private_ready_requires_consistent_routes(self):
        result=self.report({'PrivateReady':0,'PrivateDriverRoute':0,'PrivateAuthRoute':1,'PrivateBSDRoute':None})
        self.assertFalse(result['passed']);self.assertTrue(result['warnings'])

    def test_public_kpi_mode_requires_both_extra_routes(self):
        result=self.report({'PrivateIfnetMode':1,'PrivateDriverRoute':0,'PrivateAuthRoute':0,
                            'PrivateBSDRoute':0,'PrivateReady':0})
        self.assertFalse(result['passed'])
        result=self.report({'PrivateIfnetMode':1,'PrivateDriverRoute':0,'PrivateAuthRoute':0,
                            'PrivateBSDRoute':0,'PrivateReady':0,'PrivatePublicIoctlRoute':0,'PrivateInterfaceIoctlRoute':0})
        self.assertEqual(result['private_routes'],'installed');self.assertTrue(result['passed'])

    def test_ambiguous_snapshot_and_inconsistent_sentinel_rejected(self):
        with self.assertRaisesRegex(ValueError,'sentinel'):
            self.report({}, {'ScanRoute':{'Reached':True,'Code':0xffffffff}})
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'two.plist';path.write_bytes(plistlib.dumps([
                {'ScanCompatDiagnostics':{'Schema':1}},{'ScanCompatDiagnostics':{'Schema':1}}]))
            with self.assertRaisesRegex(ValueError,'exactly one'):tool.diagnose(path)
