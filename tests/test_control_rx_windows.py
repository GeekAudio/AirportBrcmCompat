from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ControlRxWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='brcm-window-', dir='/private/tmp')
        cls.binaries = {}
        for sanitizer in ('address,undefined', 'thread'):
            binary = Path(cls.tmp.name)/sanitizer.replace(',', '-')
            command = ['xcrun','clang++','-std=c++14','-pthread','-Wall','-Wextra','-Werror',
                       '-DAIRPORT_BRCM_BASELINE_WINDOW=1','-fsanitize='+sanitizer,'-fno-omit-frame-pointer',
                       '-I',str(ROOT/'src/awdl_kernel'),str(ROOT/'tests/control_window_host.cpp'),
                       str(ROOT/'src/awdl_kernel/baseline_trace.cpp'),'-o',str(binary)]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode:
                raise AssertionError(result.stdout+result.stderr)
            cls.binaries[sanitizer] = binary

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_mode(self, mode, sanitizer='address,undefined'):
        result = subprocess.run([str(self.binaries[sanitizer]),str(mode)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_invalid_arm_thinning_separate_pools_and_once_only_banks(self): self.run_mode(1)
    def test_shared_alias_address_states_clock_and_immutable_snapshot_fence(self): self.run_mode(2)
    def test_predeadline_writer_blocks_closed_and_stays_in_original_bank(self): self.run_mode(3, 'thread')
    def test_concurrent_arm_observers_and_snapshots(self): self.run_mode(4, 'thread')


if __name__ == '__main__': unittest.main()
