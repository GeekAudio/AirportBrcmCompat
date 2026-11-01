"""Synthetic Intel BootKC fixtures; never evidence of macOS 27 support."""
import contextlib
import io
import json
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import brcmctl
import upgrade_check as upgrade

BASE=0xffffff8000200000
NET=BASE+0x1000000
KERNEL_OFFSET=0x1000
NETWORK_OFFSET=0x10000


def header(filetype,commands):
    body=b''.join(commands)
    return struct.pack('<8I',0xfeedfacf,0x1000007,3,filetype,len(commands),len(body),0,0)+body


def segment(name,base,fileoff,size,section=False):
    command=struct.pack('<II16sQQQQiiII',0x19,152 if section else 72,name.encode(),
                        base,size,fileoff,size,5 if section else 3,5 if section else 3,
                        int(section),0)
    if section:
        command+=struct.pack('<16s16sQQIIIIIIII',b'__text',name.encode(),base+0x1000,
                             size-0x1000,fileoff+0x1000,4,0,0,0x80000400,0,0,0)
    return command


def entry(name,base,offset):
    raw=name.encode()+b'\0';size=(32+len(raw)+7)&~7
    return struct.pack('<IIQQII',0x80000035,size,base,offset,32,0)+raw+b'\0'*(size-32-len(raw))


def symbols(blob,offset,strings_offset,values):
    strings=b'\0';records=b''
    for name,value in values.items():
        records+=struct.pack('<IBBHQ',len(strings),0xf,1,0,value)
        strings+=name.encode()+b'\0'
    blob[offset:offset+len(records)]=records
    blob[strings_offset:strings_offset+len(strings)]=strings
    return struct.pack('<6I',2,24,offset,len(values),strings_offset,len(strings))


def fixture(darwin='26.0.0'):
    blob=bytearray(0x16000)
    uuid=struct.pack('<II16s',0x1b,24,bytes(range(1,17)))
    outer=header(0xc,[uuid,entry('com.apple.kernel',BASE,KERNEL_OFFSET),
                      entry(upgrade.NETWORK_ID,NET,NETWORK_OFFSET)])
    blob[:len(outer)]=outer
    kernel_values={'__mh_execute_header':BASE,'_ifnet_ioctl':BASE+0x1000,
                   '_ifnet_softc':BASE+0x1100,'__ZNK9IOService10isInactiveEv':BASE+0x1200,
                   '_version':BASE+0x4000,'_osrelease':BASE+0x4200}
    kernel=header(2,[segment('__TEXT',BASE,KERNEL_OFFSET,0x4000,True),
                     segment('__DATA',BASE+0x4000,0x5000,0x1000),
                     segment('__LINKEDIT',BASE+0x5000,0x6000,0x1000),uuid,
                     symbols(blob,0x6000,0x6800,kernel_values)])
    blob[KERNEL_OFFSET:KERNEL_OFFSET+len(kernel)]=kernel
    version=('Darwin Kernel Version '+darwin+': synthetic host test; RELEASE_X86_64\0').encode()
    blob[0x5000:0x5000+len(version)]=version
    blob[0x5200:0x5200+len(darwin)+1]=darwin.encode()+b'\0'
    prefix=bytes.fromhex('554889e54157415641554154534883ec28')
    blob[0x2000:0x2030]=prefix+b'\x90'*(48-len(prefix))
    blob[0x2100]=0xc3;blob[0x2200]=0xc3
    values=dict(zip(upgrade.NETWORK_SYMBOLS,[NET+0x1000,NET+0x1142,NET+0x2000,NET+0x2100,NET+0x2200]))
    network=header(11,[segment('__TEXT',NET,NETWORK_OFFSET,0x4000,True),
                       segment('__LINKEDIT',NET+0x4000,0x14000,0x1000),uuid,
                       symbols(blob,0x14000,0x14800,values)])
    blob[NETWORK_OFFSET:NETWORK_OFFSET+len(network)]=network
    init=bytearray.fromhex(
        '554889e54156534889f34989fe488b07ff90a008000048894310498b8608010000'
        '8b4804894b208b00894318488d053100000048894328488d050401000048894360'
        '488d057b01000048894368488d0568020000488943704c897358b0015b415e5dc390')
    callback=bytearray.fromhex(
        '554889e5415741564155415453504889d34989f74989fee80253f4fd41bd660000'
        '004885c074494989c44889c7e86ca63afe84c0753a498bb424880000004885f67427'
        '498b0424488b80600900004c89e74c89fa4c89f14989d84883c4085b415c415d415e'
        '415f5dffe041bd160000004489e84883c4085b415c415d415e415f5dc3')
    for operand,end,target in ((0x2f,0x33,NET+0x2000),(0x3a,0x3e,NET+0x1142),
                                (0x45,0x49,NET+0x2100),(0x50,0x54,NET+0x2200)):
        struct.pack_into('<i',init,operand,target-(NET+0x1000+end))
    struct.pack_into('<i',callback,0x18,BASE+0x1100-(NET+0x1142+0x1c))
    struct.pack_into('<i',callback,0x2e,BASE+0x1200-(NET+0x1142+0x32))
    blob[0x11000:0x11000+len(init)]=init
    blob[0x11142:0x11142+len(callback)]=callback
    return blob


class UpgradeChecksTests(unittest.TestCase):
    def read(self,data,target=(26,0,0)):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'synthetic.kc';path.write_bytes(data)
            return upgrade.read_sample(path,target)

    def test_unknown_version_and_uuid_can_pass_exact_production_contracts(self):
        for darwin in ('26.0.0','26.9.3','27.0.0','99.1.2'):
            with self.subTest(darwin=darwin):
                data=fixture(darwin);data[48]^=0x80 # New UUID, without an allowlist.
                metadata,prefix,mapped,args=self.read(data,tuple(map(int,darwin.split('.'))))
                self.assertEqual(metadata['actual_darwin'],darwin)
                self.assertEqual(metadata['architecture'],'x86_64')
                self.assertTrue(upgrade.run_probe(prefix,mapped,args)['passed'])

    def test_old_sample_cannot_qualify_a_future_target(self):
        with self.assertRaisesRegex(ValueError,'does not match'):
            self.read(fixture('25.6.0'))
        data=fixture();data[0x5200:0x5206]=b'25.6.0'
        with self.assertRaisesRegex(ValueError,'disagree'):self.read(data)

    def test_arm64_outer_or_member_and_non_filesets_are_rejected(self):
        for offset in (0,KERNEL_OFFSET,NETWORK_OFFSET):
            data=fixture();struct.pack_into('<I',data,offset+4,0x100000c)
            with self.subTest(offset=offset),self.assertRaisesRegex(upgrade.macho.VerificationError,'not x86_64'):
                self.read(data)
        data=fixture();struct.pack_into('<I',data,12,2)
        with self.assertRaisesRegex(upgrade.macho.VerificationError,'MH_FILESET'):self.read(data)

    def test_missing_or_duplicate_member_and_zero_uuid_are_rejected(self):
        data=fixture();name=upgrade.NETWORK_ID.encode();offset=data.find(name)
        data[offset]=ord('x')
        with self.assertRaisesRegex(ValueError,'exactly one'):self.read(data)
        data=fixture();first=entry('com.apple.kernel',BASE,KERNEL_OFFSET)
        duplicate=header(0xc,[struct.pack('<II16s',0x1b,24,bytes(range(1,17))),first,
                              entry(upgrade.NETWORK_ID,NET,NETWORK_OFFSET),
                              entry(upgrade.NETWORK_ID,NET,NETWORK_OFFSET)])
        data[:len(duplicate)]=duplicate
        with self.assertRaisesRegex(ValueError,'exactly one'):self.read(data)
        data=fixture();data[40:56]=b'\0'*16
        with self.assertRaisesRegex(ValueError,'UUID is zero'):self.read(data)

    def test_missing_symbols_header_mismatch_and_oversized_maps_are_rejected(self):
        data=fixture();where=data.find(b'_ifnet_softc\0');data[where]=ord('x')
        with self.assertRaisesRegex(ValueError,'symbols are missing'):self.read(data)
        data=fixture();struct.pack_into('<Q',data,0x6000+8,BASE+8)
        with self.assertRaisesRegex(ValueError,'header mapping differ'):self.read(data)
        data=fixture();struct.pack_into('<Q',data,NETWORK_OFFSET+32+32,65*1024*1024)
        with self.assertRaisesRegex(ValueError,'mapping exceeds limits'):self.read(data)

    def test_unsafe_route_prefix_and_changed_callback_bytes_are_rejected(self):
        for offset in (0x2000,0x11142+0x60,0x11000+0x23):
            data=fixture();data[offset]^=1
            if offset==0x2000:data[offset]=0xe8 # A relative call cannot be copied safely.
            with self.subTest(offset=offset):
                _,prefix,mapped,args=self.read(data)
                self.assertFalse(upgrade.run_probe(prefix,mapped,args)['passed'])

    def test_relocation_targets_must_resolve_to_independent_symbols(self):
        data=fixture();data[0x11142+0x18]^=1
        _,prefix,mapped,args=self.read(data)
        self.assertFalse(upgrade.run_probe(prefix,mapped,args)['passed'])
        _,prefix,mapped,args=self.read(fixture());args[3]+=1
        self.assertFalse(upgrade.run_probe(prefix,mapped,args)['passed'])

    def test_no_sample_and_failed_configuration_remain_incomplete(self):
        report=upgrade.assess({'passed':True},(26,0,0))
        self.assertFalse(report['passed']);self.assertFalse(report['runtime_validated'])
        self.assertEqual(report['sample_status'],'not_supplied')
        self.assertFalse(report['ready_for_hardware_test'])
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'synthetic.kc';path.write_bytes(fixture())
            report=upgrade.assess({'passed':False},(26,0,0),path)
            self.assertEqual(report['sample_status'],'host_contracts_passed')
            self.assertFalse(report['passed'])
            report=upgrade.assess({'passed':True},(26,0,0),path)
            self.assertTrue(report['passed']);self.assertFalse(report['runtime_validated'])
            self.assertIn('request and event formats',report['remaining_live_gates'])
            self.assertNotIn(str(path),json.dumps(report))

    def test_cli_without_sample_returns_failure_and_never_overwrites_report(self):
        from test_brcmctl import DeliveryToolsTests
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);DeliveryToolsTests().stage(root);output=root/'report.json'
            args=['upgrade-check','--oc-dir',str(root),'--darwin','26.0.0','--output',str(output)]
            with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(brcmctl.main(args),1)
            before=output.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(brcmctl.main(args),2)
            self.assertEqual(output.read_bytes(),before)

    def test_shipping_fragments_select_one_nic_without_future_version_ceiling(self):
        for name in ('RELEASE','DEBUG'):
            config=plistlib.loads((ROOT/f'Examples/config-WiFi-{name}.example.plist').read_bytes())
            for target in ('23.0.0','24.99.99','25.0.0','26.0.0','26.99.99','27.0.0','99.0.0'):
                with self.subTest(flavor=name,target=target):
                    active=[e for e in config['Kernel']['Add'] if brcmctl.applies(e,brcmctl.version(target))]
                    nic=[e for e in active if 'AirPortBrcmNIC-' in e['BundlePath']]
                    self.assertEqual(len(nic),1)
                    self.assertEqual(len(active),4)
                    if brcmctl.version(target)>=(25,0,0):
                        self.assertEqual(nic[0]['BundlePath'],'AirPortBrcmNIC-Tahoe.kext')
                        self.assertEqual(nic[0]['MaxKernel'],'')


if __name__=='__main__':unittest.main()
