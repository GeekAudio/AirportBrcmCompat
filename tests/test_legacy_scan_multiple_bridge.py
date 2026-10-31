import pathlib
import subprocess
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "scan_multiple_bridge.hpp"
#include <assert.h>
#include <errno.h>
#include <string.h>
using namespace LegacyWiFi::ScanMultipleBridge;

static void put32(uint8_t *p,uint32_t value) {memcpy(p,&value,4);}
static uint32_t get32(const uint8_t *p) {uint32_t value;memcpy(&value,p,4);return value;}
static void init(uint8_t *p) {
    memset(p,0,NativeSize);
    put32(p,1);put32(p+4,2);put32(p+8,2);
    put32(p+0x0c,1);put32(p+0x10,32);memset(p+0x14,0x41,32);
    put32(p+0x34,1);put32(p+0x38,3);memcpy(p+0x3c,"abc",3);
    put32(p+NativeBSSIDCount,2);
    for (size_t i=0;i<12;i++) p[NativeBSSIDArray+i]=static_cast<uint8_t>(0x80+i);
    put32(p+NativeScanType,1);put32(p+NativePhyMode,3);
    put32(p+NativeDwellTime,1200);put32(p+NativeRestTime,47);
    put32(p+NativeChannelCount,3);
    for (uint32_t i=0;i<3;i++) {
        uint8_t *channel=p+NativeChannels+size_t(i)*ChannelStride;
        put32(channel,1);put32(channel+4,36+i);put32(channel+8,0x100+i);
    }
}
static void validMapping() {
    uint8_t native[NativeSize],copy[NativeSize],old[ElCapSize];
    init(native);memcpy(copy,native,sizeof(native));memset(old,0x7b,sizeof(old));
    const Result result=convertToElCap(native,sizeof(native),old,sizeof(old));
    assert(!result.error&&!result.field);
    assert(!memcmp(native,copy,sizeof(native)));
    assert(get32(old)==1&&get32(old+4)==2&&get32(old+8)==2);
    assert(!memcmp(old+0x0c,native+0x0c,2*SSIDStride));
    assert(get32(old+ElCapBSSIDCount)==2);
    assert(!memcmp(old+ElCapBSSIDArray,native+NativeBSSIDArray,12));
    assert(get32(old+ElCapScanType)==1&&get32(old+ElCapPhyMode)==3);
    uint16_t dwell=0;memcpy(&dwell,old+ElCapDwellTime,2);assert(dwell==1200);
    assert(old[ElCapDwellTime+2]==0&&old[ElCapDwellTime+3]==0);
    assert(get32(old+ElCapRestTime)==47&&get32(old+ElCapChannelCount)==3);
    assert(!memcmp(old+ElCapChannels,native+NativeChannels,3*ChannelStride));
    for (size_t i=ElCapChannels+3*ChannelStride;i<ElCapSize;i++) assert(old[i]==0);
}
static void maximumRepresentable() {
    uint8_t native[NativeSize],old[ElCapSize];
    init(native);put32(native+8,10);put32(native+NativeBSSIDCount,16);
    put32(native+NativeChannelCount,MaxElCapChannels);
    for (uint32_t i=0;i<MaxElCapChannels;i++) {
        uint8_t *channel=native+NativeChannels+size_t(i)*ChannelStride;
        put32(channel,1);put32(channel+4,i+1);put32(channel+8,0xabc00000U+i);
    }
    assert(!convertToElCap(native,sizeof(native),old,sizeof(old)).error);
    assert(get32(old+ElCapBSSIDCount)==16);
    assert(get32(old+ElCapChannelCount)==MaxElCapChannels);
    assert(!memcmp(old+ElCapChannels,native+NativeChannels,
                   MaxElCapChannels*ChannelStride));
    assert(get32(old+ElCapUnknownTail)==0);
}
static void rejectsWithoutPartialWrite() {
    uint8_t native[NativeSize],old[ElCapSize],before[ElCapSize];
    auto reject=[&](int error,size_t field) {
        memset(old,0x6d,sizeof(old));memcpy(before,old,sizeof(old));
        const Result result=convertToElCap(native,sizeof(native),old,sizeof(old));
        assert(result.error==error&&result.field==field);
        assert(!memcmp(old,before,sizeof(old)));
    };
    init(native);put32(native+8,11);reject(EINVAL,NativeSSIDCount);
    init(native);put32(native+NativeBSSIDCount,17);reject(EINVAL,NativeBSSIDCount);
    init(native);put32(native+NativeChannelCount,129);reject(EOPNOTSUPP,NativeChannelCount);
    init(native);put32(native+NativeChannelCount,401);reject(EINVAL,NativeChannelCount);
    init(native);put32(native+4,0);reject(EINVAL,4);
    init(native);put32(native+NativeScanType,4);reject(EINVAL,NativeScanType);
    init(native);put32(native+NativeDwellTime,0x10000);reject(EOPNOTSUPP,NativeDwellTime);
    init(native);put32(native+0x10,33);reject(EINVAL,0x10);
    init(native);native[NativeUnmappedTail+3]=1;
    reject(EOPNOTSUPP,NativeUnmappedTail+3);
    init(native);native[0x14e0]=1;reject(EOPNOTSUPP,0x14e0);
    init(native);put32(native,2);reject(EINVAL,0);
}
static void invalidBuffers() {
    uint8_t native[NativeSize],old[ElCapSize];init(native);memset(old,0x72,sizeof(old));
    assert(convertToElCap(nullptr,NativeSize,old,ElCapSize).error==EINVAL);
    assert(convertToElCap(native,NativeSize,nullptr,ElCapSize).error==EINVAL);
    assert(convertToElCap(native,NativeSize-1,old,ElCapSize).error==EINVAL);
    assert(convertToElCap(native,NativeSize,old,ElCapSize-1).error==EINVAL);
    assert(convertToElCap(native,NativeSize,native,ElCapSize).error==EINVAL);
}
int main(){validMapping();maximumRepresentable();rejectsWithoutPartialWrite();invalidBuffers();}
'''


class LegacyScanMultipleBridgeTests(unittest.TestCase):
    def test_layout_boundaries_and_lossless_subset(self):
        with tempfile.TemporaryDirectory(prefix="legacy-scan-multiple-") as folder:
            source = pathlib.Path(folder) / "test.cpp"
            binary = pathlib.Path(folder) / "test"
            source.write_text(HARNESS)
            build = subprocess.run(
                ["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                 "-I", str(PROJECT / "src/scan_kernel"),
                 "-I", str(PROJECT / "src/legacy_wifi_compat"), str(source), "-o", str(binary)],
                text=True, capture_output=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], text=True, capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
