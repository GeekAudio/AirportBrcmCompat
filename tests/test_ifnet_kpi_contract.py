"""Exercise the actual bounded trampoline-prefix validator, without a hook."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "src/private_mac_compat/ifnet_kpi_contract.hpp"
#include <cassert>
#include <cstring>
using PrivateMAC::IfnetKPIContract::safeRoutePrefix;
int main() {
    const unsigned char prefix[]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,
        0x41,0x55,0x41,0x54,0x53,0x48,0x83,0xec,0x28};
    assert(safeRoutePrefix(prefix,sizeof(prefix))==sizeof(prefix));
    assert(!safeRoutePrefix(nullptr,48));
    for (size_t n=0;n<sizeof(prefix);++n) assert(!safeRoutePrefix(prefix,n));
    unsigned char bytes[48]; memset(bytes,0x90,sizeof(bytes));
    assert(safeRoutePrefix(bytes,sizeof(bytes))==14);
    const unsigned char endbr[]={0xf3,0x0f,0x1e,0xfa};
    memcpy(bytes,endbr,4);assert(safeRoutePrefix(bytes,sizeof(bytes))==14);
    // Each transfer type and RIP-based load must refuse before copying. A
    // decoder that merely counts bytes would turn these into broken calls.
    const unsigned char rejected[][7]={
        {0xe8,0,0,0,0}, {0xe9,0,0,0,0}, {0xeb,0}, {0x74,0},
        {0x0f,0x84,0,0,0,0}, {0xff,0x25,0,0,0,0},
        {0x48,0x8b,0x05,0,0,0,0}, {0x48,0x89,0x05,0,0,0,0},
        {0xc3}, {0xcc}, {0x48,0x83,0xec,0xff}
    };
    for (const auto &instruction:rejected) for (size_t offset=0;offset<14;++offset) {
        memset(bytes,0x90,sizeof(bytes));memcpy(bytes+offset,instruction,sizeof(instruction));
        assert(!safeRoutePrefix(bytes,sizeof(bytes)));
    }
    // Reject partial instructions even if the total input reaches 14 bytes.
    memset(bytes,0x90,sizeof(bytes));bytes[13]=0x48;
    bytes[14]=0x81;bytes[15]=0xec;bytes[16]=0;bytes[17]=0x10;bytes[18]=0;bytes[19]=0;
    for(size_t n=14;n<20;++n)assert(!safeRoutePrefix(bytes,n));
    assert(safeRoutePrefix(bytes,20)==20);
    bytes[19]=0x80;assert(!safeRoutePrefix(bytes,20));
}
'''


class IfnetKPIContractTests(unittest.TestCase):
    def test_position_independent_prefix_with_sanitizers(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/"prefix.cpp"
            output=Path(directory)/"prefix"
            source.write_text(HARNESS)
            subprocess.run(["xcrun","clang++","-std=c++14","-Wall","-Wextra","-Werror",
                            "-fsanitize=address,undefined","-fno-omit-frame-pointer",
                            "-I",str(ROOT),str(source),"-o",str(output)],check=True,capture_output=True)
            subprocess.run([str(output)],check=True,capture_output=True)


if __name__ == "__main__":
    unittest.main()
