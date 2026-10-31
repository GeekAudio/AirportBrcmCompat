"""Host replay of Tahoe's native SET22 flush-dword normalization bytes.

The test extracts only cmp/setne/movzx from the retained native BootKC and
executes those instructions in a tiny userland function with a host pointer
shim. It never calls or jumps into a kernel function.
"""
from pathlib import Path
import hashlib
import platform
import shutil
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
BOOTKC = Path("/System/Library/KernelCollections/BootKernelExtensions.kc")
BOOTKC_SHA256 = "96c12f421a8e99580b5015dfd39877df38ecde9b9e056b8ccd28f15847bca35c"
FUNCTION_FILE_OFFSET = 0x2095AA6
FUNCTION_SIZE = 90
FUNCTION_SHA256 = "fc637a3ec750b83953b78ec3f6544cefaf908a6e46cc24363e8f4ed4035a64a0"


def instruction_bytes(source: bytes) -> bytes:
    """Return actual cmp/setne/movzx bytes from the pinned setDISASSOCIATE."""
    start = FUNCTION_FILE_OFFSET
    body = source[start:start + FUNCTION_SIZE]
    if len(body) != FUNCTION_SIZE:
        raise AssertionError("retained BootKC is too short for the pinned function")
    if hashlib.sha256(body).hexdigest() != FUNCTION_SHA256:
        raise AssertionError("pinned WCL setDISASSOCIATE function hash changed")

    # 0x2195ab6: cmp dword ptr [rax+8], 0
    # 0x2195aba: setne al
    # 0x2195ad5: movzx eax, al
    parts = (body[0x10:0x14], body[0x14:0x17], body[0x2F:0x32])
    if parts != (bytes.fromhex("83780800"), bytes.fromhex("0f95c0"),
                 bytes.fromhex("0fb6c0")):
        raise AssertionError("native flush normalization opcode bytes changed")
    return b"".join(parts)


def replay_source(native_bytes: bytes) -> str:
    encoded = ", ".join(f"0x{byte:02x}" for byte in native_bytes)
    return r"""
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern "C" __attribute__((naked, noinline)) uint32_t
replay_native_flush(const uint8_t *request) {
    __asm__ __volatile__(
        "mov %rdi, %rax\n\t"  // host-only argument shim: RAX = request
        ".byte NATIVE_BYTES\n\t"
        "ret\n\t"
    );
}

int main() {
    uint32_t values[37] = {0u, 1u, 2u, 3u};
    for (unsigned bit = 0; bit < 32; ++bit) values[4 + bit] = uint32_t(1u) << bit;
    values[36] = 0xffffffffu;

    for (unsigned index = 0; index < 37; ++index) {
        uint8_t request[12] = {0x11, 0x22, 0x33, 0x44,
                               0x55, 0x66, 0x77, 0x88, 0, 0, 0, 0};
        uint8_t before[sizeof(request)];
        memcpy(request + 8, &values[index], sizeof(values[index]));
        memcpy(before, request, sizeof(request));

        uint32_t got = replay_native_flush(request);
        uint32_t expected = values[index] == 0 ? 0u : 1u;
        if (got != expected || memcmp(request, before, sizeof(request)) != 0) {
            fprintf(stderr, "case %u: input=0x%08x got=%u expected=%u mutated=%d\n",
                    index, values[index], got, expected,
                    memcmp(request, before, sizeof(request)) != 0);
            return 1;
        }
    }
    puts("Tahoe native SET22 flush normalization replay passed");
    return 0;
}
""".replace("NATIVE_BYTES", encoded)


class NativeDisassociateBooleanReplay(unittest.TestCase):
    def test_native_flush_dword_is_boolean_nonzero(self):
        if platform.machine().lower() not in ("x86_64", "amd64"):
            self.skipTest("replay requires an x86_64 host for the native instruction bytes")
        if not BOOTKC.is_file():
            self.skipTest("the retained Tahoe host BootKC is unavailable")

        source = BOOTKC.read_bytes()
        if hashlib.sha256(source).hexdigest() != BOOTKC_SHA256:
            self.skipTest("host BootKC is not the retained Tahoe instruction sample")
        native_bytes = instruction_bytes(source)
        clang = shutil.which("clang++")
        if not clang:
            self.skipTest("clang++ is required for the bounded host replay")

        with tempfile.TemporaryDirectory(prefix="disassociate-boolean-") as tmp:
            root = Path(tmp)
            harness = root / "flush_replay.cpp"
            binary = root / "flush_replay"
            harness.write_text(replay_source(native_bytes))
            subprocess.run(
                [clang, "-std=c++17", "-O0", "-fno-stack-protector",
                 str(harness), "-o", str(binary)],
                check=True,
                cwd=PROJECT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            completed = subprocess.run(
                [str(binary)], check=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            )
            self.assertIn("replay passed", completed.stdout)


if __name__ == "__main__":
    unittest.main()
