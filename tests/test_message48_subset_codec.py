"""Compile and execute the real independent C codec with synthetic bodies only.

No driver, IOUserClient, network, descriptor, permission or source-provenance
claims are mocked into success. This tests bounded transport, not AirDrop.
"""
import ctypes
import pathlib
import struct
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAX = 2048
OK, ARGUMENT, CONTEXT, UNKNOWN, LENGTH, CONTENT, ALIAS = range(7)
(R_ARGUMENT, R_ALIAS, R_CONTEXT, R_MESSAGE, R_BODY_LENGTH, R_RESERVED6,
 R_RESERVED24, R_RESERVED52, R_METADATA_VERSION, R_CHANNEL, R_CHANNEL_FLAGS,
 R_FRAME_PREFIX, R_FRAME_SUBTYPE, R_FRAME_FLAGS, R_TLV_HEADER,
 R_TLV_LENGTH, R_FRAME_VERSION) = [1 << bit for bit in range(17)]
LEGAL_FLAGS = {band | width | dfs | extension
               for band in (0x8, 0x10) for width in (1, 2, 4, 0x400)
               for dfs in (0, 0x100)
               for extension in ((0, 0x200) if width == 4 else (0,))}
ORIGINAL_FLAGS = {0x9, 0x11}


class Context(ctypes.Structure):
    _fields_ = [("source_abi", ctypes.c_uint32),
                ("destination_abi", ctypes.c_uint32),
                ("virtual_role", ctypes.c_uint32)]


class Event(ctypes.Structure):
    _fields_ = [("message", ctypes.c_uint32), ("body_size", ctypes.c_uint32),
                ("attribute_count", ctypes.c_uint32),
                ("body", ctypes.c_uint8 * MAX)]


class Result(ctypes.Structure):
    _fields_ = [("error", ctypes.c_int), ("reject_mask", ctypes.c_uint32)]


def body(tlvs=b"", subtype=0, flags=0x9):
    h = bytearray(72)
    # Synthetic locally administered address, never a captured identity.
    h[:6] = bytes([2, 0, 0, 0, 0, 1])
    struct.pack_into("<III", h, 12, 1, 6, flags)
    struct.pack_into("<IiI", h, 40, 54000, -71, 0x12345678)
    f = bytes([127, 0, 0x17, 0xf2, 8, 0x10, subtype, 0])
    f += struct.pack("<II", 0x01020304, 0x8899aabb)
    return bytes(h) + f + tlvs


class Message48SubsetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="awdl48-offline-")
        lib = pathlib.Path(cls.tmp.name) / "codec.dylib"
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-O2", "-dynamiclib", "-I", str(ROOT / "src/awdl_compat"),
                        "-o", str(lib), str(ROOT / "src/awdl_compat/message48_subset_codec.c")],
                       check=True, capture_output=True)
        cls.lib = ctypes.CDLL(str(lib))
        cls.fn = cls.lib.awcm48_translate
        cls.fn.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                           ctypes.c_size_t, ctypes.c_void_p]
        cls.fn.restype = ctypes.c_int
        cls.diagnosed = cls.lib.awcm48_translate_diagnosed
        cls.diagnosed.argtypes = cls.fn.argtypes
        cls.diagnosed.restype = Result

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def invoke(self, raw, expected=OK, *, context=None, message=48, mask=None):
        ctx = context or Context(1, 2, 6)
        src = ctypes.create_string_buffer(raw, len(raw))
        original = bytes(src)
        out = Event()
        ctypes.memset(ctypes.byref(out), 0xa5, ctypes.sizeof(out))
        old = bytes(out)
        args = (ctypes.byref(ctx), message, src, len(raw), ctypes.byref(out))
        rc = self.fn(*args)
        self.assertEqual(rc, expected)
        expected_output = bytes(out)
        ctypes.memmove(ctypes.byref(out), old, ctypes.sizeof(out))
        diagnostic = self.diagnosed(*args)
        self.assertEqual(diagnostic.error, rc)
        self.assertEqual(bytes(out), expected_output)
        if mask is not None:
            self.assertEqual(diagnostic.reject_mask, mask)
        elif rc:
            self.assertNotEqual(diagnostic.reject_mask, 0)
        else:
            self.assertEqual(diagnostic.reject_mask, 0)
        self.assertEqual(bytes(src), original)
        if rc:
            self.assertEqual(bytes(out), old)
        else:
            self.assertEqual(out.message, 48)
            self.assertEqual(out.body_size, len(raw))
            self.assertEqual(bytes(out.body[:len(raw)]), raw)
            self.assertEqual(bytes(out.body[len(raw):]), bytes(MAX-len(raw)))
        return out

    def argument_error(self, args, expected, mask):
        """Also compare early-exit calls with invalid/aliased pointer shapes."""
        self.assertEqual(self.fn(*args), expected)
        value = self.diagnosed(*args)
        self.assertEqual((value.error, value.reject_mask), (expected, mask))

    def test_empty_and_both_proven_subtypes(self):
        for subtype in (0, 3):
            for flags in (0x9, 0x11):
                self.assertEqual(self.invoke(body(subtype=subtype, flags=flags)).attribute_count, 0)

    def test_all_tlv_types_preserved_without_semantic_invention(self):
        # Even an unknown semantic type is structurally copied, not dropped.
        tlvs = b"".join(bytes([t, 2, 0, t, t ^ 0xff]) for t in range(256))
        out = self.invoke(body(tlvs))
        self.assertEqual(out.attribute_count, 256)

    def test_zero_length_and_embedded_binary_tlv_values(self):
        out = self.invoke(body(b"\x00\x00\x00\xff\x04\x00\x00\xff\x80\x01"))
        self.assertEqual(out.attribute_count, 2)

    def test_each_reserved_metadata_byte_rejected(self):
        for n in [*range(6, 12), *range(24, 40), *range(52, 72)]:
            raw = bytearray(body()); raw[n] = 1
            mask = R_RESERVED6 if n < 12 else R_RESERVED24 if n < 40 else R_RESERVED52
            with self.subTest(offset=n): self.invoke(bytes(raw), CONTENT, mask=mask)

    def test_channel_version_width_and_unknown_flags(self):
        for off, value in ((12, 0), (12, 2), (12, 0x80000001),
                           (16, 0), (16, 256), (16, 0xffffffff),
                           (20, 0), (20, 0x19), (20, 0xb), (20, 0x119),
                           (20, 0x209), (20, 0x809), (20, 0x2009)):
            raw = bytearray(body()); struct.pack_into("<I", raw, off, value)
            mask = {12: R_METADATA_VERSION, 16: R_CHANNEL, 20: R_CHANNEL_FLAGS}[off]
            with self.subTest(offset=off, value=value): self.invoke(bytes(raw), CONTENT, mask=mask)
        for channel in (1, 255):
            raw = bytearray(body()); struct.pack_into("<I", raw, 16, channel)
            self.invoke(bytes(raw))

    def test_each_frame_signature_byte_and_unknown_modes_rejected(self):
        for off in range(8):
            raw = bytearray(body()); raw[72+off] ^= 0x80
            mask = (R_FRAME_PREFIX if off < 5 else R_FRAME_VERSION if off == 5
                    else R_FRAME_SUBTYPE if off == 6 else R_FRAME_FLAGS)
            with self.subTest(offset=off): self.invoke(bytes(raw), CONTENT, mask=mask)
        for subtype in (1, 2, 4, 255):
            self.invoke(body(subtype=subtype), CONTENT, mask=R_FRAME_SUBTYPE)

    def test_all_truncated_prefixes_fail_without_output_write(self):
        raw = body()
        for n in range(1, len(raw)):
            with self.subTest(size=n): self.invoke(raw[:n], LENGTH, mask=R_BODY_LENGTH)

    def test_tlv_boundaries_exhaustion_and_no_trailing_bytes(self):
        for tlv, mask in ((b"\x01", R_TLV_HEADER), (b"\x01\x00", R_TLV_HEADER),
                          (b"\x01\x01\x00", R_TLV_LENGTH),
                          (b"\x01\xff\xff", R_TLV_LENGTH),
                          (b"\x01\x00\x00\x02", R_TLV_HEADER),
                          (b"\x01\x00\x00\x02\x00", R_TLV_HEADER)):
            self.invoke(body(tlv), LENGTH, mask=mask)
        # LE16, not an accidental byte-sized length.
        tlv = bytes([0xfa, 0, 1])+bytes(range(256))
        self.assertEqual(self.invoke(body(tlv)).attribute_count, 1)

    def test_exact_capacity_and_one_over(self):
        length = MAX-72-16-3
        raw = body(bytes([0xff])+struct.pack("<H", length)+bytes([0x5a])*length)
        self.assertEqual(len(raw), MAX)
        self.invoke(raw)
        self.invoke(raw+b"\x00", LENGTH, mask=R_BODY_LENGTH)

    def test_context_and_unknown_message_are_not_authorization(self):
        for ctx in (Context(0, 2, 6), Context(1, 0, 6), Context(1, 2, 7)):
            self.invoke(body(), CONTEXT, context=ctx, mask=R_CONTEXT)
        for message in (46, 47, 55, 0xffffffff):
            self.invoke(body(), UNKNOWN, message=message, mask=R_MESSAGE)

    def test_output_alias_and_address_overflow_rejected_before_dereference(self):
        ctx = Context(1, 2, 6)
        out = Event()
        ctypes.memset(ctypes.byref(out), 0xa5, ctypes.sizeof(out)); old = bytes(out)
        self.argument_error((ctypes.byref(ctx), 48, ctypes.byref(out), 88,
                             ctypes.byref(out)), ALIAS, R_ALIAS)
        self.assertEqual(bytes(out), old)
        self.argument_error((ctypes.byref(out), 48, ctypes.byref(out), 88,
                             ctypes.byref(out)), ALIAS, R_ALIAS)
        maxptr = (1 << (ctypes.sizeof(ctypes.c_void_p)*8))-1
        self.argument_error((ctypes.byref(ctx), 48, maxptr-20, 88,
                             ctypes.byref(out)), ALIAS, R_ALIAS)
        self.assertEqual(bytes(out), old)

    def test_null_arguments_fail_without_output_write(self):
        ctx = Context(1, 2, 6); src = ctypes.create_string_buffer(body()); out = Event()
        ctypes.memset(ctypes.byref(out), 0xa5, ctypes.sizeof(out)); old = bytes(out)
        for args in ((None, 48, src, 88, ctypes.byref(out)),
                     (ctypes.byref(ctx), 48, None, 88, ctypes.byref(out)),
                     (ctypes.byref(ctx), 48, src, 88, None)):
            self.argument_error(args, ARGUMENT, R_ARGUMENT)
        self.assertEqual(bytes(out), old)

    def test_first_failed_stage_and_same_stage_masks(self):
        raw = bytearray(body(b"\x01"))
        raw[6] = raw[24] = raw[52] = 1
        struct.pack_into("<III", raw, 12, 2, 0, 0)
        raw[72:80] = bytes(8)  # Also invalid frame and TLV; not reported yet.
        self.invoke(bytes(raw), CONTENT, mask=(R_RESERVED6 | R_RESERVED24 |
                    R_RESERVED52 | R_METADATA_VERSION))
        raw = bytearray(body(b"\x01"))
        struct.pack_into("<II", raw, 16, 0, 0)
        raw[72:80] = bytes(8)
        self.invoke(bytes(raw), CONTENT, mask=R_CHANNEL | R_CHANNEL_FLAGS)
        raw = bytearray(body(b"\x01")); raw[72] = raw[77] = raw[78] = raw[79] = 1
        self.invoke(bytes(raw), CONTENT, mask=(R_FRAME_PREFIX | R_FRAME_VERSION |
                                              R_FRAME_SUBTYPE | R_FRAME_FLAGS))

    def test_original_alias_length_error_precedence_without_body_dereference(self):
        ctx = Context(1, 2, 6); bad = Context(0, 0, 0); out = Event()
        ctypes.memset(ctypes.byref(out), 0xa5, ctypes.sizeof(out)); old = bytes(out)
        # Invalid input pointer is harmless when an earlier stage must exit.
        self.argument_error((None, 0, 1, 0, ctypes.byref(out)), ARGUMENT, R_ARGUMENT)
        self.argument_error((ctypes.byref(out), 0, 1, 0, ctypes.byref(out)), ALIAS, R_ALIAS)
        self.argument_error((ctypes.byref(bad), 0, 1, 0, ctypes.byref(out)), CONTEXT, R_CONTEXT)
        self.argument_error((ctypes.byref(ctx), 0, 1, 0, ctypes.byref(out)), UNKNOWN, R_MESSAGE)
        # Input/output alias is tested AFTER body length in the original API.
        self.argument_error((ctypes.byref(ctx), 48, ctypes.byref(out), 1,
                             ctypes.byref(out)), LENGTH, R_BODY_LENGTH)
        self.assertEqual(bytes(out), old)

    def test_deterministic_mutations_keep_diagnostic_and_public_results_in_sync(self):
        raw = body(b"\x01\x03\x00abc\xff\x00\x00")
        # Exercise every metadata/frame byte and every LE16 TLV size field with
        # multiple bit patterns; old error and every output byte are the oracle.
        for offset in range(len(raw)):
            for value in (0, 1, 3, 0x11, 0x80, 0xff):
                changed = bytearray(raw); changed[offset] = value
                flags = struct.unpack_from('<I', changed, 20)[0]
                if flags in LEGAL_FLAGS - ORIGINAL_FLAGS:
                    continue  # The separately tested, explicitly authorized extension.
                ctx = Context(1, 2, 6); src = ctypes.create_string_buffer(bytes(changed))
                outputs = [Event(), Event()]
                for output in outputs:
                    ctypes.memset(ctypes.byref(output), 0xa5, ctypes.sizeof(output))
                a = (ctypes.byref(ctx), 48, src, len(changed))
                actual = self.fn(*a, ctypes.byref(outputs[0]))
                diagnostic = self.diagnosed(*a, ctypes.byref(outputs[1]))
                self.assertEqual(diagnostic.error, actual)
                self.assertEqual(bytes(outputs[0]), bytes(outputs[1]))
                self.assertEqual(bool(diagnostic.reject_mask), bool(actual))

    def test_exact_twenty_structural_channel_flag_combinations(self):
        self.assertEqual(len(LEGAL_FLAGS), 20)
        for flags in sorted(LEGAL_FLAGS):
            for subtype in (0, 3):
                with self.subTest(flags=flags, subtype=subtype):
                    out = self.invoke(body(b'\xff\x02\x00\x00\x80', subtype, flags),
                                      mask=0)
                    self.assertEqual(struct.unpack_from('<I', out.body, 20)[0], flags)

    def test_unproven_flag_fields_cannot_hide_inside_allowed_mask(self):
        bad = {0x8, 0x10, 0x108, 0x110, 0x2, 0x1a, 0x18, 0x1b,
               0x0b, 0x0d, 0x0e, 0x409, 0x209, 0x20a, 0x608,
               0x800 | 0x8, 0x2000 | 0x2}
        for bit in range(32):
            if not ((1 << bit) & 0x71f): bad.add(0x0a | (1 << bit))
        for flags in sorted(bad):
            with self.subTest(flags=flags):
                self.invoke(body(flags=flags), CONTENT, mask=R_CHANNEL_FLAGS)
        # Exhaust every flag combination in the legacy bit envelope. This is
        # a finite format allowlist, not regulatory/on-air channel approval.
        for flags in range(0x800):
            raw = body(flags=flags)
            if flags in LEGAL_FLAGS:
                self.invoke(raw, OK, mask=0)
            else:
                self.invoke(raw, CONTENT, mask=R_CHANNEL_FLAGS)

    def test_new_channel_flags_do_not_skip_other_guards(self):
        for flags in (0x0a, 0x12, 0x314, 0x510):
            for offset, mask in ((6, R_RESERVED6), (72, R_FRAME_PREFIX),
                                 (77, R_FRAME_VERSION), (78, R_FRAME_SUBTYPE),
                                 (79, R_FRAME_FLAGS)):
                raw = bytearray(body(flags=flags)); raw[offset] ^= 0x80
                self.invoke(bytes(raw), CONTENT, mask=mask)
            self.invoke(body(b'\x01', flags=flags), LENGTH,
                        mask=R_TLV_HEADER)
            self.invoke(body(b'\x01\x01\x00', flags=flags), LENGTH,
                        mask=R_TLV_LENGTH)

    def test_protected_later_stages_are_not_read_asan_ubsan(self):
        """Real codec calls; PROT_NONE begins at the next validation stage."""
        code = r'''
#include "message48_subset_codec.h"
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
static void put32(uint8_t *p,uint32_t n) {memcpy(p,&n,4);}
static void valid(uint8_t *p,size_t n) {
    memset(p,0,n);put32(p+12,1);put32(p+16,6);put32(p+20,9);
    if(n>=88) {const uint8_t f[8]={127,0,0x17,0xf2,8,0x10,0,0};memcpy(p+72,f,8);}
}
static void check(const uint8_t *p,size_t n,enum awcm_error error,uint32_t mask) {
    const struct awcm_context c={1,2,6};struct awcm48_event out,before;
    memset(&out,0xa5,sizeof(out));memcpy(&before,&out,sizeof(out));
    assert(awcm48_translate(&c,48,p,n,&out)==error);
    assert(!memcmp(&out,&before,sizeof(out)));
    struct awcm48_result r=awcm48_translate_diagnosed(&c,48,p,n,&out);
    assert(r.error==error && r.reject_mask==mask);
    assert(!memcmp(&out,&before,sizeof(out)));
}
int main(void) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    uint8_t *m=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    assert(m!=MAP_FAILED && !mprotect(m+page,page,PROT_NONE));
    uint8_t *p=m+page-72;valid(p,72);p[6]=1;
    check(p,88,AWCM_CONTENT,AWCM48_REJECT_RESERVED6);
    p[6]=0;put32(p+16,0);check(p,88,AWCM_CONTENT,AWCM48_REJECT_CHANNEL);
    p=m+page-88;valid(p,88);p[77]=0;
    check(p,91,AWCM_CONTENT,AWCM48_REJECT_FRAME_VERSION);
    p[77]=0x10;check(p,89,AWCM_LENGTH,AWCM48_REJECT_TLV_HEADER);
    p=m+page-91;valid(p,91);p[88]=1;p[89]=1;
    check(p,91,AWCM_LENGTH,AWCM48_REJECT_TLV_LENGTH);
    assert(!munmap(m,2*page));
}
'''
        folder = pathlib.Path(self.tmp.name)
        harness = folder / 'stages.c'; harness.write_text(code)
        binary = folder / 'stages'
        common = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1',
                  '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                  '-I', str(ROOT / 'src/awdl_compat')]
        subprocess.run([*common, str(harness),
                        str(ROOT / 'src/awdl_compat/message48_subset_codec.c'),
                        '-o', str(binary)], check=True, capture_output=True)
        subprocess.run([str(binary)], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
