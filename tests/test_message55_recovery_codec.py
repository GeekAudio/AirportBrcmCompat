"""Independent offline message55 shape tests; no real client/event/driver call."""
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / "src/awdl_compat/message55_recovery_codec.c"

HARNESS = r'''
#include "message55_recovery_codec.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static struct m55r_context context(void) {
    struct m55r_context c={1,2,6}; return c;
}
static void le32(uint8_t *p,uint32_t n) {
    for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(n>>(8*i));
}
/* Fixtures independently encode the actual stores in the pinned old/new
 * producers. Python tests below also bind those stores to binary bytes. */
static void old_notice(uint8_t p[184]) {
    memset(p,0,184);le32(p,4);le32(p+8,1);le32(p+12,UINT32_C(0xe0821803));
}
static void native_notice(uint8_t p[248]) {
    memset(p,0,248);le32(p,3);le32(p+8,1);le32(p+16,UINT32_C(0xe0821803));
}
static void rejected(const struct m55r_context *c,uint32_t id,
                     const void *p,size_t n,enum m55r_status expected) {
    struct m55r_event out,before;memset(&out,0x6d,sizeof(out));before=out;
    uint8_t in_before[184];struct m55r_context cb=*c;
    if(p && n==184)memcpy(in_before,p,184);
    assert(m55r_translate(c,id,p,n,&out)==expected);
    assert(!memcmp(&out,&before,sizeof(out)));
    assert(!memcmp(c,&cb,sizeof(cb)));
    if(p && n==184)assert(!memcmp(p,in_before,184));
}
static void valid(void) {
    uint8_t old[184],copy[184],expected[248];old_notice(old);
    memcpy(copy,old,184);native_notice(expected);
    struct m55r_context c=context(),before=c;struct m55r_event out;
    memset(&out,0xa5,sizeof(out));
    assert(m55r_translate(&c,55,old,184,&out)==M55R_OK);
    assert(out.message==55 && out.body_size==248);
    assert(out.meaning==M55R_REPORTED_POWER_ON_COMPLETION);
    assert(!memcmp(out.body,expected,248));
    assert(!memcmp(old,copy,184) && !memcmp(&c,&before,sizeof(c)));
    /* The legacy prefix is not copied: word0 changes and reason moves. */
    assert(out.body[0]==3 && !out.body[12] && out.body[16]==3);
}
static void exhaustive(void) {
    uint8_t old[184];old_notice(old);struct m55r_context c=context();
    for(size_t i=0;i<184;++i) {
        uint8_t original=old[i];
        for(unsigned byte=0;byte<256;++byte)if(byte!=original) {
            old[i]=(uint8_t)byte;rejected(&c,55,old,184,M55R_CONTENT);
        }
        old[i]=original;
    }
    /* Ordinary health and another real diagnostic-shaped prefix stay refused. */
    memset(old,0,184);le32(old+8,1);
    rejected(&c,55,old,184,M55R_CONTENT);
    le32(old+16,UINT32_C(0xe3ff850e));
    rejected(&c,55,old,184,M55R_CONTENT);
    memset(old,0,184);le32(old,4);le32(old+16,UINT32_C(0xe0823801));
    rejected(&c,55,old,184,M55R_CONTENT);
}
static void lengths_messages(void) {
    uint8_t old[184];old_notice(old);struct m55r_context c=context();
    for(size_t n=0;n<=512;++n)if(n!=184)rejected(&c,55,old,n,M55R_LENGTH);
    rejected(&c,55,old,SIZE_MAX,M55R_LENGTH);
    rejected(&c,55,old,SIZE_MAX-1,M55R_LENGTH);
    for(uint32_t id=0;id<=255;++id)if(id!=55)
        rejected(&c,id,old,184,M55R_UNKNOWN);
    rejected(&c,UINT32_MAX,old,184,M55R_UNKNOWN);
}
static void arguments_context(void) {
    uint8_t old[184];old_notice(old);struct m55r_context c=context();
    struct m55r_event out,before;memset(&out,0x52,sizeof(out));before=out;
    assert(m55r_translate(NULL,55,old,184,&out)==M55R_ARGUMENT);
    assert(!memcmp(&out,&before,sizeof(out)));
    assert(m55r_translate(&c,55,old,184,NULL)==M55R_ARGUMENT);
    rejected(&c,55,NULL,184,M55R_ARGUMENT);
    for(unsigned field=0;field<3;++field)for(uint32_t value=0;value<256;++value) {
        struct m55r_context bad=context();
        uint32_t *where=field==0?&bad.source_abi:
            field==1?&bad.destination_abi:&bad.destination_role;
        if(value==*where)continue;
        *where=value;rejected(&bad,55,old,184,M55R_CONTEXT);
    }
    c.source_abi=UINT32_MAX;rejected(&c,55,old,184,M55R_CONTEXT);c=context();
    assert(m55r_translate((const struct m55r_context *)(UINTPTR_MAX-3),55,
                          old,184,&out)==M55R_ARGUMENT);
    assert(m55r_translate(&c,55,old,184,
                          (struct m55r_event *)(UINTPTR_MAX-3))==M55R_ARGUMENT);
    assert(m55r_translate(&c,55,(const void *)(UINTPTR_MAX-3),184,&out)==M55R_ARGUMENT);
    assert(!memcmp(&out,&before,sizeof(out)));
    union {max_align_t align;uint8_t bytes[512];} a;
    memset(&a,0,sizeof(a));memcpy(a.bytes+1,&c,sizeof(c));
    assert(m55r_translate((const struct m55r_context *)(a.bytes+1),55,
                          old,184,&out)==M55R_ARGUMENT);
    assert(m55r_translate(&c,55,old,184,
                          (struct m55r_event *)(a.bytes+1))==M55R_ARGUMENT);
}
static void aliases(void) {
    union {max_align_t align;uint8_t bytes[1200];} a;
    uint8_t before[1200],old[184];old_notice(old);
    struct m55r_context c=context();struct m55r_event out,out_before;
    /* Every overlapping byte offset; no struct dereference before alias exit. */
    for(int delta=-259;delta<184;++delta) {
        memset(&a,0x57,sizeof(a));memcpy(a.bytes+512,old,184);
        memcpy(before,a.bytes,sizeof(before));
        assert(m55r_translate(&c,55,a.bytes+512,184,
             (struct m55r_event *)(a.bytes+512+delta))==M55R_ALIAS);
        assert(!memcmp(a.bytes,before,sizeof(before)));
    }
    for(int delta=-259;delta<12;++delta) {
        memset(&a,0x39,sizeof(a));memcpy(a.bytes+512,&c,sizeof(c));
        memcpy(before,a.bytes,sizeof(before));
        assert(m55r_translate((struct m55r_context *)(a.bytes+512),55,old,184,
             (struct m55r_event *)(a.bytes+512+delta))==M55R_ALIAS);
        assert(!memcmp(a.bytes,before,sizeof(before)));
    }
    for(int delta=-183;delta<12;++delta) {
        memset(&a,0x41,sizeof(a));memcpy(a.bytes+512+delta,old,184);
        memcpy(before,a.bytes,sizeof(before));memset(&out,0x44,sizeof(out));out_before=out;
        assert(m55r_translate((struct m55r_context *)(a.bytes+512),55,
                              a.bytes+512+delta,184,&out)==M55R_ALIAS);
        assert(!memcmp(a.bytes,before,sizeof(before)));
        assert(!memcmp(&out,&out_before,sizeof(out)));
    }
    /* Adjacent, aligned ranges are accepted rather than classified overlap. */
    for(int delta=-260;delta<=184;delta+=444) {
        memset(&a,0,sizeof(a));memcpy(a.bytes+512,old,184);
        assert(m55r_translate(&c,55,a.bytes+512,184,
             (struct m55r_event *)(a.bytes+512+delta))==M55R_OK);
    }
    memset(&a,0,sizeof(a));memcpy(a.bytes,old,184);memcpy(a.bytes+184,&c,sizeof(c));
    assert(m55r_translate((struct m55r_context *)(a.bytes+184),55,
                          a.bytes,184,(struct m55r_event *)(a.bytes+512))==M55R_OK);
    memset(&a,0,sizeof(a));memcpy(a.bytes+512,old,184);memcpy(a.bytes+260,&c,sizeof(c));
    assert(m55r_translate((struct m55r_context *)(a.bytes+260),55,
                          a.bytes+512,184,(struct m55r_event *)a.bytes)==M55R_OK);
}
static uint8_t *guarded(size_t page) {
    uint8_t *p=mmap(NULL,3*page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
    assert(p!=MAP_FAILED && mprotect(p+page,page,PROT_READ|PROT_WRITE)==0);return p;
}
static void guard_pages(void) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);assert(page>sizeof(struct m55r_event));
    uint8_t *a=guarded(page),*b=guarded(page),*d=guarded(page);
    uint8_t *input=a+2*page-184;old_notice(input);
    struct m55r_context c=context(),*cp=(struct m55r_context *)(b+2*page-sizeof(c));
    memcpy(cp,&c,sizeof(c));struct m55r_event *out=(struct m55r_event *)(d+2*page-sizeof(*out));
    assert(m55r_translate(cp,55,input,184,out)==M55R_OK);
    uint8_t expected[248];native_notice(expected);assert(!memcmp(out->body,expected,248));
    input[183]=1;assert(m55r_translate(cp,55,input,184,out)==M55R_CONTENT);
    assert(munmap(a,3*page)==0 && munmap(b,3*page)==0 && munmap(d,3*page)==0);
}
int main(int argc,char **argv) {
    assert(argc==2);
    if(!strcmp(argv[1],"valid"))valid();
    else if(!strcmp(argv[1],"exhaustive"))exhaustive();
    else if(!strcmp(argv[1],"lengths_messages"))lengths_messages();
    else if(!strcmp(argv[1],"arguments_context"))arguments_context();
    else if(!strcmp(argv[1],"aliases"))aliases();
    else if(!strcmp(argv[1],"guard_pages"))guard_pages();
    else assert(0);
    puts("offline message55 scenario passed");return 0;
}
'''


class Message55RecoveryCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="message55-offline-")
        folder = Path(cls.directory.name)
        harness = folder / "harness.c"
        harness.write_text(HARNESS)
        cls.executable = folder / "harness"
        subprocess.run([
            "xcrun", "clang", "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "-I", str(SOURCE.parent), str(SOURCE), str(harness), "-o", str(cls.executable)
        ], check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_scenario(self, name):
        result = subprocess.run([str(self.executable), name], capture_output=True,
                                text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_exact_native_shape_and_no_input_writes(self):
        self.run_scenario("valid")

    def test_all_184_times_255_single_byte_changes_rejected(self):
        self.run_scenario("exhaustive")

    def test_lengths_and_unknown_messages(self):
        self.run_scenario("lengths_messages")

    def test_abi_role_null_overflow_and_alignment(self):
        self.run_scenario("arguments_context")

    def test_every_overlap_offset_and_adjacent_ranges(self):
        self.run_scenario("aliases")

    def test_real_guard_pages_for_exact_ranges(self):
        self.run_scenario("guard_pages")

    def test_freestanding_no_driver_imports(self):
        output = Path(self.directory.name) / "codec.o"
        subprocess.run(["xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
                        "-c", str(SOURCE), "-o", str(output)],
                       check=True, capture_output=True, text=True)
        undefined = subprocess.check_output(["xcrun", "nm", "-u", str(output)], text=True)
        self.assertTrue(all(line.split()[-1] in ("_memcpy", "_memset")
                            for line in undefined.splitlines() if line.strip()), undefined)


if __name__ == "__main__":
    unittest.main()
