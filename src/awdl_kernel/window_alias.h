// SipHash-2-4 specialized to one six-byte diagnostic address. The random key
// is window-local and never exported. This is not wireless authentication.
#ifndef AIRPORT_AWDL_WINDOW_ALIAS_H
#define AIRPORT_AWDL_WINDOW_ALIAS_H
#include <stdint.h>
static inline uint64_t awdl_alias_rot(uint64_t x,unsigned n){return (x<<n)|(x>>(64-n));}
static inline uint64_t awdl_alias_load8(const uint8_t *p){uint64_t x=0;for(unsigned j=0;j<8;j++)x|=(uint64_t)p[j]<<(j*8);return x;}
static inline uint64_t awdl_window_alias6(const uint8_t key[16],const uint8_t address[6]) {
    const uint64_t k0=awdl_alias_load8(key),k1=awdl_alias_load8(key+8);
    uint64_t v0=UINT64_C(0x736f6d6570736575)^k0,v1=UINT64_C(0x646f72616e646f6d)^k1;
    uint64_t v2=UINT64_C(0x6c7967656e657261)^k0,v3=UINT64_C(0x7465646279746573)^k1;
    uint64_t m=UINT64_C(6)<<56;for(unsigned j=0;j<6;j++)m|=(uint64_t)address[j]<<(j*8);
#define AWDL_ALIAS_ROUND() do {v0+=v1;v1=awdl_alias_rot(v1,13);v1^=v0;v0=awdl_alias_rot(v0,32); \
    v2+=v3;v3=awdl_alias_rot(v3,16);v3^=v2;v0+=v3;v3=awdl_alias_rot(v3,21);v3^=v0; \
    v2+=v1;v1=awdl_alias_rot(v1,17);v1^=v2;v2=awdl_alias_rot(v2,32);} while(0)
    v3^=m;for(unsigned j=0;j<2;j++)AWDL_ALIAS_ROUND();v0^=m;v2^=0xff;
    for(unsigned j=0;j<4;j++)AWDL_ALIAS_ROUND();
#undef AWDL_ALIAS_ROUND
    return v0^v1^v2^v3;
}
#endif
