/* Audited native 25G241 x86_64 IO80211 type-0 protocol, diagnostics only.
 * Source: native getter and BindToInterfaceWithService disassembly. No system
 * headers claim this private layout; callers must pin/re-audit the native build.
 */
#ifndef AWDL_COMPAT_PROTOCOL_LAYOUT_H
#define AWDL_COMPAT_PROTOCOL_LAYOUT_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define AWC_GET40 UINT32_C(0xc02869c9)
#define AWC_FRAME_SIZE 0x3c30U
#define AWC_INLINE_LIMIT 0x3c00U
#define AWC_FOOTER_OFFSET 0x3c08U

struct awc_request40 {
    char ifname[16];
    int32_t type;
    int32_t value;
    uint32_t length;
    uint32_t padding;
    uint64_t data;
};
struct awc_native_frame {
    uint32_t command;
    uint32_t payload_length;
    uint8_t payload[AWC_INLINE_LIMIT];
    struct awc_request40 request;
};
struct awc_frame_summary {
    uint32_t command;
    uint32_t payload_length;
    int32_t type;
    int32_t value;
    uint32_t footer_length;
    int ifname_is_awdl0;
    int footer_padding_zero;
    int footer_pointer_null;
};

_Static_assert(sizeof(struct awc_request40) == 40, "native request ABI");
_Static_assert(offsetof(struct awc_request40, type) == 16, "type offset");
_Static_assert(offsetof(struct awc_request40, length) == 24, "length offset");
_Static_assert(offsetof(struct awc_request40, data) == 32, "data offset");
_Static_assert(offsetof(struct awc_native_frame, payload) == 8, "inline payload offset");
_Static_assert(offsetof(struct awc_native_frame, request) == AWC_FOOTER_OFFSET, "footer offset");
_Static_assert(sizeof(struct awc_native_frame) == AWC_FRAME_SIZE, "native packet size");

/* Never dereferences the footer pointer or serializes any inline payload. */
static inline int awc_summarize_frame(const void *input, size_t size,
                                    struct awc_frame_summary *summary) {
    if (!input || !summary || size != AWC_FRAME_SIZE) return 0;
    struct awc_request40 footer;
    memset(summary, 0, sizeof(*summary));
    memcpy(&summary->command, input, sizeof(uint32_t));
    memcpy(&summary->payload_length, (const uint8_t *)input + 4, sizeof(uint32_t));
    memcpy(&footer, (const uint8_t *)input + AWC_FOOTER_OFFSET, sizeof(footer));
    summary->type = footer.type;
    summary->value = footer.value;
    summary->footer_length = footer.length;
    static const char awdl0[16] = "awdl0";
    summary->ifname_is_awdl0 = memcmp(footer.ifname, awdl0, sizeof(awdl0)) == 0;
    summary->footer_padding_zero = footer.padding == 0;
    summary->footer_pointer_null = footer.data == 0;
    return 1;
}

/* Intentionally tiny allowlist for the bind/read-only diagnostic. No SET,
 * scans, peer operations, power changes or arbitrary selector dispatch. */
static inline int awc_readonly_frame_allowed(const struct awc_frame_summary *summary,
                                            size_t output_capacity) {
    if (!summary || summary->command != AWC_GET40 || !summary->ifname_is_awdl0 ||
        !summary->footer_padding_zero || !summary->footer_pointer_null ||
        summary->footer_length != 0 || summary->value != 0 ||
        summary->payload_length > AWC_INLINE_LIMIT) return 0;
    switch (summary->type) {
        case 43: return summary->payload_length == 0 && output_capacity == 0x180;
        case 12: return summary->payload_length == 21 && output_capacity == 21;
        case 13: return summary->payload_length == 0 && output_capacity == 4;
        default: return 0;
    }
}
#endif
