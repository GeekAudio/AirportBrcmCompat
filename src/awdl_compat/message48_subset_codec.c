#include "message48_subset_codec.h"
#include <string.h>

static int ranges_overlap(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t aa = (uintptr_t)a, bb = (uintptr_t)b;
    return an > UINTPTR_MAX-aa || bn > UINTPTR_MAX-bb ||
           (aa < bb+bn && bb < aa+an);
}
static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static int all_zero(const uint8_t *p, size_t n) {
    for (size_t i=0; i<n; ++i) if (p[i]) return 0;
    return 1;
}
static int structural_channel_flags(uint32_t flags) {
    /* Pinned Brcm chanspec2applechannel: one band (2.4/5GHz), one
     * 10/20/40/80MHz width, optional DFS, extension-above only for40MHz.
     * Exactly20 structural combinations, not RF/regulatory approval. Reject
     * widthless/default, new160MHz/6GHz, conflicting fields or other bits.
     * Preserve the scalar verbatim.
     */
    const uint32_t band = flags & 0x18U, width = flags & 0x407U;
    return !(flags & ~0x71fU) && (band == 0x8 || band == 0x10) &&
        (width == 0x1 || width == 0x2 || width == 0x4 || width == 0x400) &&
        (!(flags & 0x200U) || width == 0x4);
}

static struct awcm48_result result(enum awcm_error error, uint32_t mask) {
    const struct awcm48_result value = {error,mask};
    return value;
}

struct awcm48_result awcm48_translate_diagnosed(const struct awcm_context *context,
    uint32_t message, const void *input, size_t size, struct awcm48_event *output) {
    if (!context || !input || !output)
        return result(AWCM_ARGUMENT,AWCM48_REJECT_ARGUMENT);
    if (ranges_overlap(output,sizeof(*output),context,sizeof(*context)))
        return result(AWCM_ALIAS,AWCM48_REJECT_ALIAS);
    if (context->source_abi != AWCM_LEGACY_1200_12_2B1 ||
        context->destination_abi != AWCM_NATIVE_25G241_1200_13_1 ||
        context->virtual_role != 6)
        return result(AWCM_CONTEXT,AWCM48_REJECT_CONTEXT);
    if (message != AWCM48_ACTION_FRAME_RX)
        return result(AWCM_UNKNOWN,AWCM48_REJECT_MESSAGE);
    if (size < AWCM48_HEADER_SIZE+AWCM48_FRAME_HEADER_SIZE ||
        size > AWCM48_MAX_BODY)
        return result(AWCM_LENGTH,AWCM48_REJECT_BODY_LENGTH);
    if (ranges_overlap(output,sizeof(*output),input,size))
        return result(AWCM_ALIAS,AWCM48_REJECT_ALIAS);
    const uint8_t *bytes = (const uint8_t *)input;
    /* Every metadata byte is accounted for: source MAC[0,6), channel[12,24),
     * firmware scalars[40,52); all other bytes MUST match the zeroed producer.
     * There is no pointer-bearing or unchecked padding range in this subset.
     */
    uint32_t mask = 0;
    if (!all_zero(bytes+6,6)) mask |= AWCM48_REJECT_RESERVED6;
    if (!all_zero(bytes+24,16)) mask |= AWCM48_REJECT_RESERVED24;
    if (!all_zero(bytes+52,20)) mask |= AWCM48_REJECT_RESERVED52;
    if (load_le32(bytes+12) != 1) mask |= AWCM48_REJECT_METADATA_VERSION;
    if (mask) return result(AWCM_CONTENT,mask);
    uint32_t channel = load_le32(bytes+16), flags = load_le32(bytes+20);
    /* The producer explicitly zero-extends wf_chspec_ctlchan's AL. Do not
     * invent a regulatory channel list here; native channel parsing can reject
     * a numerically bounded channel for its own reasons. */
    if (channel == 0 || channel > 255) mask |= AWCM48_REJECT_CHANNEL;
    if (!structural_channel_flags(flags)) mask |= AWCM48_REJECT_CHANNEL_FLAGS;
    if (mask) return result(AWCM_CONTENT,mask);
    const uint8_t *frame = bytes+AWCM48_HEADER_SIZE;
    if (frame[0] != 127 || frame[1] != 0 || frame[2] != 0x17 ||
        frame[3] != 0xf2 || frame[4] != 8)
        mask |= AWCM48_REJECT_FRAME_PREFIX;
    if (frame[5] != 0x10) mask |= AWCM48_REJECT_FRAME_VERSION;
    if (frame[6] != 0 && frame[6] != 3) mask |= AWCM48_REJECT_FRAME_SUBTYPE;
    if (frame[7] != 0) mask |= AWCM48_REJECT_FRAME_FLAGS;
    if (mask) return result(AWCM_CONTENT,mask);
    size_t cursor = AWCM48_HEADER_SIZE+AWCM48_FRAME_HEADER_SIZE;
    uint32_t attributes = 0;
    while (cursor < size) {
        size_t remaining = size-cursor;
        if (remaining < 3) return result(AWCM_LENGTH,AWCM48_REJECT_TLV_HEADER);
        size_t length = (size_t)bytes[cursor+1] |
                        ((size_t)bytes[cursor+2]<<8);
        if (length > remaining-3) return result(AWCM_LENGTH,AWCM48_REJECT_TLV_LENGTH);
        cursor += 3+length;
        ++attributes;
    }
    memset(output,0,sizeof(*output));
    output->message = message;
    output->body_size = (uint32_t)size;
    output->attribute_count = attributes;
    memcpy(output->body,bytes,size);
    return result(AWCM_OK,0);
}

enum awcm_error awcm48_translate(const struct awcm_context *context,
    uint32_t message, const void *input, size_t size, struct awcm48_event *output) {
    return awcm48_translate_diagnosed(context,message,input,size,output).error;
}
