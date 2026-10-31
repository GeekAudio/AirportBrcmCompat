/* Portable, allocation-free analysis codec. No IOKit, sockets, pointer chasing,
 * requests or state changes. Unknown external calls fail closed. Not a driver.
 * The frozen live diagnostic includes protocol_layout.h, not this new codec.
 */
#ifndef AWDL_COMPAT_PROTOCOL_CODEC_H
#define AWDL_COMPAT_PROTOCOL_CODEC_H
#include "protocol_layout.h"

enum awc_decode_result {
    AWC_DECODE_OK = 0,
    AWC_REJECT_SELECTOR,
    AWC_REJECT_SHAPE,
    AWC_REJECT_FRAME,
    AWC_REJECT_OPERATION,
    AWC_REJECT_BOUNDS,
    AWC_REJECT_UNCOMMITTED
};
enum awc_read_call_kind { AWC_READ_COMMAND, AWC_QUERY_IOUC, AWC_QUERY_EVENT_PIPE, AWC_QUERY_DRIVERKIT };
struct awc_read_call {
    enum awc_read_call_kind kind;
    struct awc_frame_summary frame;
};

/* Read-only policy: native event subscription/init/exit and large-buffer
 * commands remain refused even though their selector numbers are known. */
static inline enum awc_decode_result awc_decode_read_call(
    uint32_t selector, const void *input, size_t input_size, size_t output_capacity,
    uint32_t scalar_input_count, uint32_t scalar_output_count,
    uint32_t async_reference_count, struct awc_read_call *call) {
    if (!call || scalar_input_count || scalar_output_count || async_reference_count)
        return AWC_REJECT_SHAPE;
    memset(call, 0, sizeof(*call));
    if (selector == 0) {
        if (!awc_summarize_frame(input,input_size,&call->frame)) return AWC_REJECT_FRAME;
        if (!awc_readonly_frame_allowed(&call->frame,output_capacity)) return AWC_REJECT_OPERATION;
        call->kind=AWC_READ_COMMAND;
        return AWC_DECODE_OK;
    }
    if (selector != 1 && selector != 5 && selector != 7) return AWC_REJECT_SELECTOR;
    if (input || input_size || output_capacity != 1) return AWC_REJECT_SHAPE;
    call->kind=selector==1 ? AWC_QUERY_IOUC : selector==5 ? AWC_QUERY_EVENT_PIPE : AWC_QUERY_DRIVERKIT;
    return AWC_DECODE_OK;
}

/* A contiguous native event record, not a ring walker. Wrap markers, producer
 * concurrency and unknown flags are intentionally not guessed. The two opaque
 * qwords and producer-name bytes are never returned by this decoder. */
struct awc_event_summary {
    uint16_t sequence;
    uint16_t payload_length;
    uint16_t padding_length;
    uint32_t message;
    size_t record_length;
};
static inline enum awc_decode_result awc_decode_contiguous_event(
    const void *input, size_t available, struct awc_event_summary *summary) {
    if (!input || !summary || available < 0x30) return AWC_REJECT_BOUNDS;
    const uint8_t *bytes=input;
    uint32_t marker;
    uint16_t flags;
    memset(summary,0,sizeof(*summary));
    memcpy(&marker,bytes,4);
    if (marker != UINT32_C(0x57)) return AWC_REJECT_UNCOMMITTED;
    memcpy(&flags,bytes+4,2);
    if (flags != 0) return AWC_REJECT_SHAPE;
    memcpy(&summary->sequence,bytes+6,2);
    memcpy(&summary->payload_length,bytes+0x18,2);
    memcpy(&summary->padding_length,bytes+0x1a,2);
    memcpy(&summary->message,bytes+0x1c,4);
    if (summary->payload_length > 0x1000 || summary->padding_length > 3 ||
        summary->padding_length != ((0U-summary->payload_length)&3U)) return AWC_REJECT_BOUNDS;
    size_t suffix=(size_t)summary->payload_length+summary->padding_length;
    if (suffix > available-0x30) return AWC_REJECT_BOUNDS;
    summary->record_length=0x30+suffix;
    return AWC_DECODE_OK;
}

/* Legacy type4/type5 async client method0 input: base uint64, count uint32,
 * padding uint32; asyncReferenceCount=8 and a nonzero wake port are required.
 * The address is validated structurally but never dereferenced or returned.
 * This is a validation subset, not permission to open or monitor that client. */
static inline enum awc_decode_result awc_validate_legacy_monitor(
    const void *input, size_t input_size, uint32_t async_reference_count,
    int wake_port_present, uint32_t *buffer_count) {
    if (!input || !buffer_count || input_size != 16 || async_reference_count != 8 || !wake_port_present)
        return AWC_REJECT_SHAPE;
    uint64_t base;
    uint32_t count, padding;
    memcpy(&base,input,8); memcpy(&count,(const uint8_t*)input+8,4);
    memcpy(&padding,(const uint8_t*)input+12,4);
    if (!base || padding || !count || count > 300 || base > UINT64_MAX-(uint64_t)count*0x800)
        return AWC_REJECT_BOUNDS;
    *buffer_count=count;
    return AWC_DECODE_OK;
}
static inline enum awc_decode_result awc_validate_legacy_ack(
    const void *input, size_t input_size, uint32_t buffer_count) {
    if (!input || input_size != 4 || !buffer_count || buffer_count > 300) return AWC_REJECT_SHAPE;
    uint32_t index;
    memcpy(&index,input,4);
    return index < buffer_count ? AWC_DECODE_OK : AWC_REJECT_BOUNDS;
}
#endif
