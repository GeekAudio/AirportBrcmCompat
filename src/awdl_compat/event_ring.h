/* Portable native 25G241 event-pipe core. No IOKit, allocation, callbacks,
 * external requests, or logging. Caller owns buffers and serializes producers.
 * See EVENT_ADAPTER.md before a kernel integration; this is not a loaded shim.
 */
#ifndef AWC_EVENT_RING_H
#define AWC_EVENT_RING_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum awc_ring_error {
    AWC_RING_OK=0, AWC_RING_ARGUMENT, AWC_RING_BOUNDS, AWC_RING_FULL,
    AWC_RING_EMPTY, AWC_RING_RESERVED, AWC_RING_CORRUPT, AWC_RING_CAPACITY,
    AWC_RING_STALE, AWC_RING_PERMISSION, AWC_RING_CLOSED, AWC_RING_BUSY,
    AWC_RING_POLICY
};
enum { AWC_EVENT_HEADER=48, AWC_EVENT_MAX_BODY=4096, AWC_LEGACY_SLOT_SIZE=2048,
       AWC_RING_PAGE=4096, AWC_RING_GAP=4 };
/* Real memory type2 is exactly12 bytes. Its last DWORD is not interpreted or
 * changed here. Offsets0/4 are synchronized 32-bit shared producer/consumer
 * fields, never trusted as pointers or allocation sizes. */
struct awc_ring_shared { uint32_t read_offset, write_offset, unknown_8; };
struct awc_ring {
    uint8_t *bytes;
    uint32_t capacity, published_write;
    uint16_t next_sequence;
    struct awc_ring_shared *shared;
    uint64_t consumer_epoch; /* Offline consumer cursor, not a wire field. */
};
struct awc_event_metadata {
    uint64_t opaque_8, opaque_10;
    uint8_t producer[16];
    uint32_t message;
};
struct awc_ring_notice {
    uint32_t notify_required, async_argument_count, record_offset, next_write;
    uint16_t sequence;
};
struct awc_ring_cursor {
    uint64_t consumer_epoch;
    uint32_t read_before, record_offset, next_read, message;
    uint16_t sequence, payload_length;
};

/* Initialize before exposing either descriptor; capacity must be page aligned
 * and hold a maximum-sized record plus the permanent 4-byte gap. */
enum awc_ring_error awc_ring_init(struct awc_ring *,void *,size_t,
                                struct awc_ring_shared *,size_t);
/* Publish one already translated event. Policy/entitlement/lifecycle validation
 * happens before this core. A native async notification has ZERO arguments.
 * FULL changes no ring bytes; notify_required=1 asks an existing reader to drain.
 * Input payload must not overlap ring storage. Caller serializes all publishers.
 */
enum awc_ring_error awc_ring_publish(struct awc_ring *,const struct awc_event_metadata *,
                                   const void *,size_t,struct awc_ring_notice *);
/* Offline consumer model of the real ring ABI, useful for contract tests.
 * peek never acknowledges. Short output or uncommitted data changes no offsets.
 * This model has one consumer. ack uses a release CAS on shared.read, as the
 * native reader does; no externalMethod ACK exists in the native pipe. A private
 * cursor epoch rejects duplicate cursors even after wire sequence/offset wrap.
 */
enum awc_ring_error awc_ring_peek(const struct awc_ring *,void *,size_t,
                                struct awc_ring_cursor *);
enum awc_ring_error awc_ring_ack(struct awc_ring *,const struct awc_ring_cursor *);

/* A real legacy async callback carries exactly3 uint64 words: message,length,
 * slotIndex. Take a bounded copy before returning its uint32 ACK index. This
 * function never acknowledges a real client and never casts an external address.
 * Only an owned backend may pass its mapped slot storage. Unknown schemas remain
 * refused by the later converter; capture does not assert payload compatibility.
 */
struct awc_legacy_capture {
    uint32_t message, length, ack_index;
    uint8_t bytes[AWC_LEGACY_SLOT_SIZE];
};
enum awc_ring_error awc_legacy_capture(const uint64_t *,size_t,const void *,size_t,
                                     uint32_t,struct awc_legacy_capture *);

/* Pointer-free lifecycle accounting for a future adapter. Tokens are trusted
 * kernel ownership/generation handles, not userspace-provided authorization.
 * The bool entitlement is the result of checking the exact OSBoolean true for
 * com.apple.wlan.authentication. Root status alone is not that entitlement.
 * All control transitions/map lease accounting must run under the adapter gate.
 * begin/end support callbacks racing a close; no allocation may be freed until
 * close_ready is true. The session object itself needs an external lifetime ref.
 */
enum awc_event_phase { AWC_EVENT_NEW=0, AWC_EVENT_OPEN, AWC_EVENT_PIPE,
                      AWC_EVENT_SUBSCRIBED, AWC_EVENT_CLOSING, AWC_EVENT_DEAD };
struct awc_event_session {
    uint64_t task_token, provider_generation;
    uint32_t phase, callbacks, leases[2];
};
void awc_event_session_init(struct awc_event_session *);
enum awc_ring_error awc_event_open(struct awc_event_session *,uint64_t,uint64_t,int);
enum awc_ring_error awc_event_pipe_init(struct awc_event_session *,uint64_t,uint64_t);
enum awc_ring_error awc_event_map(struct awc_event_session *,uint64_t,uint64_t,uint32_t);
enum awc_ring_error awc_event_unmap(struct awc_event_session *,uint32_t);
enum awc_ring_error awc_event_subscribe(struct awc_event_session *,uint64_t,uint64_t,
                                      uint32_t,int,uint32_t,uint32_t);
enum awc_ring_error awc_event_begin(struct awc_event_session *,uint64_t);
enum awc_ring_error awc_event_end(struct awc_event_session *);
enum awc_ring_error awc_event_close(struct awc_event_session *);
int awc_event_close_ready(const struct awc_event_session *);
enum awc_ring_error awc_event_finish_close(struct awc_event_session *);
#ifdef __cplusplus
}
#endif
#endif
