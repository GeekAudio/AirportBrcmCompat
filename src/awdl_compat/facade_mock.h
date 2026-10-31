/* OFFLINE MODEL ONLY. This is not an IOUserClient and must not be linked into
 * a loaded extension. All authority/backend inputs are trusted mock fixtures,
 * never user-supplied entitlement claims. See FACADE_DESIGN.md.
 */
#ifndef AWC_FACADE_MOCK_H
#define AWC_FACADE_MOCK_H
#include "event_ring.h"
#ifdef __cplusplus
extern "C" {
#endif

enum { AWCF_FIXTURE_LEGACY_MESSAGE=240, AWCF_FIXTURE_NATIVE_MESSAGE=241,
       AWCF_MAP_ANYWHERE=1, AWCF_MAP_READONLY=0x1000 };
enum awcf_backend_kind { AWCF_OWNED_SLOTS=1, AWCF_POST_OBSERVER=2 };
struct awcf_identity { uint64_t task, provider_generation; };
struct awcf_authority {
    struct awcf_identity identity;
    int native_wlan_authentication_true, legacy_awdl_event_monitor_true;
};
/* exclusive_reserved is a trusted backend-lease result, not a request to take
 * another client's type4/5 slot. No backend is opened by this code. */
struct awcf_backend_fixture {
    uint64_t owner, epoch, provider_generation;
    uint32_t kind, legacy_role, legacy_open_type;
    int exclusive_reserved, observer_lease, fixture_schema_ready;
    const void *slots;
    size_t slots_size;
    uint32_t slot_count;
};
struct awcf_call_shape {
    size_t input_size, output_size;
    uint32_t scalar_input_count, scalar_output_count, async_reference_count;
    int wake_port_present;
};
enum awcf_pending {
    AWCF_IDLE=0, AWCF_NEEDS_PUBLISH, AWCF_COMMITTED, AWCF_DROPPED
};
struct awcf_actions {
    uint64_t delivery;
    uint32_t ack_required, ack_index, notify_required, async_argument_count;
    uint32_t dropped, committed;
};
struct awcf_mock {
    struct awc_event_session session;
    struct awc_ring ring;
    struct awcf_backend_fixture backend;
    void *ring_storage;
    size_t ring_size;
    struct awc_ring_shared *state_storage;
    uint64_t next_map_lease, map_leases[2], last_delivery, pending_delivery;
    uint32_t backend_attached, schema_ready, pending, ack_pending, notify_pending;
    struct awc_legacy_capture snapshot;
    uint8_t translated[8]; /* Only the synthetic fixture schema, never AWDL. */
};

/* Every function is allocation-free and performs no external call. The caller
 * serializes all methods under one gate and owns a reference to the session.
 * It supplies disjoint owned memory, not addresses received in an ioctl. */
enum awc_ring_error awcf_mock_open(struct awcf_mock *,const struct awcf_authority *,
                                  const struct awcf_backend_fixture *,void *,size_t,
                                  struct awc_ring_shared *);
/* Only event selectors1/2/3/4/5/7 are modeled. Driver command0, large command6,
 * mapUserBuffer8 and all unknown calls remain refused. Bool1/7 are false;
 * bool5 is true only for a ready MOCK backend/schema. No runtime capability. */
enum awc_ring_error awcf_mock_method(struct awcf_mock *,struct awcf_identity,
                                    uint32_t,const struct awcf_call_shape *,uint8_t *);
enum awc_ring_error awcf_mock_map(struct awcf_mock *,struct awcf_identity,
                                 uint32_t,uint32_t,uint64_t *);
enum awc_ring_error awcf_mock_unmap(struct awcf_mock *,struct awcf_identity,
                                   uint32_t,uint64_t);
/* provider/owner/epoch/delivery come from the owned backend callback, not the
 * event body. Delivery is a monotonic private cookie; it is not a wire field.
 * Capture first, then translate, then publish, then request notify/legacy ACK.
 * Unknown bodies are deliberately dropped and may be ACKed only by this owned
 * backend. FULL retains one snapshot and returns BUSY without legacy ACK.
 */
enum awc_ring_error awcf_mock_receive(struct awcf_mock *,uint64_t,uint64_t,uint64_t,
                                     uint64_t,const uint64_t *,size_t);
/* Alternative non-occupying postMessage observer model. Its body is owned
 * kernel memory valid for the duration of this callback, never a user pointer.
 * It takes a bounded snapshot and never requests a legacy type4/5 slot ACK.
 * observer_lease is the external registry's retained, quiesceable subscription.
 */
enum awc_ring_error awcf_mock_receive_post(struct awcf_mock *,uint64_t,uint64_t,uint64_t,
                                          uint64_t,uint32_t,const void *,size_t);
enum awc_ring_error awcf_mock_retry_publish(struct awcf_mock *);
enum awc_ring_error awcf_mock_actions(const struct awcf_mock *,struct awcf_actions *);
enum awc_ring_error awcf_mock_complete_notify(struct awcf_mock *,uint64_t,int);
enum awc_ring_error awcf_mock_complete_ack(struct awcf_mock *,uint64_t,int);
enum awc_ring_error awcf_mock_begin_close(struct awcf_mock *,struct awcf_identity);
/* Detach is allowed only after an externally proven quiesce and all pending
 * owned-slot ACKs complete. There is no timeout that silently frees a callback.
 * finish requires descriptor leases/callbacks zero and backend detached. */
enum awc_ring_error awcf_mock_detach(struct awcf_mock *,uint64_t,int);
enum awc_ring_error awcf_mock_finish_close(struct awcf_mock *);
#ifdef __cplusplus
}
#endif
#endif
