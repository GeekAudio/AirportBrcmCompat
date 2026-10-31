/* Two proven legacy1200.12.2b1 -> native1200.13.1/25G241 AWDL schemas.
 * OFFLINE CODEC ONLY: no IOKit, event subscription, requests or state changes.
 * Provider identity, actual executable hashes and task authorization must be
 * verified outside this codec. Unknown messages are never passed through.
 * See MESSAGE_SCHEMAS.md for the producer AND real daemon consumer evidence.
 */
#ifndef AWC_AWDL_MESSAGE_CODEC_H
#define AWC_AWDL_MESSAGE_CODEC_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum { AWCM_LEGACY_1200_12_2B1=1, AWCM_NATIVE_25G241_1200_13_1=2,
       AWCM_SYNC_STATE_CHANGED=46, AWCM_PEER_PRESENCE=47, AWCM_PEER_BODY_SIZE=68 };
enum awcm_error { AWCM_OK=0, AWCM_ARGUMENT, AWCM_CONTEXT, AWCM_UNKNOWN,
                  AWCM_LENGTH, AWCM_CONTENT, AWCM_ALIAS };
enum awcm_meaning { AWCM_INVALIDATE_SYNC_STATE=1, AWCM_LOST_PEER=2 };
struct awcm_context { uint32_t source_abi, destination_abi, virtual_role; };
struct awcm_event {
    uint32_t message, body_size, meaning;
    uint8_t body[AWCM_PEER_BODY_SIZE];
};
/* Input is a bounded independent snapshot of owned kernel memory, not an
 * address embedded in an external request. Output is unchanged on every error.
 * ID46 carries NO enabled value: it only invalidates cached AWDL state.
 * ID47 only accepts the proven absence shape(state1); peer address remains in
 * the internal output body because the real consumer needs it. Never log it.
 */
enum awcm_error awcm_translate(const struct awcm_context *,uint32_t,const void *,size_t,
                               struct awcm_event *);
#ifdef __cplusplus
}
#endif
#endif
