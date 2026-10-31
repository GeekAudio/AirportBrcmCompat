/* Independent, OFFLINE message48 transport candidate. Not production-linked.
 * This validates one proven legacy receive-header shape and Apple AWDL16
 * framing, then preserves ALL body bytes. It does not claim that an attribute
 * is semantically valid: the real native AWDLAttribute decoder still decides.
 * The caller must supply a bounded owned snapshot captured before the pinned
 * postAFToP2pd -> Virtual::postMessage call returns, and independently prove
 * provider/image/task/observer lifetime. Context numbers are not that proof.
 * See research/test012-message-body-review.md. Never log this event body.
 */
#ifndef AWC_MESSAGE48_SUBSET_CODEC_H
#define AWC_MESSAGE48_SUBSET_CODEC_H
#include "awdl_message_codec.h"
#ifdef __cplusplus
extern "C" {
#endif
enum { AWCM48_ACTION_FRAME_RX = 48, AWCM48_HEADER_SIZE = 72,
       AWCM48_FRAME_HEADER_SIZE = 16, AWCM48_MAX_BODY = 2048 };
struct awcm48_event {
    uint32_t message, body_size, attribute_count;
    uint8_t body[AWCM48_MAX_BODY];
};
/* Numeric rejection categories only; never an input byte, address or body.
 * The mask describes ONLY the first failed validation stage. Independent
 * checks within metadata, channel or frame stages may set multiple bits.
 */
enum awcm48_reject {
    AWCM48_REJECT_ARGUMENT         = 1U << 0,
    AWCM48_REJECT_ALIAS            = 1U << 1,
    AWCM48_REJECT_CONTEXT          = 1U << 2,
    AWCM48_REJECT_MESSAGE          = 1U << 3,
    AWCM48_REJECT_BODY_LENGTH      = 1U << 4,
    AWCM48_REJECT_RESERVED6        = 1U << 5,
    AWCM48_REJECT_RESERVED24       = 1U << 6,
    AWCM48_REJECT_RESERVED52       = 1U << 7,
    AWCM48_REJECT_METADATA_VERSION = 1U << 8,
    AWCM48_REJECT_CHANNEL          = 1U << 9,
    AWCM48_REJECT_CHANNEL_FLAGS    = 1U << 10,
    AWCM48_REJECT_FRAME_PREFIX     = 1U << 11,
    AWCM48_REJECT_FRAME_SUBTYPE    = 1U << 12,
    AWCM48_REJECT_FRAME_FLAGS      = 1U << 13,
    AWCM48_REJECT_TLV_HEADER       = 1U << 14,
    AWCM48_REJECT_TLV_LENGTH       = 1U << 15,
    AWCM48_REJECT_FRAME_VERSION    = 1U << 16
};
struct awcm48_result {
    enum awcm_error error;
    uint32_t reject_mask;
};
/* Unknown message/header/version/subtype, nonzero reserved metadata, unknown
 * channel flags, incomplete TLVs, capacity and any output alias fail closed.
 * Output is unchanged on every error; unused output bytes are zero on success.
 * No bytes (including unknown attribute types) are dropped or rewritten.
 * Channel flags accept exactly one2.4/5GHz band and one10/20/40/80MHz width,
 * optional DFS, and extension-above only with40MHz (20 structural combinations, not RF/regulatory approval).
 * Widthless/conflicting/new160MHz/6GHz/unknown bits still fail closed.
 * Frame flags0 and all other source-shape restrictions remain mandatory.
 */
enum awcm_error awcm48_translate(const struct awcm_context *, uint32_t,
                                 const void *, size_t, struct awcm48_event *);
/* Same acceptance, validation/error order and output contract as translate.
 * Returns by value: no diagnostic destination may alias input or output.
 * Success is {AWCM_OK,0}; failure leaves the complete output unchanged.
 */
struct awcm48_result awcm48_translate_diagnosed(const struct awcm_context *,
    uint32_t, const void *, size_t, struct awcm48_event *);
#ifdef __cplusplus
}
#endif
#endif
