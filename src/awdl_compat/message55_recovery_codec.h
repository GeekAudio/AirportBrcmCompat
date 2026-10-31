/* Offline shape converter for one paired legacy/native message55 notice.
 * No driver calls, event capture, authorization, replay or ready capability.
 * See research/test014-message55-recovery-pairing.md for both actual producers.
 */
#ifndef M55R_MESSAGE55_RECOVERY_CODEC_H
#define M55R_MESSAGE55_RECOVERY_CODEC_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum {
    M55R_LEGACY_1200_12_2B1=1,
    M55R_NATIVE_25G241_1200_13_1=2,
    M55R_DESTINATION_AWDL_ROLE=6,
    M55R_MESSAGE=55,
    M55R_LEGACY_SIZE=184,
    M55R_NATIVE_SIZE=248
};
enum m55r_status {
    M55R_OK=0, M55R_ARGUMENT, M55R_CONTEXT, M55R_UNKNOWN,
    M55R_LENGTH, M55R_CONTENT, M55R_ALIAS
};
enum m55r_meaning { M55R_REPORTED_POWER_ON_COMPLETION=1 };
struct m55r_context {
    uint32_t source_abi, destination_abi, destination_role;
};
struct m55r_event {
    uint32_t message, body_size, meaning;
    uint8_t body[M55R_NATIVE_SIZE];
};
/* Input must be an independently owned, bounded snapshot, never a pointer
 * embedded in a request. The ABI/role context selects a shape only: it does
 * NOT prove the producer, provider identity, entitlement or lifecycle. In
 * particular, primary->Virtual delivery is not established by this codec.
 *
 * Accepts exactly: old LE32@0=4,@8=1,@12=e0821803, all other bytes zero.
 * Emits the complete native powerOn producer shape: LE32@0=3,@8=1,
 * @16=e0821803, all other bytes zero. Never accepts general health/fault data.
 * The notice reports a producer state, not RF/association/AirDrop readiness.
 * All errors leave output, input and context untouched. All three ranges
 * must be disjoint; arithmetic-overflow and misaligned struct ranges fail.
 */
enum m55r_status m55r_translate(const struct m55r_context *, uint32_t message,
                               const void *input, size_t input_size,
                               struct m55r_event *output);
#ifdef __cplusplus
}
#endif
#endif
