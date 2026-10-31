#include "message55_recovery_codec.h"
#include <string.h>

static int valid_span(const void *p, size_t n) {
    return p && n<=UINTPTR_MAX-(uintptr_t)p;
}
static int overlaps(const void *a, size_t an, const void *b, size_t bn) {
    return (uintptr_t)a<(uintptr_t)b+bn && (uintptr_t)b<(uintptr_t)a+an;
}
static uint8_t legacy_byte(size_t i) {
    switch(i) {
        case 0:return 4;
        case 8:return 1;
        case 12:return 3;
        case 13:return 0x18;
        case 14:return 0x82;
        case 15:return 0xe0;
        default:return 0;
    }
}
static void put_le32(uint8_t *p, uint32_t value) {
    for(size_t i=0;i<4;++i)p[i]=(uint8_t)(value>>(i*8));
}
enum m55r_status m55r_translate(const struct m55r_context *context,
                               uint32_t message, const void *input, size_t size,
                               struct m55r_event *output) {
    if(!valid_span(context,sizeof(*context)) || !valid_span(output,sizeof(*output)))
        return M55R_ARGUMENT;
    if(overlaps(context,sizeof(*context),output,sizeof(*output)))return M55R_ALIAS;
    if(message!=M55R_MESSAGE)return M55R_UNKNOWN;
    if(size!=M55R_LEGACY_SIZE)return M55R_LENGTH;
    if(!valid_span(input,size))return M55R_ARGUMENT;
    if(overlaps(input,size,output,sizeof(*output)) ||
       overlaps(input,size,context,sizeof(*context)))return M55R_ALIAS;
    if((uintptr_t)context%_Alignof(struct m55r_context) ||
       (uintptr_t)output%_Alignof(struct m55r_event))return M55R_ARGUMENT;
    if(context->source_abi!=M55R_LEGACY_1200_12_2B1 ||
       context->destination_abi!=M55R_NATIVE_25G241_1200_13_1 ||
       context->destination_role!=M55R_DESTINATION_AWDL_ROLE)return M55R_CONTEXT;
    const uint8_t *bytes=input;
    for(size_t i=0;i<size;++i)if(bytes[i]!=legacy_byte(i))return M55R_CONTENT;
    struct m55r_event event;
    memset(&event,0,sizeof(event));
    event.message=M55R_MESSAGE;
    event.body_size=M55R_NATIVE_SIZE;
    event.meaning=M55R_REPORTED_POWER_ON_COMPLETION;
    put_le32(event.body,3);
    put_le32(event.body+8,1);
    put_le32(event.body+16,UINT32_C(0xe0821803));
    *output=event;
    return M55R_OK;
}
