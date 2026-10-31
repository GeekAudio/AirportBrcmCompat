#include "awdl_message_codec.h"
#include <string.h>
static int overlap(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t aa=(uintptr_t)a,bb=(uintptr_t)b;
    return an>UINTPTR_MAX-aa || bn>UINTPTR_MAX-bb || (aa<bb+bn && bb<aa+an);
}
enum awcm_error awcm_translate(const struct awcm_context *context,uint32_t message,
                               const void *input,size_t size,struct awcm_event *output){
    if(!context || !output)return AWCM_ARGUMENT;
    if(context->source_abi!=AWCM_LEGACY_1200_12_2B1 ||
       context->destination_abi!=AWCM_NATIVE_25G241_1200_13_1 ||
       context->virtual_role!=6)return AWCM_CONTEXT;
    if(overlap(output,sizeof(*output),context,sizeof(*context)))return AWCM_ALIAS;
    if(message!=AWCM_SYNC_STATE_CHANGED && message!=AWCM_PEER_PRESENCE)return AWCM_UNKNOWN;
    if(size!=(message==AWCM_SYNC_STATE_CHANGED?0U:AWCM_PEER_BODY_SIZE))return AWCM_LENGTH;
    if(size && !input)return AWCM_ARGUMENT;
    if(size && overlap(output,sizeof(*output),input,size))return AWCM_ALIAS;
    struct awcm_event event;memset(&event,0,sizeof(event));event.message=message;
    if(message==AWCM_SYNC_STATE_CHANGED)event.meaning=AWCM_INVALIDATE_SYNC_STATE;
    else{
        const uint8_t *bytes=input;
        /* Both old and native absence producers clear all68 bytes first,
         * copy a six-byte peer address, then write little-endian state1@8.
         * The native daemon requires exactly68 and maps state1 to lostPeer.
         * Do not widen this into a general peer-presence byte-copy rule. */
        for(size_t i=6;i<size;i++)if(bytes[i]!=(i==8?1U:0U))return AWCM_CONTENT;
        memcpy(event.body,bytes,6);event.body[8]=1;
        event.body_size=AWCM_PEER_BODY_SIZE;event.meaning=AWCM_LOST_PEER;
    }
    *output=event;return AWCM_OK;
}
