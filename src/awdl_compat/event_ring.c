#include "event_ring.h"
#include <string.h>

_Static_assert(sizeof(struct awc_ring_shared)==12,"native state descriptor");
_Static_assert(offsetof(struct awc_ring_shared,write_offset)==4,"native write offset");
_Static_assert(offsetof(struct awc_ring_shared,unknown_8)==8,"preserve unknown DWORD");
static uint32_t load32(const uint32_t *p){return __atomic_load_n(p,__ATOMIC_ACQUIRE);}
static void store32(uint32_t *p,uint32_t v){__atomic_store_n(p,v,__ATOMIC_RELEASE);}
static void put16(void *p,uint16_t v){memcpy(p,&v,2);}
static void put32(void *p,uint32_t v){memcpy(p,&v,4);}
static uint16_t get16(const void *p){uint16_t v;memcpy(&v,p,2);return v;}
static uint32_t get32(const void *p){uint32_t v;memcpy(&v,p,4);return v;}
static int aligned4(const void *p){return ((uintptr_t)p&3U)==0;}
static int overlap(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t aa=(uintptr_t)a,bb=(uintptr_t)b;
    if(an>UINTPTR_MAX-aa || bn>UINTPTR_MAX-bb)return 1;
    return aa<bb+bn && bb<aa+an;
}
static enum awc_ring_error offsets(const struct awc_ring *r,uint32_t *read,uint32_t *write){
    if(!r || !r->bytes || !r->shared || !aligned4(r->bytes) || !aligned4(r->shared) ||
       r->capacity<AWC_RING_PAGE*2U || r->capacity%AWC_RING_PAGE)return AWC_RING_ARGUMENT;
    *read=load32(&r->shared->read_offset);*write=load32(&r->shared->write_offset);
    if(*read>=r->capacity || *write>=r->capacity || ((*read|*write)&3U))return AWC_RING_CORRUPT;
    return AWC_RING_OK;
}
enum awc_ring_error awc_ring_init(struct awc_ring *r,void *bytes,size_t n,
                                struct awc_ring_shared *shared,size_t state_size){
    if(!r || !bytes || !shared || !aligned4(bytes) || !aligned4(shared) ||
       state_size!=sizeof(*shared) || n<AWC_RING_PAGE*2U || n>UINT32_MAX || n%AWC_RING_PAGE ||
       overlap(bytes,n,shared,sizeof(*shared)) || overlap(r,sizeof(*r),bytes,n) ||
       overlap(r,sizeof(*r),shared,sizeof(*shared)))return AWC_RING_ARGUMENT;
    memset(bytes,0,n);memset(r,0,sizeof(*r));
    r->bytes=bytes;r->capacity=(uint32_t)n;r->shared=shared;
    store32(&shared->read_offset,0);store32(&shared->write_offset,0);
    /* Deliberately preserve shared.unknown_8. */
    return AWC_RING_OK;
}
static void copy_into(const struct awc_ring *r,uint32_t at,const void *source,size_t n){
    size_t first=r->capacity-at;if(first>n)first=n;
    if(first)memcpy(r->bytes+at,source,first);
    if(n>first)memcpy(r->bytes,(const uint8_t*)source+first,n-first);
}
static void zero_into(const struct awc_ring *r,uint32_t at,size_t n){
    size_t first=r->capacity-at;if(first>n)first=n;
    if(first)memset(r->bytes+at,0,first);
    if(n>first)memset(r->bytes,0,n-first);
}
static void copy_out(const struct awc_ring *r,uint32_t at,void *target,size_t n){
    size_t first=r->capacity-at;if(first>n)first=n;
    if(first)memcpy(target,r->bytes+at,first);
    if(n>first)memcpy((uint8_t*)target+first,r->bytes,n-first);
}
enum awc_ring_error awc_ring_publish(struct awc_ring *r,const struct awc_event_metadata *meta,
                                   const void *body,size_t length,struct awc_ring_notice *notice){
    if(!notice || !meta || !meta->message || meta->message>247 || length>AWC_EVENT_MAX_BODY ||
       (!body && length))return AWC_RING_ARGUMENT;
    uint32_t read,write;enum awc_ring_error error=offsets(r,&read,&write);if(error)return error;
    if(write!=r->published_write)return AWC_RING_CORRUPT;
    if((length && overlap(body,length,r->bytes,r->capacity)) ||
       overlap(meta,sizeof(*meta),r->bytes,r->capacity) ||
       overlap(notice,sizeof(*notice),r->bytes,r->capacity) ||
       overlap(notice,sizeof(*notice),r,sizeof(*r)) ||
       overlap(notice,sizeof(*notice),r->shared,sizeof(*r->shared)) ||
       overlap(notice,sizeof(*notice),meta,sizeof(*meta)) ||
       (length && overlap(notice,sizeof(*notice),body,length)))return AWC_RING_ARGUMENT;
    memset(notice,0,sizeof(*notice));
    uint32_t padding=(uint32_t)((0U-length)&3U),total=AWC_EVENT_HEADER+(uint32_t)length+padding;
    uint32_t tail=r->capacity-write,skip=tail<AWC_EVENT_HEADER?tail:0;
    uint32_t available=read>write?read-write:r->capacity-write+read;
    available-=AWC_RING_GAP;
    if(total>available || skip>available-total){notice->notify_required=1;return AWC_RING_FULL;}
    if(skip){for(uint32_t i=write;i<r->capacity;i+=4)put32(r->bytes+i,0x50);write=0;}
    uint8_t *header=r->bytes+write;
    put32(header,0x52); /* native reserved marker; header is always contiguous */
    put16(header+4,0);put16(header+6,r->next_sequence);
    memcpy(header+8,&meta->opaque_8,8);memcpy(header+0x10,&meta->opaque_10,8);
    put16(header+0x18,(uint16_t)length);put16(header+0x1a,(uint16_t)padding);
    put32(header+0x1c,meta->message);memcpy(header+0x20,meta->producer,16);
    uint32_t payload=(write+AWC_EVENT_HEADER)%r->capacity;
    if(length)copy_into(r,payload,body,length);
    if(padding)zero_into(r,(uint32_t)(((uint64_t)payload+length)%r->capacity),padding);
    uint32_t next=(uint32_t)(((uint64_t)write+total)%r->capacity);
    /* Match native ordering: body/padding -> committed marker -> shared write
     * -> zero-argument async wake. An external publisher gate prevents an older
     * producer from publishing past a newer reservation. */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    store32((uint32_t*)(void*)header,0x57);
    r->published_write=next;store32(&r->shared->write_offset,next);
    notice->notify_required=1;notice->async_argument_count=0;
    notice->record_offset=write;notice->next_write=next;notice->sequence=r->next_sequence++;
    return AWC_RING_OK;
}
static enum awc_ring_error describe(const struct awc_ring *r,struct awc_ring_cursor *cursor){
    uint32_t read,write;enum awc_ring_error error=offsets(r,&read,&write);if(error)return error;
    if(read==write)return AWC_RING_EMPTY;
    uint32_t used=write>read?write-read:r->capacity-read+write,at=read,skip=0;
    if(r->capacity-at<AWC_EVENT_HEADER){
        skip=r->capacity-at;if(skip>used)return AWC_RING_CORRUPT;
        for(uint32_t i=at;i<r->capacity;i+=4)if(load32((uint32_t*)(void*)(r->bytes+i))!=0x50)return AWC_RING_CORRUPT;
        at=0;used-=skip;
    }
    if(used<AWC_EVENT_HEADER)return AWC_RING_CORRUPT;
    const uint8_t *h=r->bytes+at;uint32_t marker=load32((const uint32_t*)(const void*)h);
    if(marker==0x52)return AWC_RING_RESERVED;
    if(marker!=0x57 || get16(h+4))return AWC_RING_CORRUPT;
    uint16_t length=get16(h+0x18),padding=get16(h+0x1a);
    uint32_t total=AWC_EVENT_HEADER+(uint32_t)length+padding,message=get32(h+0x1c);
    if(length>AWC_EVENT_MAX_BODY || padding!=((0U-length)&3U) || total>used ||
       !message || message>247)return AWC_RING_CORRUPT;
    cursor->consumer_epoch=r->consumer_epoch;
    cursor->read_before=read;cursor->record_offset=at;
    cursor->next_read=(uint32_t)(((uint64_t)at+total)%r->capacity);
    cursor->message=message;cursor->sequence=get16(h+6);cursor->payload_length=length;
    return AWC_RING_OK;
}
enum awc_ring_error awc_ring_peek(const struct awc_ring *r,void *body,size_t capacity,
                                struct awc_ring_cursor *cursor){
    if(!cursor)return AWC_RING_ARGUMENT;
    struct awc_ring_cursor actual;
    enum awc_ring_error error=describe(r,&actual);if(error)return error;
    size_t length=actual.payload_length;
    if(capacity<length || (!body && length))return AWC_RING_CAPACITY;
    if(overlap(cursor,sizeof(*cursor),r,sizeof(*r)) ||
       overlap(cursor,sizeof(*cursor),r->bytes,r->capacity) ||
       overlap(cursor,sizeof(*cursor),r->shared,sizeof(*r->shared)) ||
       (length && (overlap(body,length,r->bytes,r->capacity) ||
                   overlap(body,length,r,sizeof(*r)) ||
                   overlap(body,length,cursor,sizeof(*cursor)) ||
                   overlap(body,length,r->shared,sizeof(*r->shared)))))return AWC_RING_ARGUMENT;
    if(length)copy_out(r,(actual.record_offset+AWC_EVENT_HEADER)%r->capacity,body,length);
    *cursor=actual;return AWC_RING_OK;
}
enum awc_ring_error awc_ring_ack(struct awc_ring *r,const struct awc_ring_cursor *cursor){
    if(!cursor)return AWC_RING_ARGUMENT;
    uint32_t read,write;enum awc_ring_error error=offsets(r,&read,&write);if(error)return error;
    if(read!=cursor->read_before || read==write)return AWC_RING_STALE;
    struct awc_ring_cursor actual;
    error=describe(r,&actual);
    if(error)return error;
    if(actual.consumer_epoch!=cursor->consumer_epoch ||
       actual.record_offset!=cursor->record_offset || actual.next_read!=cursor->next_read ||
       actual.sequence!=cursor->sequence || actual.message!=cursor->message ||
       actual.payload_length!=cursor->payload_length)return AWC_RING_STALE;
    if(r->consumer_epoch==UINT64_MAX)return AWC_RING_BOUNDS;
    uint32_t expected=actual.read_before;
    if(!__atomic_compare_exchange_n(&r->shared->read_offset,&expected,actual.next_read,0,
                                    __ATOMIC_RELEASE,__ATOMIC_RELAXED))return AWC_RING_STALE;
    r->consumer_epoch++;return AWC_RING_OK;
}
enum awc_ring_error awc_legacy_capture(const uint64_t *args,size_t count,const void *slots,size_t size,
                                     uint32_t slot_count,struct awc_legacy_capture *capture){
    if(!capture || !args || count!=3 || !slots || !slot_count || slot_count>300)return AWC_RING_ARGUMENT;
    if(args[0]>UINT32_MAX || !args[0] || args[1]>AWC_LEGACY_SLOT_SIZE || args[2]>=slot_count ||
       (size_t)slot_count>size/AWC_LEGACY_SLOT_SIZE)return AWC_RING_BOUNDS;
    size_t offset=(size_t)args[2]*AWC_LEGACY_SLOT_SIZE,length=(size_t)args[1];
    if(overlap(capture,sizeof(*capture),slots,size) || overlap(capture,sizeof(*capture),args,24))return AWC_RING_ARGUMENT;
    memset(capture,0,sizeof(*capture));
    if(length)memcpy(capture->bytes,(const uint8_t*)slots+offset,length);
    capture->message=(uint32_t)args[0];capture->length=(uint32_t)length;
    capture->ack_index=(uint32_t)args[2];return AWC_RING_OK;
}

static int authorized(const struct awc_event_session *s,uint64_t task,uint64_t provider){
    return s && task && provider && s->task_token==task && s->provider_generation==provider;
}
void awc_event_session_init(struct awc_event_session *s){if(s)memset(s,0,sizeof(*s));}
enum awc_ring_error awc_event_open(struct awc_event_session *s,uint64_t task,uint64_t provider,int entitled){
    if(!s || !task || !provider)return AWC_RING_ARGUMENT;
    if(load32(&s->phase)!=AWC_EVENT_NEW)return AWC_RING_BUSY;
    if(entitled!=1)return AWC_RING_PERMISSION;
    s->task_token=task;s->provider_generation=provider;store32(&s->phase,AWC_EVENT_OPEN);return AWC_RING_OK;
}
enum awc_ring_error awc_event_pipe_init(struct awc_event_session *s,uint64_t task,uint64_t provider){
    if(!authorized(s,task,provider))return AWC_RING_PERMISSION;
    if(load32(&s->phase)!=AWC_EVENT_OPEN)return AWC_RING_BUSY;
    store32(&s->phase,AWC_EVENT_PIPE);return AWC_RING_OK;
}
enum awc_ring_error awc_event_map(struct awc_event_session *s,uint64_t task,uint64_t provider,uint32_t type){
    if(!authorized(s,task,provider))return AWC_RING_PERMISSION;
    uint32_t p=load32(&s->phase);if(p!=AWC_EVENT_PIPE && p!=AWC_EVENT_SUBSCRIBED)return AWC_RING_CLOSED;
    if(type<1 || type>2)return AWC_RING_POLICY;
    if(s->leases[type-1]==UINT32_MAX)return AWC_RING_BOUNDS;
    s->leases[type-1]++;return AWC_RING_OK;
}
enum awc_ring_error awc_event_unmap(struct awc_event_session *s,uint32_t type){
    if(!s || type<1 || type>2)return AWC_RING_ARGUMENT;
    if(!s->leases[type-1])return AWC_RING_STALE;
    s->leases[type-1]--;return AWC_RING_OK;
}
enum awc_ring_error awc_event_subscribe(struct awc_event_session *s,uint64_t task,uint64_t provider,
                                      uint32_t references,int wake,uint32_t scalar_in,uint32_t scalar_out){
    if(!authorized(s,task,provider))return AWC_RING_PERMISSION;
    if(load32(&s->phase)!=AWC_EVENT_PIPE)return AWC_RING_BUSY;
    if(references!=8 || wake!=1 || scalar_in || scalar_out)return AWC_RING_ARGUMENT;
    if(!s->leases[0] || !s->leases[1])return AWC_RING_BUSY;
    store32(&s->phase,AWC_EVENT_SUBSCRIBED);return AWC_RING_OK;
}
enum awc_ring_error awc_event_begin(struct awc_event_session *s,uint64_t provider){
    if(!s || !provider)return AWC_RING_PERMISSION;
    if(load32(&s->phase)!=AWC_EVENT_SUBSCRIBED)return AWC_RING_CLOSED;
    if(s->provider_generation!=provider)return AWC_RING_PERMISSION;
    uint32_t value=load32(&s->callbacks);
    do{if(value==UINT32_MAX)return AWC_RING_BOUNDS;}
    while(!__atomic_compare_exchange_n(&s->callbacks,&value,value+1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE));
    if(load32(&s->phase)!=AWC_EVENT_SUBSCRIBED){__atomic_sub_fetch(&s->callbacks,1U,__ATOMIC_RELEASE);return AWC_RING_CLOSED;}
    return AWC_RING_OK;
}
enum awc_ring_error awc_event_end(struct awc_event_session *s){
    if(!s)return AWC_RING_ARGUMENT;uint32_t value=load32(&s->callbacks);
    do{if(!value)return AWC_RING_STALE;}
    while(!__atomic_compare_exchange_n(&s->callbacks,&value,value-1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE));
    return AWC_RING_OK;
}
enum awc_ring_error awc_event_close(struct awc_event_session *s){
    if(!s)return AWC_RING_ARGUMENT;uint32_t p=load32(&s->phase);
    if(p==AWC_EVENT_CLOSING || p==AWC_EVENT_DEAD)return AWC_RING_CLOSED;
    if(p==AWC_EVENT_NEW)return AWC_RING_ARGUMENT;
    store32(&s->phase,AWC_EVENT_CLOSING);return AWC_RING_OK;
}
int awc_event_close_ready(const struct awc_event_session *s){
    return s && load32(&s->phase)==AWC_EVENT_CLOSING && !load32(&s->callbacks) && !s->leases[0] && !s->leases[1];
}
enum awc_ring_error awc_event_finish_close(struct awc_event_session *s){
    if(!awc_event_close_ready(s))return AWC_RING_BUSY;
    /* Tokens stay immutable through object destruction, so a callback racing
     * the phase check cannot race a token clear. Object memory needs its own ref. */
    store32(&s->phase,AWC_EVENT_DEAD);return AWC_RING_OK;
}
