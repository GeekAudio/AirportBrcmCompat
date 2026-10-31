#include "facade_mock.h"
#include <string.h>

static int overlap(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t aa=(uintptr_t)a,bb=(uintptr_t)b;
    return an>UINTPTR_MAX-aa || bn>UINTPTR_MAX-bb || (aa<bb+bn && bb<aa+an);
}
static int owned(const struct awcf_mock *f,struct awcf_identity id){
    return f && id.task && id.provider_generation &&
        f->session.task_token==id.task && f->session.provider_generation==id.provider_generation;
}
static int live(const struct awcf_mock *f){
    return f->session.phase>=AWC_EVENT_OPEN && f->session.phase<=AWC_EVENT_SUBSCRIBED;
}
static int disjoint(const struct awcf_mock *f,const void *p,size_t n){
    return p && !overlap(p,n,f,sizeof(*f)) &&
        !overlap(p,n,f->ring_storage,f->ring_size) &&
        !overlap(p,n,f->state_storage,sizeof(*f->state_storage)) &&
        !overlap(p,n,f->backend.slots,f->backend.slots_size);
}
enum awc_ring_error awcf_mock_open(struct awcf_mock *f,const struct awcf_authority *auth,
                                  const struct awcf_backend_fixture *backend,void *bytes,
                                  size_t n,struct awc_ring_shared *state){
    if(!f || !auth || !backend || !bytes || !state || !auth->identity.task ||
       !auth->identity.provider_generation || !backend->owner || !backend->epoch ||
       n<AWC_RING_PAGE*2U || n>UINT32_MAX || n%AWC_RING_PAGE ||
       ((uintptr_t)bytes&3U) || ((uintptr_t)state&3U))return AWC_RING_ARGUMENT;
    if(auth->native_wlan_authentication_true!=1 || auth->legacy_awdl_event_monitor_true!=1)
        return AWC_RING_PERMISSION;
    if(backend->provider_generation!=auth->identity.provider_generation || backend->legacy_role!=6)
        return AWC_RING_POLICY;
    if(backend->kind==AWCF_OWNED_SLOTS){
        if(backend->legacy_open_type!=4)return AWC_RING_POLICY;
        if(backend->exclusive_reserved!=1)return AWC_RING_BUSY;
        if(!backend->slots || !backend->slot_count || backend->slot_count>300 ||
           backend->slots_size/AWC_LEGACY_SLOT_SIZE<backend->slot_count)return AWC_RING_ARGUMENT;
    }else if(backend->kind==AWCF_POST_OBSERVER){
        if(backend->legacy_open_type || backend->exclusive_reserved || backend->slots ||
           backend->slots_size || backend->slot_count)return AWC_RING_POLICY;
        if(backend->observer_lease!=1)return AWC_RING_BUSY;
    }else return AWC_RING_POLICY;
    if(backend->fixture_schema_ready!=0 && backend->fixture_schema_ready!=1)return AWC_RING_POLICY;
    if(overlap(f,sizeof(*f),auth,sizeof(*auth)) || overlap(f,sizeof(*f),backend,sizeof(*backend)) ||
       overlap(f,sizeof(*f),bytes,n) || overlap(f,sizeof(*f),state,sizeof(*state)) ||
       overlap(f,sizeof(*f),backend->slots,backend->slots_size) ||
       overlap(bytes,n,state,sizeof(*state)) ||
       overlap(bytes,n,backend->slots,backend->slots_size) ||
       overlap(state,sizeof(*state),backend->slots,backend->slots_size))return AWC_RING_ARGUMENT;
    /* Open must be invoked once on a zero-initialized owned object. */
    if(f->session.phase!=AWC_EVENT_NEW || f->backend_attached)return AWC_RING_BUSY;
    memset(f,0,sizeof(*f));
    enum awc_ring_error error=awc_event_open(&f->session,auth->identity.task,
        auth->identity.provider_generation,auth->native_wlan_authentication_true);
    if(error)return error;
    f->backend=*backend;f->backend_attached=1;f->schema_ready=(uint32_t)backend->fixture_schema_ready;
    f->ring_storage=bytes;f->ring_size=n;f->state_storage=state;f->next_map_lease=1;
    return AWC_RING_OK;
}
static int empty_shape(const struct awcf_call_shape *s){
    return s && !s->input_size && !s->scalar_input_count && !s->scalar_output_count;
}
enum awc_ring_error awcf_mock_method(struct awcf_mock *f,struct awcf_identity id,
                                    uint32_t selector,const struct awcf_call_shape *s,uint8_t *out){
    if(!owned(f,id))return AWC_RING_PERMISSION;
    if(!live(f))return AWC_RING_CLOSED;
    if(!empty_shape(s))return AWC_RING_ARGUMENT;
    if(selector==1 || selector==5 || selector==7){
        if(s->output_size!=1 || s->async_reference_count || s->wake_port_present ||
           !disjoint(f,out,1))return AWC_RING_ARGUMENT;
        *out=(uint8_t)(selector==5 && f->backend_attached && f->schema_ready);
        return AWC_RING_OK;
    }
    if(selector!=2 && selector!=3 && selector!=4)return AWC_RING_POLICY;
    if(s->output_size || out)return AWC_RING_ARGUMENT;
    if(selector==2)return awc_event_subscribe(&f->session,id.task,id.provider_generation,
        s->async_reference_count,s->wake_port_present,s->scalar_input_count,s->scalar_output_count);
    if(s->async_reference_count || s->wake_port_present)return AWC_RING_ARGUMENT;
    if(selector==4)return awcf_mock_begin_close(f,id);
    if(!f->backend_attached || !f->schema_ready)return AWC_RING_POLICY;
    if(f->session.phase!=AWC_EVENT_OPEN)return AWC_RING_BUSY;
    enum awc_ring_error error=awc_ring_init(&f->ring,f->ring_storage,f->ring_size,
                                          f->state_storage,sizeof(*f->state_storage));
    if(error)return error;
    return awc_event_pipe_init(&f->session,id.task,id.provider_generation);
}
enum awc_ring_error awcf_mock_map(struct awcf_mock *f,struct awcf_identity id,
                                 uint32_t type,uint32_t options,uint64_t *lease){
    if(!owned(f,id))return AWC_RING_PERMISSION;
    if(!disjoint(f,lease,sizeof(*lease)))return AWC_RING_ARGUMENT;
    if(type<1 || type>2 || options!=(type==1 ? AWCF_MAP_ANYWHERE|AWCF_MAP_READONLY : AWCF_MAP_ANYWHERE))
        return AWC_RING_POLICY;
    if(f->map_leases[type-1])return AWC_RING_BUSY;
    if(f->next_map_lease==UINT64_MAX)return AWC_RING_BOUNDS;
    enum awc_ring_error error=awc_event_map(&f->session,id.task,id.provider_generation,type);
    if(error)return error;
    f->map_leases[type-1]=f->next_map_lease++;*lease=f->map_leases[type-1];return AWC_RING_OK;
}
enum awc_ring_error awcf_mock_unmap(struct awcf_mock *f,struct awcf_identity id,
                                   uint32_t type,uint64_t lease){
    if(!owned(f,id))return AWC_RING_PERMISSION;
    if(type<1 || type>2 || !lease || f->map_leases[type-1]!=lease)return AWC_RING_STALE;
    enum awc_ring_error error=awc_event_unmap(&f->session,type);
    if(!error)f->map_leases[type-1]=0;
    return error;
}
static void clear_if_done(struct awcf_mock *f){
    if(f->pending && f->pending!=AWCF_NEEDS_PUBLISH && !f->ack_pending && !f->notify_pending){
        memset(&f->snapshot,0,sizeof(f->snapshot));memset(f->translated,0,sizeof(f->translated));
        f->pending=AWCF_IDLE;f->pending_delivery=0;
    }
}
static enum awc_ring_error publish(struct awcf_mock *f){
    struct awc_event_metadata meta;memset(&meta,0,sizeof(meta));
    meta.message=AWCF_FIXTURE_NATIVE_MESSAGE; /* Deliberately no real AWDL schema. */
    struct awc_ring_notice notice;
    enum awc_ring_error error=awc_ring_publish(&f->ring,&meta,f->translated,sizeof(f->translated),&notice);
    if(error==AWC_RING_FULL){f->notify_pending=1;return AWC_RING_BUSY;}
    if(error)return error;
    f->pending=AWCF_COMMITTED;f->ack_pending=f->backend.kind==AWCF_OWNED_SLOTS;
    f->notify_pending=1;return AWC_RING_OK;
}
static enum awc_ring_error receive_begin(struct awcf_mock *f,uint64_t provider,uint64_t owner,
                                         uint64_t epoch,uint64_t delivery,uint32_t kind){
    if(!f || !f->backend_attached || provider!=f->session.provider_generation ||
       owner!=f->backend.owner || epoch!=f->backend.epoch)return AWC_RING_PERMISSION;
    if(f->backend.kind!=kind)return AWC_RING_POLICY;
    if(!delivery || delivery<=f->last_delivery)return AWC_RING_STALE;
    if(f->pending)return AWC_RING_BUSY;
    return awc_event_begin(&f->session,provider);
}
static enum awc_ring_error translate(struct awcf_mock *f,uint64_t delivery){
    f->last_delivery=delivery;f->pending_delivery=delivery;f->pending=AWCF_DROPPED;
    f->ack_pending=f->backend.kind==AWCF_OWNED_SLOTS;
    /* These ids/body layouts are synthetic and do not identify any AWDL event.
     * A future integration must replace this whole fixture-only boundary with
     * audited per-message schemas; there is no byte-preserving generic path. */
    uint32_t version=0,status=0,reserved=0;
    if(f->snapshot.message==AWCF_FIXTURE_LEGACY_MESSAGE && f->snapshot.length==12){
        memcpy(&version,f->snapshot.bytes,4);memcpy(&status,f->snapshot.bytes+4,4);
        memcpy(&reserved,f->snapshot.bytes+8,4);
    }
    enum awc_ring_error error;
    if(f->snapshot.message!=AWCF_FIXTURE_LEGACY_MESSAGE || f->snapshot.length!=12 ||
       version!=1 || status>3 || reserved){error=AWC_RING_POLICY;}
    else{
        memcpy(f->translated,&version,4);memcpy(f->translated+4,&status,4);
        f->pending=AWCF_NEEDS_PUBLISH;f->ack_pending=0;error=publish(f);
    }
    clear_if_done(f);return error;
}
enum awc_ring_error awcf_mock_receive(struct awcf_mock *f,uint64_t provider,uint64_t owner,
                                     uint64_t epoch,uint64_t delivery,const uint64_t *args,size_t count){
    enum awc_ring_error error=receive_begin(f,provider,owner,epoch,delivery,AWCF_OWNED_SLOTS);
    if(error)return error;
    error=awc_legacy_capture(args,count,f->backend.slots,f->backend.slots_size,
                             f->backend.slot_count,&f->snapshot);
    if(!error)error=translate(f,delivery);
    (void)awc_event_end(&f->session);return error;
}
enum awc_ring_error awcf_mock_receive_post(struct awcf_mock *f,uint64_t provider,uint64_t owner,
                                          uint64_t epoch,uint64_t delivery,uint32_t message,
                                          const void *body,size_t size){
    enum awc_ring_error error=receive_begin(f,provider,owner,epoch,delivery,AWCF_POST_OBSERVER);
    if(error)return error;
    if(!message || size>AWC_LEGACY_SLOT_SIZE || (!body && size) ||
       (size && !disjoint(f,body,size)))error=AWC_RING_BOUNDS;
    else{
        memset(&f->snapshot,0,sizeof(f->snapshot));
        if(size)memcpy(f->snapshot.bytes,body,size);
        f->snapshot.message=message;f->snapshot.length=(uint32_t)size;
        error=translate(f,delivery);
    }
    (void)awc_event_end(&f->session);return error;
}
enum awc_ring_error awcf_mock_retry_publish(struct awcf_mock *f){
    if(!f || !f->backend_attached)return AWC_RING_CLOSED;
    if(f->pending!=AWCF_NEEDS_PUBLISH)return AWC_RING_STALE;
    if(f->session.phase!=AWC_EVENT_SUBSCRIBED)return AWC_RING_CLOSED;
    return publish(f);
}
enum awc_ring_error awcf_mock_actions(const struct awcf_mock *f,struct awcf_actions *a){
    if(!f || !disjoint(f,a,sizeof(*a)))return AWC_RING_ARGUMENT;
    memset(a,0,sizeof(*a));a->delivery=f->pending_delivery;
    a->ack_required=f->ack_pending;a->ack_index=f->snapshot.ack_index;
    a->notify_required=f->notify_pending;a->async_argument_count=0;
    a->dropped=f->pending==AWCF_DROPPED;a->committed=f->pending==AWCF_COMMITTED;
    return AWC_RING_OK;
}
enum awc_ring_error awcf_mock_complete_notify(struct awcf_mock *f,uint64_t delivery,int success){
    if(!f || !delivery || delivery!=f->pending_delivery || !f->notify_pending)return AWC_RING_STALE;
    if(success!=1)return AWC_RING_BUSY;
    f->notify_pending=0;clear_if_done(f);return AWC_RING_OK;
}
enum awc_ring_error awcf_mock_complete_ack(struct awcf_mock *f,uint64_t delivery,int success){
    if(!f || !delivery || delivery!=f->pending_delivery || !f->ack_pending)return AWC_RING_STALE;
    if(success!=1)return AWC_RING_BUSY;
    f->ack_pending=0;clear_if_done(f);return AWC_RING_OK;
}
enum awc_ring_error awcf_mock_begin_close(struct awcf_mock *f,struct awcf_identity id){
    if(!owned(f,id))return AWC_RING_PERMISSION;
    enum awc_ring_error error=awc_event_close(&f->session);if(error)return error;
    /* Once closing starts, no new publication or notification. A captured but
     * uncommitted body is discarded; its owned legacy slot still needs ACK.
     * An already committed record is not replayed or erased. */
    if(f->pending==AWCF_NEEDS_PUBLISH){
        f->pending=AWCF_DROPPED;f->ack_pending=f->backend.kind==AWCF_OWNED_SLOTS;
    }
    f->notify_pending=0;clear_if_done(f);return AWC_RING_OK;
}
enum awc_ring_error awcf_mock_detach(struct awcf_mock *f,uint64_t epoch,int quiesced){
    if(!f || !f->backend_attached || epoch!=f->backend.epoch)return AWC_RING_STALE;
    if(f->session.phase!=AWC_EVENT_CLOSING || quiesced!=1 || f->session.callbacks || f->pending)
        return AWC_RING_BUSY;
    f->backend_attached=0;return AWC_RING_OK;
}
enum awc_ring_error awcf_mock_finish_close(struct awcf_mock *f){
    if(!f || f->backend_attached || f->pending)return AWC_RING_BUSY;
    return awc_event_finish_close(&f->session);
}
