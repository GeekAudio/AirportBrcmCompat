#ifndef PRIVATE_MAC_ROUTE_CHECKED_HPP
#define PRIVATE_MAC_ROUTE_CHECKED_HPP
#include <stddef.h>
#include <stdint.h>

namespace PrivateMAC {
// A routing backend may return a nonzero error code through its wrapper-value
// channel. Require both success channels and the original trampoline before
// allowing the caller to publish the completed bridge.
template<class Patcher,class Request,class Original>
bool routeChecked(Patcher &patcher,size_t index,Request &request,Original &original,
                  uintptr_t address=0,size_t size=0) {
    patcher.clearError();
    const bool routed=patcher.routeMultiple(index,&request,1,address,size);
    const bool valid=routed && patcher.getError()==Patcher::Error::NoError && original;
    patcher.clearError();
    return valid;
}
}
#endif
