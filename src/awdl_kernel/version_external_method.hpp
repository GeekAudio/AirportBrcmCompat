// Unwired IOExternalMethodArguments adapter, not an IOUserClient or route.
#ifndef AIRPORT_AWDL_VERSION_EXTERNAL_METHOD_HPP
#define AIRPORT_AWDL_VERSION_EXTERNAL_METHOD_HPP
#include "driver_version_backend.hpp"
#include <IOKit/IOUserClient.h>

namespace AWDLKernel {
// Call only from a genuine, authorized connection's synchronous dispatch, with
// a retained owning task and provider/image stop-exclusion as required by the
// backend. This helper neither transfers nor releases async rights: a future
// dispatcher must reject/settle asynchronous calls before invoking it.
// The result preserves a real backend errno separately from adapter failures;
// it deliberately does not invent an errno-to-IOReturn mapping. Only success
// publishes the actual returned structure length. No footer pointer is used.
VersionResult runVersionExternalMethod(const DriverVersionBackend &,task_t owningTask,
                                      IOService *controller,IOService *provider,
                                      IOExternalMethodArguments &);
}
#endif
