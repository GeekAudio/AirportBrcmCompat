// Argument-boundary checks only. No pointer below is dereferenced here.
#ifndef AIRPORT_AWDL_VERSION_METHOD_SHAPE_HPP
#define AIRPORT_AWDL_VERSION_METHOD_SHAPE_HPP
#include "driver_version_format.hpp"

namespace AWDLKernel {
struct VersionMethodShape {
    uint32_t version=0,selector=0;
    uint32_t scalarInputCount=0,scalarOutputCount=0,asyncReferenceCount=0;
    bool wakePortPresent=false;
    const void *asyncReference=nullptr;
    const void *input=nullptr;
    size_t inputSize=0;
    void *output=nullptr;
    size_t outputCapacity=0;
    const void *inputDescriptor=nullptr,*outputDescriptor=nullptr;
    size_t outputDescriptorSize=0;
    const void *variableOutput=nullptr;
};

// Only the audited synchronous inline selector0 GET43 envelopes (14/15: 256;
// existing candidate route: 384). A valid shape does not authorize a task,
// establish a provider lease, or validate the frame. Those checks remain in
// the real typed backend and its integration owner.
inline bool decodeVersionMethodShape(const VersionMethodShape &shape,VersionCall &call) {
    call=VersionCall {};
    if (shape.version!=2 || shape.selector || shape.scalarInputCount ||
        shape.scalarOutputCount || shape.asyncReferenceCount || shape.wakePortPresent ||
        shape.asyncReference || shape.inputDescriptor || shape.outputDescriptor ||
        shape.outputDescriptorSize || shape.variableOutput || !shape.input || !shape.output ||
        shape.inputSize!=NativeFrameSize || !validVersionCapacity(shape.outputCapacity) ||
        reinterpret_cast<uintptr_t>(shape.input)>UINTPTR_MAX-shape.inputSize ||
        reinterpret_cast<uintptr_t>(shape.output)>UINTPTR_MAX-shape.outputCapacity ||
        versionRangesOverlap(shape.input,shape.inputSize,shape.output,shape.outputCapacity))
        return false;
    call.input=shape.input;call.inputSize=shape.inputSize;
    call.output=shape.output;call.outputCapacity=shape.outputCapacity;
    return true;
}
} // namespace AWDLKernel
#endif
