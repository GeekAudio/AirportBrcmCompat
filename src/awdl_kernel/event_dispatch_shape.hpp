// Portable argument shape, not task authorization or transport readiness.
#ifndef AIRPORT_AWDL_EVENT_DISPATCH_SHAPE_HPP
#define AIRPORT_AWDL_EVENT_DISPATCH_SHAPE_HPP
#include "version_method_shape.hpp"
namespace AWDLKernel {
inline bool validEventPipeControlShape(uint32_t selector,const VersionMethodShape &s) {
    // Native init/exit use IOConnectCallStructMethod with zero input/output.
    // MIG may still provide inband/scalar addresses. Never dereference them.
    return (selector==3 || selector==4) && s.version==2 && s.selector==selector &&
        !s.scalarInputCount && !s.scalarOutputCount && !s.asyncReferenceCount &&
        !s.wakePortPresent && !s.asyncReference && !s.inputSize && !s.outputCapacity &&
        !s.inputDescriptor && !s.outputDescriptor && !s.outputDescriptorSize && !s.variableOutput;
}
}
#endif
