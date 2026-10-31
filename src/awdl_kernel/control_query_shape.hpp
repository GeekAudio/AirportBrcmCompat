// Portable shape only. False does not advertise an event pipe or a backend.
#ifndef AIRPORT_AWDL_CONTROL_QUERY_SHAPE_HPP
#define AIRPORT_AWDL_CONTROL_QUERY_SHAPE_HPP
#include "version_method_shape.hpp"
namespace AWDLKernel {
inline bool validFalseQuery(uint32_t selector,const VersionMethodShape &s) {
    // MIG preserves its inband buffer address even for zero input bytes. The
    // length is authoritative: ignore input's value and never dereference it.
    return (selector==1 || selector==5 || selector==7) && s.version==2 && s.selector==selector &&
        !s.scalarInputCount && !s.scalarOutputCount && !s.asyncReferenceCount && !s.wakePortPresent &&
        !s.asyncReference && !s.inputSize && s.output && s.outputCapacity==1 &&
        !s.inputDescriptor && !s.outputDescriptor && !s.outputDescriptorSize && !s.variableOutput;
}
}
#endif
