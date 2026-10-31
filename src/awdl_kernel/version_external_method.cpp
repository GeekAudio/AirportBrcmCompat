#include "version_external_method.hpp"
#include "version_method_shape.hpp"

namespace AWDLKernel {
static_assert(IO_EXTERNAL_METHOD_ARGUMENTS_CURRENT_VERSION==2,
              "Re-audit the actual IOExternalMethodArguments envelope");

VersionResult runVersionExternalMethod(const DriverVersionBackend &backend,task_t owner,
                                      IOService *controller,IOService *provider,
                                      IOExternalMethodArguments &arguments) {
    VersionMethodShape shape;
    shape.version=arguments.version;shape.selector=arguments.selector;
    shape.scalarInputCount=arguments.scalarInputCount;
    shape.scalarOutputCount=arguments.scalarOutputCount;
    shape.asyncReferenceCount=arguments.asyncReferenceCount;
    shape.wakePortPresent=arguments.asyncWakePort!=MACH_PORT_NULL;
    shape.asyncReference=arguments.asyncReference;
    shape.input=arguments.structureInput;shape.inputSize=arguments.structureInputSize;
    shape.output=arguments.structureOutput;shape.outputCapacity=arguments.structureOutputSize;
    shape.inputDescriptor=arguments.structureInputDescriptor;
    shape.outputDescriptor=arguments.structureOutputDescriptor;
    shape.outputDescriptorSize=arguments.structureOutputDescriptorSize;
    shape.variableOutput=arguments.structureVariableOutputData;
    arguments.structureOutputSize=0;
    VersionCall call;
    if (!decodeVersionMethodShape(shape,call)) return VersionResult {};
    auto result=backend.get43(owner,controller,provider,call);
    if (result.status==VersionStatus::Passed && result.returned<=shape.outputCapacity)
        arguments.structureOutputSize=static_cast<uint32_t>(result.returned);
    return result;
}
} // namespace AWDLKernel
