"""Strict 256-byte native inline and 384-byte candidate GET43 envelopes."""
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include "driver_version_format.hpp"
#include "version_method_shape.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>

using namespace AWDLKernel;

static void makeFrame(std::array<uint8_t, NativeFrameSize> &frame) {
    frame.fill(0);
    const uint8_t magic[4]={0xc9,0x69,0x28,0xc0};
    const uint8_t name[16]={'a','w','d','l','0',0};
    memcpy(frame.data(),magic,sizeof(magic));
    memcpy(frame.data()+0x3c08,name,sizeof(name));
    frame[0x3c18]=43;
}

static VersionCall callFor(const void *input, void *output, size_t capacity) {
    VersionCall call{};
    call.input=input;call.inputSize=NativeFrameSize;
    call.output=output;call.outputCapacity=capacity;
    return call;
}

static VersionMethodShape shapeFor(const VersionCall &call) {
    VersionMethodShape shape{};
    shape.version=2;shape.selector=0;
    shape.input=call.input;shape.inputSize=call.inputSize;
    shape.output=call.output;shape.outputCapacity=call.outputCapacity;
    return shape;
}

static void envelopes() {
    std::array<uint8_t,NativeFrameSize> frame{};makeFrame(frame);
    std::array<uint8_t,512> output{};
    assert(validVersionCapacity(LegacyVersionCapacity));
    assert(validVersionCapacity(NativeVersionCapacity));
    for (size_t cap : {LegacyVersionCapacity,NativeVersionCapacity}) {
        const auto call=callFor(frame.data(),output.data(),cap);
        assert(validVersionCall(call));
        VersionCall decoded{};
        assert(decodeVersionMethodShape(shapeFor(call),decoded));
        assert(decoded.input==frame.data() && decoded.output==output.data());
        assert(decoded.outputCapacity==cap);
    }
    for (size_t cap : {size_t(0),size_t(1),size_t(255),size_t(257),
                       size_t(383),size_t(385),size_t(512)}) {
        assert(!validVersionCapacity(cap));
        const auto call=callFor(frame.data(),output.data(),cap);
        assert(!validVersionCall(call));
        VersionCall decoded{};
        assert(!decodeVersionMethodShape(shapeFor(call),decoded));
        assert(!decoded.input && !decoded.output && decoded.outputCapacity==0);
    }

    auto shape=shapeFor(callFor(frame.data(),output.data(),LegacyVersionCapacity));
    VersionCall decoded{};
    shape.version=1;assert(!decodeVersionMethodShape(shape,decoded));
    shape=shapeFor(callFor(frame.data(),output.data(),LegacyVersionCapacity));
    shape.selector=1;assert(!decodeVersionMethodShape(shape,decoded));
    shape=shapeFor(callFor(frame.data(),output.data(),LegacyVersionCapacity));
    shape.scalarInputCount=1;assert(!decodeVersionMethodShape(shape,decoded));
    shape=shapeFor(callFor(frame.data(),output.data(),LegacyVersionCapacity));
    shape.inputDescriptor=reinterpret_cast<const void *>(uintptr_t(1));
    assert(!decodeVersionMethodShape(shape,decoded));
    shape=shapeFor(callFor(frame.data(),output.data(),LegacyVersionCapacity));
    shape.outputDescriptor=reinterpret_cast<const void *>(uintptr_t(1));
    assert(!decodeVersionMethodShape(shape,decoded));
    shape=shapeFor(callFor(frame.data(),output.data(),LegacyVersionCapacity));
    shape.output=reinterpret_cast<void *>(std::numeric_limits<uintptr_t>::max()-127U);
    assert(!decodeVersionMethodShape(shape,decoded));
    shape=shapeFor(callFor(frame.data(),output.data(),LegacyVersionCapacity));
    shape.output=frame.data()+NativeFrameSize-16;
    assert(!decodeVersionMethodShape(shape,decoded));
}

static void frameValidation() {
    std::array<uint8_t,NativeFrameSize> frame{};makeFrame(frame);
    std::array<uint8_t,512> output{};
    auto valid=[&] {return validVersionCall(callFor(frame.data(),output.data(),LegacyVersionCapacity));};
    assert(valid());
    frame[0]^=1;assert(!valid());frame[0]^=1;
    frame[0x3c08]='w';assert(!valid());frame[0x3c08]='a';
    frame[0x3c18]=42;assert(!valid());frame[0x3c18]=43;
    frame[12]=1;assert(!valid());frame[12]=0;
    auto call=callFor(frame.data(),output.data(),LegacyVersionCapacity);
    call.selector=1;assert(!validVersionCall(call));
    call=callFor(frame.data(),output.data(),LegacyVersionCapacity);
    call.inputSize=NativeFrameSize-1;assert(!validVersionCall(call));
}

static void renderer() {
    LegacyVersion source{};source.version=1;source.length=256;
    for (size_t i=0;i<sizeof(source.string);++i) source.string[i]=uint8_t('A'+(i%26));
    for (size_t cap : {LegacyVersionCapacity,NativeVersionCapacity}) {
        std::array<uint8_t,NativeVersionCapacity+1> out{};
        out.fill(0xa5);out[cap]=0; // Native caller keeps a byte beyond its 256-byte output.
        const auto result=renderLegacyVersion(source,0,out.data(),cap);
        assert(result.status==VersionStatus::Passed && result.returned==256);
        assert(result.backendCalled && result.observedLength==256 && result.observedVersion==1);
        assert(!memcmp(out.data(),source.string,256));
        assert(out[cap]==0); // The renderer did not write beyond outputCapacity.
        if (cap==LegacyVersionCapacity)
            assert(memchr(out.data(),0,cap+1)==out.data()+cap);
        else
            assert(out[256]==0 && out[cap-1]==0);
    }

    source.length=5;
    std::array<uint8_t,NativeVersionCapacity+1> out{};out.fill(0xa5);
    const auto shortResult=renderLegacyVersion(source,0,out.data(),LegacyVersionCapacity);
    assert(shortResult.status==VersionStatus::Passed && shortResult.returned==5);
    assert(!memcmp(out.data(),source.string,5));
    for (size_t i=5;i<LegacyVersionCapacity;++i) assert(out[i]==0);
    assert(out[LegacyVersionCapacity]==0xa5);

    source.length=257;out.fill(0xa5);
    const auto tooLong=renderLegacyVersion(source,0,out.data(),LegacyVersionCapacity);
    assert(tooLong.status==VersionStatus::BackendFormat && tooLong.returned==0);
    for (size_t i=0;i<LegacyVersionCapacity;++i) assert(out[i]==0);
    assert(out[LegacyVersionCapacity]==0xa5);

    source.length=5;out.fill(0xa5);
    const auto badCapacity=renderLegacyVersion(source,0,out.data(),257);
    assert(badCapacity.status==VersionStatus::Shape);
    for (uint8_t byte : out) assert(byte==0xa5);

    const auto backendError=renderLegacyVersion(source,-5,out.data(),LegacyVersionCapacity);
    assert(backendError.status==VersionStatus::BackendError && backendError.returned==0);
    for (size_t i=0;i<LegacyVersionCapacity;++i) assert(out[i]==0);
}

int main() {envelopes();frameValidation();renderer();}
'''

EXTERNAL_HARNESS = r'''
#include "version_external_method.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
using namespace AWDLKernel;

static uint32_t backendCalls=0;
static uint16_t returnedLength=7;

VersionResult DriverVersionBackend::get43(task_t,IOService *,IOService *,
                                          const VersionCall &call) const {
    ++backendCalls;
    LegacyVersion source{};source.version=1;source.length=returnedLength;
    for (size_t i=0;i<source.length;++i) source.string[i]=uint8_t('a'+i);
    return renderLegacyVersion(source,0,call.output,call.outputCapacity);
}

static void makeFrame(std::array<uint8_t,NativeFrameSize> &frame) {
    frame.fill(0);const uint8_t magic[4]={0xc9,0x69,0x28,0xc0};
    const uint8_t name[16]={'a','w','d','l','0',0};
    memcpy(frame.data(),magic,4);memcpy(frame.data()+0x3c08,name,16);frame[0x3c18]=43;
}

static void callCapacity(size_t capacity) {
    std::array<uint8_t,NativeFrameSize> frame{};makeFrame(frame);
    std::array<uint8_t,NativeVersionCapacity+1> output{};output.fill(0xa5);
    IOExternalMethodArguments args{};
    args.version=2;args.selector=0;args.structureInput=frame.data();
    args.structureInputSize=static_cast<uint32_t>(frame.size());
    args.structureOutput=output.data();args.structureOutputSize=static_cast<uint32_t>(capacity);
    DriverVersionBackend backend;IOService controller,provider;
    const uint32_t before=backendCalls;
    const auto result=runVersionExternalMethod(backend,reinterpret_cast<task_t>(uintptr_t(1)),
                                               &controller,&provider,args);
    assert(result.status==VersionStatus::Passed && result.backendCalled);
    assert(result.returned==returnedLength && backendCalls==before+1);
    assert(args.structureOutputSize==returnedLength);
    for (size_t i=0;i<returnedLength;++i) assert(output[i]==uint8_t('a'+i));
    if (capacity==LegacyVersionCapacity) assert(output[capacity]==0xa5);
}

int main() {
    callCapacity(LegacyVersionCapacity);
    callCapacity(NativeVersionCapacity);
    returnedLength=256;callCapacity(LegacyVersionCapacity);

    std::array<uint8_t,NativeFrameSize> frame{};makeFrame(frame);
    std::array<uint8_t,NativeVersionCapacity+1> output{};output.fill(0xa5);
    IOExternalMethodArguments args{};args.version=2;args.selector=0;
    args.structureInput=frame.data();args.structureInputSize=frame.size();
    args.structureOutput=output.data();args.structureOutputSize=257;
    DriverVersionBackend backend;IOService controller,provider;
    const uint32_t before=backendCalls;
    const auto malformed=runVersionExternalMethod(backend,reinterpret_cast<task_t>(uintptr_t(1)),
                                                   &controller,&provider,args);
    assert(malformed.status==VersionStatus::Shape && !malformed.backendCalled);
    assert(args.structureOutputSize==0 && backendCalls==before);
    for (uint8_t byte:output) assert(byte==0xa5);

    args.structureOutputSize=LegacyVersionCapacity;
    args.structureInputDescriptor=reinterpret_cast<void *>(uintptr_t(1));
    const auto descriptor=runVersionExternalMethod(backend,reinterpret_cast<task_t>(uintptr_t(1)),
                                                    &controller,&provider,args);
    assert(descriptor.status==VersionStatus::Shape && !descriptor.backendCalled);
    assert(args.structureOutputSize==0 && backendCalls==before);
}
'''

MOCK_IO_SERVICE = """
#pragma once
class IOService {};
"""

MOCK_MACH_TYPES = """
#pragma once
using task_t = void *;
"""

MOCK_IO_USER_CLIENT = """
#pragma once
#include <cstddef>
#include <cstdint>
#include <IOKit/IOService.h>
#include <mach/mach_types.h>
#define IO_EXTERNAL_METHOD_ARGUMENTS_CURRENT_VERSION 2
#define MACH_PORT_NULL nullptr
struct IOExternalMethodArguments {
    uint32_t version=2,selector=0;
    uint32_t scalarInputCount=0,scalarOutputCount=0,asyncReferenceCount=0;
    void *asyncWakePort=nullptr;
    uint64_t *asyncReference=nullptr;
    const uint64_t *scalarInput=nullptr;
    const void *structureInput=nullptr;
    uint32_t structureInputSize=0;
    void *structureInputDescriptor=nullptr;
    uint64_t *scalarOutput=nullptr;
    void *structureOutput=nullptr;
    uint32_t structureOutputSize=0;
    void *structureOutputDescriptor=nullptr;
    uint32_t structureOutputDescriptorSize=0;
    void *structureVariableOutputData=nullptr;
};
"""


class VersionMethodSchemaTests(unittest.TestCase):
    def test_audited_inline_capacities_and_frame_are_strict(self):
        with tempfile.TemporaryDirectory(prefix="version-method-schema-") as tmp:
            cpp = Path(tmp) / "schema.cpp"
            binary = Path(tmp) / "schema"
            cpp.write_text(HARNESS)
            compiled = subprocess.run(
                ["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                 "-I", str(PROJECT / "src/awdl_kernel"), str(cpp), "-o", str(binary)],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stderr)

    def test_external_method_plumbs_exact_capacity_to_renderer(self):
        with tempfile.TemporaryDirectory(prefix="version-external-method-") as tmp:
            root = Path(tmp)
            mock = root / "mock"
            (mock / "IOKit").mkdir(parents=True)
            (mock / "mach").mkdir()
            (mock / "IOKit" / "IOService.h").write_text(MOCK_IO_SERVICE)
            (mock / "mach" / "mach_types.h").write_text(MOCK_MACH_TYPES)
            (mock / "IOKit" / "IOUserClient.h").write_text(MOCK_IO_USER_CLIENT)
            cpp = root / "external.cpp"
            binary = root / "external"
            cpp.write_text(EXTERNAL_HARNESS)
            compiled = subprocess.run(
                ["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                 "-I", str(mock), "-I", str(PROJECT / "src/awdl_kernel"),
                 str(cpp), str(PROJECT / "src/awdl_kernel/version_external_method.cpp"),
                 "-o", str(binary)],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stderr)


if __name__ == "__main__":
    unittest.main()
