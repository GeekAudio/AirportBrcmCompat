#ifndef AIRPORT_BRCM_PRIMARY_INTERFACE_IOKIT_HPP
#define AIRPORT_BRCM_PRIMARY_INTERFACE_IOKIT_HPP
#include "primary_interface.hpp"
#include <IOKit/IOBSD.h>
#include <IOKit/IOService.h>
#include <libkern/c++/OSString.h>
#include <string.h>

namespace PrimaryInterface {
struct BSDNameProperty {
    char bytes[RequestNameBytes] {};
    size_t length=0;
};

inline bool copyBSDName(IOService *interface,BSDNameProperty &out) {
    out={};if (!interface) return false;
    OSObject *object=interface->copyProperty(kIOBSDNameKey);
    if (!object) return false;
    const auto *string=OSDynamicCast(OSString,object);
    const unsigned int length=string?string->getLength():0;
    const char *bytes=string?string->getCStringNoCopy():nullptr;
    Name parsed;
    const bool valid=bytes && length<RequestNameBytes &&
        parsePropertyName(bytes,length,parsed);
    if (valid) {
        memcpy(out.bytes,bytes,length);out.bytes[length]='\0';out.length=length;
    }
    object->release();
    return valid;
}
inline bool exactClass(const IOService *service,const char *className) {
    return service && service->getMetaClass() && className &&
        !strcmp(service->getMetaClass()->getClassName(),className);
}
inline bool primaryServiceMatches(IOService *controller,IOService *interface,
                                  const char *request) {
    if (!controller || !interface || controller->isInactive() || interface->isInactive() ||
        interface->getProvider()!=controller) return false;
    BSDNameProperty property;
    if (!copyBSDName(interface,property)) return false;
    const ServiceFacts facts {
        exactClass(controller,"AirPort_BrcmNIC"),
        exactClass(interface,"AirPort_BrcmNIC_Interface"),
        interface->getProvider()==controller,
        !controller->isInactive()&&!interface->isInactive()
    };
    return requestMatchesPrimaryService(request,property.bytes,property.length,facts);
}
inline bool propertyMatchesIfnet(IOService *interface,const char *ifnetName,
                                 uint32_t ifnetUnit) {
    BSDNameProperty property;
    if (!copyBSDName(interface,property)) return false;
    Name service;
    if (!parsePropertyName(property.bytes,property.length,service) || !ifnetName ||
        ifnetName[0]!='e' || ifnetName[1]!='n' || ifnetName[2]!='\0') return false;
    // Darwin's ifnet_name() returns the interface prefix ("en"); the unit is
    // a separate ifnet_unit() value. The IOService BSD Name property carries
    // the complete canonical name (for example, "en7").
    return service.unit==ifnetUnit;
}
} // namespace PrimaryInterface
#endif
