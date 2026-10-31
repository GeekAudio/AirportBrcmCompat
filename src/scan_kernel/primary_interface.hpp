// Host-testable primary Broadcom interface name rules.
#ifndef AIRPORT_BRCM_PRIMARY_INTERFACE_HPP
#define AIRPORT_BRCM_PRIMARY_INTERFACE_HPP
#include <stddef.h>
#include <stdint.h>

namespace PrimaryInterface {
constexpr size_t RequestNameBytes=16;

struct Name {
    uint32_t unit=0;
    size_t length=0;
};

inline bool parseNameBytes(const char *bytes,size_t length,Name &out) {
    out={};
    if (!bytes || length<3 || length>=RequestNameBytes || bytes[0]!='e' || bytes[1]!='n') return false;
    if (bytes[2]<'0' || bytes[2]>'9') return false;
    if (length>3 && bytes[2]=='0') return false;
    uint32_t unit=0;
    for (size_t i=2;i<length;i++) {
        const char ch=bytes[i];
        if (ch<'0' || ch>'9') return false;
        const uint32_t digit=static_cast<uint32_t>(ch-'0');
        if (unit>(UINT32_MAX-digit)/10U) return false;
        unit=unit*10U+digit;
    }
    out={unit,length};return true;
}

inline bool parseRequestName(const char *bytes,Name &out) {
    out={};if (!bytes) return false;size_t length=0;
    while (length<RequestNameBytes && bytes[length]) ++length;
    if (length==RequestNameBytes) return false;
    for (size_t i=length+1;i<RequestNameBytes;i++) if (bytes[i]) return false;
    return parseNameBytes(bytes,length,out);
}

inline bool parseCString(const char *text,size_t capacity,Name &out) {
    out={};if (!text) return false;
    size_t length=0;while (length<capacity && text[length]) ++length;
    if (length==capacity) return false;
    return parseNameBytes(text,length,out);
}

inline bool parsePropertyName(const char *text,size_t length,Name &out) {
    return parseNameBytes(text,length,out);
}

inline bool sameRequestAndProperty(const char *request,
                                   const char *property,size_t propertyLength,
                                   uint32_t *unit=nullptr) {
    Name requested,actual;
    if (!request || !parseRequestName(request,requested) || !parsePropertyName(property,propertyLength,actual) ||
        requested.unit!=actual.unit || requested.length!=actual.length) return false;
    for (size_t i=0;i<requested.length;i++) if (request[i]!=property[i]) return false;
    if (unit) *unit=requested.unit;
    return true;
}

struct ServiceFacts {
    bool exactControllerClass=false;
    bool exactInterfaceClass=false;
    bool providerIsController=false;
    bool active=false;
};

inline bool requestMatchesPrimaryService(const char *request,
                                         const char *bsdName,size_t bsdNameLength,
                                         const ServiceFacts &facts,uint32_t *unit=nullptr) {
    if (!facts.exactControllerClass || !facts.exactInterfaceClass ||
        !facts.providerIsController || !facts.active) return false;
    return sameRequestAndProperty(request,bsdName,bsdNameLength,unit);
}

} // namespace PrimaryInterface
#endif
