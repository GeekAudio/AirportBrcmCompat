// Read-only numeric metadata from one already-owned, complete native request.
// Not an admission decision, protocol conversion, payload logger or key parser.
#ifndef AIRPORT_ASSOCIATION_SURVEY_HPP
#define AIRPORT_ASSOCIATION_SURVEY_HPP

#include <stdint.h>
#include <stddef.h>

namespace AssociationSurvey {
constexpr size_t NativeSize = 908;

// Each half is <=65535, even for a raw 0xffffffff policy word. Publishing either
// half through the existing signed Code interface cannot create its -1 sentinel.
struct Word32 { uint16_t low16=0, high16=0; };
struct Snapshot {
    Word32 authLower8, authUpper12, allowedAuth508, scopeLength580;
    Word32 authUpperExt624, transitionDisabledFlags628, bandPreference632, wsecFlags636;
    Word32 keyLength64, cipher68, pmkLength472;
    uint16_t firstIELength208=0;
    uint16_t sixGPolicy899=0;
    uint16_t denyListedBSSIDCount518=0;
    uint16_t secondIELength640=0;
    uint16_t unknownTailFirstOffset=0; // 0 = no nonzero byte in900..907.
    uint16_t unknownTailNonzero=0; // One eight-byte bucket:0 or1 only.
};
static_assert(sizeof(Word32)==4 && sizeof(Snapshot)==56,
              "The survey must remain fixed-size numeric metadata without payload storage");

enum class Status : uint16_t { Ok=0, InvalidInput=1, AliasedOutput=2 };
// All identity/opaque storage is excluded even from byte-presence statistics:
// MAC512..517, BSSID storage519..579, scope584..623, second IE642..898. The
// earlier area16..507 contributes only the scalar key length/cipher/PMK length
// and first-IE length. Its SSID/BSSID/key/PMK/IE bytes are never surveyed. Only
//900..907 remains an unknown tail segment;899 is a separate named policy byte.
constexpr size_t UnknownBegin=900, UnknownEnd=NativeSize;

inline bool overlaps(const void *a,size_t an,const void *b,size_t bn) {
    if (!an || !bn) return false;
    const uintptr_t x=reinterpret_cast<uintptr_t>(a), y=reinterpret_cast<uintptr_t>(b);
    // Subtraction avoids overflow from adding a caller-supplied size to a pointer.
    return x<=y ? y-x<an : x-y<bn;
}
inline Word32 word(const uint8_t *p) {
    // Byte reads permit unaligned owned buffers and fix little-endian semantics.
    return {static_cast<uint16_t>(p[0] | static_cast<uint16_t>(p[1])<<8),
            static_cast<uint16_t>(p[2] | static_cast<uint16_t>(p[3])<<8)};
}

inline Status inspect(const uint8_t *native,size_t length,Snapshot &out) {
    // Even an invalid request must not let an aliased output overwrite const
    // input. Such failures preserve the existing output/input bytes unchanged.
    if (native && (static_cast<const void *>(native)==static_cast<const void *>(&out) ||
                   overlaps(native,length,&out,sizeof(out)))) return Status::AliasedOutput;
    out=Snapshot{};
    if (!native || length!=NativeSize) return Status::InvalidInput;

    out.authLower8=word(native+8);
    out.authUpper12=word(native+12);
    out.allowedAuth508=word(native+508);
    out.scopeLength580=word(native+580);
    out.authUpperExt624=word(native+624);
    out.transitionDisabledFlags628=word(native+628);
    out.bandPreference632=word(native+632);
    out.wsecFlags636=word(native+636);
    out.keyLength64=word(native+64);
    out.cipher68=word(native+68);
    out.pmkLength472=word(native+472);
    out.firstIELength208=static_cast<uint16_t>(native[208] | static_cast<uint16_t>(native[209])<<8);
    out.sixGPolicy899=native[899];
    out.denyListedBSSIDCount518=native[518];
    out.secondIELength640=static_cast<uint16_t>(native[640] | static_cast<uint16_t>(native[641])<<8);
    // No length, count or policy value above controls any access below.
    for (size_t offset=UnknownBegin;offset<UnknownEnd;offset++) {
        if (!native[offset]) continue;
        if (!out.unknownTailFirstOffset) out.unknownTailFirstOffset=static_cast<uint16_t>(offset);
        out.unknownTailNonzero=1;
    }
    return Status::Ok;
}
} // namespace AssociationSurvey
#endif
