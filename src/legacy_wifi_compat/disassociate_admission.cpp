#include "disassociate_admission.hpp"

#include "event_contracts.hpp"

#include <string.h>

namespace LegacyWiFi { namespace DisassociateAdmission {

namespace E = EventContracts;

namespace {

bool supportedChild(DCC::ChildKind child) {
    return child == DCC::Brcm4331 || child == DCC::Brcm43224;
}

bool resolveImageSymbol(KernelPatcher &patcher, size_t index,
                        const char *name, uintptr_t base, size_t size,
                        uintptr_t &resolved) {
    if (!name || !base || size > UINTPTR_MAX - base) return false;

    patcher.clearError();
    const mach_vm_address_t address = patcher.solveSymbol(
        index, name, static_cast<mach_vm_address_t>(base), size);
    const KernelPatcher::Error error = patcher.getError();
    patcher.clearError();

    if (!address || error != KernelPatcher::Error::NoError ||
        static_cast<uint64_t>(address) > static_cast<uint64_t>(UINTPTR_MAX))
        return false;
    resolved = static_cast<uintptr_t>(address);
    return true;
}

bool resolveKernelImport(KernelPatcher &patcher, const char *name,
                         uintptr_t &resolved) {
    if (!name) return false;

    patcher.clearError();
    const mach_vm_address_t address = patcher.solveSymbol(
        KernelPatcher::KernelID, name);
    const KernelPatcher::Error error = patcher.getError();
    patcher.clearError();

    if (!address || error != KernelPatcher::Error::NoError ||
        static_cast<uint64_t>(address) > static_cast<uint64_t>(UINTPTR_MAX))
        return false;
    resolved = static_cast<uintptr_t>(address);
    return true;
}

} // namespace

Admission::Admission()
    : ready(false), child(DCC::Brcm4331), index(0), image{nullptr, 0, 0},
      imageUUID{}, symbols{}, imports{}, routeSymbols{} {}

bool verifyChild(KernelPatcher &patcher, size_t index, uintptr_t base,
                 size_t size, DCC::ChildKind child, Admission *out) {
    if (!out) return false;
    if (out->ready) return false;

    patcher.clearError();
    *out = Admission();
    if (!supportedChild(child) || !base || !size || size > UINTPTR_MAX - base)
        return false;

    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(base);
    E::LoadedImage loaded{bytes, size};
    E::Detail::ParsedImage parsed{};
    if (!E::Detail::parseImage(loaded, parsed) || parsed.base != base ||
        parsed.size != size || !parsed.uuid)
        return false;

    Admission candidate;
    candidate.child = child;
    candidate.index = index;
    candidate.image = {bytes, size, base};
    memcpy(candidate.imageUUID, parsed.uuid, sizeof(candidate.imageUUID));

    for (size_t symbolIndex = 0; symbolIndex < DCC::FunctionCount;
         ++symbolIndex) {
        const DCC::FunctionContract &function =
            DCC::Functions[static_cast<size_t>(child)][symbolIndex];
        if (!function.symbol) continue;
        if (!resolveImageSymbol(patcher, index, function.symbol, base, size,
                                candidate.symbols.addresses[symbolIndex]))
            return false;
    }

    for (size_t symbolIndex = 0; symbolIndex < DCC::RouteSymbolCount;
         ++symbolIndex) {
        const DCC::RouteSymbolContract &symbol = DCC::RouteSymbols[symbolIndex];
        if (symbol.child != child) continue;
        if (!resolveImageSymbol(patcher, index, symbol.symbol, base, size,
                                candidate.routeSymbols.addresses[symbolIndex]))
            return false;
    }

    bool requiredImports[DCC::ImportCount]{};
    for (size_t callIndex = 0; callIndex < DCC::ExternalCallCount; ++callIndex) {
        const DCC::ExternalCall &call = DCC::ExternalCalls[callIndex];
        if (call.child != child) continue;
        const size_t importIndex = static_cast<size_t>(call.target);
        if (importIndex >= DCC::ImportCount) return false;
        requiredImports[importIndex] = true;
    }

    for (size_t importIndex = 0; importIndex < DCC::ImportCount; ++importIndex) {
        if (!requiredImports[importIndex]) continue;
        if (!resolveKernelImport(patcher, DCC::ImportNames[importIndex],
                                 candidate.imports.addresses[importIndex]))
            return false;
    }

    if (!DCC::verify(candidate.image, parsed.uuid, child, candidate.symbols,
                     candidate.imports, candidate.routeSymbols))
        return false;

    candidate.ready = true;
    *out = candidate;
    return true;
}

} } // namespace LegacyWiFi::DisassociateAdmission
