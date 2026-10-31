// Optional, bounded numeric observation of already-owned Broadcom RX message48.
// This is not part of the normal event codec and never decides acceptance.
#ifndef AIRPORT_BRCM_BASELINE_TRACE_HPP
#define AIRPORT_BRCM_BASELINE_TRACE_HPP

#include <stddef.h>
#include <stdint.h>

namespace AWDLKernel { namespace BaselineTrace {

enum : uint32_t {
    InputLimit = 2048,
    TlvLimit = 128,
    SampleLimit = 256,
    SubtypePoolLimit = 112,
    OtherPoolLimit = SampleLimit - 2 * SubtypePoolLimit
};

// Last numeric summaries for a PSF or MIF subtype. These are observations of
// the requested TLV bytes only; they do not certify the complete TLV/frame.
struct SubtypeSummary {
    uint32_t samples;
    uint32_t lastLength;
    uint32_t lastTlvCount;

    uint32_t lastTlv4Count;
    uint32_t lastTlv4Length;
    uint32_t lastTlv4HasNextChannel;
    uint32_t lastTlv4NextChannel;
    uint32_t lastTlv4HasTxDownCounter;
    uint32_t lastTlv4TxDownCounter;
    uint32_t lastTlv4HasMasterChannel;
    uint32_t lastTlv4MasterChannel;
    uint32_t lastTlv4HasAwSequence;
    uint32_t lastTlv4AwSequence;
    uint32_t lastTlv4PresenceFieldsAvailable;
    uint32_t lastTlv4MinExt;
    uint32_t lastTlv4MaxExtMulticast;
    uint32_t lastTlv4MaxExtUnicast;
    uint32_t lastTlv4MaxExtActionFrame;
    uint32_t lastTlv4PresenceMode;
    uint32_t lastTlv4PresenceModeAvailable;

    uint32_t lastTlv12Count;
    uint32_t lastTlv12Length;
    uint32_t lastTlv12FlagsWordAvailable;
    uint32_t lastTlv12Flags;
    uint32_t lastTlv12UnclassifiedFlagBits;
    uint32_t lastTlv12AwdlAddressAdvertised;
    uint32_t lastTlv12AwdlAddressPrefixComparable;
    uint32_t lastTlv12AwdlAddressPrefixMatchesMetadataSource;

    uint32_t lastTlv18Count;
    uint32_t lastTlv18Length;
    uint32_t lastTlv18HeaderAvailable;
    uint32_t lastTlv18ChannelCount;
    uint32_t lastTlv18Encoding;
    uint32_t lastTlv18DuplicateCount;
    uint32_t lastTlv18StepCount;
    uint32_t lastTlv18FillChannel;
};

// Numeric fields only. No source address, peer identity, hostname, or TLV body
// is retained. Sample counters describe bounded observations, not codec
// acceptance, control TX, or an over-the-air acknowledgement.
struct Snapshot {
    uint32_t schema;
    uint32_t controlRxOnly;
    uint32_t sampleCapacity;
    uint32_t samplesReserved;
    uint32_t samplesReady;
    uint32_t samplesDroppedAtCapacity;
    uint32_t subtypePoolCapacity;
    uint32_t otherPoolCapacity;
    uint32_t psfPoolReserved;
    uint32_t mifPoolReserved;
    uint32_t otherPoolReserved;
    uint32_t psfSamplesDroppedAtCapacity;
    uint32_t mifSamplesDroppedAtCapacity;
    uint32_t otherPoolSamplesDroppedAtCapacity;
    uint32_t message48Samples;
    uint32_t psfSamples;
    uint32_t mifSamples;
    uint32_t otherSubtypeSamples;
    uint32_t malformedActionHeaderSamples;
    uint32_t truncatedInputSamples;
    uint32_t oversizedInputSamples;
    uint32_t malformedTlvHeaderSamples;
    uint32_t truncatedTlvValueSamples;
    uint32_t tlvScanLimitSamples;
    uint32_t shortKnownTlvSamples;

    uint32_t lastLength;
    uint32_t lastMetadataVersion;
    uint32_t lastReceiveChannel;
    uint32_t lastReceiveChannelFlags;
    uint32_t lastActionVersion;
    uint32_t lastActionSubtype;
    uint32_t lastActionReserved;
    uint32_t lastTlvCount;

    uint32_t lastTlv4Count;
    uint32_t lastTlv4Length;
    uint32_t lastTlv4HasNextChannel;
    uint32_t lastTlv4NextChannel;
    uint32_t lastTlv4HasTxDownCounter;
    uint32_t lastTlv4TxDownCounter;
    uint32_t lastTlv4HasMasterChannel;
    uint32_t lastTlv4MasterChannel;
    uint32_t lastTlv4HasAwSequence;
    uint32_t lastTlv4AwSequence;
    uint32_t lastTlv4PresenceFieldsAvailable;
    uint32_t lastTlv4MinExt;
    uint32_t lastTlv4MaxExtMulticast;
    uint32_t lastTlv4MaxExtUnicast;
    uint32_t lastTlv4MaxExtActionFrame;
    uint32_t lastTlv4PresenceMode;
    uint32_t lastTlv4PresenceModeAvailable;

    uint32_t lastTlv12Count;
    uint32_t lastTlv12Length;
    uint32_t lastTlv12FlagsWordAvailable;
    uint32_t lastTlv12Flags;
    uint32_t lastTlv12UnclassifiedFlagBits;
    uint32_t lastTlv12AwdlAddressAdvertised;
    uint32_t lastTlv12AwdlAddressPrefixComparable;
    uint32_t lastTlv12AwdlAddressPrefixMatchesMetadataSource;

    uint32_t lastTlv18Count;
    uint32_t lastTlv18Length;
    uint32_t lastTlv18HeaderAvailable;
    uint32_t lastTlv18ChannelCount;
    uint32_t lastTlv18Encoding;
    uint32_t lastTlv18DuplicateCount;
    uint32_t lastTlv18StepCount;
    uint32_t lastTlv18FillChannel;

    uint32_t lastTlv21Count;
    uint32_t lastTlv21Length;
    uint32_t lastTlv21HeaderAvailable;
    uint32_t lastTlv21Version;
    uint32_t lastTlv21DeviceClass;

    SubtypeSummary psf;
    SubtypeSummary mif;
};

// Called only after the real observer owns a message48 snapshot. Reads at most
// InputLimit bytes and walks at most TlvLimit TLVs. It never writes input.
void observeOwnedMessage48(const void *bytes, size_t length);

// Bounded low-frequency aggregation. PSF and MIF have separate fixed slot
// pools, plus a small pool for all other observations. In-flight slots are
// skipped until their release-published ready bit is visible, so each global
// and per-subtype last row is self-consistent.
Snapshot snapshot();

#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
enum : uint32_t { WindowLimit=4 };
enum class ArmResult : uint32_t {Passed=0,Invalid=1,Busy=2,Exhausted=3,Clock=4};
using WindowClock=uint64_t (*)();
// Every bank is static, initialized once, and never reset or reused. The clock
// callback has static lifetime and returns mach_absolute_time scaled to ns.
ArmResult armWindow(uint32_t seconds,const uint8_t aliasKey[16],const uint8_t localLink[6],WindowClock);
struct WindowSnapshot {
    uint32_t schema=1,state=0,generation=0,windowsUsed=0,windowLimit=WindowLimit;
    uint32_t durationSeconds=0,sampleCapacity=SampleLimit,observations=0,thinned=0;
    uint32_t droppedCapacity=0,afterDeadline=0,clockRejected=0;
    uint32_t inFlightBefore=0,inFlightAfter=0,closed=0;
    uint32_t reserved[3] {},ready[3] {},pending[3] {};
    uint64_t startNs=0,endNs=0,observedNs=0,firstNs[3] {},lastNs[3] {};
    // Internal read fence: freezes exactly which immutable rows the visitor
    // exports. Never serialize this bitset or a bank/key/address pointer.
    uint32_t readyBits[SampleLimit/32] {};
};
struct WindowSample {
    uint64_t captureNs=0,sourceAlias=0;
    uint32_t sequence=0,pool=0,subtype=0,receiveChannelRaw=0,receiveChannelFlagsRaw=0;
    uint32_t parseFlags=0;
    uint32_t sourceComparable=0,sourceMatchesLocal=0,advertisedLocalComparable=0,advertisedMatchesLocal=0;
    SubtypeSummary summary {};
};
WindowSnapshot windowSnapshot();
using WindowVisitor=bool (*)(const WindowSample &,void *);
bool visitWindowSamples(const WindowSnapshot &,WindowVisitor,void *);
#endif

} } // namespace AWDLKernel::BaselineTrace

#endif
