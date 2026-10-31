#include "baseline_trace.hpp"

#include <string.h>
#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
#include "window_alias.h"
#endif

namespace AWDLKernel { namespace BaselineTrace { namespace {

struct Row {
#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
    uint64_t captureNs,sourceAlias;
    uint32_t sourceComparable,sourceMatchesLocal,advertisedLocalComparable,advertisedMatchesLocal;
#endif
    uint32_t length, metadataVersion, receiveChannel, receiveChannelFlags;
    uint32_t actionVersion, actionSubtype, actionReserved, tlvCount;
    uint32_t message48Samples, psf, mif, otherSubtype, malformedActionHeader;
    uint32_t truncatedInput, oversizedInput, malformedTlvHeader;
    uint32_t truncatedTlvValue, tlvScanLimit, shortKnownTlv;

    uint32_t tlv4Count, tlv4Length;
    uint32_t tlv4HasNextChannel, tlv4NextChannel;
    uint32_t tlv4HasTxDownCounter, tlv4TxDownCounter;
    uint32_t tlv4HasMasterChannel, tlv4MasterChannel;
    uint32_t tlv4HasAwSequence, tlv4AwSequence;
    uint32_t tlv4PresenceFieldsAvailable, tlv4MinExt, tlv4MaxExtMulticast;
    uint32_t tlv4MaxExtUnicast, tlv4MaxExtActionFrame;
    uint32_t tlv4PresenceMode, tlv4PresenceModeAvailable;

    uint32_t tlv12Count, tlv12Length, tlv12FlagsWordAvailable, tlv12Flags;
    uint32_t tlv12UnclassifiedFlagBits, tlv12AwdlAddressAdvertised;
    uint32_t tlv12AwdlAddressPrefixComparable;
    uint32_t tlv12AwdlAddressPrefixMatchesSource;

    uint32_t tlv18Count, tlv18Length, tlv18HeaderAvailable;
    uint32_t tlv18ChannelCount, tlv18Encoding, tlv18DuplicateCount;
    uint32_t tlv18StepCount, tlv18FillChannel;

    uint32_t tlv21Count, tlv21Length, tlv21HeaderAvailable;
    uint32_t tlv21Version, tlv21DeviceClass;
};
struct Slot { uint32_t ready, sequence; Row row; };
enum class SamplePool : uint32_t { Psf, Mif, Other };

// Fixed, process-lifetime POD storage. Each reservation owns one slot; no slot
// is ever rewritten. The only retained values are numeric summaries.
struct CapturePool {
    Slot slots[SampleLimit] {};
    uint32_t reservedSlots=0,droppedAtCapacity=0,poolReserved[3] {};
    uint32_t psfDroppedAtCapacity=0,mifDroppedAtCapacity=0,otherDroppedAtCapacity=0;
};
CapturePool bootPool;
#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
struct WindowBank {
    CapturePool capture;
    WindowClock clock=nullptr;
    uint64_t startNs=0,endNs=0,nextDueNs[3] {};
    uint32_t generation=0,durationSeconds=0,observations=0,thinned=0,afterDeadline=0,clockRejected=0,inFlight=0;
    uint8_t aliasKey[16] {},localLink[6] {};
};
WindowBank windowBanks[WindowLimit];
WindowBank *activeWindow=nullptr;
uint32_t armLock=0,windowsAllocated=0;
struct WindowWriter {
    WindowBank *bank;
    explicit WindowWriter(WindowBank *p):bank(p) {if (bank) __atomic_add_fetch(&bank->inFlight,1U,__ATOMIC_SEQ_CST);}
    ~WindowWriter() {if (bank) __atomic_sub_fetch(&bank->inFlight,1U,__ATOMIC_SEQ_CST);}
    WindowWriter(const WindowWriter &)=delete;WindowWriter &operator=(const WindowWriter &)=delete;
};
#endif
const uint32_t poolOffsets[3]={0,SubtypePoolLimit,2*SubtypePoolLimit};

uint16_t le16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0]) |
        static_cast<uint16_t>(static_cast<uint16_t>(p[1])<<8);
}
uint32_t le32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) |
        (static_cast<uint32_t>(p[1])<<8) |
        (static_cast<uint32_t>(p[2])<<16) |
        (static_cast<uint32_t>(p[3])<<24);
}
void saturatingIncrement(uint32_t *value) {
    uint32_t previous=__atomic_load_n(value,__ATOMIC_RELAXED);
    while (previous!=UINT32_MAX &&
           !__atomic_compare_exchange_n(value,&previous,previous+1,false,
                                        __ATOMIC_RELAXED,__ATOMIC_RELAXED)) {}
}
bool tryReservePool(CapturePool &storage,uint32_t pool,uint32_t *slotIndex,uint32_t *sequence) {
    if (pool>2 || !slotIndex || !sequence) return false;
    const uint32_t limit=pool==2?OtherPoolLimit:SubtypePoolLimit;
    uint32_t next=__atomic_load_n(&storage.poolReserved[pool],__ATOMIC_RELAXED);
    while (next<limit) {
        if (__atomic_compare_exchange_n(&storage.poolReserved[pool],&next,next+1,false,
                                        __ATOMIC_ACQ_REL,__ATOMIC_RELAXED)) {
            *slotIndex=poolOffsets[pool]+next;
            *sequence=__atomic_add_fetch(&storage.reservedSlots,1U,__ATOMIC_RELAXED);
            return true;
        }
    }
    return false;
}
SamplePool classifySample(const uint8_t *input,size_t length) {
    // The subtype byte is inside the fixed message48 header. Do not inspect
    // short, null, or over-limit caller buffers just to choose a slot pool.
    if (!input || length<88 || length>InputLimit) return SamplePool::Other;
    const uint8_t subtype=input[72+6];
    if (subtype==0) return SamplePool::Psf;
    if (subtype==3) return SamplePool::Mif;
    return SamplePool::Other;
}
uint32_t reserveSlot(CapturePool &storage,SamplePool samplePool,uint32_t *sequence) {
    uint32_t slotIndex=UINT32_MAX;
    if (samplePool==SamplePool::Psf) {
        if (tryReservePool(storage,0,&slotIndex,sequence)) return slotIndex;
        saturatingIncrement(&storage.psfDroppedAtCapacity);
    } else if (samplePool==SamplePool::Mif) {
        if (tryReservePool(storage,1,&slotIndex,sequence)) return slotIndex;
        saturatingIncrement(&storage.mifDroppedAtCapacity);
    } else {
        if (tryReservePool(storage,2,&slotIndex,sequence)) return slotIndex;
        saturatingIncrement(&storage.otherDroppedAtCapacity);
    }
    saturatingIncrement(&storage.droppedAtCapacity);
    return UINT32_MAX;
}
bool equal6(const uint8_t *a,const uint8_t *b) {
    uint8_t different=0;
    for (size_t n=0;n<6;n++) different|=static_cast<uint8_t>(a[n]^b[n]);
    return different==0;
}

void parseTlv(Row &row,uint8_t type,const uint8_t *value,uint16_t length,
              const uint8_t *metadataSource,const uint8_t *localLink) {
    (void)localLink;
    if (type==4) {
        ++row.tlv4Count;row.tlv4Length=length;
        if (length>=1) {row.tlv4HasNextChannel=1;row.tlv4NextChannel=value[0];}
        if (length>=3) {row.tlv4HasTxDownCounter=1;row.tlv4TxDownCounter=le16(value+1);}
        if (length>=4) {row.tlv4HasMasterChannel=1;row.tlv4MasterChannel=value[3];}
        // AWDL sync TLV value offsets from the bounded wire layout: presence
        // counters begin at17, presence mode at27 and next AW sequence at29.
        if (length>=21) {
            row.tlv4PresenceFieldsAvailable=1;
            row.tlv4MinExt=value[17];row.tlv4MaxExtMulticast=value[18];
            row.tlv4MaxExtUnicast=value[19];row.tlv4MaxExtActionFrame=value[20];
        }
        if (length>=28) {row.tlv4PresenceModeAvailable=1;row.tlv4PresenceMode=value[27];}
        if (length>=31) {row.tlv4HasAwSequence=1;row.tlv4AwSequence=le16(value+29);}
        if (length<31) row.shortKnownTlv=1;
    } else if (type==12) {
        ++row.tlv12Count;row.tlv12Length=length;
        row.tlv12FlagsWordAvailable=0;row.tlv12Flags=0;row.tlv12UnclassifiedFlagBits=0;
        row.tlv12AwdlAddressAdvertised=0;
        row.tlv12AwdlAddressPrefixComparable=0;
        row.tlv12AwdlAddressPrefixMatchesSource=0;
#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
        row.advertisedLocalComparable=0;row.advertisedMatchesLocal=0;
#endif
        if (length<2) {row.shortKnownTlv=1;return;}
        const uint16_t flags=le16(value);
        row.tlv12FlagsWordAvailable=1;row.tlv12Flags=flags;
        // The prefix layout is bounded by the documented pre-address fields.
        // 0x0010 (UMI), 0x1000 (unicast options), and 0x8000 (extended flags)
        // select bytes after the AWDL address, so they do not move this prefix.
        // Other unhandled bits stay visible and conservatively block comparison.
        const uint16_t addressPrefixAndKnownSuffixFlags=0x0307|0x9010;
        row.tlv12UnclassifiedFlagBits=static_cast<uint16_t>(
            flags&~addressPrefixAndKnownSuffixFlags);
        row.tlv12AwdlAddressAdvertised=(flags&0x0004U)!=0;
        if (!row.tlv12AwdlAddressAdvertised || row.tlv12UnclassifiedFlagBits) return;
        size_t offset=2;
        if (flags&0x0100U) offset+=3; // country code
        if (flags&0x0200U) offset+=2; // social channel map
        if (flags&0x0001U) offset+=8; // infrastructure BSSID + channel
        if (flags&0x0002U) offset+=6; // infrastructure address
        if (offset<=length && static_cast<size_t>(length)-offset>=6) {
            row.tlv12AwdlAddressPrefixComparable=1;
            row.tlv12AwdlAddressPrefixMatchesSource=
                equal6(value+offset,metadataSource);
#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
            if (localLink) {row.advertisedLocalComparable=1;row.advertisedMatchesLocal=equal6(value+offset,localLink);}
#endif
        }
        if (!row.tlv12AwdlAddressPrefixComparable) row.shortKnownTlv=1;
    } else if (type==18) {
        ++row.tlv18Count;row.tlv18Length=length;row.tlv18HeaderAvailable=0;
        if (length<6) {row.shortKnownTlv=1;return;}
        row.tlv18HeaderAvailable=1;row.tlv18ChannelCount=value[0];
        row.tlv18Encoding=value[1];row.tlv18DuplicateCount=value[2];
        row.tlv18StepCount=value[3];row.tlv18FillChannel=le16(value+4);
    } else if (type==21) {
        ++row.tlv21Count;row.tlv21Length=length;row.tlv21HeaderAvailable=0;
        if (length<2) {row.shortKnownTlv=1;return;}
        row.tlv21HeaderAvailable=1;row.tlv21Version=value[0];row.tlv21DeviceClass=value[1];
    }
}

void addLastRow(Snapshot &out,const Row &row) {
    out.lastLength=row.length;out.lastMetadataVersion=row.metadataVersion;
    out.lastReceiveChannel=row.receiveChannel;out.lastReceiveChannelFlags=row.receiveChannelFlags;
    out.lastActionVersion=row.actionVersion;out.lastActionSubtype=row.actionSubtype;
    out.lastActionReserved=row.actionReserved;out.lastTlvCount=row.tlvCount;
    out.lastTlv4Count=row.tlv4Count;out.lastTlv4Length=row.tlv4Length;
    out.lastTlv4HasNextChannel=row.tlv4HasNextChannel;out.lastTlv4NextChannel=row.tlv4NextChannel;
    out.lastTlv4HasTxDownCounter=row.tlv4HasTxDownCounter;
    out.lastTlv4TxDownCounter=row.tlv4TxDownCounter;
    out.lastTlv4HasMasterChannel=row.tlv4HasMasterChannel;
    out.lastTlv4MasterChannel=row.tlv4MasterChannel;
    out.lastTlv4HasAwSequence=row.tlv4HasAwSequence;out.lastTlv4AwSequence=row.tlv4AwSequence;
    out.lastTlv4PresenceFieldsAvailable=row.tlv4PresenceFieldsAvailable;
    out.lastTlv4MinExt=row.tlv4MinExt;out.lastTlv4MaxExtMulticast=row.tlv4MaxExtMulticast;
    out.lastTlv4MaxExtUnicast=row.tlv4MaxExtUnicast;
    out.lastTlv4MaxExtActionFrame=row.tlv4MaxExtActionFrame;
    out.lastTlv4PresenceMode=row.tlv4PresenceMode;
    out.lastTlv4PresenceModeAvailable=row.tlv4PresenceModeAvailable;
    out.lastTlv12Count=row.tlv12Count;out.lastTlv12Length=row.tlv12Length;
    out.lastTlv12FlagsWordAvailable=row.tlv12FlagsWordAvailable;
    out.lastTlv12Flags=row.tlv12Flags;
    out.lastTlv12UnclassifiedFlagBits=row.tlv12UnclassifiedFlagBits;
    out.lastTlv12AwdlAddressAdvertised=row.tlv12AwdlAddressAdvertised;
    out.lastTlv12AwdlAddressPrefixComparable=row.tlv12AwdlAddressPrefixComparable;
    out.lastTlv12AwdlAddressPrefixMatchesMetadataSource=
        row.tlv12AwdlAddressPrefixMatchesSource;
    out.lastTlv18Count=row.tlv18Count;out.lastTlv18Length=row.tlv18Length;
    out.lastTlv18HeaderAvailable=row.tlv18HeaderAvailable;
    out.lastTlv18ChannelCount=row.tlv18ChannelCount;
    out.lastTlv18Encoding=row.tlv18Encoding;out.lastTlv18DuplicateCount=row.tlv18DuplicateCount;
    out.lastTlv18StepCount=row.tlv18StepCount;out.lastTlv18FillChannel=row.tlv18FillChannel;
    out.lastTlv21Count=row.tlv21Count;out.lastTlv21Length=row.tlv21Length;
    out.lastTlv21HeaderAvailable=row.tlv21HeaderAvailable;
    out.lastTlv21Version=row.tlv21Version;
    out.lastTlv21DeviceClass=row.tlv21DeviceClass;
}

void addSubtypeLast(SubtypeSummary &out,const Row &row) {
    out.lastLength=row.length;out.lastTlvCount=row.tlvCount;
    out.lastTlv4Count=row.tlv4Count;out.lastTlv4Length=row.tlv4Length;
    out.lastTlv4HasNextChannel=row.tlv4HasNextChannel;
    out.lastTlv4NextChannel=row.tlv4NextChannel;
    out.lastTlv4HasTxDownCounter=row.tlv4HasTxDownCounter;
    out.lastTlv4TxDownCounter=row.tlv4TxDownCounter;
    out.lastTlv4HasMasterChannel=row.tlv4HasMasterChannel;
    out.lastTlv4MasterChannel=row.tlv4MasterChannel;
    out.lastTlv4HasAwSequence=row.tlv4HasAwSequence;
    out.lastTlv4AwSequence=row.tlv4AwSequence;
    out.lastTlv4PresenceFieldsAvailable=row.tlv4PresenceFieldsAvailable;
    out.lastTlv4MinExt=row.tlv4MinExt;
    out.lastTlv4MaxExtMulticast=row.tlv4MaxExtMulticast;
    out.lastTlv4MaxExtUnicast=row.tlv4MaxExtUnicast;
    out.lastTlv4MaxExtActionFrame=row.tlv4MaxExtActionFrame;
    out.lastTlv4PresenceMode=row.tlv4PresenceMode;
    out.lastTlv4PresenceModeAvailable=row.tlv4PresenceModeAvailable;
    out.lastTlv12Count=row.tlv12Count;out.lastTlv12Length=row.tlv12Length;
    out.lastTlv12FlagsWordAvailable=row.tlv12FlagsWordAvailable;
    out.lastTlv12Flags=row.tlv12Flags;
    out.lastTlv12UnclassifiedFlagBits=row.tlv12UnclassifiedFlagBits;
    out.lastTlv12AwdlAddressAdvertised=row.tlv12AwdlAddressAdvertised;
    out.lastTlv12AwdlAddressPrefixComparable=
        row.tlv12AwdlAddressPrefixComparable;
    out.lastTlv12AwdlAddressPrefixMatchesMetadataSource=
        row.tlv12AwdlAddressPrefixMatchesSource;
    out.lastTlv18Count=row.tlv18Count;out.lastTlv18Length=row.tlv18Length;
    out.lastTlv18HeaderAvailable=row.tlv18HeaderAvailable;
    out.lastTlv18ChannelCount=row.tlv18ChannelCount;
    out.lastTlv18Encoding=row.tlv18Encoding;
    out.lastTlv18DuplicateCount=row.tlv18DuplicateCount;
    out.lastTlv18StepCount=row.tlv18StepCount;
    out.lastTlv18FillChannel=row.tlv18FillChannel;
}

} // namespace

void observeOwnedMessage48(const void *bytes,size_t length) {
    const uint8_t *input=static_cast<const uint8_t *>(bytes);
    CapturePool *selected=&bootPool;
    const auto kind=classifySample(input,length);
    const uint8_t *localLink=nullptr;
#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
    WindowBank *window=__atomic_load_n(&activeWindow,__ATOMIC_ACQUIRE);
    WindowWriter writer(window); // Before timestamp/deadline; covers every return.
    uint64_t captureNs=0;
    if (window) {
        // Capture one immutable bank pointer. A concurrent arm can never move
        // this observation into another generation or reclaim its storage.
        captureNs=window->clock();
        if (!captureNs || captureNs<window->startNs) {saturatingIncrement(&window->clockRejected);return;}
        if (captureNs>=window->endNs) {saturatingIncrement(&window->afterDeadline);return;}
        saturatingIncrement(&window->observations);
        const auto pool=static_cast<uint32_t>(kind);
        const uint64_t limit=pool==2?OtherPoolLimit:SubtypePoolLimit;
        const uint64_t interval=(window->endNs-window->startNs+limit-1)/limit;
        uint64_t due=__atomic_load_n(&window->nextDueNs[pool],__ATOMIC_RELAXED);
        for (;;) {
            if (captureNs<due) {saturatingIncrement(&window->thinned);return;}
            const uint64_t next=window->endNs-captureNs<interval?window->endNs:captureNs+interval;
            if (__atomic_compare_exchange_n(&window->nextDueNs[pool],&due,next,false,__ATOMIC_RELAXED,__ATOMIC_RELAXED)) break;
        }
        selected=&window->capture;
    }
#endif
    CapturePool &storage=*selected;
    uint32_t sequence=0;
    const uint32_t slotIndex=reserveSlot(storage,kind,&sequence);
    if (slotIndex==UINT32_MAX) return;
    Row row {};
#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
    row.captureNs=captureNs;
    if (window && input && length>=88 && length<=InputLimit && le32(input+12)==1) {
        row.sourceComparable=1;row.sourceMatchesLocal=equal6(input,window->localLink);
        row.sourceAlias=awdl_window_alias6(window->aliasKey,input);localLink=window->localLink;
    }
#endif
    row.length=length>UINT32_MAX?UINT32_MAX:static_cast<uint32_t>(length);
    row.message48Samples=1;
    if (!input) {
        row.truncatedInput=1;row.malformedActionHeader=1;
    } else if (length>InputLimit) {
        // Strict upper bound: never inspect the oversized caller buffer.
        row.oversizedInput=1;
    } else if (length<88) {
        row.truncatedInput=1;
    } else {
        row.metadataVersion=le32(input+12);
        row.receiveChannel=le32(input+16);
        row.receiveChannelFlags=le32(input+20);
        const uint8_t *frame=input+72;
        const size_t frameLength=length-72;
        row.actionVersion=frame[5];row.actionSubtype=frame[6];row.actionReserved=frame[7];
        const bool appleActionHeader=frame[0]==127 && frame[1]==0x00 &&
            frame[2]==0x17 && frame[3]==0xf2 && frame[4]==8;
        if (!appleActionHeader || frame[7]!=0 || (frame[6]!=0 && frame[6]!=3))
            row.malformedActionHeader=1;
        if (frame[6]==0) row.psf=1;
        else if (frame[6]==3) row.mif=1;
        else row.otherSubtype=1;

        size_t cursor=16;
        for (uint32_t index=0;index<TlvLimit && cursor<frameLength;index++) {
            const size_t remaining=frameLength-cursor;
            if (remaining<3) {
                row.malformedTlvHeader=1;row.truncatedTlvValue=1;break;
            }
            const uint8_t *tlv=frame+cursor;
            const uint16_t tlvLength=le16(tlv+1);
            if (static_cast<size_t>(tlvLength)>remaining-3) {
                row.truncatedTlvValue=1;break;
            }
            parseTlv(row,tlv[0],tlv+3,tlvLength,input,localLink);
            ++row.tlvCount;
            cursor+=3+static_cast<size_t>(tlvLength);
        }
        if (cursor<frameLength && !row.malformedTlvHeader && !row.truncatedTlvValue)
            row.tlvScanLimit=1;
    }
    storage.slots[slotIndex].sequence=sequence;
    storage.slots[slotIndex].row=row;
    __atomic_store_n(&storage.slots[slotIndex].ready,1U,__ATOMIC_RELEASE);
}

Snapshot snapshot() {
    CapturePool &storage=bootPool;
    Snapshot out {};
    out.schema=2;out.controlRxOnly=1;out.sampleCapacity=SampleLimit;
    out.subtypePoolCapacity=SubtypePoolLimit;
    const uint32_t psfReserved=__atomic_load_n(&storage.poolReserved[0],__ATOMIC_ACQUIRE);
    const uint32_t mifReserved=__atomic_load_n(&storage.poolReserved[1],__ATOMIC_ACQUIRE);
    const uint32_t otherReserved=__atomic_load_n(&storage.poolReserved[2],__ATOMIC_ACQUIRE);
    out.psfPoolReserved=psfReserved;out.mifPoolReserved=mifReserved;
    out.otherPoolCapacity=OtherPoolLimit;out.otherPoolReserved=otherReserved;
    out.samplesReserved=psfReserved+mifReserved+otherReserved;
    out.samplesDroppedAtCapacity=__atomic_load_n(&storage.droppedAtCapacity,__ATOMIC_ACQUIRE);
    out.psfSamplesDroppedAtCapacity=__atomic_load_n(
        &storage.psfDroppedAtCapacity,__ATOMIC_ACQUIRE);
    out.mifSamplesDroppedAtCapacity=__atomic_load_n(
        &storage.mifDroppedAtCapacity,__ATOMIC_ACQUIRE);
    out.otherPoolSamplesDroppedAtCapacity=__atomic_load_n(
        &storage.otherDroppedAtCapacity,__ATOMIC_ACQUIRE);
    const Row *last=nullptr,*lastPsf=nullptr,*lastMif=nullptr;
    uint32_t lastSequence=0,lastPsfSequence=0,lastMifSequence=0;
    const auto accumulate=[&](uint32_t index) {
        if (!__atomic_load_n(&storage.slots[index].ready,__ATOMIC_ACQUIRE)) return;
        const Row &row=storage.slots[index].row;
        ++out.samplesReady;
        out.message48Samples+=row.message48Samples;
        out.psfSamples+=row.psf;out.mifSamples+=row.mif;
        out.otherSubtypeSamples+=row.otherSubtype;
        out.malformedActionHeaderSamples+=row.malformedActionHeader;
        out.truncatedInputSamples+=row.truncatedInput;
        out.oversizedInputSamples+=row.oversizedInput;
        out.malformedTlvHeaderSamples+=row.malformedTlvHeader;
        out.truncatedTlvValueSamples+=row.truncatedTlvValue;
        out.tlvScanLimitSamples+=row.tlvScanLimit;
        out.shortKnownTlvSamples+=row.shortKnownTlv;
        const uint32_t sequence=storage.slots[index].sequence;
        if (!last||sequence>lastSequence) {last=&row;lastSequence=sequence;}
        if (row.psf) {
            if (!lastPsf||sequence>lastPsfSequence) {
                lastPsf=&row;lastPsfSequence=sequence;
            }
        }
        if (row.mif) {
            if (!lastMif||sequence>lastMifSequence) {
                lastMif=&row;lastMifSequence=sequence;
            }
        }
    };
    for (uint32_t index=0;index<psfReserved;index++) accumulate(index);
    for (uint32_t index=0;index<mifReserved;index++)
        accumulate(SubtypePoolLimit+index);
    for (uint32_t index=0;index<otherReserved;index++)
        accumulate(2*SubtypePoolLimit+index);
    if (last) addLastRow(out,*last);
    if (lastPsf) addSubtypeLast(out.psf,*lastPsf);
    if (lastMif) addSubtypeLast(out.mif,*lastMif);
    out.psf.samples=out.psfSamples;out.mif.samples=out.mifSamples;
    return out;
}

#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
ArmResult armWindow(uint32_t seconds,const uint8_t key[16],const uint8_t local[6],WindowClock clock) {
    if (!seconds || seconds>120 || !key || !local || !clock || (local[0]&1)) return ArmResult::Invalid;
    uint8_t keyBits=0,localBits=0;
    for (unsigned j=0;j<16;j++) keyBits|=key[j];
    for (unsigned j=0;j<6;j++) localBits|=local[j];
    if (!keyBits || !localBits) return ArmResult::Invalid;
    uint32_t unlocked=0;
    if (!__atomic_compare_exchange_n(&armLock,&unlocked,1U,false,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))
        return ArmResult::Busy;
    const auto finish=[](ArmResult result) {__atomic_store_n(&armLock,0U,__ATOMIC_RELEASE);return result;};
    const uint64_t now=clock(),duration=uint64_t(seconds)*1000000000ULL;
    if (!now || now>UINT64_MAX-duration) return finish(ArmResult::Clock);
    WindowBank *previous=__atomic_load_n(&activeWindow,__ATOMIC_ACQUIRE);
    if (previous && previous->clock!=clock) return finish(ArmResult::Clock);
    if (previous && now<previous->endNs) return finish(ArmResult::Busy);
    if (windowsAllocated==WindowLimit) return finish(ArmResult::Exhausted);
    WindowBank &bank=windowBanks[windowsAllocated];
    // Fresh BSS bank only. Never clear a slot, reset a counter, or reuse keys.
    bank.clock=clock;bank.startNs=now;bank.endNs=now+duration;
    bank.durationSeconds=seconds;bank.generation=windowsAllocated+1;
    memcpy(bank.aliasKey,key,16);memcpy(bank.localLink,local,6);
    for (unsigned j=0;j<3;j++) bank.nextDueNs[j]=now;
    __atomic_store_n(&activeWindow,&bank,__ATOMIC_RELEASE);
    ++windowsAllocated;
    return finish(ArmResult::Passed);
}

WindowSnapshot windowSnapshot() {
    WindowSnapshot out;
    WindowBank *bank=__atomic_load_n(&activeWindow,__ATOMIC_ACQUIRE);
    if (!bank) return out;
    out.generation=bank->generation;out.windowsUsed=bank->generation;
    out.startNs=bank->startNs;out.endNs=bank->endNs;out.durationSeconds=bank->durationSeconds;
    out.observedNs=bank->clock();
    out.inFlightBefore=__atomic_load_n(&bank->inFlight,__ATOMIC_SEQ_CST);
    out.state=out.observedNs<out.startNs?3U:out.observedNs<out.endNs?1U:2U;
    out.observations=__atomic_load_n(&bank->observations,__ATOMIC_RELAXED);
    out.thinned=__atomic_load_n(&bank->thinned,__ATOMIC_RELAXED);
    out.afterDeadline=__atomic_load_n(&bank->afterDeadline,__ATOMIC_RELAXED);
    out.clockRejected=__atomic_load_n(&bank->clockRejected,__ATOMIC_RELAXED);
    out.droppedCapacity=__atomic_load_n(&bank->capture.droppedAtCapacity,__ATOMIC_RELAXED);
    for (unsigned kind=0;kind<3;kind++) {
        out.reserved[kind]=__atomic_load_n(&bank->capture.poolReserved[kind],__ATOMIC_ACQUIRE);
        for (uint32_t j=0;j<out.reserved[kind];j++) {
            const uint32_t index=poolOffsets[kind]+j;
            const Slot &slot=bank->capture.slots[index];
            if (!__atomic_load_n(&slot.ready,__ATOMIC_ACQUIRE)) continue;
            out.readyBits[index/32]|=uint32_t(1)<<(index%32);
            ++out.ready[kind];
            const uint64_t at=slot.row.captureNs;
            if (!out.firstNs[kind] || at<out.firstNs[kind]) out.firstNs[kind]=at;
            if (at>out.lastNs[kind]) out.lastNs[kind]=at;
        }
        out.pending[kind]=out.reserved[kind]-out.ready[kind];
    }
    out.inFlightAfter=__atomic_load_n(&bank->inFlight,__ATOMIC_SEQ_CST);
    out.closed=out.state==2 && !out.inFlightBefore && !out.inFlightAfter &&
        !out.pending[0] && !out.pending[1] && !out.pending[2];
    return out;
}

bool visitWindowSamples(const WindowSnapshot &view,WindowVisitor visitor,void *context) {
    if (!visitor || view.schema!=1 || !view.generation || view.generation>WindowLimit) return false;
    const WindowBank *published=__atomic_load_n(&activeWindow,__ATOMIC_ACQUIRE);
    if (!published || view.generation>published->generation) return false;
    const WindowBank &bank=windowBanks[view.generation-1];
    if (bank.generation!=view.generation || bank.startNs!=view.startNs || bank.endNs!=view.endNs) return false;
    for (unsigned kind=0;kind<3;kind++) {
        if (view.reserved[kind]>(kind==2?OtherPoolLimit:SubtypePoolLimit)) return false;
        for (uint32_t j=0;j<view.reserved[kind];j++) {
            const uint32_t index=poolOffsets[kind]+j;
            if (!(view.readyBits[index/32]&(uint32_t(1)<<(index%32)))) continue;
            const Slot &slot=bank.capture.slots[index];
            if (!__atomic_load_n(&slot.ready,__ATOMIC_ACQUIRE)) return false;
            const Row &row=slot.row;
            WindowSample sample;
            sample.captureNs=row.captureNs;sample.sourceAlias=row.sourceAlias;
            sample.sequence=slot.sequence;sample.pool=kind;sample.subtype=row.actionSubtype;
            sample.parseFlags=(row.malformedActionHeader?1U:0U)|(row.truncatedInput?2U:0U)|
                (row.oversizedInput?4U:0U)|(row.malformedTlvHeader?8U:0U)|
                (row.truncatedTlvValue?16U:0U)|(row.tlvScanLimit?32U:0U)|(row.shortKnownTlv?64U:0U);
            sample.receiveChannelRaw=row.receiveChannel;sample.receiveChannelFlagsRaw=row.receiveChannelFlags;
            sample.sourceComparable=row.sourceComparable;sample.sourceMatchesLocal=row.sourceMatchesLocal;
            sample.advertisedLocalComparable=row.advertisedLocalComparable;sample.advertisedMatchesLocal=row.advertisedMatchesLocal;
            addSubtypeLast(sample.summary,row);sample.summary.samples=1;
            if (!visitor(sample,context)) return false;
        }
    }
    return true;
}
#endif

} } // namespace AWDLKernel::BaselineTrace
