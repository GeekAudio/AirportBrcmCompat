#include "baseline_trace.hpp"

#include <assert.h>
#include <atomic>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <vector>

using AWDLKernel::BaselineTrace::Snapshot;
using AWDLKernel::BaselineTrace::observeOwnedMessage48;
using AWDLKernel::BaselineTrace::snapshot;

static const uint8_t sourceAddress[6]={0x21,0x43,0x65,0x87,0xa9,0xcb};
static void put16(uint8_t *p,uint16_t value){p[0]=value&0xff;p[1]=(value>>8)&0xff;}
static void put32(uint8_t *p,uint32_t value){p[0]=value&0xff;p[1]=(value>>8)&0xff;p[2]=(value>>16)&0xff;p[3]=(value>>24)&0xff;}
static std::vector<uint8_t> message(uint8_t subtype) {
    std::vector<uint8_t> result(88,0);
    memcpy(result.data(),sourceAddress,6);
    put32(result.data()+12,1);put32(result.data()+16,6);put32(result.data()+20,0x10);
    uint8_t *frame=result.data()+72;
    frame[0]=127;frame[1]=0;frame[2]=0x17;frame[3]=0xf2;frame[4]=8;
    frame[5]=0x10;frame[6]=subtype;frame[7]=0;
    put32(frame+8,0x12345678);put32(frame+12,0x87654321);
    return result;
}
static void addTlv(std::vector<uint8_t> &input,uint8_t type,const std::vector<uint8_t> &value) {
    const size_t old=input.size();input.resize(old+3+value.size());
    input[old]=type;put16(input.data()+old+1,static_cast<uint16_t>(value.size()));
    if (!value.empty())memcpy(input.data()+old+3,value.data(),value.size());
}
static std::vector<uint8_t> dataPathValue(uint16_t flags,
        const uint8_t *address=sourceAddress,
        const std::vector<uint8_t> &suffix={}) {
    std::vector<uint8_t> value(2,0);put16(value.data(),flags);
    if (flags&0x0100) value.insert(value.end(),3,0x31);
    if (flags&0x0200) value.insert(value.end(),2,0x42);
    if (flags&0x0001) value.insert(value.end(),8,0x53);
    if (flags&0x0002) value.insert(value.end(),6,0x64);
    if ((flags&0x0004)&&address) value.insert(value.end(),address,address+6);
    value.insert(value.end(),suffix.begin(),suffix.end());
    return value;
}
static std::vector<uint8_t> syncValue() {
    std::vector<uint8_t> value(33,0);
    value[0]=11;put16(value.data()+1,0x1234);value[3]=44;
    value[17]=1;value[18]=2;value[19]=3;value[20]=4;value[27]=5;
    put16(value.data()+29,0x9876);return value;
}
static std::vector<uint8_t> channelSequence() {
    std::vector<uint8_t> value(6,0);
    value[0]=17;value[1]=2;value[2]=0;value[3]=4;put16(value.data()+4,0xffff);
    return value;
}
static void modeOne() {
    auto psf=message(0);addTlv(psf,4,syncValue());
    std::vector<uint8_t> path(8,0);put16(path.data(),4);memcpy(path.data()+2,sourceAddress,6);
    addTlv(psf,12,path);addTlv(psf,18,channelSequence());
    addTlv(psf,21,std::vector<uint8_t>{0x10,2});
    observeOwnedMessage48(psf.data(),psf.size());
    Snapshot first=snapshot();
    assert(first.schema==2&&first.controlRxOnly==1&&first.message48Samples==1);
    assert(first.psfSamples==1&&!first.mifSamples&&!first.malformedActionHeaderSamples);
    assert(first.psf.samples==1&&!first.mif.samples);
    assert(first.lastMetadataVersion==1&&first.lastReceiveChannel==6&&first.lastReceiveChannelFlags==0x10);
    assert(first.lastTlv4Count==1&&first.lastTlv4Length==33&&first.lastTlv4NextChannel==11);
    assert(first.lastTlv4TxDownCounter==0x1234&&first.lastTlv4MasterChannel==44);
    assert(first.lastTlv4AwSequence==0x9876&&first.lastTlv4MinExt==1);
    assert(first.lastTlv4MaxExtMulticast==2&&first.lastTlv4MaxExtUnicast==3);
    assert(first.lastTlv4MaxExtActionFrame==4&&first.lastTlv4PresenceMode==5);
    assert(first.lastTlv4PresenceFieldsAvailable&&first.lastTlv4PresenceModeAvailable);
    assert(first.lastTlv12FlagsWordAvailable&&first.lastTlv12Flags==4);
    assert(first.lastTlv12AwdlAddressAdvertised&&first.lastTlv12AwdlAddressPrefixComparable);
    assert(first.lastTlv12AwdlAddressPrefixMatchesMetadataSource);
    assert(first.lastTlv18HeaderAvailable&&first.lastTlv18Length==6&&first.lastTlv18Encoding==2);
    assert(first.lastTlv18ChannelCount==17&&first.lastTlv18StepCount==4&&first.lastTlv18FillChannel==0xffff);
    assert(first.lastTlv21HeaderAvailable&&first.lastTlv21Version==0x10&&first.lastTlv21DeviceClass==2);

    auto mif=message(3);addTlv(mif,12,dataPathValue(4,sourceAddress,{1}));
    observeOwnedMessage48(mif.data(),mif.size());
    Snapshot second=snapshot();
    assert(second.message48Samples==2&&second.psfSamples==1&&second.mifSamples==1);
    assert(second.lastActionSubtype==3&&second.lastTlv12AwdlAddressPrefixComparable);
    assert(second.lastTlv12AwdlAddressPrefixMatchesMetadataSource);
    assert(second.psf.samples==1&&second.mif.samples==1);
    assert(second.psf.lastTlv4NextChannel==11&&second.mif.lastTlv12AwdlAddressPrefixComparable);
}
static void modeTwo() {
    auto shortHeader=message(0);shortHeader.push_back(0x55);
    observeOwnedMessage48(shortHeader.data(),shortHeader.size());
    auto shortValue=message(3);addTlv(shortValue,12,std::vector<uint8_t>{4,0,1});
    observeOwnedMessage48(shortValue.data(),shortValue.size());
    auto unknownFlags=message(0);addTlv(unknownFlags,12,dataPathValue(0x0404));
    observeOwnedMessage48(unknownFlags.data(),unknownFlags.size());
    auto badLength=message(3);const size_t offset=badLength.size();badLength.resize(offset+4,0);
    badLength[offset]=12;put16(badLength.data()+offset+1,8);badLength[offset+3]=4;
    observeOwnedMessage48(badLength.data(),badLength.size());
    observeOwnedMessage48(nullptr,0);
    observeOwnedMessage48(unknownFlags.data(),unknownFlags.size());
    Snapshot s=snapshot();
    assert(s.message48Samples==6&&s.psfSamples==3&&s.mifSamples==2);
    assert(s.malformedTlvHeaderSamples==1&&s.truncatedTlvValueSamples==2);
    assert(s.truncatedInputSamples==1&&s.shortKnownTlvSamples>=1);
    assert(s.lastTlv12UnclassifiedFlagBits==0x0400);
    assert(s.lastTlv12AwdlAddressAdvertised&&!s.lastTlv12AwdlAddressPrefixComparable);
}
static void modeThree() {
    std::vector<uint8_t> input=message(0);
    for (unsigned i=0;i<129;i++) addTlv(input,0x7f,std::vector<uint8_t>());
    observeOwnedMessage48(input.data(),input.size());
    Snapshot s=snapshot();
    assert(s.lastTlvCount==128&&s.tlvScanLimitSamples==1);
    assert(s.samplesReserved==1&&s.samplesReady==1&&s.samplesDroppedAtCapacity==0);

    std::vector<uint8_t> maxInput=message(3);
    const size_t payload=2048-maxInput.size()-3;
    std::vector<uint8_t> large(payload,0xa5);addTlv(maxInput,0x7f,large);
    assert(maxInput.size()==2048);observeOwnedMessage48(maxInput.data(),maxInput.size());
    std::vector<uint8_t> oversized(2049,0);
    observeOwnedMessage48(oversized.data(),oversized.size());
    Snapshot limited=snapshot();
    assert(limited.message48Samples==3&&limited.mifSamples==1);
    assert(limited.lastLength==2049&&limited.oversizedInputSamples==1);
}
static void modeFour() {
    auto padded=message(0);
    // Unknown zero-length TLV and a flags=0 two-byte data-path TLV act as
    // harmless opaque/padded content. The observer must not reject or rewrite.
    addTlv(padded,0,std::vector<uint8_t>());addTlv(padded,12,std::vector<uint8_t>{0,0});
    observeOwnedMessage48(padded.data(),padded.size());
    Snapshot s=snapshot();
    assert(s.lastTlvCount==2&&s.lastTlv12Length==2&&s.lastTlv12Flags==0);
    assert(!s.lastTlv12AwdlAddressAdvertised&&!s.malformedTlvHeaderSamples);
}
static void modeFive() {
    auto input=message(0);addTlv(input,4,syncValue());
    std::thread threads[8];
    for (unsigned t=0;t<8;t++) threads[t]=std::thread([t]() {
        for (unsigned n=0;n<64;n++) {
            auto sample=message(((t+n)&1)?0:3);
            observeOwnedMessage48(sample.data(),sample.size());
        }
    });
    for (auto &thread:threads)thread.join();
    Snapshot s=snapshot();
    assert(s.samplesReserved==224&&s.samplesReady==224&&s.samplesDroppedAtCapacity==288);
    assert(s.psfPoolReserved==112&&s.mifPoolReserved==112&&s.otherPoolReserved==0);
    assert(s.psfSamplesDroppedAtCapacity==144&&s.mifSamplesDroppedAtCapacity==144);
    assert(s.message48Samples==224&&s.psfSamples+s.mifSamples==224);
    assert(s.psf.samples==112&&s.mif.samples==112);
}

static void modeSixPsfFloodThenMif() {
    for (unsigned i=0;i<160;i++) {
        auto psf=message(0);
        auto sync=syncValue();sync[0]=static_cast<uint8_t>(i);
        auto channel=channelSequence();channel[0]=static_cast<uint8_t>(i);
        addTlv(psf,4,sync);addTlv(psf,12,dataPathValue(4));addTlv(psf,18,channel);
        observeOwnedMessage48(psf.data(),psf.size());
    }
    auto mif=message(3);
    auto sync=syncValue();sync[0]=222;
    auto channel=channelSequence();channel[0]=99;
    addTlv(mif,4,sync);addTlv(mif,12,dataPathValue(0x0014,sourceAddress,{0x34,0x12}));
    addTlv(mif,18,channel);observeOwnedMessage48(mif.data(),mif.size());
    const Snapshot s=snapshot();
    assert(s.samplesReserved==113&&s.samplesReady==113);
    assert(s.psfPoolReserved==112&&s.mifPoolReserved==1);
    assert(s.psfSamplesDroppedAtCapacity==48&&!s.mifSamplesDroppedAtCapacity);
    assert(s.psfSamples==112&&s.mifSamples==1&&s.psf.samples==112&&s.mif.samples==1);
    assert(s.psf.lastTlv4NextChannel==111&&s.mif.lastTlv4NextChannel==222);
    assert(s.psf.lastTlv18ChannelCount==111&&s.mif.lastTlv18ChannelCount==99);
    assert(s.psf.lastTlv12AwdlAddressPrefixComparable&&
           s.mif.lastTlv12AwdlAddressPrefixComparable);
}

static void modeSevenMifFloodThenPsf() {
    for (unsigned i=0;i<160;i++) {
        auto mif=message(3);
        auto sync=syncValue();sync[0]=static_cast<uint8_t>(i);
        addTlv(mif,4,sync);addTlv(mif,18,channelSequence());
        observeOwnedMessage48(mif.data(),mif.size());
    }
    auto psf=message(0);auto sync=syncValue();sync[0]=201;
    addTlv(psf,4,sync);addTlv(psf,18,channelSequence());
    observeOwnedMessage48(psf.data(),psf.size());
    const Snapshot s=snapshot();
    assert(s.psfPoolReserved==1&&s.mifPoolReserved==112);
    assert(!s.psfSamplesDroppedAtCapacity&&s.mifSamplesDroppedAtCapacity==48);
    assert(s.psf.samples==1&&s.mif.samples==112);
    assert(s.psf.lastTlv4NextChannel==201&&s.mif.lastTlv4NextChannel==111);
}

static void modeEightKnownSuffixAndPrefixOffsets() {
    // Value length 8 is flags plus six address bytes only: the selected UMI
    // suffix is absent, while the address prefix remains independently comparable.
    auto shortSuffixUmi=message(0);addTlv(shortSuffixUmi,12,dataPathValue(0x0014));
    observeOwnedMessage48(shortSuffixUmi.data(),shortSuffixUmi.size());
    Snapshot s=snapshot();
    assert(s.lastTlv12AwdlAddressPrefixComparable&&
           s.lastTlv12AwdlAddressPrefixMatchesMetadataSource);
    assert(s.lastTlv12Length==8&&s.shortKnownTlvSamples==0);

    const std::vector<uint8_t> options={2,0,0xaa,0xbb};
    auto optionsPath=message(0);addTlv(optionsPath,12,dataPathValue(0x1004,sourceAddress,options));
    observeOwnedMessage48(optionsPath.data(),optionsPath.size());s=snapshot();
    assert(s.lastTlv12AwdlAddressPrefixComparable&&s.lastTlv12AwdlAddressPrefixMatchesMetadataSource);
    assert(s.lastTlv12Flags==0x1004);

    auto extension=message(0);addTlv(extension,12,dataPathValue(0x8004,sourceAddress,{0,0}));
    observeOwnedMessage48(extension.data(),extension.size());s=snapshot();
    assert(s.lastTlv12AwdlAddressPrefixComparable&&s.lastTlv12AwdlAddressPrefixMatchesMetadataSource);
    assert(s.lastTlv12Flags==0x8004);

    auto prefixed=message(0);addTlv(prefixed,12,dataPathValue(0x0307));
    observeOwnedMessage48(prefixed.data(),prefixed.size());s=snapshot();
    assert(s.lastTlv12AwdlAddressPrefixComparable&&s.lastTlv12AwdlAddressPrefixMatchesMetadataSource);
    assert(s.lastTlv12Length==27); // address begins at value offset 21

    auto shortAddress=message(0);
    auto shortValue=dataPathValue(0x0307);shortValue.pop_back();
    addTlv(shortAddress,12,shortValue);observeOwnedMessage48(shortAddress.data(),shortAddress.size());
    s=snapshot();
    assert(!s.lastTlv12AwdlAddressPrefixComparable&&s.lastTlv12UnclassifiedFlagBits==0);
    assert(s.shortKnownTlvSamples==1);

}

static void modeNineConcurrentAggregation() {
    std::atomic<bool> done{false};
    std::thread producers[4];
    for (unsigned t=0;t<4;t++) producers[t]=std::thread([t]() {
        for (unsigned n=0;n<80;n++) {
            auto sample=message(((t+n)&1)?0:3);
            addTlv(sample,4,syncValue());addTlv(sample,18,channelSequence());
            observeOwnedMessage48(sample.data(),sample.size());
        }
    });
    std::thread reader([&done]() {
        while (!done.load(std::memory_order_acquire)) {
            const Snapshot s=snapshot();
            assert(s.samplesReady<=s.samplesReserved&&s.samplesReserved<=256);
            assert(s.psfSamples<=s.psfPoolReserved&&s.mifSamples<=s.mifPoolReserved);
            assert(s.psf.samples==s.psfSamples&&s.mif.samples==s.mifSamples);
        }
    });
    for (auto &thread:producers)thread.join();
    done.store(true,std::memory_order_release);reader.join();
    const Snapshot s=snapshot();
    assert(s.samplesReserved==224&&s.samplesReady==224);
    assert(s.psfSamples==112&&s.mifSamples==112);
}

static void modeTenOtherFloodKeepsSubtypePools() {
    for (unsigned i=0;i<40;i++) {
        auto other=message(1);
        observeOwnedMessage48(other.data(),other.size());
    }
    auto psf=message(0);addTlv(psf,4,syncValue());
    observeOwnedMessage48(psf.data(),psf.size());
    auto mif=message(3);addTlv(mif,4,syncValue());
    observeOwnedMessage48(mif.data(),mif.size());
    const Snapshot s=snapshot();
    assert(s.psfPoolReserved==1&&s.mifPoolReserved==1&&s.otherPoolReserved==32);
    assert(s.otherPoolCapacity==32&&s.otherPoolSamplesDroppedAtCapacity==8);
    assert(s.psfSamples==1&&s.mifSamples==1&&s.otherSubtypeSamples==32);
    assert(s.psf.lastTlv4NextChannel==11&&s.mif.lastTlv4NextChannel==11);
}
int main(int argc,char **argv) {
    assert(argc==2);const int mode=atoi(argv[1]);
    switch(mode) {
        case 1:modeOne();break;case 2:modeTwo();break;case 3:modeThree();break;
        case 4:modeFour();break;case 5:modeFive();break;
        case 6:modeSixPsfFloodThenMif();break;
        case 7:modeSevenMifFloodThenPsf();break;
        case 8:modeEightKnownSuffixAndPrefixOffsets();break;
        case 9:modeNineConcurrentAggregation();break;
        case 10:modeTenOtherFloodKeepsSubtypePools();break;
        default:abort();
    }
}
