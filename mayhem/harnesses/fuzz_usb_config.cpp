// Fuzzes managarm's USB configuration-descriptor walker
// (protocols/usb/include/protocols/usb/usb.hpp), which every USB driver runs over the
// device-supplied configuration descriptor (GET_DESCRIPTOR(CONFIGURATION)): the HCDs
// (xhci/ehci/uhci) and serial drivers call configDescriptorFrom(), the storage driver
// walks groupByInterface()/endpointsOf(), usb_net extracts CDC functional descriptors.
// The input is the raw configuration descriptor buffer as returned by the device.
#include <protocols/usb/usb.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace proto = protocols::usb;

static volatile uint64_t sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// usbDevice.configurationDescriptor() hands drivers a std::string; keep an
	// exact-size heap copy so ASan sees any over-read.
	std::string descriptor(reinterpret_cast<const char *>(data), size);
	auto cfg = proto::configurationRange(descriptor);

	// HCD / serial drivers: the configuration descriptor header.
	if(auto conf = proto::configDescriptorFrom(cfg))
		sink += conf->totalLength + conf->numInterfaces + conf->configValue;

	// usb_net (usb-ncm.cpp): CDC functional descriptors by subtype.
	for(const auto &[head, body] : cfg) {
		if(head.descriptorType != proto::descriptor_type::cs_interface)
			continue;
		auto desc = proto::extractDescriptor<proto::CdcDescriptor>(body);
		if(!desc)
			continue;
		using St = proto::CdcDescriptor::CdcSubType;
		switch(desc->subtype) {
		case St::Header:
			if(auto d = proto::extractDescriptor<proto::CdcHeader>(body)) sink += d->bcdCDC;
			break;
		case St::Union:
			if(auto d = proto::extractDescriptor<proto::CdcUnion>(body)) sink += d->bControlInterface;
			break;
		case St::EthernetNetworking:
			if(auto d = proto::extractDescriptor<proto::CdcEthernetNetworking>(body)) sink += d->wMaxSegmentSize;
			break;
		case St::Ncm:
			if(auto d = proto::extractDescriptor<proto::CdcNcm>(body)) sink += d->bcdNcmVersion;
			break;
		case St::Mbim:
			if(auto d = proto::extractDescriptor<proto::CdcMbim>(body)) sink += d->wMaxControlMessage;
			break;
		case St::MbimExtended:
			if(auto d = proto::extractDescriptor<proto::CdcMbimExtended>(body)) sink += d->wMTU;
			break;
		default:
			break;
		}
	}

	// storage / hid drivers: interfaces, then their endpoints and class descriptors.
	for(auto [intf, body] : proto::groupByInterface(cfg)) {
		sink += intf.interfaceNumber + intf.alternateSetting + intf.interfaceClass;
		for(auto ep : proto::endpointsOf(body))
			sink += ep.endpointAddress + ep.maxPacketSize;
		for(auto [ep, extra] : proto::groupByEndpoint(body)) {
			sink += ep.attributes;
			for(const auto &[h, b] : extra)
				sink += h.descriptorType + b.size();
		}
	}
	for(auto intf : proto::interfacesOf(cfg))
		sink += intf.numEndpoints;
	return 0;
}
