// Known-answer tests for the code the fuzz targets exercise: managarm's classic-BPF
// interpreter (core/lib/bpf/bpf.cpp) and the USB configuration-descriptor walker
// (protocols/usb/include/protocols/usb/usb.hpp). Upstream has no host-runnable unit
// tests for these (its testsuites run inside a booted managarm), so these assert the
// documented behaviour directly. Prints one "PASS <name>" / "FAIL <name>" per check.
#include <core/bpf.hpp>
#include <protocols/usb/usb.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace proto = protocols::usb;

static int failures = 0;

static void check(const char *name, bool ok) {
	std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
	if(!ok)
		failures++;
}

static std::vector<char> prog(std::initializer_list<sock_filter> insns) {
	std::vector<char> v(insns.size() * sizeof(sock_filter));
	std::memcpy(v.data(), insns.begin(), v.size());
	return v;
}

static uint32_t runOn(std::vector<char> p, std::vector<uint8_t> frame) {
	Bpf b{p};
	return b.run(arch::dma_buffer_view{nullptr, frame.data(), frame.size()});
}

static void bpfTests() {
	// "accept IPv4 only": ldh [12]; jeq #0x800, 0, 1; ret #0xffff; ret #0
	auto ipv4 = prog({
		BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, 0xffff),
		BPF_STMT(BPF_RET | BPF_K, 0),
	});
	{ Bpf b{ipv4}; check("bpf_validate_ipv4_filter", b.validate()); }
	std::vector<uint8_t> frame(60, 0);
	frame[12] = 0x08; frame[13] = 0x00;
	check("bpf_ipv4_frame_accepted", runOn(ipv4, frame) == 0xffff);
	frame[13] = 0x06; // ARP
	check("bpf_arp_frame_dropped", runOn(ipv4, frame) == 0);

	// Indexed load, multiply, return A: ldx #3; ldb [x+1]; mul #3; ret a
	auto arith = prog({
		BPF_STMT(BPF_LDX | BPF_W | BPF_IMM, 3),
		BPF_STMT(BPF_LD | BPF_B | BPF_IND, 1),
		BPF_STMT(BPF_ALU | BPF_MUL | BPF_K, 3),
		BPF_STMT(BPF_RET | BPF_A, 0),
	});
	std::vector<uint8_t> f2{0, 1, 2, 3, 14, 5};
	check("bpf_ldb_ind_mul_ret_a", runOn(arith, f2) == 42);

	// Big-endian word load + and + neg + tax/txa + add.
	auto word = prog({
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x0000ffff),
		BPF_STMT(BPF_MISC | BPF_TAX, 0),
		BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
		BPF_STMT(BPF_RET | BPF_A, 0),
	});
	std::vector<uint8_t> f3{0x12, 0x34, 0x01, 0x02};
	check("bpf_ld_w_abs_big_endian", runOn(word, f3) == 0x0204);

	// jset: ldb [x+0] with x=0; jset #0x80, 0, 1; ret #1; ret #2
	auto jset = prog({
		BPF_STMT(BPF_LDX | BPF_W | BPF_IMM, 0),
		BPF_STMT(BPF_LD | BPF_B | BPF_IND, 0),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x80, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, 1),
		BPF_STMT(BPF_RET | BPF_K, 2),
	});
	check("bpf_jset_taken", runOn(jset, {0x81}) == 1);
	check("bpf_jset_not_taken", runOn(jset, {0x01}) == 2);

	// The validator rejects programs the interpreter cannot run safely.
	{ std::vector<char> empty; Bpf b{empty}; check("bpf_reject_empty", !b.validate()); }
	{ auto p = prog({BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0)}); Bpf b{p};
	  check("bpf_reject_no_return", !b.validate()); }
	{ auto p = prog({BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 5, 0), BPF_STMT(BPF_RET | BPF_K, 0)}); Bpf b{p};
	  check("bpf_reject_jump_out_of_range", !b.validate()); }
	{ auto p = prog({BPF_STMT(BPF_LD | BPF_B | BPF_MSH, 0), BPF_STMT(BPF_RET | BPF_K, 0)}); Bpf b{p};
	  check("bpf_reject_unsupported_opcode", !b.validate()); }
}

static void usbTests() {
	const uint8_t raw[] = {
		9, 0x02, 39, 0, 1, 1, 0, 0x80, 50,          // configuration, wTotalLength = 39
		9, 0x04, 0, 0, 2, 0x08, 0x06, 0x50, 0,      // interface 0: mass storage, 2 endpoints
		7, 0x05, 0x81, 0x02, 0x00, 0x02, 0,         // bulk IN  ep1, 512
		7, 0x05, 0x02, 0x02, 0x00, 0x02, 0,         // bulk OUT ep2, 512
		5, 0x24, 0x00, 0x10, 0x01,                  // CDC header, bcdCDC 0x0110
		2, 0x24,                                    // truncated CDC descriptor
	};
	std::string desc(reinterpret_cast<const char *>(raw), sizeof(raw));
	auto cfg = proto::configurationRange(desc);

	auto conf = proto::configDescriptorFrom(cfg);
	check("usb_config_header", conf && conf->totalLength == 39 && conf->numInterfaces == 1
			&& conf->configValue == 1 && conf->maxPower == 50);

	size_t entries = 0;
	for(auto it = cfg.begin(); it != cfg.end(); ++it)
		entries++;
	check("usb_descriptor_count", entries == 6);

	int intfs = 0, in = -1, out = -1, mps = 0;
	for(auto [intf, body] : proto::groupByInterface(cfg)) {
		intfs++;
		if(intf.interfaceClass != 0x08 || intf.numEndpoints != 2)
			intfs += 100;
		for(auto ep : proto::endpointsOf(body)) {
			if(ep.endpointAddress & 0x80) in = ep.endpointAddress & 0x0F;
			else out = ep.endpointAddress & 0x0F;
			mps += ep.maxPacketSize;
		}
	}
	check("usb_group_by_interface", intfs == 1);
	check("usb_endpoints", in == 1 && out == 2 && mps == 1024);

	int cdcHeaders = 0, cdcTruncated = 0;
	for(const auto &[head, body] : cfg) {
		if(head.descriptorType != proto::descriptor_type::cs_interface)
			continue;
		auto h = proto::extractDescriptor<proto::CdcHeader>(body);
		if(h && h->bcdCDC == 0x0110) cdcHeaders++;
		if(!proto::extractDescriptor<proto::CdcDescriptor>(body)) cdcTruncated++;
	}
	check("usb_cdc_header_extracted", cdcHeaders == 1);
	check("usb_truncated_descriptor_rejected", cdcTruncated == 1);

	// A descriptor whose bLength overruns the buffer ends the walk.
	const uint8_t bad[] = {9, 0x02, 9, 0, 0, 1, 0, 0x80, 50, 200, 0x04, 0};
	std::string bd(reinterpret_cast<const char *>(bad), sizeof(bad));
	size_t n = 0;
	for(const auto &e : proto::configurationRange(bd)) { (void)e; n++; }
	check("usb_overlong_length_stops_walk", n == 1);
	// bLength < 2 also ends the walk.
	const uint8_t zero[] = {0, 0x02, 9, 9};
	std::string zd(reinterpret_cast<const char *>(zero), sizeof(zero));
	check("usb_zero_length_stops_walk", !proto::configDescriptorFrom(proto::configurationRange(zd)));
}

int main() {
	bpfTests();
	usbTests();
	std::printf("failures: %d\n", failures);
	return failures ? 1 : 0;
}
