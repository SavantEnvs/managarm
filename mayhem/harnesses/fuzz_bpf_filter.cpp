// Fuzzes managarm's classic-BPF socket filter (core/lib/bpf/bpf.cpp) the way
// netserver's packet sockets use it (servers/netserver/src/raw.cpp):
//   setsockopt(SO_ATTACH_FILTER): Bpf{optbuf}.validate() rejects bad programs,
//   Raw::feedPacket():            Bpf{filter}.run(frame) for every received frame.
// Both the filter program (from an unprivileged socket user) and the frame (from
// the network) are untrusted.
//
// Input layout: byte 0 = instruction count N; next N*8 bytes = struct sock_filter[N]
// (the SO_ATTACH_FILTER optbuf, whose size raw.cpp asserts is a multiple of 8);
// remaining bytes = the received frame.
#include <core/bpf.hpp>

#include <cstdint>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if(size < 1)
		return -1;
	size_t n = data[0];
	size_t progBytes = n * sizeof(struct sock_filter);
	if(size - 1 < progBytes)
		return -1;

	std::vector<char> optbuf(data + 1, data + 1 + progBytes);
	Bpf validator{optbuf};
	if(!validator.validate())
		return 0;

	// The frame is copied into its own exact-size heap buffer so ASan sees any
	// read past its end.
	size_t frameLen = size - 1 - progBytes;
	std::vector<uint8_t> frame(data + 1 + progBytes, data + size);
	Bpf bpf{optbuf};
	volatile uint32_t accept = bpf.run(arch::dma_buffer_view{nullptr, frame.data(), frameLen});
	(void)accept;
	return 0;
}
