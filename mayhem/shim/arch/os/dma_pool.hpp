#pragma once
// Host stand-in for managarm's core/arch/include/arch/os/dma_pool.hpp.
// The real header backs DMA pools with helix memory objects (managarm syscalls),
// which cannot run on a Linux host. The fuzzed code (core/lib/bpf) only uses
// arch::dma_buffer_view over host memory (dma_buffer_view{nullptr, ptr, len}),
// so this shim only provides the contiguous_pool interface that
// <arch/dma_pool.hpp> statically checks for.
#include <arch/dma_structs.hpp>
#include <cstddef>

namespace arch {

struct contiguous_pool {
	dma_ptr allocate(size_t, size_t, size_t);
	void deallocate(dma_ptr, size_t, size_t, size_t);
};

} // namespace arch
