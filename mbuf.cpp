#include "mbuf.h"

#include "hex.h"

#include "debugbreak/debugbreak.h"
#include "dbgtools/callstack.h"

#include <cassert>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <utility>
#include <vector>



#include "cxx-prettyprint/prettyprint.hpp"
#include "fmt/format.h"
#include "fmt/ostream.h"

void print_callstack()
{
	void* addresses[256];
	int num_addresses = callstack( 0, addresses, 256 );

	callstack_symbol_t symbols[256];
	char  symbols_buffer[2048];
	num_addresses = callstack_symbols( addresses, symbols, num_addresses, symbols_buffer, 2048 );

	int i;
	for( i = 0; i < num_addresses; ++i )
		printf( "%3d) %-50s %s(%u)\n", i, symbols[i].function, symbols[i].file, symbols[i].line );
}

typedef std::map<u64, std::unique_ptr<std::vector<u8>>> mbufs_t;
typedef mbufs_t::value_type mbuf_pair_t;
typedef std::pair<const u64, std::reference_wrapper<std::unique_ptr<std::vector<u8>>>> mbuf_pair_ref_t;

bool operator==(const mbuf_pair_ref_t &a, const mbuf_pair_ref_t &b) {
	return a.first == b.first && a.second.get() == b.second.get();
}

bool operator!=(const mbuf_pair_ref_t &a, const mbuf_pair_ref_t &b) {
	return a.first != b.first || a.second.get() != b.second.get();
}

class MemBuf {
private:
	mbufs_t mbufs;

public:
	void alloc(u64 ea, u32 sz);
	bool is_alloced(u64 ea);
	bool is_alloced(u64 ea, u32 sz);
	mbuf_pair_ref_t find(u64 ea);
	mbuf_pair_ref_t find(u64 ea, u32 sz);
	mbufs_t::mapped_type& operator[](u64 ea);
};

MemBuf gmb;

void MemBuf::alloc(u64 ea, u32 sz) {
	fmt::print("MemBuf::alloc(0x{:016x}, 0x{:08x})\n", ea, sz);
	if (is_alloced(ea)) {
		auto mbuf = find(ea);
		const auto buf_ea = mbuf.first;
		auto &buf = *mbuf.second.get();
		const auto buf_sz = buf.size();
		const auto buf_ea_end = buf_ea + buf_sz;
		const auto over = buf_ea_end - (ea + sz);
		if (over > 0) {
			fmt::print("MemBuf::alloc(0x{:016x}, 0x{:08x}) resize\n", ea, sz);
			buf.resize(buf_sz + over);
			memset(buf.data() + buf_sz, 0, over);
		}
	} else {
		fmt::print("MemBuf::alloc(0x{:016x}, 0x{:08x}) making new vector\n", ea, sz);
		// print_callstack();
		// debug_break();
		mbufs[ea] = std::make_unique<mbufs_t::mapped_type::element_type>(sz, 0);
	}
	if (is_alloced(ea + sz)) {
		fmt::print("found adjacent after\n");
		auto mbuf = find(ea);
		auto &buf = *mbuf.second.get();
		auto adj_mbuf = find(ea + sz);
		auto &adj_buf = *adj_mbuf.second.get();
		fmt::print("mbuf: {} adj_mbuf: {}\n", mbuf, adj_mbuf);
		if (mbuf != adj_mbuf) {
			fmt::print("found adjacent after differs\n");
			const auto buf_sz = buf.size();
			const auto adj_buf_sz = adj_buf.size();
			buf.resize(buf_sz + adj_buf_sz);
			memcpy(buf.data() + buf_sz, adj_buf.data(), adj_buf_sz);
			mbufs.erase(adj_mbuf.first);
		} else {
			fmt::print("found adjacent after same\n");
		}
	}
	if (is_alloced(ea - 1)) {
		fmt::print("found adjacent before\n");
		auto mbuf = find(ea);
		auto &buf = *mbuf.second.get();
		auto prev_adj_mbuf = find(ea - 1);
		auto &prev_adj_buf = *prev_adj_mbuf.second.get();
		fmt::print("mbuf: {} prev_adj_mbuf: {}\n", mbuf, prev_adj_mbuf);
		if (mbuf != prev_adj_mbuf) {
			fmt::print("found adjacent before differs\n");
			const auto buf_sz = buf.size();
			const auto prev_adj_buf_sz = prev_adj_buf.size();
			prev_adj_buf.resize(prev_adj_buf_sz + buf_sz);
			memcpy(prev_adj_buf.data() + prev_adj_buf_sz, buf.data(), buf_sz);
			mbufs.erase(mbuf.first);
		} else {
			fmt::print("found adjacent before same\n");
		}
	}
}

bool MemBuf::is_alloced(u64 ea) {
	return is_alloced(ea, 1);
}

bool MemBuf::is_alloced(u64 ea, u32 sz) {
	fmt::print("MemBuf::is_alloced(0x{:016x}, 0x{:08x})\n", ea, sz);
	for (const auto &bufp : mbufs) {
		const auto buf_ea = bufp.first;
		const auto &buf = *bufp.second;
		const auto buf_ea_end = buf_ea + buf.size();
		fmt::print("MemBuf::is_alloced(0x{:016x}, 0x{:08x}) buf_ea = 0x{:016x} buf_ea_end = 0x{:016x}\n", ea, sz, buf_ea, buf_ea_end);
		if (ea >= buf_ea && ea + sz <= buf_ea_end) {
			fmt::print("MemBuf::is_alloced(0x{:016x}, 0x{:08x}) = true\n", ea, sz);
			return true;
		}
	}
	fmt::print("MemBuf::is_alloced(0x{:016x}, 0x{:08x}) = false\n", ea, sz);
	return false;
}

mbuf_pair_ref_t MemBuf::find(u64 ea) {
	return find(ea, 1);
}

mbuf_pair_ref_t MemBuf::find(u64 ea, u32 sz) {
	fmt::print("MemBuf::find(0x{:016x}, 0x{:08x})\n", ea, sz);
	for (auto &bufp : mbufs) {
		const auto buf_ea = bufp.first;
		const auto &buf = *bufp.second;
		const auto buf_ea_end = buf_ea + buf.size();
		fmt::print("MemBuf::find(0x{:016x}, 0x{:08x}) buf_ea = 0x{:016x} buf_ea_end = 0x{:016x}\n", ea, sz, buf_ea, buf_ea_end);
		if (ea >= buf_ea && ea + sz <= buf_ea_end) {
			fmt::print("MemBuf::find(0x{:016x}, 0x{:08x}) = true\n", ea, sz);
			return std::make_pair(buf_ea, std::ref(bufp.second));
		}
	}
	assert(!"value does not exist");
}

mbufs_t::mapped_type& MemBuf::operator[](u64 ea) {
	(void)ea;
	assert(!"not implemented");
}

extern "C"
int mbuf_is_alloced(u64 ea, u32 sz) {
	fmt::print("mbuf_is_alloced(0x{:016x}, 0x{:08x})\n", ea, sz);
	return gmb.is_alloced(ea, sz);
}

extern "C"
void mbuf_alloc(u64 ea, u32 sz) {
	fmt::print("mbuf_alloc(0x{:016x}, 0x{:08x})\n", ea, sz);
	gmb.alloc(ea, sz);
	return;
}

extern "C"
u64 mbuf_get_buf_base_ea(u64 ea) {
	if (!gmb.is_alloced(ea)) {
		assert(!"not mapped");
	}
	return gmb.find(ea).first;
}

extern "C"
u32 mbuf_get_buf_sz(u64 ea) {
	if (!gmb.is_alloced(ea)) {
		assert(!"not mapped");
	}
	return gmb.find(ea).second.get()->size();
}

extern "C"
void mbuf_set(u64 ea, const u8 *buf, u32 sz) {
	fmt::print("mbuf_set(0x{:016x}, {}, 0x{:08x})\n", ea, buf, sz);
	memcpy(mbuf_get(ea, sz), buf, sz);
	return;
}

extern "C"
u8 *mbuf_get(u64 ea, u32 sz) {
	fmt::print("mbuf_get(0x{:016x}, 0x{:08x})\n", ea, sz);
	if (!gmb.is_alloced(ea, sz)) {
		gmb.alloc(ea, sz);
	}
	auto mbuf = gmb.find(ea);
	const auto buf_ea = mbuf.first;
	auto buf = &mbuf.second.get();
	return (*buf)->data() + (ea - buf_ea);
}
