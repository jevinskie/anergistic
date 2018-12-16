#include "mbuf.h"

#include "hex.h"

#include "debugbreak/debugbreak.h"

#include <cassert>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

typedef std::map<u64, std::unique_ptr<std::vector<u8>>> mbufs_t;
typedef mbufs_t::value_type mbuf_pair_t;
typedef std::pair<const u64, std::reference_wrapper<std::unique_ptr<std::vector<u8>>>> mbuf_pair_ref_t;

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
	printf("MemBuf::alloc(0x%016llx, 0x%08x)\n", ea, sz);
	if (is_alloced(ea)) {
		auto mbuf = find(ea);
		const auto buf_ea = mbuf.first;
		auto &buf = *mbuf.second.get();
		const auto buf_sz = buf.size();
		const auto buf_ea_end = buf_ea + buf_sz;
		const auto over = buf_ea_end - (ea + sz);
		if (over > 0) {
			printf("MemBuf::alloc(0x%016llx, 0x%08x) resize\n", ea, sz);
			buf.resize(buf_sz + over);
			memset(buf.data() + buf_sz, 0, over);
		}
	} else {
		mbufs[ea] = std::make_unique<mbufs_t::mapped_type::element_type>(sz, 0);
	}
	if (is_alloced(ea + sz)) {
		printf("found adjacent after\n");
		auto mbuf = find(ea);
		auto &buf = *mbuf.second.get();
		const auto buf_sz = buf.size();
		auto adj_mbuf = find(ea + sz);
		auto &adj_buf = *adj_mbuf.second.get();
		const auto adj_buf_sz = adj_buf.size();
		buf.resize(buf_sz + adj_buf_sz);
		memcpy(buf.data() + buf_sz, adj_buf.data(), adj_buf_sz);
		mbufs.erase(adj_mbuf.first);
	} else if (is_alloced(ea - 1)) {
		printf("found adjacent before\n");
		auto mbuf = find(ea);
		auto &buf = *mbuf.second.get();
		const auto buf_sz = buf.size();
		auto prev_adj_mbuf = find(ea - 1);
		auto &prev_adj_buf = *prev_adj_mbuf.second.get();
		const auto prev_adj_buf_sz = prev_adj_buf.size();
		prev_adj_buf.resize(prev_adj_buf_sz + buf_sz);
		memcpy(prev_adj_buf.data() + prev_adj_buf_sz, buf.data(), buf_sz);
		mbufs.erase(mbuf.first);
	}
}

bool MemBuf::is_alloced(u64 ea) {
	return is_alloced(ea, 1);
}

bool MemBuf::is_alloced(u64 ea, u32 sz) {
	printf("MemBuf::is_alloced(0x%016llx, 0x%08x)\n", ea, sz);
	for (const auto &bufp : mbufs) {
		const auto buf_ea = bufp.first;
		const auto &buf = *bufp.second;
		const auto buf_ea_end = buf_ea + buf.size();
		printf("MemBuf::is_alloced(0x%016llx, 0x%08x) buf_ea = 0x%016llx buf_ea_end = 0x%016llx\n", ea, sz, buf_ea, buf_ea_end);
		if (ea >= buf_ea && ea + sz <= buf_ea_end) {
			printf("MemBuf::is_alloced(0x%016llx, 0x%08x) = true\n", ea, sz);
			return true;
		}
	}
	printf("MemBuf::is_alloced(0x%016llx, 0x%08x) = false\n", ea, sz);
	return false;
}

mbuf_pair_ref_t MemBuf::find(u64 ea) {
	return find(ea, 1);
}

mbuf_pair_ref_t MemBuf::find(u64 ea, u32 sz) {
	printf("MemBuf::find(0x%016llx, 0x%08x)\n", ea, sz);
	for (auto &bufp : mbufs) {
		const auto buf_ea = bufp.first;
		const auto &buf = *bufp.second;
		const auto buf_ea_end = buf_ea + buf.size();
		printf("MemBuf::find(0x%016llx, 0x%08x) buf_ea = 0x%016llx buf_ea_end = 0x%016llx\n", ea, sz, buf_ea, buf_ea_end);
		if (ea >= buf_ea && ea + sz <= buf_ea_end) {
			printf("MemBuf::find(0x%016llx, 0x%08x) = true\n", ea, sz);
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
	printf("mbuf_is_alloced(0x%016llx, 0x%08x)\n", ea, sz);
	return gmb.is_alloced(ea, sz);
}

extern "C"
void mbuf_alloc(u64 ea, u32 sz) {
	printf("mbuf_alloc(0x%016llx, 0x%08x)\n", ea, sz);
	gmb.alloc(ea, sz);
	return;
}

extern "C"
void mbuf_set(u64 ea, const u8 *buf, u32 sz) {
	printf("mbuf_set(0x%016llx, %p, 0x%08x)\n", ea, buf, sz);
	memcpy(mbuf_get(ea, sz), buf, sz);
	return;
}

extern "C"
u8 *mbuf_get(u64 ea, u32 sz) {
	printf("mbuf_get(0x%016llx, 0x%08x)\n", ea, sz);
	if (!gmb.is_alloced(ea, sz)) {
		return nullptr;
	} else {
		gmb.alloc(ea, sz);
		auto mbuf = gmb.find(ea);
		const auto buf_ea = mbuf.first;
		auto buf = &mbuf.second.get();
		return (*buf)->data() + (ea - buf_ea);
	}
}
