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
	if (is_alloced(ea)) {
		auto mbuf = find(ea);
		const auto buf_ea = mbuf.first;
		auto buf = &mbuf.second.get();
		const auto buf_sz = (*buf)->size();
		const auto buf_ea_end = buf_ea + buf_sz;
		const auto over = buf_ea_end - (ea + sz);
		if (over > 0) {
			(*buf)->resize(buf_sz + over);
			memset((*buf)->data() + buf_sz, 0, over);
		}
	} else {
		mbufs[ea] = std::make_unique<mbufs_t::mapped_type::element_type>(sz, 0);
	}
}

bool MemBuf::is_alloced(u64 ea) {
	return is_alloced(ea, 1);
}

bool MemBuf::is_alloced(u64 ea, u32 sz) {
	const auto bufp = mbufs.lower_bound(ea);
	if (bufp == mbufs.cend()) {
		return false;
	}
	const auto buf_ea = bufp->first;
	const auto buf = &bufp->second;
	const auto buf_ea_end = buf_ea + (*buf)->size();
	if (ea >= buf_ea && ea + sz <= buf_ea_end) {
		return true;
	}
	return false;
}

mbuf_pair_ref_t MemBuf::find(u64 ea) {
	return find(ea, 1);
}

mbuf_pair_ref_t MemBuf::find(u64 ea, u32 sz) {
	auto bufp = mbufs.lower_bound(ea);
	if (bufp == mbufs.cend()) {
		assert(!"value does not exist");
	}
	const auto buf_ea = bufp->first;
	auto buf = &bufp->second;
	const auto buf_ea_end = buf_ea + (*buf)->size();
	if (ea >= buf_ea && ea + sz <= buf_ea_end) {
		return std::make_pair(buf_ea, std::ref(bufp->second));
	}
	assert(!"value does not exist");
}

mbufs_t::mapped_type& MemBuf::operator[](u64 ea) {
	(void)ea;
	assert(!"not implemented");
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
