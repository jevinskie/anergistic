#include "mbuf.h"

#include <map>
#include <optional>
#include <utility>
#include <vector>

std::map<u64, std::vector<u8>> g_mbuf;

typedef std::pair<u64, std::vector<u8> *> mbuf_ptr_pair;
typedef std::pair<u64, std::vector<u8> &> mbuf_ref_pair;

std::optional<mbuf_ptr_pair> mbuf_find(u64 ea, u32 sz, bool include_sz) {
	for (auto &bufp : g_mbuf) {
		auto buf_ea = bufp.first;
		auto buf = bufp.second;
		if (include_sz && buf_ea + buf.size() <= ea + sz) {
			return std::make_pair(buf_ea, &buf);
		} else if (buf_ea + buf.size() < ea) {
			return std::make_pair(buf_ea, &buf);
		}
	}
	return std::nullopt;
}

mbuf_ptr_pair mbuf_alloc_non_void(u64 ea, u32 sz) {
	if (auto found_buf = mbuf_find(ea, sz, false)) {
		auto buf_ea = found_buf->first;
		auto buf = found_buf->second;
		if (buf_ea + buf->size() == ea) {
			auto buf_orig_sz = buf->size();
			buf->resize(buf->size() + sz);
			memset(buf->data() + buf_orig_sz, 0, sz);
		}
		return std::make_pair(buf_ea, buf);
	}
	auto buf = std::vector<u8>(sz, 0);
	g_mbuf[ea] = buf;
	return std::make_pair(ea, &buf);
}

extern "C"
void mbuf_alloc(u64 ea, u32 sz) {
	mbuf_alloc_non_void(ea, sz);
	return;
}

extern "C"
void mbuf_set(u64 ea, const u8 *buf, u32 sz) {
	auto bufp = mbuf_alloc_non_void(ea, sz);
	memcpy(bufp.second->data() + (ea - bufp.first), buf, sz);
	return;
}

extern "C"
u8 *mbuf_get(u64 ea, u32 sz) {

	return nullptr;
}
