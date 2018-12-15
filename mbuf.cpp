#include "mbuf.h"

#include "hex.h"

#include <map>
#include <optional>
#include <utility>
#include <vector>

std::map<u64, std::vector<u8>> g_mbuf;

typedef std::pair<u64, std::vector<u8> *> mbuf_ptr_pair;
typedef std::pair<u64, std::vector<u8> &> mbuf_ref_pair;

std::optional<mbuf_ptr_pair> mbuf_find(u64 ea, u32 sz, bool include_sz) {
	printf("mbuf_find(0x%016llx, 0x%08x, %d)\n", ea, sz, include_sz);
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
	printf("mbuf_alloc_non_void(0x%016llx, 0x%08x)\n", ea, sz);
	if (auto found_buf = mbuf_find(ea, sz, false)) {
		auto buf_ea = found_buf->first;
		auto buf = found_buf->second;
		if (buf_ea + buf->size() == ea) {
			auto buf_orig_sz = buf->size();
			buf->resize(buf->size() + sz);
			memset(buf->data() + buf_orig_sz, 0, sz);
			printf("mbuf_alloc_non_void(0x%016llx, 0x%08x) resizing from %p\n", ea, sz, (void*)buf_orig_sz);

		} else {
			printf("mbuf_alloc_non_void(0x%016llx, 0x%08x) found existing alloc of appropriate size\n", ea, sz);
		}
		return std::make_pair(buf_ea, buf);
	}
	auto buf = std::vector<u8>(sz, 0);
	g_mbuf[ea] = buf;
	printf("mbuf_alloc_non_void(0x%016llx, 0x%08x) new alloc\n", ea, sz);
	return std::make_pair(ea, &buf);
}

extern "C"
void mbuf_alloc(u64 ea, u32 sz) {
	printf("mbuf_alloc(0x%016llx, 0x%08x)\n", ea, sz);
	mbuf_alloc_non_void(ea, sz);
	return;
}

extern "C"
void mbuf_set(u64 ea, const u8 *buf, u32 sz) {
	printf("mbuf_set(0x%016llx, %p, 0x%08x)\n", ea, buf, sz);
	mbuf_ptr_pair bufp;
	if (auto b = mbuf_find(ea, sz, true)) {
		printf("mbuf_set(0x%016llx, %p, 0x%08x) found existing\n", ea, buf, sz);
		bufp = *b;
	} else {
		printf("mbuf_set(0x%016llx, %p, 0x%08x) allocing new\n", ea, buf, sz);
		bufp = mbuf_alloc_non_void(ea, sz);
	}
	auto bufp_off = bufp.second->data() + (ea - bufp.first);
	printf("bufp_off before: ");
	print_hex(bufp_off, 0x10);
	printf("\n");
	memcpy(bufp_off, buf, sz);
	printf("bufp_off after: ");
	print_hex(bufp_off, 0x10);
	printf("\n");
	return;
}

extern "C"
u8 *mbuf_get(u64 ea, u32 sz) {
	printf("mbuf_get(0x%016llx, 0x%08x)\n", ea, sz);
	if (auto found_buf = mbuf_find(ea, sz, true)) {
		auto buf_ea = found_buf->first;
		auto buf = found_buf->second;
		printf("mbuf_get(0x%016llx, 0x%08x) buf = %p buf->data() = %p\n", ea, sz, buf, buf->data());
		return buf->data() + (ea - buf_ea);
	}
	return nullptr;
}
