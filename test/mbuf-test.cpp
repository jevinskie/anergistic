#include "gtest/gtest.h"

#include "mbuf.h"

#include "hex.h"

#include <string.h>

TEST(MBufGetNotAlloced, MBuf) {
	const u64 ea = 0x10000000;
	const u32 sz = 0x1000;
	auto bufp = mbuf_get(ea, sz);
	EXPECT_EQ(bufp, nullptr);
}

TEST(MBufGetAlloced, MBuf) {
	const u64 ea = 0x10000000;
	const u32 sz = 0x1000;
	auto bufp = mbuf_get(ea, sz);
	EXPECT_EQ(bufp, nullptr);
	mbuf_alloc(ea, sz);
	bufp = mbuf_get(ea, sz);
	EXPECT_NE(bufp, nullptr);
	for (u32 i = 0; i < sz; ++i) {
		EXPECT_EQ(bufp[i], 0);
	}
}

TEST(MBufSetAlloced, MBuf) {
	const u64 ea = 0x10000000;
	const u32 sz = 0x1000;
	u8 new_buf[sz];
	memset(new_buf, 0xFF, sz);
	printf("new_buf: %p ", new_buf);
	print_hex(new_buf, 0x10);
	printf("\n");
	mbuf_set(ea, new_buf, sz);
	auto bufp = mbuf_get(ea, sz);
	printf("bufp: %p ", bufp);
	print_hex(bufp, 0x10);
	printf("\n");
	EXPECT_NE(bufp, nullptr);
	EXPECT_EQ(memcmp(bufp, new_buf, sz), 0);
}
