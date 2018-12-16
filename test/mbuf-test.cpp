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

TEST(MBufAllocAdjacent, MBuf) {
	const u64 ea = 0x10000000;
	const u32 sz = 0x1000;
	EXPECT_TRUE(mbuf_is_alloced(ea, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + sz-1, 1));
	EXPECT_FALSE(mbuf_is_alloced(ea + sz, 1));
	EXPECT_FALSE(mbuf_is_alloced(ea + 2*sz-1, 1));
	auto orig_bufp = mbuf_get(ea, sz);
	EXPECT_NE(orig_bufp, nullptr);
	auto new_bufp = mbuf_get(ea + sz, sz);
	EXPECT_EQ(new_bufp, nullptr);
	mbuf_alloc(ea + sz, sz);
	EXPECT_TRUE(mbuf_is_alloced(ea + sz, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + sz-1, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + 2*sz-1, 1));
	EXPECT_FALSE(mbuf_is_alloced(ea + 2*sz, 1));
	new_bufp = mbuf_get(ea + sz, sz);
	EXPECT_EQ(orig_bufp + sz, new_bufp);
}

TEST(MBufAllocNonAdjacent, MBuf) {
	const u64 ea = 0x10000000;
	const u32 sz = 0x1000;
	EXPECT_TRUE(mbuf_is_alloced(ea, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + sz-1, 1));
	EXPECT_FALSE(mbuf_is_alloced(ea + 3*sz-1, 1));
	EXPECT_FALSE(mbuf_is_alloced(ea + 3*sz, 1));
	EXPECT_FALSE(mbuf_is_alloced(ea + 4*sz-1, 1));
	EXPECT_FALSE(mbuf_is_alloced(ea + 4*sz, 1));
	auto orig_bufp = mbuf_get(ea, sz);
	EXPECT_NE(orig_bufp, nullptr);
	auto new_bufp = mbuf_get(ea + 3*sz, sz);
	EXPECT_EQ(new_bufp, nullptr);
	mbuf_alloc(ea + 3*sz, sz);
	EXPECT_FALSE(mbuf_is_alloced(ea + 3*sz-1, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + 3*sz, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + 4*sz-1, 1));
	EXPECT_FALSE(mbuf_is_alloced(ea + 4*sz, 1));
	new_bufp = mbuf_get(ea + 3*sz, sz);
	EXPECT_NE(orig_bufp + 3*sz, new_bufp);
}

TEST(MBufAllocMerge, MBuf) {
	const u64 ea = 0x10000000;
	const u32 sz = 0x1000;
	EXPECT_TRUE(mbuf_is_alloced(ea, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + sz-1, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + 2*sz-1, 1));
	EXPECT_FALSE(mbuf_is_alloced(ea + 2*sz, 1));
	EXPECT_FALSE(mbuf_is_alloced(ea + 3*sz-1, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + 3*sz, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + 4*sz-1, 1));
	EXPECT_FALSE(mbuf_is_alloced(ea + 4*sz, 1));
	auto orig_bufp = mbuf_get(ea, sz);
	EXPECT_NE(orig_bufp, nullptr);
	auto end_bufp = mbuf_get(ea + 3*sz, sz);
	EXPECT_NE(end_bufp, nullptr);
	auto middle_bufp = mbuf_get(ea + 2*sz, sz);
	EXPECT_EQ(middle_bufp, nullptr);
	mbuf_alloc(ea + 2*sz, sz);
	EXPECT_TRUE(mbuf_is_alloced(ea, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + sz-1, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + 2*sz-1, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + 2*sz, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + 3*sz-1, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + 3*sz, 1));
	EXPECT_TRUE(mbuf_is_alloced(ea + 4*sz-1, 1));
	EXPECT_FALSE(mbuf_is_alloced(ea + 4*sz, 1));
	middle_bufp = mbuf_get(ea + 2*sz, sz);
	EXPECT_EQ(orig_bufp + 2*sz, middle_bufp);
	auto new_end_bufp = mbuf_get(ea + 3*sz, sz);
	EXPECT_NE(end_bufp, new_end_bufp);
	EXPECT_EQ(orig_bufp + 3*sz, new_end_bufp);
}

