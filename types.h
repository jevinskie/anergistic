// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#ifndef TYPES_H__
#define TYPES_H__

#include <stdint.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef uint8_t u1;

typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;
typedef int8_t s1;

static inline u8 be8(u8 *p)
{
	return *p;
}

static inline u16 be16(u8 *p)
{
	u16 a;

	a  = p[0] << 8;
	a |= p[1];

	return a;
}

static inline u32 be32(u8 *p)
{
	u32 a;

	a  = p[0] << 24;
	a |= p[1] << 16;
	a |= p[2] <<  8;
	a |= p[3] <<  0;

	return a;
}

static inline u64 be64(u8 *p)
{
	u32 a, b;

	a = be32(p);
	b = be32(p + 4);

	return ((u64)a<<32) | b;
}

static inline void wbe16(u8 *p, u16 v)
{
	p[0] = v >> 8;
	p[1] = v;
}

static inline void wbe32(u8 *p, u32 v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >>  8;
	p[3] = v;
}

static inline void wbe64(u8 *p, u64 v)
{
	wbe32(p + 4, v);
	v >>= 32;
	wbe32(p, v);
}


// sign extension for immediate values inside opcodes
static inline u32 se(u32 v, int b)
{
	v <<= 32-b;
	v = ((s32)v) >> (32-b);
	return v;
}

static inline u32 se7(u32 v) { return se(v, 7); }
static inline u32 se10(u32 v) { return se(v, 10); }
static inline u32 se16(u32 v) { return se(v, 16); }
static inline u32 se18(u32 v) { return se(v, 18); }

//Endian swap for u32
#define _ES32(val) \
	((u32)(((((u32)val) & 0xff000000) >> 24) | \
	       ((((u32)val) & 0x00ff0000) >> 8 ) | \
	       ((((u32)val) & 0x0000ff00) << 8 ) | \
	       ((((u32)val) & 0x000000ff) << 24)))

//Endian swap for u64.
#define _ES64(val) \
	((u64)(((((u64)val) & 0xff00000000000000ull) >> 56) | \
	       ((((u64)val) & 0x00ff000000000000ull) >> 40) | \
	       ((((u64)val) & 0x0000ff0000000000ull) >> 24) | \
	       ((((u64)val) & 0x000000ff00000000ull) >> 8 ) | \
	       ((((u64)val) & 0x00000000ff000000ull) << 8 ) | \
	       ((((u64)val) & 0x0000000000ff0000ull) << 24) | \
	       ((((u64)val) & 0x000000000000ff00ull) << 40) | \
	       ((((u64)val) & 0x00000000000000ffull) << 56)))
#endif
