#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

#define EMU_PAGE_SZ (64*1024)
#define EMU_PAGE_ROUND_DOWN(ea) (ea & ~(EMU_PAGE_SZ-1))
#define EMU_PAGE_ROUND_UP(ea) ((ea + EMU_PAGE_SZ) & ~(EMU_PAGE_SZ-1))

int mbuf_is_alloced(u64 ea, u32 sz);
void mbuf_alloc(u64 ea, u32 sz);
u64 mbuf_get_buf_base_ea(u64 ea);
u32 mbuf_get_buf_sz(u64 ea);
void mbuf_set(u64 ea, const u8 *buf, u32 sz);
u8 *mbuf_get(u64 ea, u32 sz);
void mbuf_dump_hex_printf(void);

#ifdef __cplusplus
}
#endif
