#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"
#include <stdlib.h>

void print_hex(const u8 *buf, u32 len);
void hexdump(const void* data, size_t size, u64 addrbase);

#ifdef __cplusplus
}
#endif
