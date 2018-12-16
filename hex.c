#include "hex.h"

#include <stdio.h>

void print_hex(const u8 *buf, u32 len) {
  for (u32 i = 0; i < len; ++i) {
    printf("%02hhx", buf[i]);
  }
}
