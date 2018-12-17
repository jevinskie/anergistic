#include "hex.h"

#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>

void print_hex(const u8 *buf, u32 len) {
  for (u32 i = 0; i < len; ++i) {
    printf("%02hhx", buf[i]);
  }
}

/* Adapted from https://gist.github.com/ccbrown/9722406 and fusee */
void hexdump(const void* data, size_t size, u64 addrbase) {
    const uint8_t *d = (const uint8_t *)data;
    char ascii[17];
    ascii[16] = '\0';

    for (size_t i = 0; i < size; i++) {
        if (i % 16 == 0) {
            printf("0x%0*" PRIx64 ": | ", (int)(2 * sizeof(addrbase)), addrbase + i);
        }
        printf("%02X ", d[i]);
        if (d[i] >= ' ' && d[i] <= '~') {
            ascii[i % 16] = d[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (size_t j = (i+1) % 16; j < 16; j++) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}