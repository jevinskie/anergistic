#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

void *mmap_file(const char *path, size_t *size);
void memcpy_to_file(const char *fname, void *buf, size_t size);

#ifdef __cplusplus
extern }
#endif
