#include "util.h"

#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void *mmap_file(const char *path, size_t *size) {
  int fd;
  struct stat st;
  void *ptr;

  fd = open(path, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "open %s", path);
    _exit(-1);
  }
  if (fstat(fd, &st) != 0) {
    fprintf(stderr, "fstat %s", path);
    _exit(-1);
  }

  if (size)
    *size = (size_t)st.st_size;

  ptr = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (ptr == NULL) {
    fprintf(stderr, "mmap");
    _exit(-1);
  }
  close(fd);

  return ptr;
}

void memcpy_to_file(const char *fname, void *buf, size_t size) {
  FILE *fp;

  fp = fopen(fname, "wb");
  fwrite(buf, size, 1, fp);
  fclose(fp);
}
