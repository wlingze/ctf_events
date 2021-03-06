/*
 * Created 19.10.2017 by Tim RÃ¼hsen
 *
 * Call glob() using data from fuzzer crash file
 *
 * Build and execute with instrumented gnulib (amend -I paths as needed):
 *
 * clang build (spills out WRITE heap buffer overflow)
 * export CC=clang-6.0
 * export CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address -fsanitize-address-use-after-scope"
 * $CC $CFLAGS -I.. -I../lib glob_crash.c -o glob_crash ../lib/.libs/libgnu.a
 * ./glob_crash
 *  
 * gcc build (spills out READ heap buffer overflow):
 * export CC=gcc
 * export CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address -fsanitize-address-use-after-scope"
 * $CC $CFLAGS -I.. -I../lib glob_crash.c -o glob_crash ../lib/.libs/libgnu.a
 * ./glob_crash
 */

#include <glob.h>

int main(int argc, char **argv)
{
static unsigned char data[] = {
  0x7e, 0xff, 0xbf, 0xf1, 0xff, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x3d,
  0x2a, 0x6f, 0x2a, 0x2a, 0x2f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x2d, 0x64,
  0x6f, 0x63, 0x65, 0x78, 0x6b, 0x65, 0x65, 0x70, 0x2d, 0x73, 0x65, 0x73,
  0x73, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x73,
  0x3d, 0x63, 0x72, 0x6f, 0x41, 0x67, 0x6e, 0x66, 0xff, 0x69, 0x67, 0x3d,
  0x2a, 0x6f, 0x2a, 0x2a, 0x2f, 0x75, 0x74, 0x70, 0x75, 0x74, 0xff, 0x3d,
  0x2d, 0x64, 0x6f, 0x63, 0x65, 0x78, 0x6b, 0x65, 0x65, 0x70, 0x2d, 0x73,
  0x65, 0x73, 0x73, 0x69, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x3d, 0x2a,
  0x6f, 0x2a, 0x2a, 0x2f, 0x75, 0x74, 0x70, 0x75, 0xd3, 0x2d, 0x64, 0x6f,
  0x2d, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x6f, 0x6f,
  0x6b, 0x72, 0x6f, 0x41, 0x67, 0x6e, 0x2a, 0x69, 0x67, 0x3d, 0x2a, 0x6f,
  0x2a, 0x2a, 0x2f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x2d, 0x64, 0x6f, 0x63,
  0x65, 0x78, 0x6b, 0x65, 0x65, 0x70, 0x2d, 0x73, 0x65, 0x73, 0x73, 0x69,
  0x6f, 0x6e, 0x2d, 0x63, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x73, 0x3d, 0x63,
  0x72, 0x6f, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x2f, 0x65, 0x6e, 0x3b, 0x2f,
  0x31, 0x2d, 0x63, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x73, 0x3d, 0x63, 0x72,
  0x6f, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x2f, 0x65, 0x6e, 0x74, 0x2f, 0x31,
  0x2a, 0x2e, 0x3b, 0x2e, 0x35, 0x73, 0x20, 0x0b, 0x00
};

	glob_t pglob;
	if (glob(data, GLOB_TILDE|GLOB_ONLYDIR|GLOB_NOCHECK, NULL, &pglob) == 0)
		globfree(&pglob);

	return 0;
} 
