#include<sys/mman.h>
#include<stdio.h>

main(){
    void *ptr;
    int flags;
    void *buf;
    int prot = PROT_READ|PROT_WRITE|PROT_EXEC;
    flags = MAP_ANONYMOUS;
    if ( (buf =mmap(0x10000000, 0x1000, prot, flags, NULL, 0x0)) == -1)
        perror("oh jebus: ");
    printf("addr: %p\n", buf);
    printf("prot: %d\n", prot);
    printf("flags: %d\n", flags);
}