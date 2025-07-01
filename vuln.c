#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "md5.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define GOOD_HASH "\x85\x23\x93\x84\xc0\x24\x3e\x32\xef\x2e\x37\xe8\xcd\x3b\x31\x14"

int main(int argc, char *argv[])
{
    int fd;
    char file_contents[256] = {0, };
    uint8_t *data;

    if(argc != 2) {
        return -1;
    }

    data = (uint8_t*)malloc(64);
    memset(data, '\x00', 64);

    fd = open(argv[1], O_RDONLY);
    read(fd, file_contents, 255);
      
    data = md5String( file_contents );

    if(memcmp(data, GOOD_HASH, 16) == 0) {
        printf("[+] Access granted. execute script. \n");
        system(argv[1]);
    } else {
        printf("[-] WTF?\n");
        return -1;
    }
}
