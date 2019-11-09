#include <unistd.h>
#include <linux/unistd.h> //get from kernel
#include <seccomp.h> //include typedef of scmp_filter_ctx  seccomp_init ...
#include <errno.h>
#include <fcntl.h> // open
#include <linux/filter.h>
#include <stdio.h>
#include <sys/stat.h>
#include <linux/seccomp.h>
#include <stdlib.h>
#include <sys/prctl.h>


/*
    1. Write the SECCOMP rules into the .bpf file.
    2. Use prctl to load the .bpf into the kernel.

    gcc 3-prctl-bpf-and-system.c -lseccomp -o 3-prctl-bpf-and-system
*/

#define BPF_FILE "/tmp/scmp_filter_ctx.bpf"

int my_protect_seccomp()
{
    int rc = 0;
    scmp_filter_ctx ctx = NULL;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if(ctx == NULL)
        return ENOMEM;
    rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    if(rc < 0)
        goto out;

    int fd = open(BPF_FILE, O_CREAT | O_WRONLY);          
    if(fd == -1){
        rc = -1;
        goto out;
    }
    rc = seccomp_export_bpf(ctx, fd);               // write SECCOMP rules into a file.
    if(rc<0){
        close(fd);
        goto out;
    }
    // seccomp_load(ctx);                           // don't load it
out:    
    seccomp_release(ctx);
    return (rc < 0 ? -rc : rc); 
}

int my_protect_prctl()
{
    struct sock_filter *filter;
    int fd;
    fd = open(BPF_FILE, O_RDONLY);
    if(fd < 0){
        write(1, "read failed\n", 12);
        return -1;
    }
    struct stat st;
    stat(BPF_FILE, &st);
    int size = st.st_size;
    if(size <= 0){
        printf("size <= 0\n ");
        return -1;
    }
    
    printf("size is %d" , size);
    filter = malloc(size);
    read(fd, filter, size);                             // write the SECCOMP rules into struct sock_filter
    struct sock_fprog prog = {                          // initial the struct sock_fprog
        .len = (unsigned short) (size / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {       // call prctl
        perror("prctl");
        return -1;
    }
    prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);    // call prctl  
}

int main()
{
	char *filename = "/bin/sh";
	char *argv[] = {"/bin/sh", NULL};
	char *envp[] = {NULL};
    my_protect_prctl();

    syscall(__NR_execve, filename, argv, envp);
    return 0;
}

