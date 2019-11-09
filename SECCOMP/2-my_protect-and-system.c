#include <unistd.h>
#include <linux/unistd.h> //get from kernel
#include <seccomp.h> //include typedef of scmp_filter_ctx  seccomp_init ...
#include <errno.h>


/*
	Put the SECCOMP function into my_protect() function.
	Also the program will receive a SIGNAL and is goint to be killed.

    gcc 2-my_protect-and-system.c -lseccomp -o 2-my_protect-and-system
  
*/

int my_protect()
{
    int rc = 0;
    scmp_filter_ctx ctx = NULL;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if(ctx == NULL)
        return ENOMEM;
    rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    if(rc < 0)
        goto out;
    seccomp_load(ctx);
out:    
    seccomp_release(ctx);
    return (rc < 0 ? -rc : rc); 
}

int main()
{
	char *filename = "/bin/sh";
	char *argv[] = {"/bin/sh", NULL};
	char *envp[] = {NULL};

    my_protect();

	syscall(__NR_execve, filename, argv, envp);
    return 0;
}

