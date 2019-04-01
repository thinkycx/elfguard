#include <stdio.h>
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>

int main(void){
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
	seccomp_load(ctx);

	char * filename = "/bin/sh";
	char * argv[] = {"/bin/sh",NULL};
	char * envp[] = {NULL};
	syscall(59,filename,argv,envp);//execve
	return 0;
}

