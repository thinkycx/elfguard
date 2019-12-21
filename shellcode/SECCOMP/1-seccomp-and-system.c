#include <stdio.h>
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>


/*
	Use SECCOMP to restrict syscall.
	Then the program will receive a SIGNAL and is goint to be killed.

	To include the header, you should run
		sudo apt install libseccomp-dev libseccomp2 seccomp
	Then, you will find *.h in/usr/include/
		seccomp.h
		./linux/seccomp.h
	gcc 1-seccomp-and-system.c -o 1-seccomp-and-system -lseccomp
*/

int main(void){
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
	seccomp_load(ctx);

	char * filename = "/bin/sh";
	char * argv[] = {"/bin/sh",NULL};
	char * envp[] = {NULL};

	syscall(__NR_execve, filename, argv, envp); //execve
	return 0;
}

