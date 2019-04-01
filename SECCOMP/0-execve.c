#include <unistd.h>

int main(void){
	char *filename = "/bin/sh";
	char *argv[] = {"/bin/sh", NULL};
	char *envp[] = {NULL};
	write(1, "execve syscall:\n", 16);
	syscall(59, filename, argv, envp);    //execve
	return 0;
}
