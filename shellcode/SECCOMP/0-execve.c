#include <unistd.h>
#include <linux/unistd.h> //get from kernel

/*
	Use execve syscall to run /bin/sh program. 
*/
int main()
{
	char *filename = "/bin/sh";
	char *argv[] = {"/bin/sh", NULL};
	char *envp[] = {NULL};
	write(1, "syscall(__NR_execve, '/bin/sh', 0, 0);\n", 39);
	syscall(__NR_execve, filename, argv, envp);
	// 	syscall(59, filename, argv, envp);    //execve
    return 0;
}