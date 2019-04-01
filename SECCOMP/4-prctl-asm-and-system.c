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
    rc = seccomp_export_bpf(ctx, fd);
    if(rc<0){
        close(fd);
        goto out;
    }
    // seccomp_load(ctx);
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
    read(fd, filter, size);
    struct sock_fprog prog = {
        .len = (unsigned short) (size / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl");
        return -1;
    }
    prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
}

int shellcode()
{
    __asm__ __volatile__ (
  "  push     %%r13\n"
  "  push     %%r12\n"
  // "  push     %%rbp\n"
  // "  mov      %%rsp, %%rbp\n"
  "  sub      $0x100, %%rsp\n"
  "  mov      $0x6, %%rax\n"
  "  push     %%rax\n"
  "  mov      $0x7fff000000000006, %%rax\n"
  "  push     %%rax\n"
  "  mov      $0x3b00010015, %%rax\n"
  "  push     %%rax\n"
  "  mov      $0x4000000000020035, %%rax\n"
  "  push     %%rax\n"
  "  mov      $0x20, %%rax\n"
  "  push     %%rax\n"
  "  mov      $0xc000003e04000015, %%rax\n"
  "  push     %%rax\n"
  "  mov      $0x400000020, %%rax\n"
  "  push     %%rax\n"
  "  mov      %%rsp, %%r12\n"
  "  push     %%r12\n"
  "  push     $0x7\n"
  "  mov      %%rsp, %%r13\n"

  "  mov      $0x0, %%r8\n"
  "  mov      $0x0, %%ecx\n"
  "  mov      $0x0, %%edx\n"
  "  mov      $0x1, %%esi\n"
  "  mov      $0x26, %%edi\n"
  "  mov      $0x9d, %%eax\n"
  "  syscall\n"

  "  mov      %%r13, %%rdx\n"
  "  mov      $0x2, %%esi\n"
  "  mov      $0x16, %%edi\n"
  "  mov      $0x9d, %%eax\n"
  "  syscall\n"

  "  pop      %%r12\n"
  "  pop      %%r13\n"
  "  pop      %%rbx\n"
  "  mov      %%rbp, %%rsp\n"
  "  pop      %%rbp\n"
  "  ret\n"

  :
  :
  :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
);
   
       
}

int main()
{
	char *filename = "/bin/sh";
	char *argv[] = {"/bin/sh", NULL};
	char *envp[] = {NULL};
    //my_protect_prctl();
    //shellcode();
    __asm__ __volatile__ (
  "  push     %%r13\n"
  "  push     %%r12\n"
  "  push     %%rbp\n"
  "  mov      %%rsp, %%rbp\n"
  "  sub      $0x100, %%rsp\n"
  "  mov      $0x6, %%rax\n"
  "  push     %%rax\n"
  "  mov      $0x7fff000000000006, %%rax\n"
  "  push     %%rax\n"
  "  mov      $0x3b00010015, %%rax\n"
  "  push     %%rax\n"
  "  mov      $0x4000000000020035, %%rax\n"
  "  push     %%rax\n"
  "  mov      $0x20, %%rax\n"
  "  push     %%rax\n"
  "  mov      $0xc000003e04000015, %%rax\n"
  "  push     %%rax\n"
  "  mov      $0x400000020, %%rax\n"
  "  push     %%rax\n"
  "  mov      %%rsp, %%r12\n"
  "  push     %%r12\n"
  "  push     $0x7\n"
  "  mov      %%rsp, %%r13\n"
  
  "  mov      $0x0, %%r8\n"
  "  mov      $0x0, %%ecx\n"
  "  mov      $0x0, %%edx\n"
  "  mov      $0x1, %%esi\n"
  "  mov      $0x26, %%edi\n"
  "  mov      $0x9d, %%eax\n"
  "  syscall\n"
  
  "  mov      %%r13, %%rdx\n"
  "  mov      $0x2, %%esi\n"
  "  mov      $0x16, %%edi\n"
  "  mov      $0x9d, %%eax\n"
  "  syscall\n"
  
  "  mov      %%rbp, %%rsp\n"
  "  pop      %%rbp\n"
  "  pop      %%r12\n"
  "  pop      %%r13\n"
  //"  ret\n"
  
  
  
  
  :
  :
  :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
);
    
    syscall(__NR_execve, filename, argv, envp);
    return 0;
}
