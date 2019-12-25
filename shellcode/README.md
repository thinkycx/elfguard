## how to debug shellcode
```bash
gdb ./samples/heapcreator-protected.out --ex "set follow-fork-mode parent" --ex "start" --ex "break *0x4034b0" --ex "c"
```

## Tree
```    
SECCOMP/
    0-execve.c                  use execve syscall to getshell
    1-seccomp-and-system.c      use seccomp to restrict execve syscall 
    2-my_protect-and-system.c   put seccomp in my_protect function , ref: linux man 
    3-prctl-bpf-and-system.c    export seccomp to bpf and use two prctl syscall to implement it.
    4-1-asm-seccomp-intel.s     use prctl syscall written in assembly to restict execve syscall
    4-2-asm-seccomp-AT&T.s      AT&T assembly, call it in .c 
    4-3-prctl-asm-and-system.c  check the prctl shellcode 
    scmp_filter_ctx.bpf         binary bpf, use `cat scmp_filter_ctx.bpf | xxd` to see it 
    seccomp.py                  a shellcode wrapper for elfguard to call

reverseshell/
    fork-fork-reverseshell.c    shellcode in c
    fork-fork-reverseshell.s    shellcode in asm
    forkfork_reverseshell.py    a shellcode wrapper for elfguard to call
```