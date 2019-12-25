# ELFGuard
ELFGuard is a simple tool which helps you to guard your ELF binary.  
You could insert the shellcode into the ELF binary to do anything you want, such as 

1. use a SECCOMP shellcode to restrict syscalls
2. use a reverse shell shellcode to leave a backdoor
3. ... 

Only support amd64 arch now. Wish you enjoy it and don't be evil ;)

![menu](docs/image-1.png)

# Prerequisites
- python2  
- pwntools & [binutils](http://docs.pwntools.com/en/stable/install/binutils.html)


# Usage
```python
python elfguard.py -f /bin/bash
```

# Modules
## Storage Module
Find proper space to store the shellcode and return the file's offset to write shellcode.
- expand a segment
- add a segment
- .eh_frame
- ...


## Shellcode Module
Generate specified shellcode to use:
- SECCOMP
- reverse shell
- ...

## Controller Module
control the flow control: 
- entry point hjack
- PLT HOOK
- ...

# how to debug shellcode
```bash
gdb ./samples/heapcreator-protected.out --ex "set follow-fork-mode parent" --ex "start" --ex "break *0x4034b0" --ex "c"
```

# Tree
```
samples/
    exp.py                      exploit for heapcreator
    heapcreator                 the vulnerable program
    heapcreator-expanded.out        segment expanded
    heapcreator-protected.out       output of elfguard
    
SECCOMP/
    0-execve.c                  use execve syscall to getshell
    1-seccomp-and-system.c      use seccomp to restrict execve syscall 
    2-my_protect-and-system.c   put seccomp in my_protect function , ref: linux man 
    3-prctl-bpf-and-system.c    export seccomp to bpf and use two prctl syscall to implement it.
    4-1-asm-seccomp-intel.s     use prctl syscall written in assembly to restict execve syscall
    4-2-asm-seccomp-AT&T.s      AT&T assembly, call it in .c 
    4-3-prctl-asm-and-system.c  check the prctl shellcode 
    scmp_filter_ctx.bpf         binary bpf, use `cat scmp_filter_ctx.bpf | xxd` to see it 

```

# TODO
- [ ] i386 arch supported
- [ ] more shellcode