# SHELLGUARD
This is a simple tool which helps you protect your ELF binary.


# Prerequisites
- python  
- pwntools & [binutils](http://docs.pwntools.com/en/stable/install/binutils.html)

# Usage
```python
python shellguard.py <FILENAME>
```

# What does it do?
method1:
1. add a segment to store shellcode in ELF binary
2. copy a seccomp shellcode to the segment
3. hook a plt and jump to your shellcode

method2:
1. store shellcode in the .eh_phem


# Tree
```
samples/
    exp.py                      exploit for heapcreator
    heapcreator                 the vulnerable program
    heapcreator.expanded        segment expanded
    heapcreator.protected       output of shellguard
    start.sh                    give it permissions to run
    
SECCOMP/

	0-execve.c                  use execve syscall to getshell
	0-execve-NR.c               get syscall number from <linux/unistd.h>
	1-seccomp-and-system.c      use seccomp to restrict execve syscall 
	2-my_protect-and-system.c   put seccomp in my_protect function , ref: linux man 
	3-prctl-bpf-and-system.c    export seccomp to bpf and use two prctl syscall to implement it.
	
	asm-seccomp-intel.s         use prctl syscall written in assembly to restict execve syscall
	asm-seccomp-AT&T.s          AT&T assembly, call it in .c 
	scmp_filter_ctx.bpf         binary bpf, use `cat scmp_filter_ctx.bpf | xxd` to see it 
	
	4-prctl-asm-and-system.c    check the prctl shellcode 

```


# output

- function addSegment  
debug the samples/heapcreator.expanded
```bash
$ chmod u+x ./heapcreator.expanded
$ gdb ./heapcreator.expanded
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x400000           0x402000 r-xp     2000 0      /root/Pwn/heapcreator.expanded
          0x403000           0x404000 rwxp     1000 3000   /root/Pwn/heapcreator.expanded
          0x601000           0x603000 rw-p     2000 1000   /root/Pwn/heapcreator.expanded
```

- function copyShellcode    
    Copy shellcode to the end of the file.  
- function pltHook  
    Hook one function's plt to jump to the shellcode.

demo:
```bash
[*] 
             __         ____                           __
       _____/ /_  ___  / / /___ ___  ______ __________/ /
      / ___/ __ \/ _ \/ / / __ `/ / / / __ `/ ___/ __  / 
     (__  ) / / /  __/ / / /_/ / /_/ / /_/ / /  / /_/ /  
    /____/_/ /_/\___/_/_/\__, /\__,_/\__,_/_/   \__,_/   
                        /____/            
    								[thinkycx@gmail.com]						
    	
[*] ================add segment================
[*] [1] copy Program header table to the end...
[*] [2] add new PT_LOAD phdr entry
[*] 	 find PT_PHDR, going to fix it...
[*] 	 find first PT_LOAD, going to add a new PT_LOAD...
[*] 	 len(phdr_table) + e_phentsize : 230
[*] 	 output filename: ./samples/heapcreator.expanded 
[*] ================copy shellcode================
[*] 	 shellcode base @ 0x403718 
[*] 	 malloc PLT @ 0x400700, GOT @ 0x602050
[*] 	 filename: ./samples/heapcreator.protected vaddr: 0x400700 disasmmbly:   400700:       ff 25 4a 19 20 00       jmp    DWORD PTR ds:0x20194a 
[*] 	           new PLT @ 0x4037d5 
[*] 	           PLT: 	 jmp [rip+0x1fe875]
[*] 	 shellcode length: 0xc3
[*] ================hook func@plt================
[*] 	 patching malloc@plt 0x400700...
[*] 	 shellcode load va : 0x403718
[*] 	 jmp shellcode : 	 jmp [rip+0x3012]
[*] 	 relative_offset 0x3012
[*] 	 filename: ./samples/heapcreator.protected vaddr: 0x400700 disasmmbly:   400700:       ff 25 4a 19 20 00       jmp    DWORD PTR ds:0x20194a 
[*] 	 filename: ./samples/heapcreator.protected vaddr: 0x400700 disasmmbly:   400700:       ff 25 12 30 00 00       jmp    DWORD PTR ds:0x3012 
[*] =======================enjoy=======================
[*] Protected file is ./samples/heapcreator.protected
```




