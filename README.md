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
1. store shellcode in the .eh_frame_hdr and .eh_frame
```
pwndbg> telescope 0x401088+8
00:0000│   0x401090 (__GNU_EH_FRAME_HDR+8) ◂— mov    rax, 0x602050
01:0008│   0x401098 (__GNU_EH_FRAME_HDR+16) ◂— mov    esi, dword ptr [rax]
02:0010│   0x4010a0 (__GNU_EH_FRAME_HDR+24) ◂— add    byte ptr [rdi], cl
03:0018│   0x4010a8 (__GNU_EH_FRAME_HDR+32) ◂— push   rbp
04:0020│   0x4010b0 (__GNU_EH_FRAME_HDR+40) ◂— sub    esp, 0x100
05:0028│   0x4010b8 (__GNU_EH_FRAME_HDR+48) ◂— rol    byte ptr [rsi], 0
06:0030│   0x4010c0 (__GNU_EH_FRAME_HDR+56) ◂— 0x7fff000000000006
07:0038│   0x4010c8 (__GNU_EH_FRAME_HDR+64) ◂— push   rax
```

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

# demo
## method 1
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

## method2
```bash
[*] 
             __         ____                           __
       _____/ /_  ___  / / /___ ___  ______ __________/ /
      / ___/ __ \/ _ \/ / / __ `/ / / / __ `/ ___/ __  / 
     (__  ) / / /  __/ / / /_/ / /_/ / /_/ / /  / /_/ /  
    /____/_/ /_/\___/_/_/\__, /\__,_/\__,_/_/   \__,_/   
                        /____/            
    								[thinkycx@gmail.com]						
    	
[*] 	 find GNU_EH_FRAME @0x401088
[*] [1] start to copy shellcode
[*] ================copy shellcode================
[*] 	 shellcode base @ 0x401088 
[*] 	 malloc PLT @ 0x400700, GOT @ 0x602050
[*] 	 filename: ./samples/heapcreator-eh_frame.protected vaddr: 0x400700 disasmmbly:   400700:       ff 25 4a 19 20 00       jmp    DWORD PTR ds:0x20194a 
[*] 	           new PLT @ 0x401145 
[*] 	           PLT: 	 jmp [rip+0x200f05]
[*] 	 shellcode length: 0xc3
[*] [2] plt hook
[*] ================hook func@plt================
[*] 	 patching malloc@plt 0x400700...
[*] 	 shellcode load va : 0x401088
[*] 	 jmp shellcode : 	 jmp [rip+0x982]
[*] 	 relative_offset 0x982
[*] 	 filename: ./samples/heapcreator-eh_frame.protected vaddr: 0x400700 disasmmbly:   400700:       ff 25 4a 19 20 00       jmp    DWORD PTR ds:0x20194a 
[*] 	 filename: ./samples/heapcreator-eh_frame.protected vaddr: 0x400700 disasmmbly:   400700:       ff 25 82 09 00 00       jmp    DWORD PTR ds:0x982 
[*] =======================enjoy=======================
[*] Protected file is ./samples/heapcreator-eh_frame.protected
```


