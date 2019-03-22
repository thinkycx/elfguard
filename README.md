# SHELLGUARD
This is a simple tool which helps you protect your ELF binary.


# Usage
```python
python main.py <FILENAME>
```

# What does it do?
1. add a segment to store shellcode in ELF binary
2. copy a seccomp shellcode to the segment
2. hook a plt and jump to your shellcode


# output
1. function addSegment
```bash
[*] ================start to add segment================
[*] './shellguard/samples/heapcreator'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
[*] stage1: copy Program header table to the end...
[*] stage2: add new PT_LOAD phdr entry
[*] 	 find PT_PHDR, going to fix it...
[*] 	 find first PT_LOAD, going to add a new PT_LOAD...
```
debug the samples/heapcreator.stage2
```bash
$ chmod u+x ./heapcreator.stage2
$ gdb ./heapcreator.stage2
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x400000           0x402000 r-xp     2000 0      /root/Pwn/heapcreator.stage2
          0x403000           0x404000 rwxp     1000 3000   /root/Pwn/heapcreator.stage2
          0x601000           0x603000 rw-p     2000 1000   /root/Pwn/heapcreator.stage2
```
