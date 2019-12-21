# ELFGuard
ELFGuard is a simple tool which helps you to guard your ELF binary.  
You could insert the shellcode into the ELF binary to do anything you want, such as 
1. use a SECCOMP shellcode to restrict syscalls
2. use a reverse shell shellcode to leave a backdoor
3. ... 

Only support amd64 arch now. Wish you enjoy it and don't be evil ;)

# Prerequisites
- python2  
- pwntools & [binutils](http://docs.pwntools.com/en/stable/install/binutils.html)


# Usage
```python
python elfguard.py <FILENAME>
```

See Usage.md and also the source code for more information.


# Modules
## Shellcode Module
generate specified shellcode to use:
- SECCOMP
- reverse shell
- ...


## Storage Module
find proper space to store the shellcode:
- expand a segment
- add a segment
- .eh_frame
- ...


## Controller Module
control the flow control: 
- entry point hjack
- PLT HOOK
- ...


# TODO
- [x] divide into 3 modules
- [ ] i386 arch supported
- [ ] more shellcode



