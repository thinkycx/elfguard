seccomp_shellcode = '''
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
'''

save_registers = '''
push rax
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push r12;
push r13;
push rbp
'''

restore_registers = '''
pop rbp
pop r13;
pop r12;
pop r9
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
pop rax
'''

def get_shellcode():
    return save_registers + seccomp_shellcode + restore_registers
