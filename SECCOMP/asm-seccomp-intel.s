push r13
push r12
push rbp
mov rbp, rsp
sub rsp, 0x100
mov rax,0x0000000000000006
push rax
mov rax,0x7fff000000000006
push rax
mov rax,0x0000003b00010015
push rax
mov rax,0x4000000000020035
push rax
mov rax,0x0000000000000020
push rax
mov rax,0xc000003e04000015
push rax
mov rax,0x0000000400000020
push rax
mov r12, rsp
push r12
push 0x7
mov r13, rsp
; (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
mov r8, 0
mov ecx, 0
mov edx, 0
mov esi, 1
mov edi, 0x26
mov eax, 157
syscall
;prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog)
mov rdx, r13
mov esi, 2
mov edi, 0x16
mov eax, 157
syscall
; return
mov rsp, rbp
pop rbp
pop r12
pop r13
ret

