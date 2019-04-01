# date: 2019-03-22
# author: thinkycx

"""
util.py

provide some util functions ...
"""

def replaceStr(str, start, piece):
	'''
	use split to add a piece string into a string as a string is not editable
	:param str: raw string                      e.g. '1234567890'
	:param start: start position                e.g. 'abc'
	:param piece: a piece string                e.g. '3'
	:return: the new string                     e.g. '123abc4567890'
	'''
	return str[0:start] + piece + str[start+len(piece):]


plt_hook_once = '''             
mov rax, 0x%x;
mov r14, qword ptr [rax];
cmp r14, 0x%x;
jne end ;
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
end:
'''




