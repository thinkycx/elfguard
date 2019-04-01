# PURPOSE: seccomp program that filter execve syscall with prctl syscall
# aufhor: thinkycx
# date: 2019-03-19
#
# Usage:
#    as asm-seccomp.s -o asm-seccomp.o
#    ld asm-seccomp.o -o asm-seccomp

.section .text
.globl _start
_start:
  push     %r13
  push     %r12
  push     %rbp
  mov      %rsp, %rbp
  sub      $0x100, %rsp
  mov      $0x6, %rax
  push     %rax
  mov      $0x7fff000000000006, %rax
  push     %rax
  mov      $0x3b00010015, %rax
  push     %rax
  mov      $0x4000000000020035, %rax
  push     %rax
  mov      $0x20, %rax
  push     %rax
  mov      $0xc000003e04000015, %rax
  push     %rax
  mov      $0x400000020, %rax
  push     %rax
  mov      %rsp, %r12
  push     %r12
  push     $0x7
  mov      %rsp, %r13

  mov      $0x0, %r8
  mov      $0x0, %ecx
  mov      $0x0, %edx
  mov      $0x1, %esi
  mov      $0x26, %edi
  mov      $0x9d, %eax
  syscall

  mov      %r13, %rdx
  mov      $0x2, %esi
  mov      $0x16, %edi
  mov      $0x9d, %eax
  syscall

  mov      %rbp, %rsp
  pop      %rbp
  pop      %r12
  pop      %r13

getshell:
  xor %rax, %rax
  mov    %rax, %rsi
  mov    %rax, %rdx
  push %rax
  mov    $0x68732f2f6e69622f, %rax
  push   %rax
  mov    %rsp, %rdi
  mov    $59, %rax
  syscall
