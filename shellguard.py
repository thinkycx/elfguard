# date: 2019-03-19
# author: thinkycx


import shutil
from pwn import *
import os
import sys
import util


context.log_level = 'info'


def showMenu(usage):
	menu = '''
         __         ____                           __
   _____/ /_  ___  / / /___ ___  ______ __________/ /
  / ___/ __ \/ _ \/ / / __ `/ / / / __ `/ ___/ __  / 
 (__  ) / / /  __/ / / /_/ / /_/ / /_/ / /  / /_/ /  
/____/_/ /_/\___/_/_/\__, /\__,_/\__,_/_/   \__,_/   
                    /____/            
								[thinkycx@gmail.com]						
	'''
	menu_usage = 'Usage:  python shellguard.py <FILENAME>'
	if usage == 1:
		menu += menu_usage

	log.info(menu)


def addSegment(elf):
	"""
	add a PT_LOAD segment in ELF x86_64 which stores the PHDR and maybe shellcode in future
	:return: new filename, writtable address
	"""

	log.info("="*0x10 + "start to add segment" + "="*0x10)

	# get e_phoff e_phnum e_phentsize from ELF header
	with open(elf.path, 'rb+') as fd:
		filesize = os.path.getsize(filename)
		log.debug("file size %s" % hex(filesize))
		e_phoff = elf.header.e_phoff                # Elf64_Ehdr->e_phoff       /* Program header table file offset */
		e_phnum = elf.header.e_phnum                # Elf64_Ehdr->e_phnum       /* Program header table entry count */
		e_phentsize = elf.header.e_phentsize        # Elf64_Ehdr0>e_phentsize   /* Program header table entry size */
		log.debug("e_phoff: " + hex(e_phoff) + " e_phnum: " + hex(e_phnum) + " e_phentsize: " + hex(e_phentsize))

	# copy filename to filename.stage1
	log.info("stage1: copy Program header table to the end...")
	filename_stage1 = elf.path + '.stage1'
	shutil.copyfile(elf.path, filename_stage1)

	# append program header table to the end and fix Elf64_Ehdr->e_phoff and
	with open(filename_stage1, 'rb+') as fd:
		fd.seek(e_phoff, 0)                        # mov fd to Elf64_Ehdr->e_phoff
		phdr_table = fd.read(e_phnum*e_phentsize)  # read program header table value

		fd.seek(0x20, 0)                           # mov fd to Elf64_Ehdr->e_phoff
		raw_filesize = filesize
		fd.write(p64(raw_filesize))                # change Elf64_Ehdr->e_phoff to filesize
		filesize += e_phnum*e_phentsize            # update now filesize

		fd.seek(0, 2)                              # mov fd to file end
		fd.write(phdr_table)                       # append program header table to the end

	# copy filename to filename.expanded
	log.info("stage2: add new PT_LOAD phdr entry")
	filename_expanded = elf.path + '.expanded'
	shutil.copyfile(filename_stage1, filename_expanded)

	# fix new Program Header Table and add new PT_LOAD to load it
	with open(filename_expanded, 'rb+') as fd:
		fd.seek(raw_filesize)
		phdr = [phdr_table[i*e_phentsize:i*e_phentsize+e_phentsize] for i in range(e_phnum)]    # get phdr list
		log.debug(b"raw phdr: " + b''.join(phdr))

		for i in range(len(phdr)):
			# fix the new Program Header Table
			if u32(phdr[i][0:4]) == 0x6:
				log.info("\t find PT_PHDR, going to fix it...")
				tmp = phdr[i]
				tmp = util.replaceStr(tmp, 0x8, p64(raw_filesize))                           # p_offset
				tmp = util.replaceStr(tmp, 0x10, p64(0x400000 + raw_filesize))               # p_pvaddr
				tmp = util.replaceStr(tmp, 0x18, p64(0x400000 + raw_filesize))               # p_paddr
				tmp = util.replaceStr(tmp, 0x20, p64(len(phdr_table) + e_phentsize))         # p_filesz
				tmp = util.replaceStr(tmp, 0x28, p64(len(phdr_table) + e_phentsize))         # p_memsz
				phdr[i] = tmp

			# add new PT_LOAD to load new Program Header Table and maybe shellcode in future
			if u32(phdr[i][0:4]) == 0x1:
				log.info("\t find first PT_LOAD, going to add a new PT_LOAD...")
				new_phdr = phdr[i]
				new_phdr = util.replaceStr(new_phdr, 0x4, p32(0x7))                                      # p_flags 7
				new_phdr = util.replaceStr(new_phdr, 0x8, p64(raw_filesize))                             # p_offset
				new_phdr = util.replaceStr(new_phdr, 0x10, p64(0x400000 + raw_filesize))                 # p_pvaddr
				new_phdr = util.replaceStr(new_phdr, 0x18, p64(0x400000 + raw_filesize))                 # p_paddr
				new_phdr = util.replaceStr(new_phdr, 0x20, p64(len(phdr_table) + e_phentsize + 0xc3))           # p_filesz
				segAlign = (len(phdr_table) + e_phentsize) % 0x10
				new_phdr = util.replaceStr(new_phdr, 0x28, p64(len(phdr_table) + e_phentsize + segAlign + 0xc3))# p_memsz
				phdr.insert(i+1, new_phdr)
				break

		new_phdr_table = b''.join(phdr)
		log.debug("Now Elf64_Ehdr->e_phnum :" + str(len(phdr)))
		log.debug(new_phdr_table)

		# save new_phdr_table to filename.expanded
		fd.write(new_phdr_table)

		# shellcode can be write in the end
		return (filename_expanded, os.path.getsize(filename_expanded))


def copyShellcode(elf, func_name):
	"""
	generate shellcode : check_once + seccomp + jmp GOT
	and copy it into filename end
	:param elf:
	:param func_name:
	:return:
	"""
	log.info("="*0x10 + "start to copy shellcode" + "="*0x10)

	func_plt_addr = elf.plt[func_name]
	func_got_addr = elf.got[func_name]
	filename = elf.path

	log.info("\t GOT address: 0x%x" % func_got_addr)
	log.info("\t plt address: 0x%x" % func_plt_addr)

	with open(filename, 'rb+') as fd:
		fd.seek(func_plt_addr & 0xfffff, 0)                                # get file
		plt_first_asm = fd.read(6)
		plt_disasm = disasm(plt_first_asm, arch='amd64', os='linux')
		log.info("\t disasm: " + plt_disasm)

		# get GOT from plt disasm
		# jmp_offset = u64(plt_first_asm[2:].ljust(8, '\x00'))
		# log.info("\t jmp offset: 0x%x" % jmp_offset)
		# func_got_addr = func_plt_addr + jmp_offset + 6

		# check_once
		plt_hook_once = util.plt_hook_once % (func_got_addr, func_plt_addr+6)
		shellcode_part1 = plt_hook_once + util.shellcode_seccomp
		shellcode_part1_asm = asm(shellcode_part1.replace('\n', ''), arch='amd64')

		shellcode_va = elf.load_addr + elf.header.e_phoff + elf.header.e_phentsize * elf.header.e_phnum + 0x40
		now_vaddr = shellcode_va + len(shellcode_part1_asm)
		log.info("\t shellcode start virtual address 0x%x " % shellcode_va)
		log.info("\t shellcode new jmp GOT virtual address 0x%x " % now_vaddr)

		jmp_got_relative_offset = elf.got[func_name] - (now_vaddr + 6)
		raw_jmp_got = '\t jmp [rip+0x%x]' % (jmp_got_relative_offset)
		raw_jmp_got_asm = asm(raw_jmp_got, arch='amd64')

		shellcode = p64(shellcode_va) + shellcode_part1_asm + raw_jmp_got_asm

		fd.seek(0, 2)
		fd.write(shellcode)
		log.info('\t shellcode length 0x%x' % len(shellcode))

		# todo fix phdr PT_LOAD 2


def pltHook(elf, func_name):
	"""
	hook an elf file func_name@plt first 6 bytes to jmp 0x:shellcode_addr
	:param elf:
	:param func_name:
	:param shellcode_addr:
	:return:
	"""
	log.info("="*0x10 + 'start to hook func@plt' + "="*0x10)

	func_plt_addr = elf.plt[func_name]
	log.info("\t patching %s@plt 0x%x..." % (func_name, func_plt_addr))

	shellcode_va = elf.load_addr + elf.header.e_phoff + elf.header.e_phentsize * elf.header.e_phnum + 0x40
	relative_offset = shellcode_va - (func_plt_addr + 6) - 8
	jmp_shellcode = '\t jmp [rip+0x%x]' % relative_offset
	jmp_shellcode_asm = asm(jmp_shellcode, vma=func_plt_addr, arch='amd64', os='linux')
	log.info("\t shellcode load va : 0x%x" % shellcode_va)
	log.info("\t jmp shellcode  : %s" % jmp_shellcode)

	log.info("\t relative_offset 0x%x" % relative_offset)

	with open(elf.path, 'rb+') as fd:
		fd.seek(func_plt_addr & 0xfffff, 0)                     #
		plt_first_asm = fd.read(6)
		plt_disasm = disasm(plt_first_asm, vma=func_plt_addr, arch='amd64', os='linux')
		log.info("\t disasm: " + plt_disasm)

		log.info("\t patch...")
		fd.seek(func_plt_addr & 0xfffff, 0)
		fd.write(jmp_shellcode_asm)
		fd.seek(func_plt_addr & 0xfffff, 0)
		plt_first_asm = fd.read(6)
		plt_disasm = disasm(plt_first_asm, vma=func_plt_addr, arch='amd64', os='linux')
		log.info("\t disasm: " + plt_disasm)


if __name__ == '__main__':
	# show menu
	debug = 1
	if len(sys.argv) < 2:
		showMenu(usage=1)
		os._exit(0)
	else:
		showMenu(usage=0)

	# get filename
	filename = sys.argv[1]
	log.debug("filename: %s" % filename)
	if not os.path.exists(filename):
		os._exit(-1)

	# 1. add a segment
	elf = ELF(filename, checksec=False)
	filename, file_offset = addSegment(elf)

	# 2 copy shellcode
	filename_stage3 = sys.argv[1] + '.protected'
	shutil.copyfile(filename, filename_stage3)
	elf = ELF(filename_stage3, checksec=False)

	func_name = [i for i in elf.plt][0]
	copyShellcode(elf, func_name)

	# 3 last plt hook . If plt is not the last, elf cannot find elf.plt[func_name]
	pltHook(elf, func_name)

	log.info("="*0x17 + 'enjoy' + "="*0x17)

	if debug != 1:
		os.system('rm '+sys.argv[1]+'.stage1')
		os.system('rm '+sys.argv[1]+'.expanded')
	log.info("Protected file is %s" % filename_stage3)
