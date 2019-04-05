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


def addSegment(filename):
	"""
	add a PT_LOAD segment entry in filename's PHDR
	the segment will load the new PHDR and shellcode in future
	:param filename:
	:return:
	"""

	log.info("="*0x10 + "add segment" + "="*0x10)

	# get e_phoff e_phnum e_phentsize from ELF header
	elf = ELF(filename, checksec=False)
	raw_filesize = os.path.getsize(filename)
	e_phoff = elf.header.e_phoff                # Elf64_Ehdr->e_phoff       /* Program header table file offset */
	e_phnum = elf.header.e_phnum                # Elf64_Ehdr->e_phnum       /* Program header table entry count */
	e_phentsize = elf.header.e_phentsize        # Elf64_Ehdr0>e_phentsize   /* Program header table entry size */
	log.debug("raw filesize %s" % hex(raw_filesize))
	log.debug("e_phoff: " + hex(e_phoff) + " e_phnum: " + hex(e_phnum) + " e_phentsize: " + hex(e_phentsize))

	with open(filename, 'rb+') as fd:
		# append program header table to the end and fix Elf64_Ehdr->e_phoff
		log.info("[1] copy Program header table to the end...")

		# fix ELF header first
		# fix e_phoff to raw file size
		fd.seek(0x20, 0)                           # mov fd to Elf64_Ehdr->e_phoff
		fd.write(p64(raw_filesize))                # change Elf64_Ehdr->e_phoff to filesize

		# fix e_phnum to e_phnum + 1
		fd.seek(0x38, 0)
		fd.write(p16(e_phnum+1))
		now_filesize = raw_filesize + e_phnum*e_phentsize        # update now filesize

		# write phdr table to the end
		# read phdr table
		fd.seek(e_phoff, 0)                        # mov fd to Elf64_Ehdr->e_phoff
		phdr_table = fd.read(e_phnum*e_phentsize)  # read program header table value

		# write new phdr table
		fd.seek(0, 2)                              # mov fd to file end
		fd.write(phdr_table)                       # append program header table to the end

		# fix new Program Header Table and add new PT_LOAD to load it
		log.info("[2] add new PT_LOAD phdr entry")
		fd.seek(raw_filesize)
		phdr = [phdr_table[i*e_phentsize:i*e_phentsize+e_phentsize] for i in range(e_phnum)]    # get phdr list
		log.debug(b"raw phdr: " + b''.join(phdr))

		for i in range(len(phdr)):
			# fix the new Program Header Table
			if u32(phdr[i][0:4]) == 0x6:
				log.info("\t find PT_PHDR, going to fix it...")
				tmp = phdr[i]
				tmp = util.replaceStr(tmp, 0x08, p64(raw_filesize))                          # p_offset
				tmp = util.replaceStr(tmp, 0x10, p64(0x400000 + raw_filesize))               # p_pvaddr
				tmp = util.replaceStr(tmp, 0x18, p64(0x400000 + raw_filesize))               # p_paddr
				tmp = util.replaceStr(tmp, 0x20, p64(e_phnum*e_phentsize + e_phentsize))     # p_filesz
				tmp = util.replaceStr(tmp, 0x28, p64(e_phnum*e_phentsize + e_phentsize))     # p_memsz
				phdr[i] = tmp

			# add new PT_LOAD to load new Program Header Table and maybe shellcode in future
			# todo IDA cannot load it and pwntools command: got  is also failed
			segAlign = (len(phdr_table) + e_phentsize) % 0x10
			if u32(phdr[i][0:4]) == 0x1:
				log.info("\t find first PT_LOAD, going to add a new PT_LOAD...")
				log.info("\t len(phdr_table) + e_phentsize : %x", len(phdr_table) + e_phentsize);
				new_phdr = phdr[i]
				new_phdr = util.replaceStr(new_phdr, 0x4, p32(0x5))                                      # p_flags 7
				new_phdr = util.replaceStr(new_phdr, 0x8, p64(raw_filesize))                             # p_offset
				new_phdr = util.replaceStr(new_phdr, 0x10, p64(0x400000 + raw_filesize))                 # p_pvaddr
				new_phdr = util.replaceStr(new_phdr, 0x18, p64(0x400000 + raw_filesize))                 # p_paddr
				new_phdr = util.replaceStr(new_phdr, 0x20, p64(len(phdr_table) + e_phentsize + 0xc3))    # p_filesz
				new_phdr = util.replaceStr(new_phdr, 0x28, p64(len(phdr_table) + e_phentsize + 0xc3))# p_memsz
				phdr.insert(i+1, new_phdr)
				break

		new_phdr_table = b''.join(phdr)
		log.debug("Now Elf64_Ehdr->e_phnum :" + str(len(phdr)))
		log.debug(new_phdr_table)

		# save new_phdr_table to filename.expanded
		fd.write(new_phdr_table)


def copyShellcode(elf, func_name, shellcode_vaddr):
	"""
	generate shellcode : contidion + seccomp + func_plt0(changable, related to vaddr & GOT)
	copy the vaddr
	:param elf:
	:param func_name:
	:return:
	"""
	log.info("="*0x10 + "copy shellcode" + "="*0x10)
	log.info("\t shellcode base @ 0x%x " % shellcode_vaddr)

	filename = elf.file.name
	func_plt_addr = elf.plt[func_name]
	func_got_addr = elf.got[func_name]
	shellcode_offset = elf.vaddr_to_offset(shellcode_vaddr)

	log.info("\t %s PLT @ 0x%x, GOT @ 0x%x" % (func_name, func_plt_addr, func_got_addr))
	util.showDisasm(filename, func_plt_addr, 6)

	# 1 asm(plt_hook_condition + seccomp)
	shellcode = util.plt_hook_condition % (func_got_addr, func_plt_addr + 6)   # check GOT ?= plt+6
	shellcode += util.shellcode_seccomp
	shellcode_asm = asm(shellcode.replace('\n', ''), arch='amd64')

	# 2 new_plt
	new_plt_vaddr = shellcode_vaddr + 8 + len(shellcode_asm)                   # shellcode_vaddr + shellcode
	new_plt_got_offset = elf.got[func_name] - (new_plt_vaddr + 6)
	new_plt = '\t jmp [rip+0x%x]' % (new_plt_got_offset)
	new_plt_asm = asm(new_plt, arch='amd64')
	log.info("\t           new PLT @ 0x%x " % new_plt_vaddr)
	log.info("\t           PLT: %s", new_plt)

	#                   address + (condition + seccomp) + new_plt
	shellcode = p64(shellcode_vaddr+8) + shellcode_asm + new_plt_asm
	log.info("\t shellcode length: 0x%x" % len(shellcode))

	# write shellcode at the end of the file
	with open(filename, 'rb+') as fd:
		fd.seek(shellcode_offset, 0)
		fd.write(shellcode)
	# todo fix phdr PT_LOAD 2


def pltHook(elf, func_name, addr_addr):
	"""
	hook an elf file func_name@plt first 6 bytes to jmp 0x:shellcode_addr
	:param elf:
	:param func_name:
	:param shellcode_addr:
	:return:
	"""
	log.info("="*0x10 + 'hook func@plt' + "="*0x10)

	filename = elf.file.name
	func_plt_addr = elf.plt[func_name]
	func_plt_offset = elf.vaddr_to_offset(func_plt_addr)

	log.info("\t patching %s@plt 0x%x..." % (func_name, func_plt_addr))

	relative_offset = addr_addr - (func_plt_addr + 6)
	jmp_shellcode = '\t jmp [rip+0x%x]' % relative_offset
	jmp_shellcode_asm = asm(jmp_shellcode, vma=func_plt_addr, arch='amd64', os='linux')
	log.info("\t shellcode load va : 0x%x" % addr_addr)
	log.info("\t jmp shellcode : %s" % jmp_shellcode)
	log.info("\t relative_offset 0x%x" % relative_offset)

	util.showDisasm(filename, func_plt_addr, 6)
	# patch
	with open(filename, 'rb+') as fd:
		fd.seek(func_plt_offset, 0)
		fd.write(jmp_shellcode_asm)
	util.showDisasm(filename, func_plt_addr, 6)


def method1(filename):
	# 1. add a segment
	expanded_filename = filename + '.expanded'
	shutil.copyfile(filename, expanded_filename)

	addSegment(expanded_filename)
	log.info("\t output filename: %s " % expanded_filename)

	# 2 copy shellcode
	filename_protected = sys.argv[1] + '.protected'
	shutil.copyfile(expanded_filename, filename_protected)
	elf = ELF(filename_protected, checksec=False)

	# shellcode virtual address 					   new Program Header offset         size  *  number
	# shellcode_base = elf.load_addr + elf.header.e_ehsize + elf.header.e_phoff + \
	#                 elf.header.e_phentsize * elf.header.e_phnum
	# shellcode base, is there any method to get vaddr from offset?
	shellcode_base = elf.load_addr + elf.header.e_ehsize + os.path.getsize(expanded_filename)
	func_name = [i for i in elf.plt][0]
	copyShellcode(elf, func_name, shellcode_base)

	# 3 last plt hook . If plt is not the last, elf cannot find elf.plt[func_name]
	pltHook(elf, func_name, shellcode_base)
	log.info("="*0x17 + 'enjoy' + "="*0x17)
	log.info("Protected file is %s" % filename_protected)


def method2(filename):
	"""
	use .eh_frame_hdr and .eh_frame to store shellcode, which is r-x when the program loads
	the space is: 0x401088 - 0x402000
	thanks to p4nda@DUBHE http://p4nda.top/2018/07/02/patch-in-pwn/
	:param filename:
	:return:
	"""
	eh_frame_filename = filename + '-eh_frame.protected'
	shutil.copyfile(filename, eh_frame_filename)

	elf = ELF(eh_frame_filename, checksec=False)
	eh_frame_hdr_addr = 0
	for segment in elf.segments:
		if segment.header.p_type == 'PT_GNU_EH_FRAME':
			eh_frame_hdr_addr = segment.header.p_vaddr
			log.info("\t find GNU_EH_FRAME @0x%x" % eh_frame_hdr_addr)
			break

	log.info("[1] start to copy shellcode")
	func_name = [i for i in elf.plt][0]
	copyShellcode(elf, func_name, eh_frame_hdr_addr)

	log.info("[2] plt hook")
	pltHook(elf, func_name, eh_frame_hdr_addr)

	log.info("="*0x17 + 'enjoy' + "="*0x17)
	log.info("Protected file is %s" % eh_frame_filename)



if __name__ == '__main__':
	context.local(arch='amd64', os='linux')

	# show menu
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

	method2(filename)