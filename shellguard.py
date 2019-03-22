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
	usage = 'Usage:  python shellguard.py <FILENAME>'
	if usage == 1:
		menu += usage

	print(menu)


def addSegment(filename):
	"""
	add a segment in ELF x86_64
	:param filename:
	:return: the writtable file offset and length
	"""

	log.info("="*0x10 + "start to add segment" + "="*0x10)

	# check filename exits
	log.debug("filename: %s" % filename)
	if not os.path.exists(filename):
		os._exit(-1)
	elf = ELF(filename)

	# get e_phoff e_phnum e_phentsize from ELF header
	with open(filename, 'rb+') as fd:
		filesize = os.path.getsize(filename)
		log.debug("file size %s" % hex(filesize))
		e_phoff = elf.header.e_phoff                # Elf64_Ehdr->e_phoff       /* Program header table file offset */
		e_phnum = elf.header.e_phnum                # Elf64_Ehdr->e_phnum       /* Program header table entry count */
		e_phentsize = elf.header.e_phentsize        # Elf64_Ehdr0>e_phentsize   /* Program header table entry size */
		log.debug("e_phoff: " + hex(e_phoff) + " e_phnum: " + hex(e_phnum) + " e_phentsize: " + hex(e_phentsize))


	# copy filename to filename.stage1
	log.info("stage1: copy Program header table to the end...")
	filename_stage1 = filename + '.stage1'
	shutil.copyfile(filename, filename_stage1)

	# append program header table to the end and fix Elf64_Ehdr->e_phoff and
	with open(filename_stage1, 'rb+') as fd:
		fd.seek(e_phoff, 0)                        # mov fd to Elf64_Ehdr->e_phoff
		phdr_table = fd.read(e_phnum*e_phentsize)  # read program header table value

		fd.seek(0x20,0)                            # mov fd to Elf64_Ehdr->e_phoff
		raw_filesize = filesize
		fd.write(p64(raw_filesize))                # change Elf64_Ehdr->e_phoff to filesize
		filesize += e_phnum*e_phentsize            # update now filesize

		fd.seek(0,2)                               # mov fd to file end
		fd.write(phdr_table)                       # append program header table to the end

	# copy filename to filename.stage2
	log.info("stage2: add new PT_LOAD phdr entry")
	filename_stage2 = filename + '.stage2'
	shutil.copyfile(filename_stage1,filename_stage2)

	# fix new Program Header Table and add new PT_LOAD to load it
	with open(filename_stage2, 'rb+') as fd:
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
				new_phdr = util.replaceStr(new_phdr, 0x20, p64(len(phdr_table) + e_phentsize))           # p_filesz
				segAlign = (len(phdr_table) + e_phentsize) % 0x10
				new_phdr = util.replaceStr(new_phdr, 0x28, p64(len(phdr_table) + e_phentsize + segAlign))# p_memsz
				phdr.insert(i+1, new_phdr)
				break

		new_phdr_table = b''.join(phdr)
		log.debug("Now Elf64_Ehdr->e_phnum :" + str(len(phdr)))
		log.debug(new_phdr_table)

		# save new_phdr_table to filename.stage2
		fd.write(new_phdr_table)


def pltHook(filename,jmp_addr):
	pass


def copyShellcode(filename, start_addr):
	pass


if __name__ == '__main__':
	if len(sys.argv) < 2:
		showMenu(usage=1)
		os._exit(0)
	else:
		showMenu(usage=0)

	filename = sys.argv[1]
	addSegment(filename)
