# date: 2019-03-22
# author: thinkycx

"""
util.py

provide some util functions ...
"""

from pwn import ELF, disasm, log
import argparse
import sys
import os


def menu():
    menu_info = '''
    ______ __     ______ ______                         __
   / ____// /    / ____// ____/__  __ ____ _ _____ ____/ /
  / __/  / /    / /_   / / __ / / / // __ `// ___// __  / 
 / /___ / /___ / __/  / /_/ // /_/ // /_/ // /   / /_/ /  
/_____//_____//_/     \____/ \__,_/ \__,_//_/    \__,_/ %s{%sv%s%s}%s                            
                                    [*] thinkycx@gmail.com
                                    [*] github.com/thinkycx/elfguard
    '''
    version = '1.0.0'
    green_color = '\033[32m'
    red_color = '\033[0;31m'
    yellow_color = '\033[01;33m'
    white_color = '\033[01;37m'
    color_end = '\033[0m'
    print menu_info % (white_color, yellow_color, version, white_color, color_end)

    parser = argparse.ArgumentParser(add_help=True, description='python elfguard.py -f /bin/bash')
    parser.add_argument('-f',  '--filename', dest='filename', required=True, metavar='', help='filename required to be guarded')
    
    parser.add_argument('-st', '--storage', default='expand', help='expand [add, eh_frame, ...]', metavar='')
    # SECCOMP should not be uppercase, or the argparse could not get it
    parser.add_argument('-sc', '--shellcode', default='reverseshell', help='reverseshell [seccomp, ...]', metavar='')
    parser.add_argument('-c', '--controller', default='plthook', help='plthook [entryhook, ...]', metavar='')
    parser.add_argument('-m', '--method', default='func_plt_number', help='func_plt_number [func_name, ...]', metavar='')  # plt hook method
    parser.add_argument('-mp', '--mplt_num', default=2, type=int, help='2 [0, 1, 2, ...]', metavar='')  # plt hook method
    parser.add_argument('-mf', '--mfunc_name', default='malloc', help='malloc [free, printf, ...]', metavar='')  # plt hook method

    parser.add_argument('--ip', default='127.0.0.1', help='reverseshell default ip: 127.0.0.1', metavar='')
    parser.add_argument('--port', default=7777, type=int, help='reverseshell default port: 7777', metavar='')

    # args = parser.parse_args(['--filename','/bin/bash','--storage', 'expand', '--shellcode', 'reverseshell', '--controller', 'plthook'])
    args = parser.parse_args()
    if args.filename is None or not os.path.exists(args.filename):
        log.info("file not found: %s" % args.filename)
        parser.print_help()
        os._exit(-1)
    log.info("filename: %s" % args.filename)

    # Namespace info
    # print args
    return args




    

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
    # log.info("\t filename: %s vaddr: 0x%x \n\t disassembly: %s " % (filename, vaddr, disassembly))
    log.info("\t disassembly: %s " % disassembly)
