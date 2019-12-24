# date: 2019-03-22
# author: thinkycx

"""
util.py

provide some util functions ...
"""

from pwn import ELF, disasm, log


def showMenu(usage):
    menu = '''
    ______ __     ______ ______                         __
   / ____// /    / ____// ____/__  __ ____ _ _____ ____/ /
  / __/  / /    / /_   / / __ / / / // __ `// ___// __  / 
 / /___ / /___ / __/  / /_/ // /_/ // /_/ // /   / /_/ /  
/_____//_____//_/     \____/ \__,_/ \__,_//_/    \__,_/                             
                                    [*] thinkycx@gmail.com
                                    [*] github.com/thinkycx/elfguard
    '''

    menu_usage = 'Usage:  python elfguard.py <FILENAME>\n'

    print menu
    if usage:
        print menu_usage

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
