#date: 20191223
import util
import os
from pwn import log,asm,ELF,p64

class Controller(object):
    def __init__(self, filename, shellcode_offset, core_shellcode):
        self.filename = filename
        self.elf = ELF(filename, checksec=False)
        self.shellcode_offset = shellcode_offset
        self.core_shellcode = core_shellcode

        self.shellcode_vaddr = self.elf.load_addr + self.shellcode_offset

    def __plthook_shellcode_contidion_wrapper(self, func_name):
        """
        generate shellcode : contidion + core_shellcode + func_plt0
        shellcode is  related to shellcode_vaddr & func_name @ GOT addr
        :param func_name:
        :return: shellcode_vaddr_for_plt_hook + shellcode
        """
        log.info("__plthook_shellcode_contidion_wrapper()")

        func_plt_addr = self.elf.plt[func_name]
        func_got_addr = self.elf.got[func_name]

        # log.info("\t %s PLT @ 0x%x, GOT @ 0x%x" % (func_name, func_plt_addr, func_got_addr))
        # util.showDisasm(filename, func_plt_addr, 6)

        # Check GOT value, only suitable for ELF with Lazy binding 
        plt_hook_condition = '''             
        mov rax, 0x%x;
        mov r14, qword ptr [rax];
        cmp r14, 0x%x;
        jne plt_hook_end ;
        '''
        # jne 32addr ;  Opcode is \x0f\x85, however pwntools cannot asm it.

        # 1 asm(plt_hook_condition + core_shellcode)
        shellcode_wrapper = plt_hook_condition % (func_got_addr, func_plt_addr + 6)   # check GOT ?= plt+6
        shellcode_wrapper += self.core_shellcode
        shellcode_wrapper += 'plt_hook_end:'
        shellcode_wrapper_asm = asm(shellcode_wrapper, vma=self.shellcode_vaddr, arch='amd64')

        # 2 asm(new_plt)
        new_plt_vaddr = self.shellcode_vaddr + 8 + len(shellcode_wrapper_asm)     # shellcode_vaddr + shellcode
        new_plt_got_offset = self.elf.got[func_name] - (new_plt_vaddr + 6)
        new_plt = '\t jmp [rip+0x%x]' % (new_plt_got_offset)
        new_plt_asm = asm(new_plt, arch='amd64')
        log.info("\t contition + core_shellcode + new PLT\n\t\t 0x%x: %s # 0x%x" % (new_plt_vaddr, new_plt, (new_plt_vaddr+new_plt_got_offset+6)))

        #                   address + (condition + core_shellcode) + new_plt
        final_shellcode = p64(self.shellcode_vaddr+8) + shellcode_wrapper_asm + new_plt_asm
        return final_shellcode


    def __patchPLT(self, func_name):
        """
        hook an elf file func_name@plt first 6 bytes to jmp 0x:shellcode_addr
        :param func_name:
        :param shellcode_addr:
        :return:
        """
        log.info("__patchPLT()")

        shellcode_load_vaddr = self.elf.load_addr + self.shellcode_offset
        func_plt_addr = self.elf.plt[func_name]
        func_plt_offset = self.elf.vaddr_to_offset(func_plt_addr)

        log.info("\t patching %s@plt 0x%x..." % (func_name, func_plt_addr))

        relative_offset = shellcode_load_vaddr - (func_plt_addr + 6)
        jmp_shellcode = '\t jmp [rip+0x%x]' % relative_offset
        jmp_shellcode_asm = asm(jmp_shellcode, vma=func_plt_addr, arch='amd64', os='linux')

        # log.info("\t shellcode load va : 0x%x" % shellcode_load_vaddr)
        # log.info("\t jmp shellcode : %s" % jmp_shellcode)
        # log.info("\t relative_offset 0x%x" % relative_offset)

        util.showDisasm(self.filename, func_plt_addr, 6)
        # patch
        with open(self.filename, 'rb+') as fd:
            fd.seek(func_plt_offset, 0)
            fd.write(jmp_shellcode_asm)
        util.showDisasm(self.filename, func_plt_addr, 6)


    def pltHookControl(self, method='func_name', func_name='malloc', func_plt_number=0):
        '''
        plt hook by :func_name or func_plt_number
        method: 'func_name' or 'func_plt_number'
        func_name: default set to malloc
        func_plt_number: number in elf.plt
        '''
        log.info("pltHookControl()")
        log.info("\t shellcode vaddr: 0x%x " % self.shellcode_vaddr)

        func_names = [i for i in self.elf.plt]

        if method == 'func_name':
            log.info("\t method: func_name")
            if func_name not in func_names:
                log.info("\t func_name %s is not in program's plt \n program's plt: %s" % (func_name , ' '.join(func_names))) 
                os._exit(-1)  
            
        elif method == 'func_plt_number':
            log.info("\t method: func_plt_number")
            func_name = func_names[func_plt_number]
        
        log.info("\t func_name: %s" % func_name)
        
        # generate shellcode wrapper
        final_shellcode = self.__plthook_shellcode_contidion_wrapper(func_name)

        # write shellcode into filename
        with open(self.filename, 'rb+') as fd:
            fd.seek(self.shellcode_offset, 0)
            fd.write(final_shellcode)

        log.info("write final_shellcode length: 0x%x" % len(final_shellcode))
        
        # patch original func_name's plt to jump tp the shellcode_wrapper
        self.__patchPLT(func_name)
    
    def entrypointHook(self):
        '''
        hook ELF entry point and jmp to shellcode
        '''
        log.info("entrypointHook()")
        entry_point = self.elf.header.e_entry
        shellcode = self.core_shellcode + 'mov rax, 0x%x ; jmp rax' % entry_point
        final_shellcode = asm(shellcode, arch='amd64')

        new_entry_point = self.elf.load_addr + self.shellcode_offset

        with open(self.filename, 'rb+') as fd:
            fd.seek(0x18, 0)
            fd.write(p64(new_entry_point))
            fd.seek(self.shellcode_offset, 0)
            fd.write(final_shellcode)

        log.info("\t hjack entry point: 0x%x -> 0x%x" % (entry_point, new_entry_point))
        log.info("write final_shellcode length: 0x%x" % len(final_shellcode))