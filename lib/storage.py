# date: 20191223
# updated: 20191224

from pwn import ELF, log, u32, p64, p16, p32
import os
import util

class Storage(object):
    """
    This class adds storage in an ELF file.
    """

    def __init__(self, filename, expanded_length=0x1000):
        self.filename = filename
        self.elf = ELF(self.filename, checksec=False)
        self.raw_filesize = os.path.getsize(filename)
        self.expanded_length = expanded_length

    def expandSegment(self):
        """
        expand PT_LOAD segment(R-X): p_filesz, p_memsz
        return: (offset, length) to storge data later
        """
        log.info("expandSegment()")

        # get e_phoff e_phnum e_phentsize from ELF header
        e_phoff = self.elf.header.e_phoff  # Elf64_Ehdr->e_phoff       /* Program header table file offset */
        e_phnum = self.elf.header.e_phnum  # Elf64_Ehdr->e_phnum       /* Program header table entry count */
        e_phentsize = self.elf.header.e_phentsize  # Elf64_Ehdr0>e_phentsize   /* Program header table entry size */
        log.debug("raw filesize %s" % hex(self.raw_filesize))
        log.debug("e_phoff: " + hex(e_phoff) + " e_phnum: " + hex(e_phnum) + " e_phentsize: " + hex(e_phentsize))

        with open(self.filename, 'rb+') as fd:
            # update program header table in the original position the end and update Elf64_Ehdr->e_phoff
            log.info("\t update p_filesz, pmemsz in segment PT_LOAD(1) R_X")

            fd.seek(e_phoff, 0)  # mov fd to Elf64_Ehdr->e_phoff
            phdr_table = fd.read(e_phnum * e_phentsize)  # read program header table value
            phdr = [phdr_table[i * e_phentsize:i * e_phentsize + e_phentsize] for i in range(e_phnum)]  # get phdr list
            for i in range(len(phdr)):
                if u32(phdr[i][0:4]) == 0x1:
                    tmp = phdr[i]
                    tmp = util.replaceStr(tmp, 0x20, p64(self.raw_filesize + self.expanded_length))  # p_filesz
                    tmp = util.replaceStr(tmp, 0x28, p64(self.raw_filesize + self.expanded_length))  # p_memsz
                    phdr[i] = tmp
                    break
            new_phdr = ''.join(phdr)
            fd.seek(e_phoff, 0)  # mov fd to Elf64_Ehdr->e_phoff
            fd.write(new_phdr)

        # actually the length at the file end to write is larger than expanded_length.
        return (self.raw_filesize, self.expanded_length)


    def addSegment(self):
        """
        create a new PHDR table at the end of the filename
        add a new PT_LOAD segment(R-X) after the original PT_LOAD segment(R-X)
        the new segment will load from: (0x400000 + raw_filesize) & -0x1000
        :param filename:
        :return:
        """

        log.info("addSegment()")

        # get e_phoff e_phnum e_phentsize from ELF header
        e_phoff = self.elf.header.e_phoff  # Elf64_Ehdr->e_phoff       /* Program header table file offset */
        e_phnum = self.elf.header.e_phnum  # Elf64_Ehdr->e_phnum       /* Program header table entry count */
        e_phentsize = self.elf.header.e_phentsize  # Elf64_Ehdr0>e_phentsize   /* Program header table entry size */
        log.debug("raw filesize %s" % hex(self.raw_filesize))
        log.debug("e_phoff: " + hex(e_phoff) + " e_phnum: " + hex(e_phnum) + " e_phentsize: " + hex(e_phentsize))

        with open(self.filename, 'rb+') as fd:
            # append program header table to the end and update Elf64_Ehdr->e_phoff
            log.info("[1] copy Program header table to the end...")

            # 1. update ELF header first
            # update PHDR position:  0x40 -> filesize
            fd.seek(0x20, 0)  # mov fd to Elf64_Ehdr->e_phoff
            fd.write(p64(self.raw_filesize))  # change Elf64_Ehdr->e_phoff to filesize

            # update e_phnum to e_phnum + 1
            fd.seek(0x38, 0)
            fd.write(p16(e_phnum + 1))  # for the new PT_LOAD entry in new Program Header Table

            now_filesize = self.raw_filesize + e_phnum * e_phentsize  # update now filesize

            log.info("[2] add new PT_LOAD phdr entry")
            # 2. copy phdr table to the end
            # read phdr table
            fd.seek(e_phoff, 0)  # mov fd to Elf64_Ehdr->e_phoff
            phdr_table = fd.read(e_phnum * e_phentsize)  # read program header table value

            # write new phdr table
            fd.seek(0, 2)  # mov fd to file end
            fd.write(phdr_table)  # append program header table to the end

            # update new Program Header Table and add new PT_LOAD to load it
            fd.seek(self.raw_filesize)
            phdr = [phdr_table[i * e_phentsize:i * e_phentsize + e_phentsize] for i in range(e_phnum)]  # get phdr list
            log.debug(b"raw phdr: " + b''.join(phdr))

            for i in range(len(phdr)):
                # update the first entry in PHDR( load the new Program Header Table)
                if u32(phdr[i][0:4]) == 0x6:
                    log.info("\t find PT_PHDR, going to update it...")
                    tmp = phdr[i]
                    tmp = util.replaceStr(tmp, 0x08, p64(self.raw_filesize))  # p_offset
                    tmp = util.replaceStr(tmp, 0x10, p64(0x400000 + self.raw_filesize))  # p_pvaddr
                    tmp = util.replaceStr(tmp, 0x18, p64(0x400000 + self.raw_filesize))  # p_paddr
                    tmp = util.replaceStr(tmp, 0x20, p64(e_phnum * e_phentsize + e_phentsize))  # p_filesz
                    tmp = util.replaceStr(tmp, 0x28, p64(e_phnum * e_phentsize + e_phentsize))  # p_memsz
                    phdr[i] = tmp

                # add new PT_LOAD to load new Program Header Table and maybe shellcode in future
                # todo IDA cannot load it and pwntools command: got  is also failed
                if u32(phdr[i][0:4]) == 0x1:
                    log.info("\t find first PT_LOAD, going to add a new PT_LOAD...")
                    log.info("\t len(phdr_table) + e_phentsize : %x", len(phdr_table) + e_phentsize);
                    new_phdr = phdr[i]
                    new_phdr = util.replaceStr(new_phdr, 0x4, p32(0x5))  # p_flags 7
                    new_phdr = util.replaceStr(new_phdr, 0x8, p64(self.raw_filesize))  # p_offset
                    new_phdr = util.replaceStr(new_phdr, 0x10, p64(0x400000 + self.raw_filesize))  # p_pvaddr
                    new_phdr = util.replaceStr(new_phdr, 0x18, p64(0x400000 + self.raw_filesize))  # p_paddr
                    new_phdr = util.replaceStr(new_phdr, 0x20, p64(
                        len(phdr_table) + e_phentsize + self.expanded_length))  # p_filesz, 0xc3 is not needed, if storage < 0x1000
                    new_phdr = util.replaceStr(new_phdr, 0x28, p64(len(phdr_table) + e_phentsize + self.expanded_length))  # p_memsz
                    phdr.insert(i + 1, new_phdr)
                    break

            new_phdr_table = b''.join(phdr)
            log.debug("Now Elf64_Ehdr->e_phnum :" + str(len(phdr)))
            log.debug(new_phdr_table)

            # save new_phdr_table to filename.expanded
            fd.write(new_phdr_table)
            
            # now offset to write is at the end of the file
            return (self.raw_filesize + len(new_phdr_table), self.expanded_length)
    
    def eh_frameSegment(self):
        '''
        use .eh_frame_hdr and .eh_frame to store shellcode, which is r-x when the program loads
        the space is: 0x401088 - 0x402000 or more
        thanks to p4nda@DUBHE http://p4nda.top/2018/07/02/patch-in-pwn/
        '''
        log.info("eh_frame()")
        eh_frame_hdr_addr = 0
        for segment in self.elf.segments:
            if segment.header.p_type == 'PT_GNU_EH_FRAME':
                eh_frame_hdr_addr = segment.header.p_vaddr
                log.info("\t find GNU_EH_FRAME @0x%x" % eh_frame_hdr_addr)
                break 
        # p_filesz is not long, but the data after it sometimes is useless
        return segment.header.p_offset,  segment.header.p_filesz