# elfcore.py - defines a python interface for reading ELF corefiles.
# Copyright 2007 Red Hat, Inc.
# Author: Will Woods <wwoods@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA

import struct

# XXX I should do it this way..
elfident = (('4s','magic'),
            ('b','elfclass'),
            ('b','endian'),
            ('b','version'),
            ('b','osabi'),
            ('b','abiversion'),
            ('xxxxxxx','padding'))

# These come from /usr/include/elf.h
# XXX we're ignoring the endianness because I'm writing this for
# parsing core files as they are written by the kernel, therefore
# they're always going to be in native byte order
elfident = "4sbbbbbxxxxxxx" # N.B. padded to EI_NIDENT bytes
elf32header = "hhiPiiihhhhhh"
elf64header = "hhiPllihhhhhh"

class ElfCore:
    '''A class that defines an ELF corefile. I think this will mostly conform
    to SysV but I'm writing it specifically for Linux corefiles.'''
    def __init__(self,filename=None):
        self.program_headers = []
        self.elf_notes = []
        self.magic = ''
        self.rawdata = ''
        self.offset = 0
        # FIXME: initialize the rest of the attributes
        if filename:
            self.file = open(filename,"r")
            self.parse()
    
    def read(self,n):
        data = self.file.read(n)
        self.offset += len(data)
        self.rawdata += data
        return data

    def seek(self,n):
        '''Fake seeking - only forward - that can be used on a pipe'''
        assert n >= self.offset
        if n > self.offset:
            self.read(n - self.offset)

    def parse(self):
        # woo boy - parse whatever headers we know about
        self.parse_elf_header()
        if self.phnum:
            self.parse_program_headers()
        for note_header in [h for h in self.program_headers if h.type == 4]:
            self.parse_notes(note_header)
        for prstatus_note in [n for n in self.elf_notes if n.enh.type == 1]:
            self.prstatus = ElfPRStatus(prstatus_note.data)

    def parse_elf_ident(self):
        assert self.offset == 0
        data = self.read(struct.calcsize(elfident))
        (self.magic,
        self.elfclass,
        self.data_encoding,
        self.version,
        self.osabi,
        self.abiversion) = struct.unpack(elfident,data)
        assert self.magic == "\x7fELF"

    def parse_elf_header(self):
        if not self.magic:
            self.parse_elf_ident()    
        if self.elfclass == 1:
            elfheader = elf32header
        else:
            elfheader = elf64header
        data = self.read(struct.calcsize(elfheader))
        (self.type,self.machine,self.version,self.entry,self.phoff,self.shoff,
        self.flags,self.ehsize,self.phentsize,self.phnum,self.shentsize,
        self.shnum,self.shstrndx) = struct.unpack(elfheader,data)

    def parse_program_headers(self):
        if self.phoff:
            if self.phoff != self.offset:
                self.seek(self.phoff)
            for n in range(0,self.phnum):
                self.parse_program_header()

    def parse_program_header(self):
        '''Parse an ELF program header.'''
        progheader = ElfProgramHeader(self.elfclass)
        data = self.read(self.phentsize)
        progheader.parse(data)
        self.program_headers.append(progheader)

    def parse_notes(self,notehead):
        '''Given the header for the notes section, parse the notes therein'''
        self.seek(notehead.offset)
        while self.offset < (notehead.offset + notehead.filesz):
            enh = ElfNoteHeader()
            enh.parse(self.read(enh.size))
            en = ElfNote(enh)
            en.parse(self.read(en.size))
            self.elf_notes.append(en)
         
class ElfProgramHeader:
    '''An ELF program header.'''
    format_32 = "iiPPiiii"
    format_64 = "iilPPlll"
    def __init__(self, elfclass, data=None):
        self.type = 0
        self.offset = 0
        self.vaddr = 0
        self.paddr = 0
        self.filesz = 0
        self.memsz = 0
        self.flags = 0
        self.align = 0
        self.elfclass = elfclass
        if self.elfclass == 1:
            self.format = ElfProgramHeader.format_32
        else:
            self.format = ElfProgramHeader.format_64
        if data:
            self.parse(data)

    def parse(self,data):
        data = data[:struct.calcsize(self.format)]
        if self.elfclass == 1:
            self.parse_32(data)
        else:
            self.parse_64(data)

    def parse_32(self,data):
        (self.type,self.offset,self.vaddr,self.paddr,self.filesz,
         self.memsz,self.flags,self.align) = struct.unpack(self.format_32,data)

    def parse_64(self,data):
        (self.type,self.flags,self.offset,self.vaddr,self.paddr,self.filesz,
         self.memsz,self.align) = struct.unpack(self.format_64,data)

def align(n,width):
    if n % width:
        n = width * ((n/width)+1)
    return n

class ElfNoteHeader:
    '''The header for an ELF Note section'''
    format = "iii"
    def __init__(self,data=None):
        self.namesz = 0
        self.descsz = 0
        self.type   = 0
        self.size   = struct.calcsize(self.format)
        if data:
            self.parse(data)

    def parse(self,data):
        (self.namesz,self.descsz,self.type) = struct.unpack(self.format,data)

class ElfNote:
    '''An ELF note section'''
    # We need an ElfNoteHeader to tell us how big this is
    def __init__(self, enh, data=None):
        self.enh = enh
        self.name = ''
        self.data = ''
        self.size = align(self.enh.namesz,8) + self.enh.descsz
        if data:
            self.parse(data)

    def parse(self,data):
        namelen = align(self.enh.namesz,8)
        self.name = data[0:namelen].strip('\x00')
        self.data = data[namelen:namelen+self.enh.descsz]

# see /usr/include/linux/elfcore.h
class ElfPRStatus:
    '''A prstatus struct (see /usr/include/linux/elfcore.h), containing some
    information about the process which dumped core'''
    format = 'iiihLLiiii'
    def __init__(self,data=None):
        if data:
            self.parse(data)

    def parse(self,data):
        data = data[:struct.calcsize(self.format)]
        (self.signo, self.sigcode, self.errno, self.cursig, self.sigpend,
         self.sighold, self.pid, self.ppid, self.pgrp, self.sid) = \
            struct.unpack(self.format,data)
