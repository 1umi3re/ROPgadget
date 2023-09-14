## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-13
##
##  http://shell-storm.org
##  http://twitter.com/JonathanSalwan
##

from capstone import *

from ROPgadget.ropgadget.ropchain.arch.ropmakerx64 import *
from ROPgadget.ropgadget.ropchain.arch.ropmakerx86 import *


class ROPMaker(object):
    def __init__(self, binary, gadgets, offset, rawoutput=False):
        self.__binary  = binary
        self.__gadgets = gadgets
        self.__offset  = offset
        self.__rawoutput = rawoutput

        if not self.__rawoutput:
            self.__handlerArch()

    def __handlerArch(self):

        if (
            self.__binary.getArch() == CS_ARCH_X86
            and self.__binary.getArchMode() == CS_MODE_32
            and self.__binary.getFormat() == "ELF"
        ):
            ROPMakerX86(self.__binary, self.__gadgets, self.__offset)

        elif (
            self.__binary.getArch() == CS_ARCH_X86
            and self.__binary.getArchMode() == CS_MODE_64
            and self.__binary.getFormat() == "ELF"
        ):
            ROPMakerX64(self.__binary, self.__gadgets, self.__offset)

        else:
            print("\n[Error] ROPMaker.__handlerArch - Arch not supported yet for the rop chain generation")

    def build(self):
        result = None

        if (
            self.__binary.getArch() == CS_ARCH_X86
            and self.__binary.getArchMode() == CS_MODE_32
            and self.__binary.getFormat() == "ELF"
        ):
            maker = ROPMakerX86(self.__binary, self.__gadgets, self.__offset, self.__rawoutput)
            result = maker.generate()

        elif (
            self.__binary.getArch() == CS_ARCH_X86
            and self.__binary.getArchMode() == CS_MODE_64
            and self.__binary.getFormat() == "ELF"
        ):
            maker = ROPMakerX64(self.__binary, self.__gadgets, self.__offset, self.__rawoutput)
            result = maker.generate()

        else:
            print("\n[Error] ROPMaker.__handlerArch - Arch not supported yet for the rop chain generation")

        return result