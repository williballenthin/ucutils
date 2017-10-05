#!/usr/bin/env python

import struct

import unicorn
import capstone

import ucutils
from ucutils.arch.x64 import U2C
from ucutils.arch.x64 import C2U
from ucutils.arch.x64 import U2S
from ucutils.arch.x64 import C2S
from ucutils.arch.x64 import S2U
from ucutils.arch.x64 import S2C
from ucutils.arch.x64 import REGS


# the unicorn constant for $pc
PROGRAM_COUNTER = unicorn.x86_const.UC_X86_REG_EIP

# via: https://github.com/unicorn-engine/unicorn/blob/master/tests/regress/x86_gdt.py
F_GRANULARITY = 0x8
F_PROT_32 = 0x4
F_LONG = 0x2
F_AVAILABLE = 0x1

A_PRESENT = 0x80

A_PRIV_3 = 0x60
A_PRIV_2 = 0x40
A_PRIV_1 = 0x20
A_PRIV_0 = 0x0

A_CODE = 0x10
A_DATA = 0x10
A_TSS = 0x0
A_GATE = 0x0

A_DATA_WRITABLE = 0x2
A_CODE_READABLE = 0x2

A_DIR_CON_BIT = 0x4

S_GDT = 0x0
S_LDT = 0x4
S_PRIV_3 = 0x3
S_PRIV_2 = 0x2
S_PRIV_1 = 0x1
S_PRIV_0 = 0x0


def get_capstone():
    '''
    construct a capstone disassembler instance appropriate for this architecture.
    '''
    return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)


# our own definitions, not standardized?
GSINDEX = 1
FSINDEX = 2


def init_gdt(emu, gdt):
    # unclear why `emu.gdtr = (...)` doesn't work
    emu.reg_write(unicorn.x86_const.UC_X86_REG_GDTR, (0, gdt, 0x1000, 0x0))


# via: https://github.com/unicorn-engine/unicorn/blob/master/tests/regress/x86_gdt.py
def create_gdt_entry(base, limit, access, flags):
    to_ret = limit & 0xffff
    to_ret |= (base & 0xffffff) << 16
    to_ret |= (access & 0xff) << 40
    to_ret |= ((limit >> 16) & 0xf) << 48
    to_ret |= (flags & 0xff) << 52
    to_ret |= ((base >> 24) & 0xff) << 56
    return struct.pack('<Q', to_ret)


def set_gdt_entry(emu, gdt, entry, index):
    emu.mem_write(gdt + 8 * index, entry)


# via: https://github.com/unicorn-engine/unicorn/blob/master/tests/regress/x86_gdt.py
def create_selector(idx, flags):
    to_ret = flags
    to_ret |= idx << 3
    return to_ret


def set_gs(emu, gdt, addr, size):
    '''
    set the GS.base descriptor-register field to the given address.
    this enables referencing the gs segment on x86-32.

    note: the GDT must have been initialized elsewhere for this to take effect.

    example::

        gdt = alloc_page(emu)
        init_gdt(emu, gdt)
        set_gs(emu, gdt, 0x2000, 0x1000)
    '''

    gdt_entry = create_gdt_entry(addr, size, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)
    set_gdt_entry(emu, gdt, gdt_entry, GSINDEX)
    emu.gs = create_selector(GSINDEX, S_GDT | S_PRIV_3)


def get_gs(emu, gdt):
    # TODO: need to learn to parse a GDT entry to handle this.
    raise NotImplementedError()


def set_fs(emu, gdt, addr, size):
    '''
    set the FS.base descriptor-register field to the given address.
    this enables referencing the fs segment on x86-32.

    note: the GDT must have been initialized elsewhere for this to take effect.

    example::

        gdt = alloc_page(emu)
        init_gdt(emu, gdt)
        set_fs(emu, gdt, 0x2000, 0x1000)
    '''
    entry = create_gdt_entry(addr, size, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)
    set_gdt_entry(emu, gdt, entry, FSINDEX)
    emu.fs = create_selector(FSINDEX, S_GDT | S_PRIV_3)


def get_fs(uc, gdt):
    # TODO: need to learn to parse a GDT entry to handle this.
    raise NotImplementedError()


def emit_ptr(emu, addr, value):
    ucutils.emit_uint32(emu, addr, value)


def get_pc(emu):
    return emu.reg_read(PROGRAM_COUNTER)


def set_pc(emu, val):
    return emu.reg_write(PROGRAM_COUNTER, val)


def emu_go(emu, addr):
    emu.emu_start(get_pc(emu), addr)


def emu_stepi(emu):
    emu.emu_start(get_pc(emu), 0xFFFFFFFF, count=1)


def parse_ptr(emu, addr):
    buf = emu.mem_read(addr, 0x4)
    return struct.unpack('<I', buf)[0]
