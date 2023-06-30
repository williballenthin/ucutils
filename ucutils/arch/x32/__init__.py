#!/usr/bin/env python

import struct
import logging

import unicorn
import capstone

import ucutils

logger = logging.getLogger(__name__)


# the unicorn constant for $pc
PROGRAM_COUNTER = unicorn.x86_const.UC_X86_REG_EIP

# the unicorn constant for $sp
STACK_POINTER = unicorn.x86_const.UC_X86_REG_ESP

# the unicorn constant for $bp
BASE_POINTER = unicorn.x86_const.UC_X86_REG_EBP


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

# unicorn and capstone are separate projects.
# i'm not sure that the register mappings are guaranteed to be consistent.
# so we build a mapping that translates capstone <-> unicorn register constants
U2C = {}  # from unicorn constant to capstone constant
C2U = {}  # from capstone constant to unicorn constant
U2S = {}  # from unicorn constant to string
C2S = {}  # from capstone constant to string
S2U = {}  # from string to unicorn constant
S2C = {}  # from string to capstone constant
REGS = set([])  # valid register names
for const_name in dir(capstone.x86_const):
    if not const_name.startswith("X86_REG_"):
        continue

    uconst_name = "UC_" + const_name
    reg_name = const_name[len("X86_REG_") :].lower()
    uconst = getattr(unicorn.x86_const, uconst_name, None)
    cconst = getattr(capstone.x86_const, const_name, None)

    U2C[uconst] = cconst
    C2U[cconst] = uconst
    U2S[uconst] = reg_name
    C2S[cconst] = reg_name
    S2U[reg_name] = uconst
    S2C[reg_name] = uconst
    REGS.add(reg_name)


def get_capstone():
    """
    construct a capstone disassembler instance appropriate for this architecture.
    """
    return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)


# our own definitions, not standardized?
GSINDEX = 1
FSINDEX = 2


def init_gdt(emu, gdt):
    # unclear why `emu.gdtr = (...)` doesn't work
    emu.reg_write(unicorn.x86_const.UC_X86_REG_GDTR, (0, gdt, 0x1000, 0x0))


# via: https://github.com/unicorn-engine/unicorn/blob/master/tests/regress/x86_gdt.py
def create_gdt_entry(base, limit, access, flags):
    to_ret = limit & 0xFFFF
    to_ret |= (base & 0xFFFFFF) << 16
    to_ret |= (access & 0xFF) << 40
    to_ret |= ((limit >> 16) & 0xF) << 48
    to_ret |= (flags & 0xFF) << 52
    to_ret |= ((base >> 24) & 0xFF) << 56
    return struct.pack("<Q", to_ret)


def set_gdt_entry(emu, gdt, entry, index):
    emu.mem_write(gdt + 8 * index, entry)


def read_gdt_entry(emu, gdt, index):
    buf = emu.mem_read(gdt + 8 * index, 8)
    entry = struct.unpack("<Q", buf)[0]
    limit = entry & 0xFFFF
    base = (entry >> 16) & 0xFFFFFF
    access = (entry >> 40) & 0xFF
    limit |= ((entry >> 48) & 0xF) << 16
    flags = (entry >> 52) & 0xFF
    base |= ((entry >> 56) & 0xFF) << 24
    return base, limit, access, flags


# via: https://github.com/unicorn-engine/unicorn/blob/master/tests/regress/x86_gdt.py
def create_selector(idx, flags):
    to_ret = flags
    to_ret |= idx << 3
    return to_ret


def set_gs(emu, gdt, addr, size):
    """
    set the GS.base descriptor-register field to the given address.
    this enables referencing the gs segment on x86-32.

    note: the GDT must have been initialized elsewhere for this to take effect.

    example::

        gdt = alloc_page(emu)
        init_gdt(emu, gdt)
        set_gs(emu, gdt, 0x2000, 0x1000)
    """

    gdt_entry = create_gdt_entry(
        addr,
        size,
        A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT,
        F_PROT_32,
    )
    set_gdt_entry(emu, gdt, gdt_entry, GSINDEX)
    emu.gs = create_selector(GSINDEX, S_GDT | S_PRIV_3)


def get_gs(emu, gdt):
    base, limit, access, flags = read_gdt_entry(emu, gdt, GSINDEX)
    return base


def set_fs(emu, gdt, addr, size):
    """
    set the FS.base descriptor-register field to the given address.
    this enables referencing the fs segment on x86-32.

    note: the GDT must have been initialized elsewhere for this to take effect.

    example::

        gdt = alloc_page(emu)
        init_gdt(emu, gdt)
        set_fs(emu, gdt, 0x2000, 0x1000)
    """
    entry = create_gdt_entry(
        addr,
        size,
        A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT,
        F_PROT_32,
    )
    set_gdt_entry(emu, gdt, entry, FSINDEX)
    emu.fs = create_selector(FSINDEX, S_GDT | S_PRIV_3)


def get_fs(emu: unicorn.Uc, gdt):
    base, limit, access, flags = read_gdt_entry(emu, gdt, FSINDEX)
    return base


def get_pc(emu: unicorn.Uc):
    return emu.reg_read(PROGRAM_COUNTER)


def set_pc(emu: unicorn.Uc, val):
    return emu.reg_write(PROGRAM_COUNTER, val)


def get_sp(emu: unicorn.Uc):
    return emu.reg_read(STACK_POINTER)


def set_sp(emu: unicorn.Uc, val):
    return emu.reg_write(STACK_POINTER, val)


def get_bp(emu: unicorn.Uc):
    return emu.reg_read(BASE_POINTER)


def set_bp(emu: unicorn.Uc, val: int):
    return emu.reg_write(BASE_POINTER, val)


def emu_go(emu: unicorn.Uc, addr: int):
    emu.emu_start(get_pc(emu), addr)


def emu_stepi(emu: unicorn.Uc):
    emu.emu_start(begin=get_pc(emu), until=0xFFFFFFFF, count=1)


def emit_ptr(emu: unicorn.Uc, addr, value):
    ucutils.emit_uint32(emu, addr, value)


def parse_ptr(emu: unicorn.Uc, addr):
    buf = emu.mem_read(addr, 0x4)
    return struct.unpack("<I", buf)[0]


def get_ptr_size():
    return 0x4


def get_gdt(emu):
    if "GDT" not in emu.mem.symbols.values():
        raise KeyError("GDT not mapped")
    return [addr for addr, name in emu.mem.symbols.items() if name == "GDT"][0]


def map_fs(emu, size=ucutils.FS_SIZE):
    try:
        gdt_addr = get_gdt(emu)
    except KeyError:
        gdt_addr = emu.mem.alloc(ucutils.FS_SIZE, reason="GDT")
        init_gdt(emu, gdt_addr)

    fs_addr = emu.mem.alloc(size, reason="fs segment")
    logger.debug("mapped fs segment at 0x%x", fs_addr)
    set_fs(emu, gdt_addr, fs_addr, size)
    return fs_addr
