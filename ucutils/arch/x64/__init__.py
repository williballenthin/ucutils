#!/usr/bin/env python

import struct
import logging

import unicorn
import capstone

import ucutils


logger = logging.getLogger(__name__)


# the unicorn constant for $pc
PROGRAM_COUNTER = unicorn.x86_const.UC_X86_REG_RIP

# the unicorn constant for $sp
STACK_POINTER = unicorn.x86_const.UC_X86_REG_RSP

# the unicorn constant for $bp
BASE_POINTER = unicorn.x86_const.UC_X86_REG_RBP


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
    if not const_name.startswith('X86_REG_'):
        continue

    uconst_name = 'UC_' + const_name
    reg_name = const_name[len('X86_REG_'):].lower()
    uconst = getattr(unicorn.x86_const, uconst_name)
    cconst = getattr(capstone.x86_const, const_name)

    U2C[uconst] = cconst
    C2U[cconst] = uconst
    U2S[uconst] = reg_name
    C2S[cconst] = reg_name
    S2U[reg_name] = uconst
    S2C[reg_name] = uconst
    REGS.add(reg_name)


def get_capstone():
    '''
    construct a capstone disassembler instance appropriate for this architecture.
    '''
    return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


# via: https://github.com/unicorn-engine/unicorn/pull/901/files
def set_msr(uc, msr, value, scratch):
    '''
    set the given model-specific register (MSR) to the given value.
    this will clobber some memory at the given scratch address, as it emits some code.
    '''
    # save clobbered registers
    orax = uc.reg_read(unicorn.x86_const.UC_X86_REG_RAX)
    ordx = uc.reg_read(unicorn.x86_const.UC_X86_REG_RDX)
    orcx = uc.reg_read(unicorn.x86_const.UC_X86_REG_RCX)
    orip = uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP)

    # x86: wrmsr
    buf = b'\x0f\x30'
    uc.mem_write(scratch, buf)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RAX, value & 0xFFFFFFFF)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RDX, (value >> 32) & 0xFFFFFFFF)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch+len(buf), count=1)

    # restore clobbered registers
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RAX, orax)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RDX, ordx)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RCX, orcx)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RIP, orip)


def get_msr(uc, msr, scratch):
    '''
    fetch the contents of the given model-specific register (MSR).
    this will clobber some memory at the given scratch address, as it emits some code.
    '''
    # save clobbered registers
    orax = uc.reg_read(unicorn.x86_const.UC_X86_REG_RAX)
    ordx = uc.reg_read(unicorn.x86_const.UC_X86_REG_RDX)
    orcx = uc.reg_read(unicorn.x86_const.UC_X86_REG_RCX)
    orip = uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP)

    # x86: rdmsr
    buf = b'\x0f\x32'
    uc.mem_write(scratch, buf)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch+len(buf), count=1)
    eax = uc.reg_read(unicorn.x86_const.UC_X86_REG_EAX)
    edx = uc.reg_read(unicorn.x86_const.UC_X86_REG_EDX)

    # restore clobbered registers
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RAX, orax)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RDX, ordx)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RCX, orcx)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RIP, orip)

    return (edx << 32) | (eax & 0xFFFFFFFF)


def set_gs(uc, addr, scratch):
    '''
    set the GS.base hidden descriptor-register field to the given address.
    this enables referencing the gs segment on x86-64.
    '''
    return set_msr(uc, 0xC0000101, addr, scratch)


def get_gs(uc, scratch):
    '''
    fetch the GS.base hidden descriptor-register field.
    '''
    return get_msr(uc, 0xC0000101, scratch)


def set_fs(uc, addr, scratch):
    '''
    set the FS.base hidden descriptor-register field to the given address.
    this enables referencing the fs segment on x86-64.
    '''
    return set_msr(uc, 0xC0000100, addr, scratch)


def get_fs(uc, scratch):
    '''
    fetch the FS.base hidden descriptor-register field.
    '''
    return get_msr(uc, 0xC0000100, scratch)


def emit_ptr(emu, addr, value):
    ucutils.emit_uint64(emu, addr, value)


def get_pc(emu):
    return emu.reg_read(PROGRAM_COUNTER)


def set_pc(emu, val):
    return emu.reg_write(PROGRAM_COUNTER, val)


def get_sp(emu):
    return emu.reg_read(STACK_POINTER)


def set_sp(emu, val):
    return emu.reg_write(STACK_POINTER, val)


def get_bp(emu):
    return emu.reg_read(BASE_POINTER)


def set_bp(emu, val):
    return emu.reg_write(BASE_POINTER, val)


def emu_go(emu, addr):
    emu.emu_start(get_pc(emu), addr)


def emu_stepi(emu):
    emu.emu_start(get_pc(emu), 0xFFFFFFFFFFFFFFFF, count=1)


def parse_ptr(emu, addr):
    buf = emu.mem_read(addr, 0x8)
    return struct.unpack('<Q', buf)[0]
