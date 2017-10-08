#!/usr/bin/env python

import struct
import logging

import hexdump
import unicorn


logger = logging.getLogger(__name__)


PAGE_SIZE = 0x1000
GS_SIZE = 0x1000
GS_ADDR = 0x70000000
HEAP_ADDR = 0x80000000
STACK_ADDR = 0x69690000
SCRATCH_ADDR = 0x60000000
SCRATCH_SIZE = 0x1000


def align(value, alignment):
    '''
    align the given value.
    result will be greater than or equal to the given value.

    Args:
      value (int): the base value.
      alignment (int): the alignment increment.

    Returns:
      int: the aligned value.
    '''
    if value % alignment == 0:
        return value
    return value + (alignment - (value % alignment))


def get_page_base(addr):
    '''
    compute the starting address of the page that contains the given address.

    example::

        assert get_page_base(0x1002) == 0x1000
    '''
    return addr & 0b11111111111111111111000000000000


def mem_hexdump(emu, addr, size):
    buf = emu.mem_read(addr, size)
    return hex(addr) + ':\n' + hexdump.hexdump(buf, result='return')


def emit_uint16(emu, addr, value):
    emu.mem_write(addr, struct.pack('<H', value))


def parse_uint16(emu, addr):
    buf = emu.mem_read(addr, 0x2)
    return struct.unpack('<H', buf)[0]


def emit_uint32(emu, addr, value):
    emu.mem_write(addr, struct.pack('<I', value))


def parse_uint32(emu, addr):
    buf = emu.mem_read(addr, 0x4)
    return struct.unpack('<I', buf)[0]


def emit_uint64(emu, addr, value):
    emu.mem_write(addr, struct.pack('<Q', value))


def parse_uint64(emu, addr):
    buf = emu.mem_read(addr, 0x8)
    return struct.unpack('<Q', buf)[0]


def parse_utf16(emu, addr, length=0x100):
    return emu.mem_read(addr, length).partition(b'\x00')[0].decode('ascii')


def probe_addr(emu, addr):
    try:
        emu.mem_read(addr, 0x1)
    except unicorn.UcError:
        return False
    else:
        return True


def alloc_page(emu):
    addr = HEAP_ADDR
    while True:
        if probe_addr(emu, addr):
            addr += 0x1000
            continue
        emu.mem_map(addr, 0x1000)
        return addr


def free_page(emu, addr):
    emu.mem_free(addr, 0x1000)
