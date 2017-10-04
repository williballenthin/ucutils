#!/usr/bin/env python
import binascii

import pytest
import unicorn

import ucutils
import ucutils.emu


@pytest.mark.xfail
def test_fs():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)

    emu.mem_map(0x0, 0x1000)     # code
    emu.mem_map(0x1000, 0x1000)  # fs segment
    emu.mem_map(0x2000, 0x1000)  # gdt

    ucutils.arch.x32.init_gdt(emu, 0x2000)
    # TODO: this segfaults
    #ucutils.arch.x32.set_fs(emu, 0x2000, 0x1000, 0x1000)

    code = binascii.unhexlify(b'64330D18000000')  # x86-32: xor ecx, dword ptr fs:[0x18]
    emu.mem_write(0x0, code)
    emu.mem_write(0x1000+0x18, b'AAAA')

    emu.emu_start(0x0, len(code))

    assert emu.ecx == 0x41414141


@pytest.mark.xfail
def test_gs():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)

    emu.mem_map(0x0, 0x1000)     # code
    emu.mem_map(0x1000, 0x1000)  # gs segment
    emu.mem_map(0x2000, 0x1000)  # gdt

    ucutils.arch.x32.init_gdt(emu, 0x2000)
    # TODO: this segfaults
    #ucutils.arch.x32.set_gs(emu, 0x2000, 0x1000, 0x1000)

    code = binascii.unhexlify(b'65330d18000000')  # x86-32: xor ecx, dword ptr gs:[0x18]
    emu.mem_write(0x0, code)
    emu.mem_write(0x1000+0x18, b'AAAA')

    emu.emu_start(0x0, len(code))

    assert emu.ecx == 0x41414141


def test_ptr():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    emu.mem_map(0x0, 0x1000)
    ucutils.arch.x32.emit_ptr(emu, 0x0, 0x11223344)

    assert emu.mem[0x0:0x4] == b'\x44\x33\x22\x11'
    assert ucutils.arch.x32.parse_ptr(emu, 0x0) == 0x11223344
