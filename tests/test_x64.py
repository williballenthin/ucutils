#!/usr/bin/env python
import binascii

import unicorn

import ucutils
import ucutils.emu


def test_fs():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

    emu.mem_map(0x0, 0x1000)  # code
    emu.mem_map(0x1000, 0x1000)  # fs segment
    emu.mem_map(0x2000, 0x1000)  # scratch

    code = binascii.unhexlify(b"6448330C2518000000")  # x86-64: xor rcx, qword ptr fs:[0x18]
    emu.mem_write(0x0, code)
    emu.mem_write(0x1000 + 0x18, b"AAAAAAAA")

    ucutils.arch.x64.set_fs(emu, 0x1000, scratch=0x2000)
    assert ucutils.arch.x64.get_fs(emu, scratch=0x2000) == 0x1000

    emu.emu_start(0x0, len(code))

    assert emu.rcx == 0x4141414141414141


def test_gs():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

    emu.mem_map(0x0, 0x1000)  # code
    emu.mem_map(0x1000, 0x1000)  # gs segment
    emu.mem_map(0x2000, 0x1000)  # scratch

    code = binascii.unhexlify(b"6548330C2518000000")  # x86-64: xor rcx, qword ptr gs:[0x18]
    emu.mem_write(0x0, code)
    emu.mem_write(0x1000 + 0x18, b"AAAAAAAA")

    ucutils.arch.x64.set_gs(emu, 0x1000, scratch=0x2000)
    assert ucutils.arch.x64.get_gs(emu, scratch=0x2000) == 0x1000

    emu.emu_start(0x0, len(code))

    assert emu.rcx == 0x4141414141414141


def test_ptr():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    emu.mem_map(0x0, 0x1000)
    ucutils.arch.x64.emit_ptr(emu, 0x0, 0x1122334455667788)

    assert emu.mem[0x0:0x8] == b"\x88\x77\x66\x55\x44\x33\x22\x11"
    assert ucutils.arch.x64.parse_ptr(emu, 0x0) == 0x1122334455667788
