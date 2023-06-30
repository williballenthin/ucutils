#!/usr/bin/env python

import unicorn

import ucutils
import ucutils.emu
import ucutils.checkpoint

# x86::
#
#     0:  c7 05 00 10 00 00 01 00 00 00   mov    DWORD PTR ds:0x1000,0x1
#     a:  b8 02 00 00 00                  mov    eax,0x2
#     f:  a3 02 20 00 00                  mov    ds:0x2002,eax
#     14: a3 00 10 00 00                  mov    ds:0x1000,eax
CODE = b"\xC7\x05\x00\x10\x00\x00\x01\x00\x00\x00\xB8\x02\x00\x00\x00\xA3\x02\x20\x00\x00\xA3\x00\x10\x00\x00"


def test_checkpoint():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    emu.mem.map_data(0x0, CODE, "code")
    emu.mem.map_region(0x1000, 0x1000, "region1")
    emu.mem.map_region(0x2000, 0x1000, "region2")
    emu.pc = 0x0

    with ucutils.checkpoint.checkpoint(emu) as cp:
        assert emu.pc == 0x0

        emu.go(len(CODE))

        # we've executed the code, and memory has changed
        assert emu.mem[0x1000:0x1004] == b"\x02\x00\x00\x00"
        assert emu.mem[0x2000:0x2008] == b"\x00\x00\x02\x00\x00\x00\x00\x00"
        # so have the registers.
        assert emu.eax == 0x2

    # we've restored the memory state
    assert emu.mem[0x1000:0x1004] == b"\x00" * 4
    assert emu.mem[0x2000:0x2008] == b"\x00" * 8
    # and restored the registers
    assert emu.eax == 0x0

    # and tracked the pages that had been written
    assert 0x1000 in cp.written_pages
    assert 0x2000 in cp.written_pages

    # saving off the content for later inspection
    assert cp.written_pages[0x1000][0x0:0x4] == b"\x02\x00\x00\x00"
    assert cp.written_pages[0x2000][0x0:0x8] == b"\x00\x00\x02\x00\x00\x00\x00\x00"


def test_nested_checkpoints():
    """
    demonstrate that checkpoints can be nested.
    that is, something like:

        with checkpoint(emu):
            emu.go(...)
            with checkpoint(emu):
                emu.go(...)
                with checkpoint(emu):
                    emu.go(...)
    """
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    emu.mem.map_data(0x0, CODE, "code")
    emu.mem.map_region(0x1000, 0x1000, "region1")
    emu.mem.map_region(0x2000, 0x1000, "region2")

    emu.eax = 0x0
    with ucutils.checkpoint.checkpoint(emu) as cp:
        emu.go(0x14)

        assert emu.mem[0x1000:0x1004] == b"\x01\x00\x00\x00"

        with ucutils.checkpoint.checkpoint(emu) as cp2:
            emu.go(len(CODE))
            assert emu.mem[0x1000:0x1004] == b"\x02\x00\x00\x00"

        # same assertions as above.
        assert emu.mem[0x1000:0x1004] == b"\x01\x00\x00\x00"

    # things are restored ok
    assert emu.mem[0x1000:0x1004] == b"\x00" * 4
    assert emu.mem[0x2000:0x2008] == b"\x00" * 8
    assert emu.eax == 0x0

    # checkpoint1 has both written pages,
    assert 0x1000 in cp.written_pages
    assert 0x2000 in cp.written_pages
    # but checkpoint two only saw one page written to
    assert 0x1000 in cp2.written_pages
    assert 0x2000 not in cp2.written_pages

    assert cp.written_pages[0x1000][0x0:0x4] == b"\x01\x00\x00\x00"
    assert cp2.written_pages[0x1000][0x0:0x4] == b"\x02\x00\x00\x00"
