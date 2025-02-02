#!/usr/bin/env python

import unicorn

import ucutils
import ucutils.emu

# x86-64::
#
#    0: mov rax, 0x1
#    7: mov rbx, 0x2
#    e: sub rbx, rax
CODE = b"\x48\xc7\xc0\x01\x00\x00\x00\x48\xc7\xc3\x02\x00\x00\x00\x48\x29\xc3"


def test_read_reg():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    emu.mem_map(0x0, 0x1000)
    emu.mem_write(0x0, CODE)
    emu.emu_start(0x0, len(CODE))
    assert emu.rax == 0x1
    assert emu.rbx == 0x1


def test_write_reg():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    emu.rax = 0x1
    assert emu.reg_read(unicorn.x86_const.UC_X86_REG_RAX) == 0x1

    emu.pc = 0x7
    assert emu.pc == 0x7
    assert emu.rip == 0x7

    emu.pc = 0x0
    assert emu.pc == 0x0
    assert emu.rip == 0x0


def test_read_mem_slice():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    emu.mem_map(0x0, 0x1000)
    emu.mem_write(0x0, CODE)
    assert emu.mem[0x0:0x2] == b"\x48\xc7"


def test_read_mem_index():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    emu.mem_map(0x0, 0x1000)
    emu.mem_write(0x0, CODE)
    assert emu.mem[0x0] == 0x48


def test_stepi():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    emu.mem_map(0x0, 0x1000)
    emu.mem_write(0x0, CODE)
    emu.stepi()
    assert emu.pc == 0x7
    assert emu.rax == 0x1


def test_stepi32():
    # x86::
    #
    #     0:  c7 05 00 10 00 00 01 00 00 00   mov    DWORD PTR ds:0x1000,0x1
    #     a:  b8 02 00 00 00                  mov    eax,0x2
    #     f:  a3 02 20 00 00                  mov    ds:0x2002,eax
    #     14: a3 00 10 00 00                  mov    ds:0x1000,eax
    CODE = b"\xc7\x05\x00\x10\x00\x00\x01\x00\x00\x00\xb8\x02\x00\x00\x00\xa3\x02\x20\x00\x00\xa3\x00\x10\x00\x00"

    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    emu.mem.map_data(0x0, CODE, "code")
    emu.mem.map_region(0x1000, 0x1000, "region1")
    emu.mem.map_region(0x2000, 0x1000, "region2")

    assert emu.mem_read(0x0, len(CODE)) == CODE
    assert emu.pc == 0x0

    emu.pc = 0x0
    assert emu.pc == 0x0

    emu.stepi()
    assert emu.pc == 0xA

    emu.stepi()
    assert emu.pc == 0xF

    emu.stepi()
    assert emu.pc == 0x14

    emu.stepi()
    assert emu.pc == 0x19
    assert emu.pc == len(CODE)

    emu.mem_read(0x0, len(CODE)) == CODE
    emu.mem_read(0x1000, 0x4) == b"\x02\x00\x00\x00"
    emu.mem_read(0x2000, 0x4) == b"\x00\x00\x02\x00"


def test_go():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    emu.mem_map(0x0, 0x1000)
    emu.mem_write(0x0, CODE)
    emu.go(0xE)
    assert emu.pc == 0xE
    assert emu.rax == 0x1
    assert emu.rbx == 0x2


def test_go32():
    # x86::
    #
    #     0:  c7 05 00 10 00 00 01 00 00 00   mov    DWORD PTR ds:0x1000,0x1
    #     a:  b8 02 00 00 00                  mov    eax,0x2
    #     f:  a3 02 20 00 00                  mov    ds:0x2002,eax
    #     14: a3 00 10 00 00                  mov    ds:0x1000,eax
    CODE = b"\xc7\x05\x00\x10\x00\x00\x01\x00\x00\x00\xb8\x02\x00\x00\x00\xa3\x02\x20\x00\x00\xa3\x00\x10\x00\x00"

    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    emu.mem.map_data(0x0, CODE, "code")
    emu.mem.map_region(0x1000, 0x1000, "region1")
    emu.mem.map_region(0x2000, 0x1000, "region2")

    assert emu.mem_read(0x0, len(CODE)) == CODE
    assert emu.pc == 0x0

    emu.go(len(CODE))
    assert emu.pc == 0x19
    assert emu.pc == len(CODE)

    emu.mem_read(0x0, len(CODE)) == CODE
    emu.mem_read(0x1000, 0x4) == b"\x02\x00\x00\x00"
    emu.mem_read(0x2000, 0x4) == b"\x00\x00\x02\x00"


class InsnCounter(ucutils.emu.Hook):
    """
    counts the number of times the code tracing hook is invoked.
    """

    HOOK_TYPE = unicorn.UC_HOOK_CODE

    def __init__(self):
        super(ucutils.emu.Hook, self).__init__()
        self.count = 0

    def hook(self, uc, address, size, user_data):
        self.count += 1


def test_hooks():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    emu.mem_map(0x0, 0x1000)
    emu.mem_write(0x0, CODE)

    c0 = InsnCounter()
    c1 = InsnCounter()

    with ucutils.emu.hook(emu, c0):
        emu.stepi()

        with ucutils.emu.hook(emu, c1):
            emu.stepi()

    assert c0.count == 2
    assert c1.count == 1


def test_context():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    emu.mem_map(0x0, 0x1000)
    emu.mem_write(0x0, CODE)

    emu.rax = 0x0
    emu.rbx = 0x0
    emu.pc = 0x0

    with ucutils.emu.context(emu):
        emu.go(0xE)
        assert emu.pc == 0xE
        assert emu.rax == 0x1
        assert emu.rbx == 0x2

    assert emu.rax == 0x0
    assert emu.rbx == 0x0
    assert emu.pc == 0x0


def test_alloc():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

    assert emu.mem.alloc(0x1000) == ucutils.HEAP_ADDR
    assert emu.mem.alloc(0x1) == ucutils.HEAP_ADDR + 0x1000
    assert emu.mem.alloc(0x2000) == ucutils.HEAP_ADDR + 0x2000
    assert emu.mem.alloc(0x2, reason="last") == ucutils.HEAP_ADDR + 0x4000
    assert emu.mem.symbols[ucutils.HEAP_ADDR + 0x4000] == "last"


def test_map_data():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

    emu.mem.map_data(0x1000, b"aaaa", reason="Aaaaah!")
    assert emu.mem[0x1000 : 0x1000 + 0x4] == b"aaaa"
    assert emu.mem.symbols[0x1000] == "Aaaaah!"


def test_map_region():
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

    emu.mem.map_region(0x1000, 0x1000, reason="Aaaaah!")
    assert ucutils.probe_addr(emu, 0x1000) is True
    assert emu.mem.symbols[0x1000] == "Aaaaah!"
