import unicorn

import ucutils
import ucutils.emu
import ucutils.plat.win32
import ucutils.plat.win64

# offsets used by code that walks the loaded modules, like shellcode:
#   TEB->PEB, PEB->Ldr, PEB_LDR_DATA.InLoadOrderModuleList,
#   LDR_DATA_TABLE_ENTRY.SizeOfImage and .BaseDllName, and UNICODE_STRING.Buffer
X32 = {"peb": 0x30, "ldr": 0x0C, "load_order": 0x0C, "size": 0x20, "basename": 0x2C, "buffer": 0x4}
X64 = {"peb": 0x60, "ldr": 0x18, "load_order": 0x10, "size": 0x40, "basename": 0x58, "buffer": 0x8}


def walk_modules(emu, offsets):
    """the (name, size of image) of each module in load order, read the way shellcode does."""
    teb = emu.plat.get_teb_addr()
    peb = ucutils.parse_ptr(emu, teb + offsets["peb"])
    ldr = ucutils.parse_ptr(emu, peb + offsets["ldr"])
    head = ldr + offsets["load_order"]

    modules = []
    entry = ucutils.parse_ptr(emu, head)
    while entry != head:
        us = entry + offsets["basename"]
        length = ucutils.parse_uint16(emu, us)
        buffer = ucutils.parse_ptr(emu, us + offsets["buffer"])
        name = emu.mem_read(buffer, length).decode("utf-16le")
        size = ucutils.parse_uint32(emu, entry + offsets["size"])
        modules.append((name, size))
        entry = ucutils.parse_ptr(emu, entry)
    return modules


def add_module(emu, name, base, size):
    us = emu.plat.alloc_unicode(name)
    entry = emu.mem.alloc(0x1000, reason="LDR_DATA_TABLE_ENTRY: " + name)
    emu.plat.emit_ldr_data_table_entry(entry, base, base + 0x1000, size, us, us)
    emu.plat.append_ldr_data_entry(entry)


def check(mode, plat, offsets):
    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, mode, plat=plat)
    emu.plat.map_teb()
    assert walk_modules(emu, offsets) == []

    add_module(emu, "ntdll.dll", 0x7700_0000, 0x1A0000)
    add_module(emu, "kernel32.dll", 0x7600_0000, 0xF0000)
    assert walk_modules(emu, offsets) == [("ntdll.dll", 0x1A0000), ("kernel32.dll", 0xF0000)]


def test_x32_module_list():
    check(unicorn.UC_MODE_32, ucutils.plat.win32, X32)


def test_x64_module_list():
    check(unicorn.UC_MODE_64, ucutils.plat.win64, X64)
