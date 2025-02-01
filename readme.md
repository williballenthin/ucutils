# ucutils - Unicorn Emulator Utilities

ucutils provides helper utilities and abstractions for working with the [Unicorn CPU emulator](https://www.unicorn-engine.org/).
It simplifies memory management, register access, and architecture-specific operations while supporting both x86 and x64 architectures.
The library also includes Windows-specific utilities for emulating Windows structures and behaviors.

For more comprehensive Windows emulation including API hooking and system call emulation, consider using the [Speakeasy](https://github.com/mandiant/speakeasy) project.
ucutils focuses on providing low-level CPU emulation utilities rather than full system emulation.

Create the extended emulator instance:
```py
emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
```

Map and access memory (typical Unicorn API):
```py
emu.mem_map(0x0, 0x1000)
code = b"\x48\xC7\xC0\x01\x00\x00\x00"  # mov rax, 0x1
emu.mem_write(0x0, code)
emu.emu_start(0x0, len(code))
````

Easily access registers:
```py
assert emu.rax == 0x1
```

And, easily allocate and access memory:
```py
addr = emu.mem.alloc(0x1000)
emu.mem_write(addr, b"AAAA")
assert emu.mem[addr:addr+4] == b"AAAA"
```

Stack operations:
```py
emu.push(0xAA)
assert emu.pop() == 0xAA
```

Emulation stepping:
```python
emu.mem_map(0x0, 0x1000)
code = b"\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC3\x02\x00\x00\x00"  # mov rax,0x1; mov rbx,0x2
emu.mem_write(0x0, code)
emu.stepi()  # Execute first instruction
assert emu.pc == 0x7
assert emu.rax == 0x1
```

Checkpointing:
```python
assert emu.rax == 0x0
assert emu.rbx == 0x0

with ucutils.checkpoint.checkpoint(emu):
    emu.rax = 0x1
    emu.rbx = 0x2

    emu.stepi()

    # changes will be reverted after the block,
    # including memory contents and registry context.

assert emu.rax == 0x0
assert emu.rbx == 0x0
```

Install TEB and PEB for Windows process emulation (useful for shellcode):
```python
# Thread Environment Block (TEB)
teb_addr = ucutils.plat.win64.map_teb(emu)

# Process Environment Block (PEB)
peb_addr = ucutils.plat.win64.map_peb(emu)

ucutils.arch.x64.set_fs(emu, teb_addr)
```

Load a PE file:
```python
pe = pefile.PE(data=b"MZ...")
ucutils.plat.win.load_dll(emu, {"filename": "payload.dll", "pe": pe})

# exports are added to emu.symbols
assert "payload.dll!ServiceMain" in emu.symbols

# LDR_ENTRY is registered in emulated memory,
# which is useful for (shellcode) payloads that manually resolve imports.
```

