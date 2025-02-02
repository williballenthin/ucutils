#!/usr/bin/env python

import logging
import functools
import contextlib
import collections
from typing import Any

import unicorn

import ucutils
import ucutils.arch
import ucutils.plat
from ucutils import PAGE_SIZE

SCRATCH_SIZE = PAGE_SIZE


logger = logging.getLogger(__name__)


class MemoryAccessor:
    def __init__(self, emu):
        self.emu = emu
        self.symbols: dict[int, str] = {}

    def __getitem__(self, key):
        if isinstance(key, slice):
            if key.step not in (1, None):
                raise ValueError("unsupported step value")

            if key.stop < key.start:
                raise ValueError("must have positive range")

            size = key.stop - key.start
            return self.emu.mem_read(key.start, size)
        elif isinstance(key, int):
            buf = self.emu.mem_read(key, 1)
            return buf[0]
        else:
            raise TypeError("unsupported type")

    # TODO: __setitem__ to write to memory

    def _find_heap_range(self, size: int):
        num_pages = ucutils.align(size, PAGE_SIZE) // PAGE_SIZE

        addr = ucutils.HEAP_ADDR
        while True:
            is_valid = True
            for i in range(num_pages):
                if ucutils.probe_addr(self.emu, addr + i * PAGE_SIZE):
                    is_valid = False
                    break

            if not is_valid:
                addr += PAGE_SIZE
                continue
            else:
                return addr

    def alloc(self, size: int, reason=""):
        addr = self._find_heap_range(size)
        self.emu.mem_map(addr, ucutils.align(size, PAGE_SIZE))
        self.symbols[addr] = reason
        return addr

    def map_data(self, addr: int, data: bytes, reason=""):
        size = ucutils.align(len(data), PAGE_SIZE)
        self.emu.mem_map(addr, size)
        self.emu.mem_write(addr, data)
        self.symbols[addr] = reason

    def map_region(self, addr: int, size: int, reason=""):
        self.emu.mem_map(addr, ucutils.align(size, PAGE_SIZE))
        self.symbols[addr] = reason


@unicorn.ucsubclass
class Emulator(unicorn.Uc):
    """
    enhancements:
      - supports multiple hooks of the same type in parallel
      - shortcuts for reg get/set as properties
      - shortcut to memory reads

    Example::

        # register shortcuts
        print(hex(emu.pc))

        # memory slice access
        hexdump(emu.mem[0x401000:0x402000])

        # multiple simultaneous hooks
        emu.hook_add(unicorn.UC_HOOK_CODE, lambda *args: print(args))
        emu.hook_add(unicorn.UC_HOOK_CODE, lambda *args: logger.debug('%s', args))
    """

    def __init__(self, arch_const: int, mode_const: int, plat=None, *args, **kwargs):
        # must be set before super called, because its referenced in getattr

        super().__init__(arch_const, mode_const, *args, **kwargs)

        self.arch = ucutils.arch.get_arch(arch_const, mode_const)

        # public.
        self.mem = MemoryAccessor(self)

        # public.
        # mapping from address to symbolic name
        self.symbols: dict[int, str] = {}

        # public.
        self.is64 = mode_const == unicorn.UC_MODE_64

        # public.
        # platform specific helper instance from `ucutils.plat.*`.
        self.plat = ucutils.plat.bind(self, plat)

        # public.
        self.ptr_size = self.arch.get_ptr_size()

        # mapping from hook type to list of handlers.
        # we install a convenient handler that dispatches to each of the registered handlers
        #  (which are grouped by hook_type).
        self._hooks: dict[int, Any] = collections.defaultdict(lambda: [])
        # mapping from hook type to the handle representing that low level dispatch handler.
        self._handles: dict[int, int] = {}

        self._scratch = None

        self._dis = None

    @property
    def scratch(self):
        if self._scratch is None:
            self._scratch = self.mem.alloc(SCRATCH_SIZE, reason="scratch")
            logger.debug("mapped scratch space at 0x%x", self._scratch)

        return self._scratch

    @property
    def dis(self):
        if self._dis is None:
            self._dis = self.arch.get_capstone()
            assert self._dis is not None
            self._dis.detail = True
        return self._dis

    def _handle_hook(self, hook_type, *args, **kwargs):
        should_stop = False
        for fn in self._hooks[hook_type]:
            try:
                fn(*args, **kwargs)
            except Hook.Stop:
                logger.debug("hook asking to stop: %s", fn)
                should_stop = True

        if should_stop:
            logger.debug("stopping")
            self.emu_stop()

        # for memory events, this may not stop the emulator
        # see: https://github.com/unicorn-engine/unicorn/blob/master/include/unicorn/unicorn.h#L267
        # (return type of callback is void)
        #
        # therefore, we explicitly call `emu_stop()` above.
        return should_stop

    def hook_add(self, hook_type, fn):
        hook_list = self._hooks[hook_type]
        was_empty = len(hook_list) == 0
        self._hooks[hook_type].append(fn)
        if was_empty:
            handler = functools.partial(self._handle_hook, hook_type)
            handle = super().hook_add(hook_type, handler)
            self._handles[hook_type] = handle

    def hook_del(self, fn):
        if isinstance(fn, int):
            # TODO: handle better
            raise ValueError("this is an Emulator, not unicorn.Uc!")

        for hook_type, hook_list in self._hooks.items():
            try:
                hook_list.remove(fn)
            except ValueError:
                # it wasnt there
                pass
            else:
                if not hook_list:
                    super().hook_del(self._handles[hook_type])
                    del self._handles[hook_type]

    def go(self, addr):
        self.arch.emu_go(self, addr)

    def stepi(self):
        self.arch.emu_stepi(self)

    def push(self, val: int):
        self.stack_pointer -= self.ptr_size
        self.arch.emit_ptr(self, self.stack_pointer, val)

    def pop(self) -> int:
        r = self.arch.parse_ptr(self, self.stack_pointer)
        self.stack_pointer += self.ptr_size
        return r

    def __getattr__(self, k):
        """
        support reg access shortcut, like::

            print(hex(emu.pc))
            print(hex(emu.rax))

        register names are lowercase.
        `pc` is a shortcut for the platform program counter.
        """
        if k == "pc" or k == "program_counter":
            return self.arch.get_pc(self)
        elif k == "stack_pointer":
            return self.arch.get_sp(self)
        elif k == "base_pointer":
            return self.arch.get_bp(self)

        arch = unicorn.Uc.__getattribute__(self, "arch")
        # c = self.arch.S2C.get(k, None)
        c = arch.S2C.get(k, None)
        if c is None:
            # unicorn.Uc has no __getattr__, so fall back directly to __getattribute__
            return unicorn.Uc.__getattribute__(self, k)

        return self.reg_read(c)

    def __setattr__(self, k, v):
        """
        set reg shortcut, like::

            emu.pc  = 0x401000
            emu.rax = 0xAABBCCDD

        register names are lowercase.
        `pc` is a shortcut for the platform program counter.
        """
        if k == "pc" or k == "program_counter":
            return self.arch.set_pc(self, v)
        elif k == "stack_pointer":
            return self.arch.set_sp(self, v)
        elif k == "base_pointer":
            return self.arch.set_bp(self, v)

        if hasattr(self, "arch"):
            c = self.arch.S2C.get(k, None)
            if c is not None:
                return self.reg_write(c, v)

        return super().__setattr__(k, v)


class Hook:
    """
    note: for use with `Emulator` instances, not `unicorn.Uc` instances.
    """

    class Stop(Exception):
        pass

    HOOK_TYPE = NotImplementedError()

    def hook(self, *args, **kwargs):
        raise NotImplementedError()

    def install(self, emu):
        logger.debug("installing hook")
        emu.hook_add(self.HOOK_TYPE, self.hook)

    def uninstall(self, emu):
        logger.debug("uninstalling hook")
        # note: this doesn't work with vanilla `unicorn.Uc`.
        # would have to remove the hook by type.
        emu.hook_del(self.hook)


@contextlib.contextmanager
def hook(emu, hook):
    try:
        hook.install(emu)
        yield
    finally:
        hook.uninstall(emu)


class CodeLogger(Hook):
    """
    Example::

        cl = CodeLogger(dis)
        with hook(emu, cl):
            emu.go(0x401000)
    """

    HOOK_TYPE = unicorn.UC_HOOK_CODE

    def __init__(self, dis):
        super(Hook, self).__init__()
        self.dis = dis

    def hook(self, uc, address, size, user_data):
        buf = uc.mem_read(address, size)
        op = next(self.dis.disasm(bytes(buf), address))
        logger.debug("0x%x:\t%s\t%s" % (op.address, op.mnemonic, op.op_str))


class WriteLogger(Hook):
    """
    Example::

        wl = WriteLogger(dis)
        with hook(emu, wl):
            emu.go(0x401000)
    """

    HOOK_TYPE = unicorn.UC_HOOK_MEM_WRITE

    MEM_TYPES = {
        unicorn.UC_MEM_READ: "mem read",
        unicorn.UC_MEM_WRITE: "mem write",
        unicorn.UC_MEM_FETCH: "mem fetch",
        unicorn.UC_MEM_READ_UNMAPPED: "mem read (unmapped)",
        unicorn.UC_MEM_WRITE_UNMAPPED: "mem write (unmapped)",
        unicorn.UC_MEM_FETCH_UNMAPPED: "mem fetch (unmapped)",
        unicorn.UC_MEM_WRITE_PROT: "mem write (protected)",
        unicorn.UC_MEM_READ_PROT: "mem read (protected)",
        unicorn.UC_MEM_FETCH_PROT: "mem fetch (protected)",
        unicorn.UC_MEM_READ_AFTER: "mem read (after)",
    }

    def hook(self, uc, write_type, address, size, value, user_data):
        logger.debug(
            "%s: addr:0x%x size:0x%x value:0x%x",
            self.MEM_TYPES[write_type],
            address,
            size,
            value,
        )


PAGE_MASK = 0xFFFFFFFFFFFFE000


@contextlib.contextmanager
def context(emu):
    """
    provide a temporary emulation block, and restore the CPU context at the end.
    this won't restore memory, so be careful.

    example::

        assert emu.pc == 0xAAAA
        with context(emu):
            emu.go(0x401000)
            assert emu.pc == 0x401000
        assert emu.pc == 0xAAAA
    """
    try:
        ctx = emu.context_save()
        yield
    finally:
        emu.context_restore(ctx)
