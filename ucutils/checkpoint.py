#!/usr/bin/env python
import logging
import contextlib

import unicorn

from ucutils import PAGE_SIZE
import ucutils.emu


logger = logging.getLogger(__name__)


class MemWriteTracker(ucutils.emu.Hook):
    HOOK_TYPE = unicorn.UC_HOOK_MEM_WRITE

    def __init__(self):
        super(ucutils.emu.Hook, self).__init__()

        # keys are the page starting addresses.
        # values are the contents of the page before the first write.
        self.original_pages = {}

    def hook(self, uc, optype, addr, size, value, data):
        page_addr = ucutils.get_page_base(addr)
        logger.debug('captured memory write: %x:%x@0x%x', value, size, addr)

        if page_addr in self.original_pages:
            return

        self.original_pages[page_addr] = uc.mem_read(page_addr, PAGE_SIZE)


def restore_pages(emu, tracker):
    for page_addr, page_buf in tracker.original_pages.items():
        emu.mem_write(page_addr, bytes(page_buf))


@contextlib.contextmanager
def checkpoint(emu):
    '''
    save the state of the emulator and restore it after executing some block of logic.
    the contents of the context manager are a dictionary with the keys:
      - written_pages (Map[int, bytes]): the address and contents of written pages

    example::
        emu.eax = 0x0
        with checkpoint(emu) as cp:
            emu.go(...)
            assert emu.eax == 69
            assert emu.mem[0x0:0x4] == 'AAAA'
        assert emu.eax == 0x0
        assert emu.mem[0x0:0x4] == '\x00\x00\x00\x00'
        assert 0x0 in cp['written_pages']
    '''

    # we are a little clever with this dictionary.
    # we'll yield it as the context manager block is entered, but it won't yet contain anything.
    # since dictionaries are mutable, we can place results into it after the block exits.
    ret = {}
    tracker = ucutils.checkpoint.MemWriteTracker()
    try:
        with ucutils.emu.context(emu):
            with ucutils.emu.hook(emu, tracker):
                yield ret

    finally:
        ret['written_pages'] = {page_addr: bytes(emu.mem_read(page_addr, PAGE_SIZE))
                                for page_addr in tracker.original_pages.keys()}
        restore_pages(emu, tracker)
