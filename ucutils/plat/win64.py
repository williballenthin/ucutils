import logging

import ucutils
from ucutils.plat.win import *


logger = logging.getLogger(__name__)


# recall the PEB/TEB structure layout (64-bit)::
#
#     gs (TEB)         PEB             LDR_DATA
#    +----------+ +-->+----------+ +->+----------+ +-->+--------+  +--------+
#    |          | |   |          | |  |          | |   |        +->+        +->  load order list
#    |          | |   |          | |  | +10h +-----+   |        +<-+        +<-
#    |          | |   |          | |  |          |     +--------+  +--------+
#    |          | |   |          | |  | +20h +-------+
#    | +60h  +----+   | +18h +-----+  |          |   +>+--------+  +--------+
#    |          |     |          |    | +30h +-----+   |        +->+        +->  memory order list
#    |          |     |          |    |          | |   |        +<-+        +<-
#    +----------+     +----------+    +----------+ |   +--------+  +--------+
#                                                  |
#                                                  +-->+--------+  +--------+
#                                                      |        +->+        +->  init order list
#                                                      |        +<-+        +<-
#                                                      +--------+  +--------+

def emit_teb(emu, addr, peb_addr):
    logger.debug('emitting teb')
    ucutils.emit_ptr(emu, addr+0x60, peb_addr)


def parse_teb(emu, addr):
    return {
        'peb': ucutils.parse_ptr(emu, addr+0x60),
    }


def emit_peb(emu, addr, ldr_data_addr):
    logger.debug('emitting peb')
    ucutils.emit_ptr(emu, addr+0x18, ldr_data_addr)


def parse_peb(emu, addr):
    return {
        'ldr_data': ucutils.parse_ptr(emu, addr+0x18)
    }


def emit_ldr_data(emu, addr):
    logger.debug('emitting ldr data')
    load_order_addr = addr + 0x10
    mem_order_addr = addr + 0x20
    init_order_addr = addr + 0x30

    for list_addr in (load_order_addr, mem_order_addr, init_order_addr):
        init_list_entry(emu, list_addr)


def parse_ldr_data(emu, addr):
    return {
        'load_order_list': addr + 0x10,
        'mem_order_list': addr + 0x20,
        'init_order_list': addr + 0x30,
    }


def append_list_entry(emu, head_addr, entry_addr):
    head = parse_list_entry(emu, head_addr)
    prev_addr = head['blink']
    prev_entry = parse_list_entry(emu, prev_addr)

    emit_list_entry(emu, entry_addr, flink=head_addr, blink=prev_addr)

    if head['flink'] == head_addr:
        # list is empty
        emit_list_entry(emu, head_addr, flink=entry_addr, blink=entry_addr)
    else:
        emit_list_entry(emu, prev_addr, flink=entry_addr, blink=prev_entry['blink'])
        emit_list_entry(emu, head_addr, flink=head['flink'], blink=entry_addr)


def emit_ldr_data_table_entry(emu, addr,
                              dllbase_addr,
                              entrypoint_addr,
                              sizeofimage,
                              fulldllname_us,
                              basedllname_us):
    logger.debug('emitting ldr data table entry %s', fulldllname_us['s'])
    init_list_entry(emu, addr+0x00)  # load order
    init_list_entry(emu, addr+0x10)  # mem order
    init_list_entry(emu, addr+0x20)  # init order
    ucutils.emit_ptr(emu, addr+0x30, dllbase_addr)
    ucutils.emit_ptr(emu, addr+0x38, entrypoint_addr)
    ucutils.emit_uint32(emu, addr+0x40, sizeofimage)
    emu.plat.emit_unicode(addr+0x48, fulldllname_us)
    emu.plat.emit_unicode(addr+0x58, basedllname_us)


def get_teb_addr(emu):
    return ucutils.arch.x64.get_gs(emu, emu.scratch)


def map_teb(emu):
    '''
    allocate and initialize the TEB, PEB, and LDR_DATA structures.
    '''
    ldr_data_addr = emu.mem.alloc(0x1000, reason='LDR_DATA')
    emit_ldr_data(emu, ldr_data_addr)
    logger.debug('ldr data at 0x%x', ldr_data_addr)

    peb_addr = emu.mem.alloc(0x1000, reason='PEB')
    emit_peb(emu, peb_addr, ldr_data_addr)
    logger.debug('peb at 0x%x', peb_addr)

    teb_addr = emu.arch.map_gs(emu)
    emit_teb(emu, teb_addr, peb_addr)
    logger.debug('teb at 0x%x', teb_addr)


def append_ldr_data_entry(emu, entry_addr):
    teb_addr = get_teb_addr(emu)
    teb = parse_teb(emu, teb_addr)
    peb = parse_peb(emu, teb['peb'])
    ldr_data_addr = peb['ldr_data']

    # we'll just put all these in the same order
    append_list_entry(emu, ldr_data_addr+0x10, entry_addr+0x00)  # load lorder
    append_list_entry(emu, ldr_data_addr+0x20, entry_addr+0x10)  # mem lorder
    append_list_entry(emu, ldr_data_addr+0x30, entry_addr+0x20)  # init lorder
