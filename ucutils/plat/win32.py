import logging

import ucutils
import ucutils.plat.win as ucwin

logger = logging.getLogger(__name__)


# recall the PEB/TEB structure layout (32-bit)::
#
#     gs (TEB)         PEB             LDR_DATA
#    +----------+ +-->+----------+ +->+----------+ +-->+--------+  +--------+
#    |          | |   |          | |  |          | |   |        +->+        +->  load order list
#    |          | |   |          | |  | +0Ch +-----+   |        +<-+        +<-
#    |          | |   |          | |  |          |     +--------+  +--------+
#    |          | |   |          | |  | +14h +-------+
#    | +30h  +----+   | +0Ch +-----+  |          |   +>+--------+  +--------+
#    |          |     |          |    | +1Ch +-----+   |        +->+        +->  memory order list
#    |          |     |          |    |          | |   |        +<-+        +<-
#    +----------+     +----------+    +----------+ |   +--------+  +--------+
#                                                  |
#                                                  +-->+--------+  +--------+
#                                                      |        +->+        +->  init order list
#                                                      |        +<-+        +<-
#                                                      +--------+  +--------+

OFFSET_PEB = 0x30
OFFSET_LDR_DATA = 0xC
OFFSET_IN_LOAD_ORDER = 0x0C
OFFSET_IN_MEM_ORDER = 0x14
OFFSET_IN_INIT_ORDER = 0x1C


def emit_teb(emu, teb_addr, peb_addr):
    logger.debug("emitting teb")
    ucutils.emit_ptr(emu, teb_addr + OFFSET_PEB, peb_addr)


def parse_teb(emu, teb_addr):
    print("parse teb: " + hex(teb_addr))
    return {
        "peb": ucutils.parse_ptr(emu, teb_addr + OFFSET_PEB),
    }


def emit_peb(emu, peb_addr, ldr_data_addr):
    logger.debug("emitting peb")
    ucutils.emit_ptr(emu, peb_addr + OFFSET_LDR_DATA, ldr_data_addr)


def parse_peb(emu, peb_addr):
    return {"ldr_data": ucutils.parse_ptr(emu, peb_addr + OFFSET_LDR_DATA)}


def emit_ldr_data(emu, ldr_addr):
    logger.debug("emitting ldr data")
    load_order_addr = ldr_addr + OFFSET_IN_LOAD_ORDER
    mem_order_addr = ldr_addr + OFFSET_IN_MEM_ORDER
    init_order_addr = ldr_addr + OFFSET_IN_INIT_ORDER

    for list_addr in (load_order_addr, mem_order_addr, init_order_addr):
        ucwin.init_list_entry(emu, list_addr)


def parse_ldr_data(emu, ldr_addr):
    return {
        "load_order_list": ldr_addr + OFFSET_IN_LOAD_ORDER,
        "mem_order_list": ldr_addr + OFFSET_IN_MEM_ORDER,
        "init_order_list": ldr_addr + OFFSET_IN_INIT_ORDER,
    }


def append_list_entry(emu, head_addr, entry_addr):
    head = ucwin.parse_list_entry(emu, head_addr)
    prev_addr = head["blink"]
    prev_entry = ucwin.parse_list_entry(emu, prev_addr)

    ucwin.emit_list_entry(emu, entry_addr, flink=head_addr, blink=prev_addr)

    if head["flink"] == head_addr:
        # list is empty
        ucwin.emit_list_entry(emu, head_addr, flink=entry_addr, blink=entry_addr)
    else:
        ucwin.emit_list_entry(emu, prev_addr, flink=entry_addr, blink=prev_entry["blink"])
        ucwin.emit_list_entry(emu, head_addr, flink=head["flink"], blink=entry_addr)


def emit_ldr_data_table_entry(
    emu,
    ldr_addr,
    dllbase_addr,
    entrypoint_addr,
    sizeofimage,
    fulldllname_us,
    basedllname_us,
):
    logger.debug("emitting ldr data table entry %s", fulldllname_us["s"])
    ucwin.init_list_entry(emu, ldr_addr + 0x00)  # load order
    ucwin.init_list_entry(emu, ldr_addr + 0x08)  # mem order
    ucwin.init_list_entry(emu, ldr_addr + 0x10)  # init order
    ucutils.emit_ptr(emu, ldr_addr + 0x18, dllbase_addr)
    ucutils.emit_ptr(emu, ldr_addr + 0x1C, entrypoint_addr)
    emu.plat.emit_unicode(ldr_addr + 0x24, fulldllname_us)
    emu.plat.emit_unicode(ldr_addr + 0x2C, basedllname_us)


def get_teb_addr(emu):
    gdt = ucutils.arch.x32.get_gdt(emu)
    return ucutils.arch.x32.get_fs(emu, gdt)


def map_teb(emu):
    """
    allocate and initialize the TEB, PEB, and LDR_DATA structures.
    """
    ldr_data_addr = emu.mem.alloc(0x1000, reason="LDR_DATA")
    emit_ldr_data(emu, ldr_data_addr)
    logger.debug("ldr data at 0x%x", ldr_data_addr)

    peb_addr = emu.mem.alloc(0x1000, reason="PEB")
    emit_peb(emu, peb_addr, ldr_data_addr)
    logger.debug("peb at 0x%x", peb_addr)

    teb_addr = emu.arch.map_fs(emu)
    emit_teb(emu, teb_addr, peb_addr)
    logger.debug("teb at 0x%x", teb_addr)


def append_ldr_data_entry(emu, entry_addr):
    teb_addr = get_teb_addr(emu)
    teb = parse_teb(emu, teb_addr)
    peb = parse_peb(emu, teb["peb"])
    ldr_data_addr = peb["ldr_data"]

    # we'll just put all these in the same order
    append_list_entry(emu, ldr_data_addr + 0x8, entry_addr + 0x00)  # load lorder
    append_list_entry(emu, ldr_data_addr + 0x10, entry_addr + 0x8)  # mem lorder
    append_list_entry(emu, ldr_data_addr + 0x18, entry_addr + 0x10)  # init lorder
