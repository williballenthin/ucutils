import logging

import ucutils


logger = logging.getLogger(__name__)


def emit_list_entry(emu, addr, flink, blink):
    ucutils.emit_ptr(emu, addr+0x0,          flink)
    ucutils.emit_ptr(emu, addr+emu.ptr_size, blink)


def init_list_entry(emu, addr):
    emit_list_entry(emu, addr, addr, addr)


def parse_list_entry(emu, addr):
    # TODO: use ptrsize
    return {
        'flink': ucutils.parse_ptr(emu, addr+0x0),
        'blink': ucutils.parse_ptr(emu, addr+emu.ptr_size),
    }


def emit_unicode(emu, addr, ustring):
    ucutils.emit_uint16(emu, addr+0x0, ustring['length'])
    ucutils.emit_uint16(emu, addr+0x2, ustring['maxlength'])
    ucutils.emit_ptr(emu, addr+0x4, ustring['address'])


def parse_unicode(emu, addr):
    u = {
        'length': ucutils.parse_uint16(emu, addr+0x0),
        'maxlength': ucutils.parse_uint16(emu, addr+0x2),
        'address': ucutils.parse_ptr(emu, addr+0x4),
    }

    u['s'] = emu.mem_read(u['address'], u['length']).decode('utf-16le')
    return u


def alloc_unicode(emu, s):
    buf = s.encode('utf-16le')
    if len(buf) > 0x1000:
        raise ValueError("can't allocate string longer than one page")

    addr = emu.mem.alloc(len(buf), reason='string: ' + s)
    emu.mem_write(addr, buf)
    return {
        'length': len(buf),
        'maxlength': len(buf),
        'address': addr,
        's': s,
    }


class DllAlreadyLoaded(ValueError): pass


def load_dll(emu, dll):
    '''
    Args:
      emu (ucutils.Emulator): the emulator instance.
      dll (Dict[str, any]): dictionary with keys:
        filename (str): DLL filename.
        pe (pefile.PE): the parsed PE file.

    Raises:
      DllAlreadyLoaded: if memory is already mapped at the preferred base address.
    '''
    pe = dll['pe']

    pe_addr = pe.OPTIONAL_HEADER.ImageBase
    if ucutils.probe_addr(emu, pe_addr):
        raise DllAlreadyLoaded('memory already mapped for pe: %s 0x%x' % (dll['filename'], pe_addr))

    dllbuf = pe.get_memory_mapped_image()
    dllsize = ucutils.align(len(dllbuf), 0x1000)
    logger.debug('mapping %s to 0x%x', dll['filename'], pe_addr)
    emu.mem.map_data(pe_addr, dllbuf, reason='DLL: ' + dll['filename'])

    basename = alloc_unicode(emu, dll['filename'])

    ldr_entry_addr = emu.mem.alloc(0x1000, reason='LDR_ENTRY_ADDR: ' + dll['filename'])
    logger.debug('ldr data for %s at 0x%x', dll['filename'], ldr_entry_addr)

    emu.plat.emit_ldr_data_table_entry(ldr_entry_addr, pe_addr,
                                       pe_addr+pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                                       dllsize, basename, basename)

    emu.plat.append_ldr_data_entry(ldr_entry_addr)

    for symbol in dll['pe'].DIRECTORY_ENTRY_EXPORT.symbols:
        if not symbol.name:
            continue
        sym_addr = pe_addr + symbol.address
        sym_name = '%s!%s' % (dll['filename'], symbol.name.decode('ascii'))
        emu.symbols[sym_addr] = sym_name
