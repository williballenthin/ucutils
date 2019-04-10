import os
import sys
import logging

import ucutils
import unicorn
import argparse

import ucutils.emu
import ucutils.cli
import ucutils.plat.win32


logger = logging.getLogger(__name__)


class WriteLogger(ucutils.emu.Hook):
    '''
    Example::

        wl = WriteLogger(dis)
        with hook(emu, wl):
            emu.go(0x401000)
    '''
    HOOK_TYPE = unicorn.UC_HOOK_MEM_WRITE

    def __init__(self, dis):
        super(Hook, self).__init__()

    def hook(self, uc, address, size, user_data):
        buf = uc.mem_read(address, size)
        op = next(self.dis.disasm(bytes(buf), address))
        logger.debug("0x%x:\t%s\t%s" % (op.address, op.mnemonic, op.op_str))


def load(emu, sc_addr, sc, dlls):
    '''
    load the shellcode at the given address, and map in the given DLLs.
    maps the following:
      - instructions
      - TEB, PEB, and LDR_DATA
      - stack
      - each DLL
    '''

    logger.debug('mapping instructions at 0x%x', sc_addr)
    emu.mem.map_data(sc_addr, sc, reason='code')

    # stack layout:
    #
    #   min-addr -> STACK_ADDR
    #   $sp ------> STACK_ADDR + 0x1000
    #   $bp ------> STACK_ADDR + 0x2000
    #   max-addr -> STACK_ADDR + 0x3000
    logger.debug('mapping stack at 0x%x', ucutils.STACK_ADDR)
    emu.mem.map_region(ucutils.STACK_ADDR, ucutils.STACK_SIZE, reason='stack')
    emu.stack_pointer = ucutils.STACK_ADDR + 0x1000
    emu.base_pointer = ucutils.STACK_ADDR + 0x2000

    emu.plat.map_teb()

    for dll in dlls:
        emu.plat.load_dll(dll)

    return sc_addr


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="CLI to emulate shellcode.")
    parser.add_argument("input", type=str,
                        help="Path to input file")
    parser.add_argument("dlls", type=str, nargs='*',
                        help="Paths to DLL files to map")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Disable all output but errors")
    parser.add_argument("-c", type=str, help="Commands to run")
    args = parser.parse_args(args=argv)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR)
        logging.getLogger().setLevel(logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    with open(args.input, 'rb') as f:
        sc = f.read()

    dlls = []
    for dllpath in args.dlls:
        pe = pefile.PE(dllpath)
        dlls.append({
            'filename': os.path.basename(dllpath),
            'path': dllpath,
            'pe': pe
        })

    emu = ucutils.emu.Emulator(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32, plat=ucutils.plat.win32)

    load(emu, ucutils.CODE_ADDR, sc, dlls)
    emu.program_counter = ucutils.CODE_ADDR

    cl = ucutils.emu.CodeLogger(emu.arch.get_capstone())
    cl.install(emu)

    cli = ucutils.cli.UnicornCli(emu)
    if args.c:
        for cmd in args.c.split(';'):
            print(cmd)
            if not cmd:
                continue
            if cli.onecmd(cmd):
                break
    else:
        cli.cmdloop()

    return 0


if __name__ == "__main__":
    sys.exit(main())



