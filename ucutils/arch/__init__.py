#!/usr/bin/env python

import unicorn


def get_arch(arch, mode):
    if arch == unicorn.UC_ARCH_X86 and mode == unicorn.UC_MODE_32:
        # NB: dynamic import
        import ucutils.arch.x32

        return ucutils.arch.x32
    elif arch == unicorn.UC_ARCH_X86 and mode == unicorn.UC_MODE_64:
        # NB: dynamic import
        import ucutils.arch.x64

        return ucutils.arch.x64
    else:
        raise NotImplementedError()
