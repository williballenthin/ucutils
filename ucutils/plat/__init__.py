import functools


class Wrapper(object):
    def __init__(self, emu, plat):
        self.emu = emu
        self.plat = plat

    def __getattr__(self, k):
        o = getattr(self.plat, k)
        if callable(o):
            return functools.partial(o, self.emu)
        else:
            return o


def bind(emu, plat):
    '''
    return an object that behaves like a `ucutils.plat.*` instance,
    and if a property is called, passes the given emulator as the first argument
    '''
    return Wrapper(emu, plat)
