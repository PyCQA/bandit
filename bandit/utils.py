#!/usr/bin/env python

import symtable

"""Various helper functions."""

sev = [ 'INFO', 'WARN', 'ERROR' ]

color = {
    'DEFAULT': '\033[0m',
    'HEADER': '\033[95m',
    'INFO': '\033[94m',
    'WARN': '\033[93m',
    'ERROR': '\033[91m',
}

def deepgetattr(obj, attr):
    """Recurses through an attribute chain to get the ultimate value."""
    for key in attr.split('.'):
        obj = getattr(obj, key)
    return obj

def describe_symbol(sym):
    assert type(sym) == symtable.Symbol
    print("Symbol:", sym.get_name())

    for prop in [
            'referenced', 'imported', 'parameter',
            'global', 'declared_global', 'local',
            'free', 'assigned', 'namespace']:
        if getattr(sym, 'is_' + prop)():
            print('    is', prop)

def mid_range(mid, count):
    if count == 1:
        return range(mid, mid + 1)
    diff = count / 2
    if count % 2 == 0:
        start = mid - diff
        stop = mid + diff
    else:
        start = mid - diff
        stop = mid + diff + 1
    if start < 1:
        stop = stop + (start * -1) + 1
        start = 1
    return range(start, stop)

