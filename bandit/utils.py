#!/usr/bin/env python

import symtable
import ast, _ast

"""Various helper functions."""

sev = [ 'INFO', 'WARN', 'ERROR' ]

color = {
    'DEFAULT': '\033[0m',
    'HEADER': '\033[95m',
    'INFO': '\033[94m',
    'WARN': '\033[93m',
    'ERROR': '\033[91m',
}

def ast_args_to_str(args):
        res = '\n\tArgument/s:\n\t\t%s' % '\n\t\t'.join([ast.dump(arg) for arg in args])
        res = ''
        return res

def get_call_name(node):
    if type(node.func) == _ast.Name:
        return(deepgetattr(node, 'func.id'))
    elif type(node.func) == _ast.Attribute:
        prefix = ""
        if type(node.func.value) == _ast.Name:
            prefix = deepgetattr(node, 'func.value.id') + "."
        return("%s%s" % (prefix, deepgetattr(node, 'func.attr')))


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

