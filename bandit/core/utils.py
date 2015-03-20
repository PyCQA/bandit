# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import _ast
import ast
import os.path
import symtable


"""Various helper functions."""


def ast_args_to_str(args):
        res = ('\n\tArgument/s:\n\t\t%s' %
               '\n\t\t'.join([ast.dump(arg) for arg in args]))
        return res


def _get_attr_qual_name(node, aliases):
    '''Get a the full name for the attribute node.

    This will resolve a pseudo-qualified name for the attribute
    rooted at node as long as all the deeper nodes are Names or
    Attributes. This will give you how the code referenced the name but
    will not tell you what the name actually refers to. If we
    encounter a node without a static name we punt with an
    empty string. If this encounters something more comples, such as
    foo.mylist[0](a,b) we just return empty string.

    :param node: AST Name or Attribute node
    :param aliases: Import aliases dictionary
    :returns: Qualified name refered to by the attribute or name.
    '''
    if type(node) == _ast.Name:
        if node.id in aliases:
            return aliases[node.id]
        return node.id
    elif type(node) == _ast.Attribute:
        name = '%s.%s' % (_get_attr_qual_name(node.value, aliases), node.attr)
        if name in aliases:
            return aliases[name]
        return name
    else:
        return ""


def get_call_name(node, aliases):
    if type(node.func) == _ast.Name:
        if deepgetattr(node, 'func.id') in aliases:
            return aliases[deepgetattr(node, 'func.id')]
        return(deepgetattr(node, 'func.id'))
    elif type(node.func) == _ast.Attribute:
        return _get_attr_qual_name(node.func, aliases)
    else:
        return ""


def get_func_name(node):
    return node.name  # TODO(tkelsey): get that qualname using enclosing scope


def get_qual_attr(node, aliases):
    prefix = ""
    if type(node) == _ast.Attribute:
        try:
            val = deepgetattr(node, 'value.id')
            if val in aliases:
                prefix = aliases[val]
            else:
                prefix = deepgetattr(node, 'value.id')
        except Exception:
            # NOTE(tkelsey): degrade gracefully when we cant get the fully
            # qualified name for an attr, just return its base name.
            pass

        return("%s.%s" % (prefix, node.attr))
    else:
        return ""  # TODO(tkelsey): process other node types


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


def lines_with_context(line_no, line_range, max_lines, file_len):
    '''Get affected lines, plus context

    This function takes a list of line numbers, adds one line
    before the specified range, and two lines after, to provide
    a bit more context. It then limits the number of lines to
    the specified max_lines value.
    :param line_no: The line of interest (trigger line)
    :param line_range: The lines that make up the whole statement
    :param max_lines: The maximum number of lines to output
    :return l_range: A list of line numbers to output
    '''

    # Catch a 0 or negative max lines, don't display any code
    if max_lines == 0:
        return []

    l_range = sorted(line_range)

    # add one line before before and after, to make sure we don't miss
    # any context.
    l_range.append(l_range[-1] + 1)
    l_range.append(l_range[0] - 1)

    l_range = sorted(l_range)

    if max_lines < 0:
        return l_range

    # limit scope to max_lines
    if len(l_range) > max_lines:
        # figure out a sane distribution of scope (extra lines after)
        after = (max_lines - 1) / 2
        before = max_lines - (after + 1)
        target = l_range.index(line_no)

        # skew things if the code is at the start or end of the statement

        if before > target:
            extra = before - target
            before = target
            after += extra

        gap = file_len - (target + 1)
        if gap < after:
            extra = after - gap
            after = gap
            before += extra

        # find start
        if before >= target:
            start = 0
        else:
            start = target - before

        # find end
        if target + after > len(l_range) - 1:
            end = len(l_range) - 1
        else:
            end = target + after

        # slice line array
        l_range = l_range[start:end + 1]

    return l_range


class InvalidModulePath(Exception):
    pass


def get_module_qualname_from_path(path):
    '''Get the module's qualified name by analysis of the path.

    Resolve the absolute pathname and eliminate symlinks. This could result in
    an incorrect name if symlinks are used to restructure the python lib
    directory.

    Starting from the right-most directory component look for __init__.py in
    the directory component. If it exists then the directory name is part of
    the module name. Move left to the subsequent directory components until a
    directory is found without __init__.py.

    :param: Path to module file. Relative paths will be resolved relative to
            current working directory.
    :return: fully qualified module name
    '''

    (head, tail) = os.path.split(path)
    if head == '' or tail == '':
        raise InvalidModulePath('Invalid python file path: "%s"'
                                ' Missing path or file name' % (path))

    qname = [os.path.splitext(tail)[0]]
    while head != '/':
        if os.path.isfile(os.path.join(head, '__init__.py')):
            (head, tail) = os.path.split(head)
            qname.insert(0, tail)
        else:
            break

    qualname = '.'.join(qname)
    return qualname


def namespace_path_join(base, name):
    '''Extend the current namespace path with an additional name

    Take a namespace path (i.e., package.module.class) and extends it
    with an additional name (i.e., package.module.class.subclass).
    This is similar to how os.path.join works.

    :param base: (String) The base namespace path.
    :param name: (String) The new name to append to the base path.
    :returns: (String) A new namespace path resulting from combination of
              base and name.
    '''
    return '%s.%s' % (base, name)


def namespace_path_split(path):
    '''Split the namespace path into a pair (head, tail).

    Tail will be the last namespace path component and head will
    be everything leading up to that in the path. This is similar to
    os.path.split.

    :param path: (String) A namespace path.
    :returns: (String, String) A tuple where the first component is the base
              path and the second is the last path component.
    '''
    return tuple(path.rsplit('.', 1))


def safe_unicode(obj, *args):
    '''return the unicode representation of obj.'''
    try:
        return unicode(obj, *args)
    except UnicodeDecodeError:
        # obj is byte string
        ascii_text = str(obj).encode('string_escape')
        return unicode(ascii_text)


def safe_str(obj):
    '''return the byte string representation of obj.'''
    try:
        return str(obj)
    except UnicodeEncodeError:
        # obj is unicode
        return unicode(obj).encode('unicode_escape')
