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
import contextlib
import logging
import os.path
import sys


logger = logging.getLogger(__name__)


"""Various helper functions."""


@contextlib.contextmanager
def output_file(filename, filemode):
    try:
        out = sys.stdout
        if filename is not None:
            if os.path.isdir(filename):
                raise RuntimeError('Specified destination is a directory')
            out = open(filename, filemode)
        yield out
    except Exception:
        raise
    finally:
        if out is not sys.stdout:
            out.close()


def _get_attr_qual_name(node, aliases):
    '''Get a the full name for the attribute node.

    This will resolve a pseudo-qualified name for the attribute
    rooted at node as long as all the deeper nodes are Names or
    Attributes. This will give you how the code referenced the name but
    will not tell you what the name actually refers to. If we
    encounter a node without a static name we punt with an
    empty string. If this encounters something more complex, such as
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


class InvalidModulePath(Exception):
    pass


class NoConfigFileFound(Exception):
    def __init__(self, config_locations):
        message = ("no config found - tried: " +
                   ", ".join(config_locations))
        super(NoConfigFileFound, self).__init__(message)


class ConfigFileUnopenable(Exception):
    """Raised when the config file cannot be opened."""
    def __init__(self, config_file):
        self.config_file = config_file
        message = 'Could not open config file: %s' % self.config_file
        super(ConfigFileUnopenable, self).__init__(message)


class ConfigFileInvalidYaml(Exception):
    """Raised when the config file YAML cannot be parsed."""
    def __init__(self, config_file):
        self.config_file = config_file
        message = 'Invalid config file specified: %s' % self.config_file
        super(ConfigFileInvalidYaml, self).__init__(message)


def warnings_formatter(message,
                       category=UserWarning,
                       filename='',
                       lineno=-1,
                       line=''):
    '''Monkey patch for warnings.warn to suppress cruft output.'''
    return "{0}\n".format(message)


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


def escaped_bytes_representation(b):
    '''PY3 bytes need escaping for comparison with other strings.

    In practice it turns control characters into acceptable codepoints then
    encodes them into bytes again to turn unprintable bytes into printable
    escape sequences.

    This is safe to do for the whole range 0..255 and result matches
    unicode_escape on a unicode string.
    '''
    return b.decode('unicode_escape').encode('unicode_escape')


def linerange(node):
    """Get line number range from a node."""
    strip = {"body": None, "orelse": None,
             "handlers": None, "finalbody": None}
    for key in strip.keys():
        if hasattr(node, key):
            strip[key] = getattr(node, key)
            setattr(node, key, [])

    lines_min = 9999999999
    lines_max = -1
    for n in ast.walk(node):
        if hasattr(n, 'lineno'):
            lines_min = min(lines_min, n.lineno)
            lines_max = max(lines_max, n.lineno)

    for key in strip.keys():
        if strip[key] is not None:
            setattr(node, key, strip[key])

    if lines_max > -1:
        return list(range(lines_min, lines_max + 1))
    return [0, 1]


def linerange_fix(node):
    """Try and work around a known Python bug with multi-line strings."""
    # deal with multiline strings lineno behavior (Python issue #16806)
    lines = linerange(node)
    if hasattr(node, 'sibling') and hasattr(node.sibling, 'lineno'):
        start = min(lines)
        delta = node.sibling.lineno - start
        if delta > 1:
            return list(range(start, node.sibling.lineno))
    return lines


def concat_string(node, stop=None):
    '''Builds a string from a ast.BinOp chain.

    This will build a string from a series of ast.Str nodes wrapped in
    ast.BinOp nodes. Somthing like "a" + "b" + "c" or "a %s" % val etc.
    The provided node can be any participant in the BinOp chain.

    :param node: (ast.Str or ast.BinOp) The node to process
    :param stop: (ast.Str or ast.BinOp) Optional base node to stop at
    :returns: (Tuple) the root node of the expression, the string value
    '''
    def _get(node, bits, stop=None):
        if node != stop:
            bits.append(
                _get(node.left, bits, stop)
                if isinstance(node.left, ast.BinOp)
                else node.left)
            bits.append(
                _get(node.right, bits, stop)
                if isinstance(node.right, ast.BinOp)
                else node.right)

    bits = [node]
    while isinstance(node.parent, ast.BinOp):
        node = node.parent
    if isinstance(node, ast.BinOp):
        _get(node, bits, stop)
    return (node, " ".join([x.s for x in bits if isinstance(x, ast.Str)]))


def get_called_name(node):
    '''Get a function name from an ast.Call node.

    An ast.Call node representing a method call with present differently to one
    wrapping a function call: thing.call() vs call(). This helper will grab the
    unqualified call name correctly in either case.

    :param node: (ast.Call) the call node
    :returns: (String) the function name
    '''
    func = node.func
    try:
        return (func.attr if isinstance(func, ast.Attribute) else func.id)
    except AttributeError:
        return ""


def get_path_for_function(f):
    '''Get the path of the file where the function is defined.

    :returns: the path, or None if one could not be found or f is not a real
        function
    '''

    if hasattr(f, "__module__"):
        module_name = f.__module__
    elif hasattr(f, "im_func"):
        module_name = f.im_func.__module__
    else:
        logger.warn("Cannot resolve file where %s is defined", f)
        return None

    module = sys.modules[module_name]
    if hasattr(module, "__file__"):
        return module.__file__
    else:
        logger.warn("Cannot resolve file path for module %s", module_name)
        return None
