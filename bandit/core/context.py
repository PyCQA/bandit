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

from bandit.core import utils


class Context():
    def __init__(self, context_object=None):
        '''Initialize the class with a context, empty dict otherwise

        :param context_object: The context object to create class from
        :return: -
        '''
        if context_object is not None:
            self._context = context_object
        else:
            self._context = dict()

    def __repr__(self):
        '''Generate representation of object for printing / interactive use

        Most likely only interested in non-default properties, so we return
        the string version of _context.

        Example string returned:
        <Context {'node': <_ast.Call object at 0x110252510>, 'function': None,
        'name': 'socket', 'imports': set(['socket']), 'module': None,
        'filename': 'examples/binding.py',
        'call': <_ast.Call object at 0x110252510>, 'lineno': 3,
        'import_aliases': {}, 'qualname': 'socket.socket'}>

        :return: A string representation of the object
        '''
        return "<Context %s>" % self._context

    @property
    def call_args(self):
        '''Get a list of function args

        :return: A list of function args
        '''
        args = []
        for arg in self._context['call'].args:
            if hasattr(arg, 'attr'):
                args.append(arg.attr)
            else:
                args.append(self._get_literal_value(arg))
        return args

    @property
    def call_args_count(self):
        '''Get the number of args a function call has

        :return: The number of args a function call has
        '''
        if hasattr(self._context['call'], 'args'):
            return len(self._context['call'].args)
        else:
            return None

    @property
    def call_args_string(self):
        '''Get a string representation of the call arguments

        :return: Returns a string representation of the call arguments
        '''
        if 'call' in self._context and hasattr(self._context, 'args'):
            return utils.ast_args_to_str(self._context['call'].args)
        else:
            return ''

    @property
    def call_function_name(self):
        '''Get the name (not FQ) of a function call

        :return: The name (not FQ) of a function call
        '''
        if 'name' in self._context:
            return self._context['name']
        else:
            return None

    @property
    def call_function_name_qual(self):
        '''Get the FQ name of a function call

        :return: The FQ name of a function call
        '''
        if 'qualname' in self._context:
            return self._context['qualname']
        else:
            return None

    @property
    def call_keywords(self):
        '''Get a dictionary of keyword parameters

        :return: A dictionary of keyword parameters for a call as strings
        '''
        if (
            'call' in self._context and
            hasattr(self._context['call'], 'keywords')
        ):
            return_dict = {}
            for li in self._context['call'].keywords:
                if hasattr(li.value, 'attr'):
                    return_dict[li.arg] = li.value.attr
                else:
                    return_dict[li.arg] = self._get_literal_value(li.value)
            return return_dict
        else:
            return None

    @property
    def node(self):
        '''Get the raw AST node associated with the context

        :return: The raw AST node associated with the context
        '''
        if 'node' in self._context:
            return self._context['node']
        else:
            return None

    @property
    def string_val(self):
        '''Get a string value of a standalone string

        :return: String value of a standalone string
        '''
        if 'str' in self._context:
            return utils.safe_str(self._context['str'])
        else:
            return None

    @property
    def statement(self):
        '''Get the raw AST for the current statement

        :return: The raw AST for the current statement
        '''
        if 'statement' in self._context:
            return self._context['statement']
        else:
            return None

    @property
    def function_def_defaults_qual(self):
        '''Get a list of fully qualified default values in a function def

        :return: List of defaults
        '''
        defaults = []
        for default in self._context['node'].args.defaults:
            defaults.append(utils.get_qual_attr(
                default,
                self._context['import_aliases']))
        return defaults

    def _get_literal_value(self, literal):
        '''Utility function to turn AST literals into native Python types

        :param literal: The AST literal to convert
        :return: The value of the AST literal
        '''
        if isinstance(literal, _ast.Num):
            return literal.n

        elif isinstance(literal, _ast.Str):
            return literal.s

        # Python 3 only
        # elif isinstance(literal, _ast.Bytes):
        #    return literal.s

        elif isinstance(literal, _ast.List):
            return_list = list()
            for li in literal.elts:
                return_list.append(self._get_literal_value(li))
            return return_list

        elif isinstance(literal, _ast.Tuple):
            return_tuple = tuple()
            for ti in literal.elts:
                return_tuple = return_tuple + (self._get_literal_value(ti),)
            return return_tuple

        elif isinstance(literal, _ast.Set):
            return_set = set()
            for si in literal.elts:
                return_set.add(self._get_literal_value(si))
            return return_set

        elif isinstance(literal, _ast.Dict):
            return dict(zip(literal.keys, literal.values))

        elif isinstance(literal, _ast.Ellipsis):
            # what do we want to do with this?
            pass

        # Python 3 only
        # elif isinstance(literal, _ast.NameConstant):
        #    return literal.value

        elif isinstance(literal, _ast.Name):
            return literal.id

        else:
            return None

    def check_call_arg_value(self, argument_name, argument_values=None):
        '''Checks for a value of a named argument in a function call.

        Returns none if the specified argument is not found.
        :param argument_name: A string - name of the argument to look for
        :param argument_values: the value, or list of values to test against
        :return: Boolean True if argument found and matched, False if
        found and not matched, None if argument not found at all
        '''
        kwd_values = self.call_keywords
        if (kwd_values is not None and
                argument_name in kwd_values):
            if not isinstance(argument_values, list):
                # if passed a single value, or a tuple, convert to a list
                argument_values = list((argument_values,))
            for val in argument_values:
                if kwd_values[argument_name] == val:
                    # if matched, fix up the context lineno for reporting
                    self.set_lineno_for_call_arg(argument_name)
                    return True
            return False
        else:
            # argument name not found, return None to allow testing for this
            # eventuality
            return None

    def set_lineno_for_call_arg(self, argument_name):
        '''Updates the line number for a specific named argument

        If a call is split over multiple lines, when a keyword arg is found
        the issue will be reported with the line number of the start of the
        call. This function updates the line number in the current context
        copy to match the actual line where the match occurs.
        :call_node: the call to find the argument in
        :param argument_name: A string - name of the argument to look for
        :return: Integer - the line number of the found argument
        '''
        for key in self.node.keywords:
            if key.arg is argument_name:
                self._context['lineno'] = key.value.lineno

    def get_call_arg_at_position(self, position_num):
        '''Returns positional argument at the specified position (if it exists)

        :param position_num: The index of the argument to return the value for
        :return: Value of the argument at the specified position if it exists
        '''
        if (
            hasattr(self._context['call'], 'args') and
            position_num < len(self._context['call'].args)
        ):
            return self._get_literal_value(
                self._context['call'].args[position_num]
            )
        else:
            return None

    def is_module_being_imported(self, module):
        '''Check for the specified module is currently being imported

        :param module: The module name to look for
        :return: True if the module is found, False otherwise
        '''
        if 'module' in self._context and self._context['module'] == module:
            return True
        else:
            return False

    def is_module_imported_exact(self, module):
        '''Check if a specified module has been imported; only exact matches.

        :param module: The module name to look for
        :return: True if the module is found, False otherwise
        '''
        if 'imports' in self._context and module in self._context['imports']:
            return True
        else:
            return False

    def is_module_imported_like(self, module):
        '''Check if a specified module has been imported

        Check if a specified module has been imported; specified module exists
        as part of any import statement.
        :param module: The module name to look for
        :return: True if the module is found, False otherwise
        '''
        if 'imports' in self._context:
            for imp in self._context['imports']:
                if module in imp:
                    return True
        return False
