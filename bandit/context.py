# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import _ast
import re
from bandit import utils

class Context():
    def __init__(self, context_object=None):
        '''
        Initialize the class with a context, empty dict otherwise
        :param context_object: The context object to create class from
        :return: -
        '''
        if context_object is not None:
            self._context = context_object
        else:
            self._context = dict()

    @property
    def call_args_string(self):
        '''
        :return: Returns a string representation of the call arguments
        '''
        if 'call' in self._context and hasattr(self._context, 'args'):
            return utils.ast_args_to_str(self._context['call'].args)
        else:
            return ''

    @property
    def call_keywords(self):
        if('call' in self._context and
               hasattr(self._context['call'],'keywords')):
            return self._context['call'].keywords
        else:
            return None

    @property
    def function_name(self):
        '''
        :return: The name (not FQ) of a function call
        '''
        if 'name' in self._context:
            return self._context['name']
        else:
            return None

    @property
    def num_of_call_args(self):
        '''
        :return: The number of args a function call has
        '''
        if hasattr(self._context['call'], 'args'):
            return len(self._context['call'].args)
        else:
            return None

    @property
    def qual_function_name(self):
        '''
        :return: The FQ name of a function call
        '''
        if 'qualname' in self._context:
            return self._context['qualname']
        else:
            return None

    @property
    def string(self):
        '''
        :return: String value of a standalone string
        '''
        if 'str' in self._context:
            return self._context['str']
        else:
            return None

    def _get_literal_value(self, literal):
        '''
        Utility function to turn AST literals into native Python types
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
                return_tuple = return_tuple + self._get_literal_value(ti)
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

    def check_call_arg_value(self, argument_name):
        """
        Checks for a value of a named argument in a function call.  Returns
        none if the specified argument is not found.
        :param argument_name: A string - name of the argument to look for
        :return: String value of the argument if found, None otherwise
        """
        for k in self.call_keywords:
            if k.arg == argument_name and isinstance(k.value, _ast.Name):
                return k.value.id
        return None

    def get_call_argument_at_position(self, position_num):
        """
        Returns the positional argument at the specified position (if it exists)
        :param position_num: The index of the argument to return the value for
        :return: The value of the argument at the specified position if it exists
        """
        if(hasattr(self._context['call'], 'args') and
                   position_num < len(self._context['call'].args)):
            return self._get_literal_value(self._context['call'].args[position_num])
        else:
            return None

    def is_module_imported(self, module):
        '''
        Check for the import of a module
        :param module: The module name to look for
        :return: True if the module is found, False otherwise
        '''
        if 'module' in self._context and self._context['module'] == module:
            return True
        else:
            return False
