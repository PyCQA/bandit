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

import ast

import bandit
from bandit.core.test_properties import *


@checks('Call')
def autoescape_false(context):
    # check type just to be safe
    if type(context.call_function_name_qual) == str:
        qualname_list = context.call_function_name_qual.split('.')
        func = qualname_list[-1]
        if 'jinja2' in qualname_list and func == 'Environment':
            for node in ast.walk(context.node):
                if isinstance(node, ast.keyword):
                    if (getattr(node, 'arg', None) == 'autoescape' and
                       getattr(node.value, 'id', None) == 'False'):
                        return(bandit.ERROR, 'Using jinja2 templates with'
                               ' autocomplete=False is dangerous and can'
                               ' lead to XSS')
                    if getattr(node, 'arg', None) == 'autoescape':
                        return(bandit.INFO, 'Using jinja2 templates with'
                               ' autocomplete=False is dangerous and can'
                               ' lead to XSS')
