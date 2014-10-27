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

import bandit
from bandit.core.test_selector import *


@checks_functions
def random_lib_calls(context):
    # Alerts on any usage of any random library function

    # check type just to be safe
    if type(context.call_function_name_qual) == str:
        qualname_list = context.call_function_name_qual.split('.')
        # if the library is random
        if len(qualname_list) >= 2 and qualname_list[-2] == 'random':
            return(bandit.INFO, 'Use of random is not suitable for security/'
                   'cryptographic purposes.')


@checks_imports
def random_lib_imports(context):
    # Alerts on importing the 'random' library

    if context.is_module_being_imported('random'):
        return(bandit.INFO, 'Random library should not be used for any '
               'security or cryptographic purposes')
