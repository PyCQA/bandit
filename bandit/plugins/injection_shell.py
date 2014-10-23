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
from bandit.test_selector import *


@checks_functions
def subprocess_popen_with_shell_equals_true(context):
    if (context.call_function_name_qual == 'subprocess.Popen' or
            context.call_function_name_qual == 'utils.execute' or
            context.call_function_name_qual == 'utils.execute_with_timeout'):
        if context.check_call_arg_value('shell') == 'True':

            return(bandit.ERROR, 'Popen call with shell=True '
                   'identified, security issue.  %s' %
                   context.call_args_string)


@checks_functions
def any_other_function_with_shell_equals_true(context):
    # Alerts on any function call that includes a shell=True parameter
    # (multiple 'helpers' with varying names have been identified across
    # various OpenStack projects).
    if context.call_function_name_qual != 'subprocess.Popen':
        if context.check_call_arg_value('shell') == 'True':

            return(bandit.WARN, 'Function call with shell=True '
                   'parameter identified, possible security issue.  %s' %
                   context.call_args_string)
