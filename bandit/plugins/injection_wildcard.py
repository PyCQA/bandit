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
from bandit.core.test_properties import *


@takes_config('shell_injection')
@checks('Call')
def linux_commands_wildcard_injection(context, config):
    if not ('shell' in config and 'subprocess' in config):
        return

    vulnerable_funcs = ['chown', 'chmod', 'tar', 'rsync']
    if context.call_function_name_qual in config['shell'] or (
            context.call_function_name_qual in config['subprocess'] and
            context.check_call_arg_value('shell', 'True')):
        if context.call_args_count >= 1:
            call_argument = context.get_call_arg_at_position(0)
            argument_string = ''
            if isinstance(call_argument, list):
                for li in call_argument:
                    argument_string = argument_string + ' %s' % li
            elif isinstance(call_argument, str):
                argument_string = call_argument

            if argument_string != '':
                for vulnerable_func in vulnerable_funcs:
                    if(
                            vulnerable_func in argument_string and
                            '*' in argument_string
                    ):
                        return bandit.Issue(
                            severity=bandit.HIGH,
                            confidence=bandit.MEDIUM,
                            text="Possible wildcard injection in call: %s" %
                                 context.call_function_name_qual
                        )
