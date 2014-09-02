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

"""Defines a set of tests targeting Call nodes in the AST."""

import bandit
import stat
import re
from bandit.test_selector import *


@checks_functions
def call_bad_names(context):
    # TODO - move this out into configuration
    bad_name_sets = [
        (['pickle\.((loads)|(dumps))', ],
         'Pickle library appears to be in use, possible security issue.'),
        (['hashlib\.md5', ],
         'Use of insecure MD5 hash function.'),
        (['subprocess\.Popen', ],
         'Use of possibly-insecure system call function '
         '(subprocess.Popen).'),
        (['subprocess\.call', ],
         'Use of possibly-insecure system call function '
         '(subprocess.call).'),
        (['os.((exec)|(spawn))((l)|(le)|(lp)|(lpe)|(v)|(ve)|(vp)|(vpe))', ],
         'Use of possibly-insecure system call function '
         '(os.exec* or os.spawn*).'),
        (['os.popen((2)|(3)|(4))*', 'popen'],
         'Use of insecure / deprecated system call function '
         '(os.popen).'),
        (['os.startfile', 'startfile'],
         'Use of insecure system function (os.startfile).'),
        (['tempfile\.mktemp', 'mktemp'],
         'Use of insecure and deprecated function (mktemp).'),
        (['eval', ],
         'Use of possibly-insecure function - consider using the safer '
         'ast.literal_eval().'),
        (['mark_safe', ],
         'Use of mark_safe() may expose cross-site scripting vulnerabilities '
         'and should be reviewed.'),
    ]

    # test for 'bad' names defined above
    for bad_name_set in bad_name_sets:
        for bad_name_regex in bad_name_set[0]:
            # various tests we could do here, re.match works for now
            if re.match(bad_name_regex, context.call_function_name_qual):
                return(bandit.WARN, "%s  %s" %
                       (bad_name_set[1],
                        context.call_args_string))


@checks_functions
def call_subprocess_popen(context):
    if (context.call_function_name_qual == 'subprocess.Popen' or
            context.call_function_name_qual == 'utils.execute' or
            context.call_function_name_qual == 'utils.execute_with_timeout'):
        if context.check_call_arg_value('shell') == 'True':

            return(bandit.ERROR, 'Popen call with shell=True '
                   'identified, security issue.  %s' %
                   context.call_args_string)



@checks_functions
def call_shell_true(context):
    # Alerts on any function call that includes a shell=True parameter
    # (multiple 'helpers' with varying names have been identified across
    # various OpenStack projects).
    if context.call_function_name_qual != 'subprocess.Popen':
        if context.check_call_arg_value('shell') == 'True':

            return(bandit.WARN, 'Function call with shell=True '
                   'parameter identified, possible security issue.  %s' %
                   context.call_args_string)


@checks_functions
def call_no_cert_validation(context):
    if('requests' in context.call_function_name_qual and
            ('get' in context.call_function_name or
                    'post' in context.call_function_name)):

        if context.check_call_arg_value('verify') == 'False':

            return(bandit.ERROR, 'Requests call with verify=False '
                   'disabling SSL certificate checks, security issue.   %s' %
                   context.call_args_string)


@checks_functions
def call_bad_permissions(context):
    if 'chmod' in context.call_function_name:
        if context.call_args_count == 2:
            mode = context.get_call_arg_at_position(1)

            if mode is not None and (mode & stat.S_IWOTH or mode & stat.S_IXGRP):
                filename = context.get_call_arg_at_position(0)
                if filename is None:
                    filename = 'NOT PARSED'

                return(bandit.ERROR, 'Chmod setting a permissive mask %s on '
                       'file (%s).' % (oct(mode), filename))


@checks_functions
def call_wildcard_injection(context):
    system_calls = ['os.system', 'subprocess.Popen', 'os.popen']
    vulnerable_funcs = ['chown', 'chmod', 'tar', 'rsync']

    for system_call in system_calls:
        if system_call in context.call_function_name_qual:
            if context.call_args_count == 1:
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

                            return(bandit.ERROR, 'Possible wildcard injection '
                                   'in call: %s' % context.call_function_name_qual)

