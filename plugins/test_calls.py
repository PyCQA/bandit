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
from bandit import utils
import ast
import _ast
import stat
import re


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
    ]

    # test for 'bad' names defined above
    for bad_name_set in bad_name_sets:
        for bad_name_regex in bad_name_set[0]:
            # various tests we could do here, re.match works for now
            if re.match(bad_name_regex, context['qualname']):
                return(bandit.WARN, "%s  %s" %
                       (bad_name_set[1],
                        utils.ast_args_to_str(context['call'].args)))


def call_subprocess_popen(context):
    if context['qualname'] == 'subprocess.Popen':
        if hasattr(context['call'], 'keywords'):
            for k in context['call'].keywords:
                if k.arg == 'shell' and isinstance(k.value, _ast.Name):
                    if k.value.id == 'True':
                        return(bandit.ERROR, 'Popen call with shell=True '
                               'identified, security issue.  %s' %
                               utils.ast_args_to_str(context['call'].args))


def call_shell_true(context):
    # Alerts on any function call that includes a shell=True parameter
    # (multiple 'helpers' with varying names have been identified across
    # various OpenStack projects).
    if context['qualname'] != 'subprocess.Popen':
        if hasattr(context['call'], 'keywords'):
            for k in context['call'].keywords:
                if k.arg == 'shell' and isinstance(k.value, _ast.Name):
                    if k.value.id == 'True':
                        return(bandit.WARN, 'Function call with shell=True '
                               'parameter identified, possible security '
                               'issue.  %s'
                                % utils.ast_args_to_str(context['call'].args))


def call_no_cert_validation(context):
    if 'requests' in context['qualname'] and ('get' in context['name'] or
                                              'post' in context['name']):
        if hasattr(context['call'], 'keywords'):
            for k in context['call'].keywords:
                if k.arg == 'verify' and isinstance(k.value, _ast.Name):
                    if k.value.id == 'False':
                        return(bandit.ERROR,
                               'Requests call with verify=False '
                               'disabling SSL certificate checks, '
                               'security issue.   %s' %
                               utils.ast_args_to_str(context['call'].args))


def call_bad_permissions(context):
    if 'chmod' in context['name']:
        if (hasattr(context['call'], 'args')):
            args = context['call'].args
            if len(args) == 2 and isinstance(args[1],  _ast.Num):
                if ((args[1].n & stat.S_IWOTH) or
                   (args[1].n & stat.S_IXGRP)):
                    filename = args[0].s if hasattr(args[0], 's') \
                        else 'NOT PARSED'
                    return(bandit.ERROR,
                           'Chmod setting a permissive mask '
                           '%s on file (%s).' %
                           (oct(args[1].n), filename))


def call_wildcard_injection(context):
    system_calls = ['os.system', 'subprocess.Popen', 'os.popen']
    vulnerable_funcs = ['chown', 'chmod', 'tar', 'rsync']

    for system_call in system_calls:
        if system_call in context['qualname']:
            if(hasattr(context['call'], 'args')):
                call_argument = None
                if len(context['call'].args) == 1:
                    if hasattr(context['call'].args[0], 's'):
                        call_argument = context['call'].args[0].s
                    elif hasattr(context['call'].args[0], 'elts'):
                        call_argument = ' '.join(
                            [n.s for n in context['call'].args[0].elts]
                        )
                if call_argument is not None:
                    for vulnerable_func in vulnerable_funcs:
                        if (
                            vulnerable_func in call_argument
                            and '*' in call_argument
                        ):

                            return(
                                bandit.ERROR,
                                'Possible wildcard injection in call: %s' % (
                                    context['qualname']
                                )
                            )
