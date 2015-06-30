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
from bandit.core.test_properties import checks
from bandit.core.test_properties import takes_config


@takes_config('shell_injection')
@checks('Call')
def subprocess_popen_with_shell_equals_true(context, config):
    if config and context.call_function_name_qual in config['subprocess']:
        if context.check_call_arg_value('shell', 'True'):
            return bandit.Issue(
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text="subprocess call with shell=True identified, security "
                     "issue.  %s" % context.call_args_string
            )


@takes_config('shell_injection')
@checks('Call')
def subprocess_without_shell_equals_true(context, config):
    if config and context.call_function_name_qual in config['subprocess']:
        if not context.check_call_arg_value('shell', 'True'):
            return bandit.Issue(
                severity=bandit.LOW,
                confidence=bandit.HIGH,
                text="subprocess call without a subshell."
            )


@takes_config('shell_injection')
@checks('Call')
def any_other_function_with_shell_equals_true(context, config):
    '''Alerts on any function call that includes a shell=True parameter.

    Multiple "helpers" with varying names have been identified across
    various OpenStack projects.
    '''
    if config and context.call_function_name_qual not in config['subprocess']:
        if context.check_call_arg_value('shell', 'True'):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.HIGH,
                text="Function call with shell=True parameter identifed, "
                     "possible security issue.  %s" % context.call_args_string
                )


@takes_config('shell_injection')
@checks('Call')
def start_process_with_a_shell(context, config):
    if config and context.call_function_name_qual in config['shell']:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            text="Starting a process with a shell: check for injection."
        )


@takes_config('shell_injection')
@checks('Call')
def start_process_with_no_shell(context, config):
    if config and context.call_function_name_qual in config['no_shell']:
        return bandit.Issue(
            severity=bandit.LOW,
            confidence=bandit.MEDIUM,
            text="Starting a process without a shell."
        )


@takes_config('shell_injection')
@checks('Call')
def start_process_with_partial_path(context, config):
    if config and len(context.call_args):
        if(context.call_function_name_qual in config['subprocess'] or
           context.call_function_name_qual in config['shell'] or
           context.call_function_name_qual in config['no_shell']):

            delims = ['/', '\\', '.']
            node = context.node.args[0]
            # some calls take an arg list, check the first part
            if isinstance(node, ast.List):
                node = node.elts[0]

            # make sure the param is a string literal and not a var name
            if(isinstance(node, ast.Str) and node.s[0] not in delims):
                return bandit.Issue(
                    severity=bandit.LOW,
                    confidence=bandit.HIGH,
                    text=("Starting a process with a partial executable path"
                          " %s" % context.call_args_string)
                )
