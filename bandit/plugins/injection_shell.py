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
import re

import bandit
from bandit.core.test_properties import checks
from bandit.core.test_properties import takes_config


def _has_special_characters(command):
    # check if it contains any of the characters that may cause globing,
    # multiple commands, subshell, or variable resolution
    # glob: [ { * ?
    # variable: $
    # subshell: ` $
    return bool(re.search(r'[{|\[;$\*\?`]', command))


def _evaluate_shell_call(context):
    no_formatting = isinstance(context.node.args[0], ast.Str)
    if no_formatting:
        command = context.call_args[0]
        no_special_chars = not _has_special_characters(command)
    else:
        no_special_chars = False

    if no_formatting and no_special_chars:
        return bandit.LOW
    elif no_formatting:
        return bandit.MEDIUM
    else:
        return bandit.HIGH


@takes_config('shell_injection')
@checks('Call')
def subprocess_popen_with_shell_equals_true(context, config):
    if config and context.call_function_name_qual in config['subprocess']:
        if context.check_call_arg_value('shell', 'True'):
            if len(context.call_args) > 0:
                sev = _evaluate_shell_call(context)
                if sev == bandit.LOW:
                    return bandit.Issue(
                        severity=bandit.LOW,
                        confidence=bandit.HIGH,
                        text="subprocess call with shell=True seems safe, but "
                             "may be changed in the future, consider "
                             "rewriting without shell"
                    )
                elif sev == bandit.MEDIUM:
                    return bandit.Issue(
                        severity=bandit.MEDIUM,
                        confidence=bandit.HIGH,
                        text="call with shell=True contains special shell "
                             "characters, consider moving extra logic into "
                             "Python code"
                    )
                else:
                    return bandit.Issue(
                        severity=bandit.HIGH,
                        confidence=bandit.HIGH,
                        text="subprocess call with shell=True identified, "
                             "security issue."
                    )


@takes_config('shell_injection')
@checks('Call')
def subprocess_without_shell_equals_true(context, config):
    if config and context.call_function_name_qual in config['subprocess']:
        if not context.check_call_arg_value('shell', 'True'):
            return bandit.Issue(
                severity=bandit.LOW,
                confidence=bandit.HIGH,
                text="subprocess call - check for execution of untrusted "
                     "input."
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
                confidence=bandit.LOW,
                text="Function call with shell=True parameter identifed, "
                     "possible security issue."
                )


@takes_config('shell_injection')
@checks('Call')
def start_process_with_a_shell(context, config):
    if config and context.call_function_name_qual in config['shell']:
        if len(context.call_args) > 0:
            sev = _evaluate_shell_call(context)
            if sev == bandit.LOW:
                return bandit.Issue(
                    severity=bandit.LOW,
                    confidence=bandit.HIGH,
                    text="Starting a process with a shell: "
                         "Seems safe, but may be changed in the future, "
                         "consider rewriting without shell"
                )
            elif sev == bandit.MEDIUM:
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.HIGH,
                    text="Starting a process with a shell and special shell "
                         "characters, consider moving extra logic into "
                         "Python code"
                )
            else:
                return bandit.Issue(
                    severity=bandit.HIGH,
                    confidence=bandit.HIGH,
                    text="Starting a process with a shell, possible injection"
                         " detected, security issue."
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
                    text="Starting a process with a partial executable path"
                )
