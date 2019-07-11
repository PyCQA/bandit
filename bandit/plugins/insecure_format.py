#
# Copyright (C) 2019 [Victor Torre](https://github.com/ehooo)
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

import six

import bandit
from bandit.core import test_properties as test


def is_param(node, name):
    if isinstance(node, ast.FunctionDef):
        for param_name in node.args.args:
            arg_name = param_name.id if six.PY2 else param_name.arg
            if arg_name == name:
                return True
    return False


def is_no_assigned_to_str(node, name):
    if isinstance(node, ast.AugAssign):
        if isinstance(node.target, ast.Name):
            if node.target.id == name:
                return not isinstance(node.value, ast.Str)
    elif isinstance(node, ast.Assign) and node.targets:
        for target in node.targets:
            if isinstance(target, ast.Name):
                if target.id == name:
                    return not isinstance(node.value, ast.Str)
            elif isinstance(target, ast.Tuple):
                pos = 0
                for tg in target.elts:
                    if tg.id == name:
                        value = node.value.elts[pos]
                        return not isinstance(value, ast.Str)
                    pos += 1


def find_no_assigned_to_str(node, name, lineno):
    no_assigned = None
    for field in node._fields:
        nodes = getattr(node, field)
        if isinstance(nodes, (list, tuple)):
            for child in nodes:
                if hasattr(child, 'lineno') and lineno < child.lineno:
                    continue
                if isinstance(child,
                              (ast.Module, ast.FunctionDef, ast.ClassDef)):
                    continue
                if isinstance(child, ast.AST):
                    no_assigned = is_no_assigned_to_str(child, name)
                    if no_assigned is None:
                        no_assigned = find_no_assigned_to_str(
                            child, name, lineno
                        )
                if no_assigned:
                    break
        elif isinstance(nodes, ast.AST):
            if hasattr(nodes, 'lineno') and lineno < nodes.lineno:
                return
            if isinstance(nodes, (ast.Module, ast.FunctionDef, ast.ClassDef)):
                continue
            no_assigned = is_no_assigned_to_str(nodes, name)
            if no_assigned is None:
                no_assigned = find_no_assigned_to_str(nodes, name, lineno)

        if no_assigned:
            return no_assigned


def check_risk(node, name):
    start_scope = node._bandit_parent
    while not isinstance(start_scope,
                         (ast.Module, ast.FunctionDef, ast.ClassDef)):
        start_scope = start_scope._bandit_parent

    if is_param(start_scope, name):
        return True

    found_other = find_no_assigned_to_str(start_scope, name, node.lineno)
    if found_other:
        return True


@test.checks('Call')
@test.test_id('B612')
def insecure_format(context):
    """**B612: Wrong use of format string can discover internal reprs**

    .. seealso::

     - http://lucumr.pocoo.org/2016/12/29/careful-with-str-format/

    .. versionadded:: 1.5.2

    """
    description = "Wrong use of format string can discover internal reprs " \
                  "as the recommended way to solve it use string.Template"
    if context.call_function_name == 'format':
        if isinstance(context.node, ast.Call):
            value = context.node.func.value
            if isinstance(value, ast.Str):
                return None  # Hard-code string is secure
            elif isinstance(value, ast.Name):
                if check_risk(context.node, value.id):
                    return bandit.Issue(
                        severity=bandit.MEDIUM,
                        confidence=bandit.HIGH,
                        text=description
                    )
            else:
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.HIGH,
                    text=description
                )
