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


HIT_VALUE = bandit.Issue(
    severity=bandit.MEDIUM,
    confidence=bandit.HIGH,
    text="Wrong use of format string can discover internal reprs"
)


def is_param(node, name):
    if (isinstance(node, ast.Name) and
            isinstance(node, ast.FunctionDef)):
        for name in node.args.args:
            arg_name = name.id if six.PY2 else name.arg
            if arg_name == name:
                return True
    return False


def is_assigned_to_str(node, name):
    if isinstance(node, ast.AugAssign):
        if isinstance(node.target, ast.Name):
            if node.target.id == name:
                return isinstance(node.value, ast.Str)
    elif isinstance(node, ast.Assign) and node.targets:
        for target in node.targets:
            if isinstance(target, ast.Name):
                if target.id == name:
                    return isinstance(node.value, ast.Str)
            elif isinstance(target, ast.Tuple):
                pos = 0
                for name in target.elts:
                    if name.id == name:
                        value = node.value.elts[pos]
                        return isinstance(value, ast.Str)
                    pos += 1


def find_assigned_to_str(node, name, lineno):
    assigned = None
    for field in node._fields:
        nodes = getattr(node, field)
        if isinstance(nodes, (list, tuple)):
            for child in nodes:
                if lineno > child.lineno:
                    continue
                if isinstance(child, ast.AST):
                    assigned = is_assigned_to_str(child, name)
                    if assigned is None:
                        assigned = find_assigned_to_str(child, name, lineno)
                if assigned is False:
                    break
        elif isinstance(nodes, ast.AST):
            if lineno > nodes.lineno:
                return
            assigned = is_assigned_to_str(nodes, name)
            if assigned is None:
                assigned = find_assigned_to_str(nodes, name, lineno)

        if assigned is False:
            return assigned


def check_risk(node, name):
    start_scope = node.parent
    while not isinstance(start_scope, (ast.Module, ast.FunctionDef)):
        start_scope = start_scope.parent

    if not is_param(start_scope, name):
        return HIT_VALUE

    secure = find_assigned_to_str(start_scope, name, node.lineno)
    if not secure:
        return HIT_VALUE


@test.checks('Call')
@test.test_id('B612')
def insecure_format(context):
    """**B612: Wrong use of format string can discover internal reprs**

    .. seealso::

     - http://lucumr.pocoo.org/2016/12/29/careful-with-str-format/

    .. versionadded:: 1.5.2

    """
    if context.call_function_name == 'format':
        if isinstance(context.node, ast.Call):
            if isinstance(context.node.func, ast.Attribute):
                value = context.node.func.value
                if isinstance(value, ast.Str):
                    return None  # Hard-code string is secure
                elif isinstance(value, ast.Name):
                    return check_risk(context.node, value.id)
                else:
                    return HIT_VALUE
            else:
                return HIT_VALUE
