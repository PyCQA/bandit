#
# Copyright 2018 Victor Torre
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


class DeepAssignation(object):
    def __init__(self, var_name, ignore_nodes=None):
        self.var_name = var_name
        self.ignore_nodes = ignore_nodes

    def is_assigned_in(self, items):
        assigned = []
        for ast_inst in items:
            new_assigned = self.is_assigned(ast_inst)
            if new_assigned:
                if isinstance(new_assigned, (list, tuple)):
                    assigned.extend(new_assigned)
                else:
                    assigned.append(new_assigned)
        return assigned

    def is_assigned(self, node):
        assigned = False
        if self.ignore_nodes:
            if isinstance(self.ignore_nodes, (list, tuple, object)):
                if isinstance(node, self.ignore_nodes):
                    return assigned

        if isinstance(node, ast.Expr):
            assigned = self.is_assigned(node.value)
        elif isinstance(node, ast.FunctionDef):
            for name in node.args.args:
                if isinstance(name, ast.Name):
                    if name.id == self.var_name.id:
                        # If is param the assignations are not affected
                        return assigned
            assigned = self.is_assigned_in(node.body)
        elif isinstance(node, ast.With):
            if six.PY2:
                if node.optional_vars.id == self.var_name.id:
                    assigned = node
                else:
                    assigned = self.is_assigned_in(node.body)
            else:
                for withitem in node.items:
                    if withitem.optional_vars.id == self.var_name.id:
                        assigned = node
                    else:
                        assigned = self.is_assigned_in(node.body)
        elif six.PY2 and isinstance(node, ast.TryFinally):
            assigned = []
            assigned.extend(self.is_assigned_in(node.body))
            assigned.extend(self.is_assigned_in(node.finalbody))
        elif six.PY2 and isinstance(node, ast.TryExcept):
            assigned = []
            assigned.extend(self.is_assigned_in(node.body))
            assigned.extend(self.is_assigned_in(node.handlers))
            assigned.extend(self.is_assigned_in(node.orelse))
        elif not six.PY2 and isinstance(node, ast.Try):
            assigned = []
            assigned.extend(self.is_assigned_in(node.body))
            assigned.extend(self.is_assigned_in(node.handlers))
            assigned.extend(self.is_assigned_in(node.orelse))
            assigned.extend(self.is_assigned_in(node.finalbody))
        elif isinstance(node, ast.ExceptHandler):
            assigned = []
            assigned.extend(self.is_assigned_in(node.body))
        elif isinstance(node, (ast.If, ast.For, ast.While)):
            assigned = []
            assigned.extend(self.is_assigned_in(node.body))
            assigned.extend(self.is_assigned_in(node.orelse))
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                if node.target.id == self.var_name.id:
                    assigned = node.value
        elif isinstance(node, ast.Assign) and node.targets:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                if target.id == self.var_name.id:
                    assigned = node.value
            elif isinstance(target, ast.Tuple):
                pos = 0
                for name in target.elts:
                    if name.id == self.var_name.id:
                        assigned = node.value.elts[pos]
                        break
                    pos += 1
        return assigned


def evaluate_var(xss_var, parent, until, ignore_nodes=None):
    secure = False
    if isinstance(xss_var, ast.Name):
        if isinstance(parent, ast.FunctionDef):
            for name in parent.args.args:
                arg_name = name.id if six.PY2 else name.arg
                if arg_name == xss_var.id:
                    return False  # Params are not secure

        analyser = DeepAssignation(xss_var, ignore_nodes)
        for node in parent.body:
            if node.lineno >= until:
                break
            to = analyser.is_assigned(node)
            if to:
                if isinstance(to, ast.Str):
                    secure = True
                elif isinstance(to, ast.Name):
                    secure = evaluate_var(to, parent,
                                          to.lineno, ignore_nodes)
                elif isinstance(to, ast.Call):
                    secure = evaluate_call(to, parent, ignore_nodes)
                elif isinstance(to, (list, tuple)):
                    num_secure = 0
                    for some_to in to:
                        if isinstance(some_to, ast.Str):
                            num_secure += 1
                        elif isinstance(some_to, ast.Name):
                            if evaluate_var(some_to, parent,
                                            node.lineno, ignore_nodes):
                                num_secure += 1
                            else:
                                break
                        else:
                            break
                    if num_secure == len(to):
                        secure = True
                    else:
                        secure = False
                        break
                else:
                    secure = False
                    break
    return secure


def evaluate_call(call, parent, ignore_nodes=None):
    secure = False
    evaluate = False
    if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute):
        if isinstance(call.func.value, ast.Str) and call.func.attr == 'format':
            evaluate = True
            if call.keywords or (six.PY2 and call.kwargs):
                evaluate = False  # TODO(??) get support for this

    if evaluate:
        args = list(call.args)
        if six.PY2 and call.starargs and isinstance(call.starargs,
                                                    (ast.List, ast.Tuple)):
            args.extend(call.starargs.elts)

        num_secure = 0
        for arg in args:
            if isinstance(arg, ast.Str):
                num_secure += 1
            elif isinstance(arg, ast.Name):
                if evaluate_var(arg, parent, call.lineno, ignore_nodes):
                    num_secure += 1
                else:
                    break
            elif isinstance(arg, ast.Call):
                if evaluate_call(arg, parent, ignore_nodes):
                    num_secure += 1
                else:
                    break
            elif not six.PY2 and isinstance(arg, ast.Starred) and isinstance(
                    arg.value, (ast.List, ast.Tuple)):
                args.extend(arg.value.elts)
                num_secure += 1
            else:
                break
        secure = num_secure == len(args)

    return secure


def transform2call(var):
    if isinstance(var, ast.BinOp):
        is_mod = isinstance(var.op, ast.Mod)
        is_left_str = isinstance(var.left, ast.Str)
        if is_mod and is_left_str:
            new_call = ast.Call()
            new_call.args = []
            new_call.args = []
            if six.PY2:
                new_call.starargs = None
            new_call.keywords = None
            if six.PY2:
                new_call.kwargs = None
            new_call.lineno = var.lineno
            new_call.func = ast.Attribute()
            new_call.func.value = var.left
            new_call.func.attr = 'format'
            if isinstance(var.right, ast.Tuple):
                new_call.args = var.right.elts
            elif six.PY2 and isinstance(var.right, ast.Dict):
                new_call.kwargs = var.right
            else:
                new_call.args = [var.right]
            return new_call


def check_risk(node):
    description = "Potential XSS on mark_safe function."
    xss_var = node.args[0]

    secure = False

    if isinstance(xss_var, ast.Name):
        # Check if the var are secure
        parent = node.parent
        while not isinstance(parent, (ast.Module, ast.FunctionDef)):
            parent = parent.parent

        is_param = False
        if isinstance(parent, ast.FunctionDef):
            for name in parent.args.args:
                arg_name = name.id if six.PY2 else name.arg
                if arg_name == xss_var.id:
                    is_param = True
                    break

        if not is_param:
            secure = evaluate_var(xss_var, parent, node.lineno)
    elif isinstance(xss_var, ast.Call):
        parent = node.parent
        while not isinstance(parent, (ast.Module, ast.FunctionDef)):
            parent = parent.parent
        secure = evaluate_call(xss_var, parent)
    elif isinstance(xss_var, ast.BinOp):
        is_mod = isinstance(xss_var.op, ast.Mod)
        is_left_str = isinstance(xss_var.left, ast.Str)
        if is_mod and is_left_str:
            parent = node.parent
            while not isinstance(parent, (ast.Module, ast.FunctionDef)):
                parent = parent.parent
            new_call = transform2call(xss_var)
            secure = evaluate_call(new_call, parent)

    if not secure:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            text=description
        )


@test.checks('Call')
@test.test_id('B703')
def django_mark_safe(context):
    """**B703: Potential XSS on mark_safe function**

    .. seealso::

     - https://docs.djangoproject.com/en/dev/topics/
        security/#cross-site-scripting-xss-protection
     - https://docs.djangoproject.com/en/dev/
        ref/utils/#module-django.utils.safestring
     - https://docs.djangoproject.com/en/dev/
        ref/utils/#django.utils.html.format_html

    .. versionadded:: 1.4.1

    """
    if context.is_module_imported_like('django.utils.safestring'):
        affected_functions = [
            'mark_safe',
            'SafeText',
            'SafeUnicode',
            'SafeString',
            'SafeBytes'
        ]
        if context.call_function_name in affected_functions:
            xss = context.node.args[0]
            if not isinstance(xss, ast.Str):
                return check_risk(context.node)
