#
# Copyright 2018 Victor Torre
#
# SPDX-License-Identifier: Apache-2.0
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test
from bandit.core import utils


class DeepAssignation:
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

        if utils.is_instance(node, "Expr"):
            assigned = self.is_assigned(node.value)
        elif utils.is_instance(node, "FunctionDef"):
            for name in node.args.args:
                if utils.is_instance(name, "Name"):
                    if name.id == self.var_name.id:
                        # If is param the assignations are not affected
                        return assigned
            assigned = self.is_assigned_in(node.body)
        elif utils.is_instance(node, "With"):
            for withitem in node.items:
                var_id = getattr(withitem.optional_vars, "id", None)
                if var_id == self.var_name.id:
                    assigned = node
                else:
                    assigned = self.is_assigned_in(node.body)
        elif utils.is_instance(node, "Try"):
            assigned = []
            assigned.extend(self.is_assigned_in(node.body))
            assigned.extend(self.is_assigned_in(node.handlers))
            assigned.extend(self.is_assigned_in(node.orelse))
            assigned.extend(self.is_assigned_in(node.finalbody))
        elif utils.is_instance(node, "ExceptHandler"):
            assigned = []
            assigned.extend(self.is_assigned_in(node.body))
        elif utils.is_instance(node, ("If", "For", "While")):
            assigned = []
            assigned.extend(self.is_assigned_in(node.body))
            assigned.extend(self.is_assigned_in(node.orelse))
        elif utils.is_instance(node, "AugAssign"):
            if utils.is_instance(node.target, "Name"):
                if node.target.id == self.var_name.id:
                    assigned = node.value
        elif utils.is_instance(node, "Assign") and node.targets:
            target = node.targets[0]
            if utils.is_instance(target, "Name"):
                if target.id == self.var_name.id:
                    assigned = node.value
            elif utils.is_instance(target, "Tuple"):
                pos = 0
                for name in target.elts:
                    if name.id == self.var_name.id:
                        assigned = node.value.elts[pos]
                        break
                    pos += 1
        return assigned


def evaluate_var(xss_var, parent, until, ignore_nodes=None):
    secure = False
    if utils.is_instance(xss_var, "Name"):
        if utils.is_instance(parent, "FunctionDef"):
            for name in parent.args.args:
                if name.arg == xss_var.id:
                    return False  # Params are not secure

        analyser = DeepAssignation(xss_var, ignore_nodes)
        for node in parent.body:
            if node.lineno >= until:
                break
            to = analyser.is_assigned(node)
            if to:
                if utils.is_instance(to, "Str"):
                    secure = True
                elif utils.is_instance(to, "Name"):
                    secure = evaluate_var(to, parent, to.lineno, ignore_nodes)
                elif utils.is_instance(to, "Call"):
                    secure = evaluate_call(to, parent, ignore_nodes)
                elif isinstance(to, (list, tuple)):
                    num_secure = 0
                    for some_to in to:
                        if utils.is_instance(some_to, "Str"):
                            num_secure += 1
                        elif utils.is_instance(some_to, "Name"):
                            if evaluate_var(
                                some_to, parent, node.lineno, ignore_nodes
                            ):
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
    if utils.is_instance(call, "Call") and utils.is_instance(
        call.func, "Attribute"
    ):
        if (
            utils.is_instance(call.func.value, "Str")
            and call.func.attr == "format"
        ):
            evaluate = True
            if call.keywords:
                evaluate = False  # TODO(??) get support for this

    if evaluate:
        args = list(call.args)
        num_secure = 0
        for arg in args:
            if utils.is_instance(arg, "Str"):
                num_secure += 1
            elif utils.is_instance(arg, "Name"):
                if evaluate_var(arg, parent, call.lineno, ignore_nodes):
                    num_secure += 1
                else:
                    break
            elif utils.is_instance(arg, "Call"):
                if evaluate_call(arg, parent, ignore_nodes):
                    num_secure += 1
                else:
                    break
            elif utils.is_instance(arg, "Starred") and utils.is_instance(
                arg.value, ("List", "Tuple")
            ):
                args.extend(arg.value.elts)
                num_secure += 1
            else:
                break
        secure = num_secure == len(args)

    return secure


def transform2call(var):
    if utils.is_instance(var, "BinOp"):
        is_mod = utils.is_instance(var.op, "Mod")
        is_left_str = utils.is_instance(var.left, "Str")
        if is_mod and is_left_str:
            new_call = ast.Call()
            new_call.args = []
            new_call.args = []
            new_call.keywords = None
            new_call.lineno = var.lineno
            new_call.func = ast.Attribute()
            new_call.func.value = var.left
            new_call.func.attr = "format"
            if utils.is_instance(var.right, "Tuple"):
                new_call.args = var.right.elts
            else:
                new_call.args = [var.right]
            return new_call


def check_risk(node):
    description = "Potential XSS on mark_safe function."
    xss_var = node.args[0]

    secure = False

    if utils.is_instance(xss_var, "Name"):
        # Check if the var are secure
        parent = node._bandit_parent
        while not utils.is_instance(parent, ("Module", "FunctionDef")):
            parent = parent._bandit_parent

        is_param = False
        if utils.is_instance(parent, "FunctionDef"):
            for name in parent.args.args:
                if name.arg == xss_var.id:
                    is_param = True
                    break

        if not is_param:
            secure = evaluate_var(xss_var, parent, node.lineno)
    elif utils.is_instance(xss_var, "Call"):
        parent = node._bandit_parent
        while not utils.is_instance(parent, ("Module", "FunctionDef")):
            parent = parent._bandit_parent
        secure = evaluate_call(xss_var, parent)
    elif utils.is_instance(xss_var, "BinOp"):
        is_mod = utils.is_instance(xss_var.op, "Mod")
        is_left_str = utils.is_instance(xss_var.left, "Str")
        if is_mod and is_left_str:
            parent = node._bandit_parent
            while not utils.is_instance(parent, ("Module", "FunctionDef")):
                parent = parent._bandit_parent
            new_call = transform2call(xss_var)
            secure = evaluate_call(new_call, parent)

    if not secure:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.BASIC_XSS,
            text=description,
        )


@test.checks("Call")
@test.test_id("B703")
def django_mark_safe(context):
    """**B703: Potential XSS on mark_safe function**

    :Example:

    .. code-block:: none

        >> Issue: [B703:django_mark_safe] Potential XSS on mark_safe function.
           Severity: Medium Confidence: High
           CWE: CWE-80 (https://cwe.mitre.org/data/definitions/80.html)
           Location: examples/mark_safe_insecure.py:159:4
           More Info: https://bandit.readthedocs.io/en/latest/plugins/b703_django_mark_safe.html
        158         str_arg = 'could be insecure'
        159     safestring.mark_safe(str_arg)

    .. seealso::

     - https://docs.djangoproject.com/en/dev/topics/security/\
#cross-site-scripting-xss-protection
     - https://docs.djangoproject.com/en/dev/ref/utils/\
#module-django.utils.safestring
     - https://docs.djangoproject.com/en/dev/ref/utils/\
#django.utils.html.format_html
     - https://cwe.mitre.org/data/definitions/80.html

    .. versionadded:: 1.5.0

    .. versionchanged:: 1.7.3
        CWE information added

    """  # noqa: E501
    if context.is_module_imported_like("django.utils.safestring"):
        affected_functions = [
            "mark_safe",
            "SafeText",
            "SafeUnicode",
            "SafeString",
            "SafeBytes",
        ]
        if context.call_function_name in affected_functions:
            xss = context.node.args[0]
            if not utils.is_instance(xss, "Str"):
                return check_risk(context.node)
