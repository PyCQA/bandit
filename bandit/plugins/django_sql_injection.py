# -*- coding:utf-8 -*-
#
# Copyright (C) 2018 [Victor Torre](https://github.com/ehooo)
#
# SPDX-License-Identifier: Apache-2.0


import ast

import bandit
from bandit.core import test_properties as test


def keywords2dict(keywords):
    kwargs = {}
    for node in keywords:
        if isinstance(node, ast.keyword):
            kwargs[node.arg] = node.value
    return kwargs


@test.checks('Call')
@test.test_id('B610')
def django_extra_used(context):
    """**B610: Potential SQL injection on extra function**

    .. seealso::

     - https://docs.djangoproject.com/en/dev/topics/security/\
#sql-injection-protection

    .. versionadded:: 1.5.0

    """
    description = "Use of extra potential SQL attack vector."
    if context.call_function_name == 'extra':
        kwargs = keywords2dict(context.node.keywords)
        args = context.node.args
        if args:
            if len(args) >= 1:
                kwargs['select'] = args[0]
            if len(args) >= 2:
                kwargs['where'] = args[1]
            if len(args) >= 3:
                kwargs['params'] = args[2]
            if len(args) >= 4:
                kwargs['tables'] = args[3]
            if len(args) >= 5:
                kwargs['order_by'] = args[4]
            if len(args) >= 6:
                kwargs['select_params'] = args[5]
        insecure = False
        for key in ['where', 'tables']:
            if key in kwargs:
                if isinstance(kwargs[key], ast.List):
                    for val in kwargs[key].elts:
                        if not isinstance(val, ast.Str):
                            insecure = True
                            break
                else:
                    insecure = True
                    break
        if not insecure and 'select' in kwargs:
            if isinstance(kwargs['select'], ast.Dict):
                for k in kwargs['select'].keys:
                    if not isinstance(k, ast.Str):
                        insecure = True
                        break
                if not insecure:
                    for v in kwargs['select'].values:
                        if not isinstance(v, ast.Str):
                            insecure = True
                            break
            else:
                insecure = True

        if insecure:
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                text=description
            )


@test.checks('Call')
@test.test_id('B611')
def django_rawsql_used(context):
    """**B611: Potential SQL injection on RawSQL function**

    .. seealso::

     - https://docs.djangoproject.com/en/dev/topics/security/\
#sql-injection-protection

    .. versionadded:: 1.5.0

    """
    description = "Use of RawSQL potential SQL attack vector."
    if context.is_module_imported_like('django.db.models'):
        if context.call_function_name == 'RawSQL':
            sql = context.node.args[0]
            if not isinstance(sql, ast.Str):
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.MEDIUM,
                    text=description
                )
