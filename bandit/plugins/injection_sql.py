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
from bandit.core import utils


def _ast_build_string(data):
    # used to return a string representation of AST data

    if isinstance(data, ast.Str):
        # Already a string, just return the value
        return utils.safe_str(data.s)

    if isinstance(data, ast.BinOp):
        # need to build the string from a binary operation
        return _ast_binop_stringify(data)

    if isinstance(data, ast.Name):
        # a variable, stringify the variable name
        return "[[" + utils.safe_str(data.id) + "]]"

    return "XXX"  # placeholder for unaccounted for values


def _ast_binop_stringify(data):
    # used to recursively build a string from a binary operation
    left = data.left
    right = data.right

    return _ast_build_string(left) + _ast_build_string(right)


@checks('Str')
def hardcoded_sql_expressions(context):
    statement = context.node.parent
    if isinstance(statement, ast.Assign):
        test_str = _ast_build_string(statement.value).lower()

    elif isinstance(statement, ast.Expr):
        test_str = ""
        if isinstance(statement.value, ast.Call):
            ctx_str = context.string_val.lower()
            for arg in statement.value.args:
                temp_str = _ast_build_string(arg).lower()
                if ctx_str in temp_str:
                    test_str = temp_str
    else:
        test_str = context.string_val.lower()

    if (
        (test_str.startswith('select ') and ' from ' in test_str) or
        test_str.startswith('insert into') or
        (test_str.startswith('update ') and ' set ' in test_str) or
        test_str.startswith('delete from ')
    ):
        # if sqlalchemy is not imported and it looks like they are using SQL
        # statements, mark it as a medium severity issue
        if not context.is_module_imported_like("sqlalchemy"):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.LOW,
                text="Possible SQL injection vector through string-based "
                     "query construction, without SQLAlchemy use."
            )

        # otherwise, if sqlalchemy is being used, mark it as low severity
        else:
            return bandit.Issue(
                severity=bandit.LOW,
                confidence=bandit.LOW,
                text="Possible SQL injection vector through string-based "
                     "query construction."
            )
