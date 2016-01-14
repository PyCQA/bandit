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

r"""
============================
B608: Test for SQL injection
============================

An SQL injection attack consists of insertion or "injection" of a SQL query via
the input data given to an application. It is a very common attack vector. This
plugin test looks for strings that resemble SQL statements that are involved in
some form of string building operation. For example:

 - "SELECT %s FROM derp;" % var
 - "SELECT thing FROM " + tab
 - "SELECT " + val + " FROM " + tab + ...

Unless care is taken to sanitize and control the input data when building such
SQL statement strings, an injection attack becomes possible. If strings of this
nature are discovered, a LOW confidence issue is reported. In order to boost
result confidence, this plugin test will also check to see if the discovered
string is in use with standard Python DBAPI calls `execute` or `executemany`.
If so, a MEDIUM issue is reported. For example:

 - cursor.execute("SELECT %s FROM derp;" % var)


:Example:

.. code-block:: none

    >> Issue: Possible SQL injection vector through string-based query
    construction.
       Severity: Medium   Confidence: Low
       Location: ./examples/sql_statements_without_sql_alchemy.py:4
    3 query = "DELETE FROM foo WHERE id = '%s'" % identifier
    4 query = "UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier
    5

.. seealso::

 - https://www.owasp.org/index.php/SQL_Injection
 - https://security.openstack.org/guidelines/dg_parameterize-database-queries.html  # noqa

.. versionadded:: 0.9.0

"""

import ast

import bandit
from bandit.core import test_properties as test
from bandit.core import utils


def _check_string(data):
    val = data.lower()
    return ((val.startswith('select ') and ' from ' in val) or
            val.startswith('insert into') or
            (val.startswith('update ') and ' set ' in val) or
            val.startswith('delete from '))


def _evaluate_ast(node):
    if not isinstance(node.parent, ast.BinOp):
        return (False, "")

    out = utils.concat_string(node, node.parent)
    if isinstance(out[0].parent, ast.Call):  # wrapped in "execute" call?
        names = ['execute', 'executemany']
        name = utils.get_called_name(out[0].parent)
        return (name in names, out[1])
    return (False, out[1])


@test.checks('Str')
@test.test_id('B608')
def hardcoded_sql_expressions(context):
    val = _evaluate_ast(context.node)
    if _check_string(val[1]):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM if val[0] else bandit.LOW,
            text="Possible SQL injection vector through string-based "
                 "query construction."
        )
