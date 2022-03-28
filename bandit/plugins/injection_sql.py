#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
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
 - "SELECT {} FROM derp;".format(var)
 - f"SELECT foo FROM bar WHERE id = {product}"

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
       CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
       Location: ./examples/sql_statements_without_sql_alchemy.py:4
    3 query = "DELETE FROM foo WHERE id = '%s'" % identifier
    4 query = "UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier
    5

.. seealso::

 - https://www.owasp.org/index.php/SQL_Injection
 - https://security.openstack.org/guidelines/dg_parameterize-database-queries.html
 - https://cwe.mitre.org/data/definitions/89.html

.. versionadded:: 0.9.0

.. versionchanged:: 1.7.3
    CWE information added

"""  # noqa: E501
import ast
import re

import bandit
from bandit.core import issue
from bandit.core import test_properties as test
from bandit.core import utils

SIMPLE_SQL_RE = re.compile(
    r"(select\s.*from\s|"
    r"delete\s+from\s|"
    r"insert\s+into\s.*values\s|"
    r"update\s.*set\s)",
    re.IGNORECASE | re.DOTALL,
)


def _check_string(data):
    return SIMPLE_SQL_RE.search(data) is not None


def _evaluate_ast(node):
    wrapper = None
    statement = ""

    if isinstance(node._bandit_parent, ast.BinOp):
        out = utils.concat_string(node, node._bandit_parent)
        wrapper = out[0]._bandit_parent
        statement = out[1]
    elif (
        isinstance(node._bandit_parent, ast.Attribute)
        and node._bandit_parent.attr == "format"
    ):
        statement = node.s
        # Hierarchy for "".format() is Wrapper -> Call -> Attribute -> Str
        wrapper = node._bandit_parent._bandit_parent._bandit_parent
    elif hasattr(ast, "JoinedStr") and isinstance(
        node._bandit_parent, ast.JoinedStr
    ):
        statement = node.s
        wrapper = node._bandit_parent._bandit_parent

    if isinstance(wrapper, ast.Call):  # wrapped in "execute" call?
        names = ["execute", "executemany"]
        name = utils.get_called_name(wrapper)
        return (name in names, statement)
    else:
        return (False, statement)


@test.checks("Str")
@test.test_id("B608")
def hardcoded_sql_expressions(context):
    val = _evaluate_ast(context.node)
    if _check_string(val[1]):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM if val[0] else bandit.LOW,
            cwe=issue.Cwe.SQL_INJECTION,
            text="Possible SQL injection vector through string-based "
            "query construction.",
        )
