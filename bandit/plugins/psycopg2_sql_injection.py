# SPDX-License-Identifier: Apache-2.0
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


@test.checks("Call")
@test.test_id("B613")
def psycopg2_sql_injection(context):
    """**B613: Potential SQL injection on psycopg2 raw SQL composable object **

    The `psycopg2.sql.SQL` composable object should not be used to represent
    variable identifiers or values that may be controlled by an attacker since
    the argument that is passed to the `SQL` constructor is not escaped when
    the SQL statement is composed. Instead, `SQL` should only be used to
    represent constant strings.

    .. seealso::

     - https://www.psycopg.org/docs/sql.html

    .. versionadded:: 1.7.6
    """
    if context.is_module_imported_like("psycopg2.sql"):
        if context.call_function_name == "SQL":
            argument = context.node.args[0]
            if not isinstance(argument, ast.Str):
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.MEDIUM,
                    cwe=issue.Cwe.SQL_INJECTION,
                    text=(
                        "Possible SQL injection vector through instantiation "
                        "of psycopg2.sql.SQL composable object on an argument "
                        "other than a string literal."
                    ),
                )
