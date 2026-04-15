#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
r"""
==================================================
B103: Test for setting permissive file permissions
==================================================

POSIX based operating systems utilize a permissions model to protect access to
parts of the file system. This model supports three roles "owner", "group"
and "world" each role may have a combination of "read", "write" or "execute"
flags sets. Python provides ``chmod`` to manipulate POSIX style permissions.

This plugin test looks for the use of ``chmod`` and will alert when it is used
to set particularly permissive control flags. A MEDIUM warning is generated if
a file is set to group write or executable and a HIGH warning is reported if a
file is set world write or executable. Warnings are given with HIGH confidence.

:Example:

.. code-block:: none

    >> Issue: Probable insecure usage of temp file/directory.
       Severity: Medium   Confidence: Medium
       CWE: CWE-732 (https://cwe.mitre.org/data/definitions/732.html)
       Location: ./examples/os-chmod.py:15
    14  os.chmod('/etc/hosts', 0o777)
    15  os.chmod('/tmp/oh_hai', 0x1ff)
    16  os.chmod('/etc/passwd', stat.S_IRWXU)

    >> Issue: Chmod setting a permissive mask 0777 on file (key_file).
       Severity: High   Confidence: High
       CWE: CWE-732 (https://cwe.mitre.org/data/definitions/732.html)
       Location: ./examples/os-chmod.py:17
    16  os.chmod('/etc/passwd', stat.S_IRWXU)
    17  os.chmod(key_file, 0o777)
    18

.. seealso::

 - https://security.openstack.org/guidelines/dg_apply-restrictive-file-permissions.html
 - https://en.wikipedia.org/wiki/File_system_permissions
 - https://security.openstack.org
 - https://cwe.mitre.org/data/definitions/732.html

.. versionadded:: 0.9.0

.. versionchanged:: 1.7.3
    CWE information added

.. versionchanged:: 1.7.5
    Added checks for S_IWGRP and S_IXOTH

"""  # noqa: E501
import ast
import stat

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


def _stat_is_dangerous(mode):
    return (
        mode & stat.S_IWOTH
        or mode & stat.S_IWGRP
        or mode & stat.S_IXGRP
        or mode & stat.S_IXOTH
    )


def _resolve_mode_from_ast(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    elif isinstance(node, getattr(ast, "Num", type(None))):
        return getattr(node, "n", None)
    elif isinstance(node, ast.Attribute):
        if hasattr(stat, node.attr):
            val = getattr(stat, node.attr)
            if isinstance(val, int):
                return val
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _resolve_mode_from_ast(node.left)
        right = _resolve_mode_from_ast(node.right)
        if left is not None and right is not None:
            return left | right
    return None


@test.checks("Call")
@test.test_id("B103")
def set_bad_file_permissions(context):
    if "chmod" in context.call_function_name:
        if context.call_args_count == 2:
            mode = context.get_call_arg_at_position(1)

            if mode is None:
                arg_node = context.node.args[1]
                mode = _resolve_mode_from_ast(arg_node)

            if (
                mode is not None
                and isinstance(mode, int)
                and _stat_is_dangerous(mode)
            ):
                # world writable is an HIGH, group executable is a MEDIUM
                if mode & stat.S_IWOTH:
                    sev_level = bandit.HIGH
                else:
                    sev_level = bandit.MEDIUM

                filename = context.get_call_arg_at_position(0)
                if filename is None:
                    filename = "NOT PARSED"
                return bandit.Issue(
                    severity=sev_level,
                    confidence=bandit.HIGH,
                    cwe=issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT,
                    text="Chmod setting a permissive mask %s on file (%s)."
                    % (oct(mode), filename),
                )
