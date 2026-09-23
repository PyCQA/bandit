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

.. versionchanged:: 1.9.5
    Added detection of stat module constants (e.g., stat.S_IWOTH)

"""  # noqa: E501
import ast
import stat

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

# Mapping of stat module constant names to their integer values.
# Only includes flags that are relevant to file permission checks.
_STAT_CONSTANTS = {
    name: getattr(stat, name) for name in dir(stat) if name.startswith("S_I")
}


def _stat_is_dangerous(mode):
    return (
        mode & stat.S_IWOTH
        or mode & stat.S_IWGRP
        or mode & stat.S_IXGRP
        or mode & stat.S_IXOTH
    )


def _resolve_stat_expression(node):
    """Resolve an AST node to an integer value if it's a stat constant
    expression (e.g., stat.S_IWOTH | stat.S_IWGRP).

    Returns the integer value if resolvable, or None if not.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value

    if isinstance(node, ast.Attribute):
        # Handle stat.S_IWOTH, stat.S_IRWXU, etc.
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == "stat"
            and node.attr in _STAT_CONSTANTS
        ):
            return _STAT_CONSTANTS[node.attr]

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _resolve_stat_expression(node.left)
        right = _resolve_stat_expression(node.right)
        if left is not None and right is not None:
            return left | right

    return None


@test.checks("Call")
@test.test_id("B103")
def set_bad_file_permissions(context):
    if "chmod" in context.call_function_name:
        if context.call_args_count == 2:
            mode = context.get_call_arg_at_position(1)

            # Try to resolve stat constant expressions from the raw AST node
            if mode is None or not isinstance(mode, int):
                raw_args = context._context["call"].args
                if len(raw_args) >= 2:
                    resolved = _resolve_stat_expression(raw_args[1])
                    if resolved is not None:
                        mode = resolved

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
