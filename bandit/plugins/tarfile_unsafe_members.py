#
# SPDX-License-Identifier: Apache-2.0
#
r"""
=================================
B202: Test for tarfile.extractall
=================================

This plugin will look for usage of ``tarfile.extractall()``

Severity are set as follows:

* ``tarfile.extractall(filter='data')`` - No issue
* ``tarfile.extractall(filter=tarfile.data_filter)`` - No issue
* ``tarfile.extractall(filter=custom_filter)`` - LOW
* ``tarfile.extractall(members=function(tarfile))`` - LOW
* ``tarfile.extractall(members=?)`` - member is not a function - MEDIUM
* ``tarfile.extractall()`` - members from the archive is trusted - HIGH

On Python 3.12 and later, prefer passing ``filter="data"`` (or
``tarfile.data_filter``) which rejects absolute paths, directory
traversal, and special file types. Alternatively, pass an iterable of
validated members via ``members`` and discard files that contain
directory traversal sequences such as ``../`` or ``\..`` along with all
special filetypes unless you explicitly need them.

:Example:

.. code-block:: none

    >> Issue: [B202:tarfile_unsafe_members] tarfile.extractall used without
    any validation. You should check members and discard dangerous ones
    Severity: High   Confidence: High
    CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
    Location: examples/tarfile_extractall.py:8
    More Info:
    https://bandit.readthedocs.io/en/latest/plugins/b202_tarfile_unsafe_members.html
    7	    tar = tarfile.open(filename)
    8	    tar.extractall(path=tempfile.mkdtemp())
    9	    tar.close()


.. seealso::

 - https://docs.python.org/3/library/tarfile.html#tarfile.TarFile.extractall
 - https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter
 - https://docs.python.org/3/library/tarfile.html#tarfile.TarInfo

.. versionadded:: 1.7.5

.. versionchanged:: 1.7.8
    Added check for filter parameter

.. versionchanged:: 1.9.5
    Recognize ``tarfile.data_filter`` and callable filters, handle
    method calls passed as ``members``, and only match calls actually
    named ``extractall``

"""
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


def exec_issue(level, args=""):
    if level == bandit.LOW:
        return bandit.Issue(
            severity=bandit.LOW,
            confidence=bandit.LOW,
            cwe=issue.Cwe.PATH_TRAVERSAL,
            text="Usage of tarfile.extractall with member validation. "
            "Make sure your function properly discards dangerous members "
            "({args}).".format(args=args),
        )
    elif level == bandit.MEDIUM:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            cwe=issue.Cwe.PATH_TRAVERSAL,
            text="Found tarfile.extractall(members=?) but couldn't "
            "identify the type of members. "
            "Check if the members were properly validated "
            "({args}).".format(args=args),
        )
    else:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.PATH_TRAVERSAL,
            text="tarfile.extractall used without any validation. "
            "Please check and discard dangerous members.",
        )


def get_members_value(context):
    for keyword in context.node.keywords:
        if keyword.arg == "members":
            arg = keyword.value
            if isinstance(arg, ast.Call):
                func = arg.func
                if isinstance(func, ast.Attribute):
                    return {"Function": func.attr}
                elif isinstance(func, ast.Name):
                    return {"Function": func.id}
                return {"Function": "?"}
            else:
                value = arg.id if isinstance(arg, ast.Name) else arg
                return {"Other": value}


def get_filter_value(context):
    for keyword in context.node.keywords:
        if keyword.arg == "filter":
            return keyword.value
    return None


def is_data_filter(filter_arg):
    if isinstance(filter_arg, ast.Constant):
        return filter_arg.value == "data"
    if isinstance(filter_arg, ast.Attribute):
        return filter_arg.attr == "data_filter"
    if isinstance(filter_arg, ast.Name):
        return filter_arg.id == "data_filter"
    return False


@test.test_id("B202")
@test.checks("Call")
def tarfile_unsafe_members(context):
    if all(
        [
            context.is_module_imported_exact("tarfile"),
            context.call_function_name == "extractall",
        ]
    ):
        filter_arg = get_filter_value(context)
        if filter_arg is not None:
            if is_data_filter(filter_arg):
                return None
            if isinstance(filter_arg, (ast.Name, ast.Attribute, ast.Lambda)):
                return exec_issue(bandit.LOW, {"Filter": "custom"})
        if "members" in context.call_keywords:
            members = get_members_value(context)
            if "Function" in members:
                return exec_issue(bandit.LOW, members)
            else:
                return exec_issue(bandit.MEDIUM, members)
        return exec_issue(bandit.HIGH)
