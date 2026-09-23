#
# SPDX-License-Identifier: Apache-2.0
#
r"""
======================================
B203: Test for zipfile.extractall
======================================

This plugin detects usage of ``zipfile.ZipFile.extractall()`` without
path validation, which may allow Zip Slip attacks (CWE-22).

An attacker can craft a ZIP archive with entries containing path traversal
sequences (e.g. ``../../etc/cron.d/evil``) that, when extracted without
validation, write files outside the intended destination directory.

Severity is set as follows:

* ``zipfile.extractall()`` with no validation - HIGH
* ``zipfile.extractall(path=?)`` with a variable path but no member check - MEDIUM

Use a manual extraction loop that validates each member path before
extracting:

.. code-block:: python

    import zipfile, os

    def safe_extract(zf, dest):
        dest = os.path.realpath(dest)
        for member in zf.namelist():
            member_path = os.path.realpath(os.path.join(dest, member))
            if not member_path.startswith(dest + os.sep):
                raise ValueError("Zip Slip detected: %s" % member)
            zf.extract(member, dest)

:Example:

.. code-block:: none

    >> Issue: [B203:zipfile_unsafe_extractall] zipfile.extractall used
    without path validation. Possible Zip Slip (path traversal) attack.
    Severity: High   Confidence: High
    CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
    Location: examples/zipfile_extractall.py:5

.. seealso::

 - https://docs.python.org/3/library/zipfile.html#zipfile.ZipFile.extractall
 - https://security.snyk.io/research/zip-slip-vulnerability
 - https://cwe.mitre.org/data/definitions/22.html

.. versionadded:: 1.8.0

"""
import bandit
from bandit.core import issue
from bandit.core import test_properties as test


@test.test_id("B203")
@test.checks("Call")
def zipfile_unsafe_extractall(context):
    if all(
        [
            context.is_module_imported_exact("zipfile"),
            "extractall" in context.call_function_name,
        ]
    ):
        if "members" in context.call_keywords:
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                cwe=issue.Cwe.PATH_TRAVERSAL,
                text=(
                    "zipfile.extractall used with a members argument but "
                    "without verified path validation. Ensure each member "
                    "path is checked against the destination directory to "
                    "prevent Zip Slip attacks (CWE-22)."
                ),
            )
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.PATH_TRAVERSAL,
            text=(
                "zipfile.extractall used without path validation. "
                "A crafted ZIP archive may extract files outside the "
                "intended directory (Zip Slip, CWE-22). Use a manual "
                "extraction loop with path validation instead."
            ),
        )
