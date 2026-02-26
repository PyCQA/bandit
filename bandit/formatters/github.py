#
# SPDX-License-Identifier: Apache-2.0
r"""
========================
GitHub Actions Formatter
========================

This formatter outputs the issues as GitHub Actions workflow commands,
which are displayed as annotations in pull requests and workflow runs.

:Example:

.. code-block:: none

    ::error file=examples/yaml_load.py,line=5,col=8,title=B301::Use of unsafe
    yaml load. Allows instantiation of arbitrary objects. Consider
    yaml.safe_load().
    ::warning file=examples/crypto.py,line=10,col=4,title=B324::Use of insecure
    MD5 hash function.

The severity levels are mapped to GitHub Actions annotation levels as follows:
- HIGH -> error
- MEDIUM -> warning
- LOW -> notice

For more information on GitHub Actions workflow commands, see:
https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions

.. versionadded:: 1.8.0

"""
import logging
import sys

from bandit.core import constants

LOG = logging.getLogger(__name__)


def _severity_to_level(severity):
    """Convert Bandit severity to GitHub Actions annotation level.

    :param severity: Bandit severity level (HIGH, MEDIUM, LOW)
    :return: GitHub Actions annotation level (error, warning, notice)
    """
    severity_map = {
        constants.HIGH: "error",
        constants.MEDIUM: "warning",
        constants.LOW: "notice",
    }
    return severity_map.get(severity, "notice")


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints issues as GitHub Actions annotations

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """

    results = manager.get_issue_list(
        sev_level=sev_level, conf_level=conf_level
    )

    with fileobj:
        for result in results:
            # Determine the annotation level based on severity
            level = _severity_to_level(result.severity)

            # Ensure column offset is valid (default to 0 if missing)
            col = result.col_offset if result.col_offset >= 0 else 0

            # Format the GitHub Actions annotation
            # Format: ::level file={file},line={line},col={col},title={title}::{message}
            annotation = (
                f"::{level} file={result.fname},line={result.lineno},"
                f"col={col},title={result.test_id}::{result.text}\n"
            )

            fileobj.write(annotation)

    if fileobj.name != sys.stdout.name:
        LOG.info("GitHub Actions output written to file: %s", fileobj.name)
