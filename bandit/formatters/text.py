# Copyright (c) 2015 Hewlett Packard Enterprise
# -*- coding:utf-8 -*-
#
# SPDX-License-Identifier: Apache-2.0

r"""
==============
Text Formatter
==============

This formatter outputs the issues as plain text.

:Example:

.. code-block:: none

    >> Issue: [B301:blacklist_calls] Use of unsafe yaml load. Allows
       instantiation of arbitrary objects. Consider yaml.safe_load().

       Severity: Medium   Confidence: High
       Location: examples/yaml_load.py:5
       More Info: https://bandit.readthedocs.io/en/latest/
    4       ystr = yaml.dump({'a' : 1, 'b' : 2, 'c' : 3})
    5       y = yaml.load(ystr)
    6       yaml.dump(y)

.. versionadded:: 0.9.0

"""

from __future__ import print_function

import datetime
import logging
import sys

from bandit.core import constants
from bandit.core import docs_utils
from bandit.core import test_properties
from bandit.formatters import utils

LOG = logging.getLogger(__name__)


def get_verbose_details(manager):
    bits = []
    bits.append(u'Files in scope (%i):' % len(manager.files_list))
    tpl = u"\t%s (score: {SEVERITY: %i, CONFIDENCE: %i})"
    bits.extend([tpl % (item, sum(score['SEVERITY']), sum(score['CONFIDENCE']))
                 for (item, score)
                 in zip(manager.files_list, manager.scores)])
    bits.append(u'Files excluded (%i):' % len(manager.excluded_files))
    bits.extend([u"\t%s" % fname for fname in manager.excluded_files])
    return '\n'.join([bit for bit in bits])


def get_metrics(manager):
    bits = []
    bits.append("\nRun metrics:")
    for (criteria, _) in constants.CRITERIA:
        bits.append("\tTotal issues (by %s):" % (criteria.lower()))
        for rank in constants.RANKING:
            bits.append("\t\t%s: %s" % (
                rank.capitalize(),
                manager.metrics.data['_totals']['%s.%s' % (criteria, rank)]))
    return '\n'.join([bit for bit in bits])


def _output_issue_str(issue, indent, show_lineno=True, show_code=True,
                      lines=-1):
    # returns a list of lines that should be added to the existing lines list
    bits = []
    bits.append("%s>> Issue: [%s:%s] %s" % (
        indent, issue.test_id, issue.test, issue.text))

    bits.append("%s   Severity: %s   Confidence: %s" % (
        indent, issue.severity.capitalize(), issue.confidence.capitalize()))

    bits.append("%s   Location: %s:%s:%s" % (
        indent, issue.fname, issue.lineno if show_lineno else "",
        issue.col_offset if show_lineno else ""))

    bits.append("%s   More Info: %s" % (
        indent, docs_utils.get_url(issue.test_id)))

    if show_code:
        bits.extend([indent + line for line in
                     issue.get_code(lines, True).split('\n')])

    return '\n'.join([bit for bit in bits])


def get_results(manager, sev_level, conf_level, lines):
    bits = []
    issues = manager.get_issue_list(sev_level, conf_level)
    baseline = not isinstance(issues, list)
    candidate_indent = ' ' * 10

    if not len(issues):
        return u"\tNo issues identified."

    for issue in issues:
        # if not a baseline or only one candidate we know the issue
        if not baseline or len(issues[issue]) == 1:
            bits.append(_output_issue_str(issue, "", lines=lines))

        # otherwise show the finding and the candidates
        else:
            bits.append(_output_issue_str(issue, "",
                                          show_lineno=False,
                                          show_code=False))

            bits.append(u'\n-- Candidate Issues --')
            for candidate in issues[issue]:
                bits.append(_output_issue_str(candidate,
                                              candidate_indent,
                                              lines=lines))
                bits.append('\n')
        bits.append(u'-' * 50)
    return '\n'.join([bit for bit in bits])


@test_properties.accepts_baseline
def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints discovered issues in the text format

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """

    bits = []

    if not manager.quiet or manager.results_count(sev_level, conf_level):
        bits.append("Run started:%s" % datetime.datetime.utcnow())

        if manager.verbose:
            bits.append(get_verbose_details(manager))

        bits.append("\nTest results:")
        bits.append(get_results(manager, sev_level, conf_level, lines))
        bits.append("\nCode scanned:")
        bits.append('\tTotal lines of code: %i' %
                    (manager.metrics.data['_totals']['loc']))

        bits.append('\tTotal lines skipped (#nosec): %i' %
                    (manager.metrics.data['_totals']['nosec']))

        skipped = manager.get_skipped()
        bits.append(get_metrics(manager))
        bits.append("Files skipped (%i):" % len(skipped))
        bits.extend(["\t%s (%s)" % skip for skip in skipped])
        result = '\n'.join([bit for bit in bits]) + '\n'

        with fileobj:
            wrapped_file = utils.wrap_file_object(fileobj)
            wrapped_file.write(result)

    if fileobj.name != sys.stdout.name:
        LOG.info("Text output written to file: %s", fileobj.name)
