# Copyright (c) 2015 Hewlett Packard Enterprise
# -*- coding:utf-8 -*-
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
================
Screen formatter
================

This formatter outputs the issues as color coded text.

:Example:

.. code-block:: none

    >> Issue: [B301:blacklist_calls] Use of unsafe yaml load. Allows
       instantiation of arbitrary objects. Consider yaml.safe_load().

       Severity: Medium   Confidence: High
       Location: examples/yaml_load.py:5
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
from bandit.core import test_properties

LOG = logging.getLogger(__name__)

COLOR = {
    'DEFAULT': '\033[0m',
    'HEADER': '\033[95m',
    'LOW': '\033[94m',
    'MEDIUM': '\033[93m',
    'HIGH': '\033[91m',
}


def header(text, *args):
    return u'%s%s%s' % (COLOR['HEADER'], (text % args), COLOR['DEFAULT'])


def get_verbose_details(manager):
    bits = []
    bits.append(header(u'Files in scope (%i):', len(manager.files_list)))
    tpl = u"\t%s (score: {SEVERITY: %i, CONFIDENCE: %i})"
    bits.extend([tpl % (item, sum(score['SEVERITY']), sum(score['CONFIDENCE']))
                 for (item, score)
                 in zip(manager.files_list, manager.scores)])
    bits.append(header(u'Files excluded (%i):', len(manager.excluded_files)))
    bits.extend([u"\t%s" % fname for fname in manager.excluded_files])
    return '\n'.join([str(bit) for bit in bits])


def get_metrics(manager):
    bits = []
    bits.append(header("\nRun metrics:"))
    for (criteria, default) in constants.CRITERIA:
        bits.append("\tTotal issues (by %s):" % (criteria.lower()))
        for rank in constants.RANKING:
            bits.append("\t\t%s: %s" % (
                rank.capitalize(),
                manager.metrics.data['_totals']['%s.%s' % (criteria, rank)]))
    return '\n'.join([str(bit) for bit in bits])


def _output_issue_str(issue, indent, show_lineno=True, show_code=True,
                      lines=-1):
    # returns a list of lines that should be added to the existing lines list
    bits = []
    bits.append("%s%s>> Issue: [%s:%s] %s" % (
        indent, COLOR[issue.severity], issue.test_id, issue.test, issue.text))

    bits.append("%s   Severity: %s   Confidence: %s" % (
        indent, issue.severity.capitalize(), issue.confidence.capitalize()))

    bits.append("%s   Location: %s:%s%s" % (
        indent, issue.fname,
        issue.lineno if show_lineno else "",
        COLOR['DEFAULT']))

    if show_code:
        bits.extend([indent + l for l in
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


def do_print(bits):
    # needed so we can mock this stuff
    print('\n'.join([bit for bit in bits]))


@test_properties.accepts_baseline
def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints discovered issues formatted for screen reading

    This makes use of VT100 terminal codes for colored text.

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """

    bits = []
    bits.append(header("Run started:%s", datetime.datetime.utcnow()))

    if manager.verbose:
        bits.append(get_verbose_details(manager))

    bits.append(header("\nTest results:"))
    bits.append(get_results(manager, sev_level, conf_level, lines))
    bits.append(header("\nCode scanned:"))
    bits.append('\tTotal lines of code: %i' %
                (manager.metrics.data['_totals']['loc']))

    bits.append('\tTotal lines skipped (#nosec): %i' %
                (manager.metrics.data['_totals']['nosec']))

    bits.append(get_metrics(manager))
    skipped = manager.get_skipped()
    bits.append(header("Files skipped (%i):", len(skipped)))
    bits.extend(["\t%s (%s)" % skip for skip in skipped])
    do_print(bits)

    if fileobj.name != sys.stdout.name:
        LOG.info("Screen formatter output was not written to file: %s, "
                 "consider '-f txt'", fileobj.name)
