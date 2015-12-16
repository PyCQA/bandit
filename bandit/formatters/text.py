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
Description
-----------
This formatter outputs the issues as plain text.

Sample Output
-------------
.. code-block:: none

    >> Issue: [blacklist_calls] Use of unsafe yaml load. Allows instantiation
       of arbitrary objects. Consider yaml.safe_load().

       Severity: Medium   Confidence: High
       Location: examples/yaml_load.py:5
    4       ystr = yaml.dump({'a' : 1, 'b' : 2, 'c' : 3})
    5       y = yaml.load(ystr)
    6       yaml.dump(y)

.. versionadded:: 0.9.0

"""

import collections
import datetime
import logging

from bandit.core import constants
from bandit.core.test_properties import accepts_baseline
from bandit.core import utils

logger = logging.getLogger(__name__)


@accepts_baseline
def report(manager, filename, sev_level, conf_level, lines=-1,
           out_format='txt'):
    """Prints baseline issues in the text format

    This is identical to normal text output except for each issue
    we're going to output the issue we've found and the candidate
    issues in the file.

    :param manager: the bandit manager object
    :param filename: The output file name, or None for stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    :param out_format: The output format name
    """

    tmpstr_list = []

    # use a defaultdict to default to an empty string
    color = collections.defaultdict(str)

    candidate_indent = ' ' * 10

    if out_format == 'txt':
        # get text colors from settings for TTY output
        get_setting = manager.b_conf.get_setting
        color = {'HEADER': get_setting('color_HEADER'),
                 'DEFAULT': get_setting('color_DEFAULT'),
                 'LOW': get_setting('color_LOW'),
                 'MEDIUM': get_setting('color_MEDIUM'),
                 'HIGH': get_setting('color_HIGH')
                 }

    # print header
    tmpstr_list.append("%sRun started:%s\n\t%s\n" % (
        color['HEADER'],
        color['DEFAULT'],
        datetime.datetime.utcnow()
    ))

    if manager.verbose:
        # print which files were inspected
        tmpstr_list.append("\n%sFiles in scope (%s):%s\n" % (
            color['HEADER'], len(manager.files_list),
            color['DEFAULT']
        ))
        for (item, score) in zip(manager.files_list, manager.scores):
            score_dict = {'SEVERITY': sum(score['SEVERITY']),
                          'CONFIDENCE': sum(score['CONFIDENCE'])}
            tmpstr_list.append("\t%s (score: %s)\n" % (item, score_dict))

        # print which files were excluded and why
        tmpstr_list.append("\n%sFiles excluded (%s):%s\n" %
                           (color['HEADER'], len(manager.excluded_files),
                            color['DEFAULT']))
        for fname in manager.excluded_files:
            tmpstr_list.append("\t%s\n" % fname)

    # print out basic metrics from run
    metrics_summary = ''
    for (label, metric) in [
        ('Total lines of code', 'loc'),
        ('Total lines skipped (#nosec)', 'nosec')
    ]:
        metrics_summary += "\t%s: %s\n" % (
            label, manager.metrics.data['_totals'][metric]
        )
    for (criteria, default) in constants.CRITERIA:
        metrics_summary += "\tTotal issues (by %s):\n" % (
            criteria.lower()
        )
        for rank in constants.RANKING:
            metrics_summary += "\t\t%s: %s\n" % (
                rank.capitalize(),
                manager.metrics.data['_totals']['%s.%s' % (criteria, rank)]
            )
    tmpstr_list.append("\n%sRun metrics:%s\n%s" % (
        color['HEADER'],
        color['DEFAULT'],
        metrics_summary
    ))

    # print which files were skipped and why
    tmpstr_list.append("\n%sFiles skipped (%s):%s\n" % (
        color['HEADER'], len(manager.skipped),
        color['DEFAULT']
    ))

    for (fname, reason) in manager.skipped:
        tmpstr_list.append("\t%s (%s)\n" % (fname, reason))

    # print the results
    tmpstr_list.append("\n%sTest results:%s\n" % (
        color['HEADER'], color['DEFAULT']
    ))

    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)

    if not len(issues):
        tmpstr_list.append("\tNo issues identified.\n")

    baseline = not isinstance(issues, list)

    for issue in issues:
        # if not a baseline or only one candidate we know the issue
        if not baseline or len(issues[issue]) == 1:
            tmpstr_list += _output_issue_str(issue, color, "",
                                             lines=lines)

        # otherwise show the finding and the candidates
        else:
            tmpstr_list += _output_issue_str(issue, color, "",
                                             show_lineno=False,
                                             show_code=False)

            tmpstr_list.append('\n-- Candidate Issues --\n')
            for candidate in issues[issue]:
                tmpstr_list += _output_issue_str(candidate, color,
                                                 candidate_indent,
                                                 lines=lines)
                tmpstr_list.append('\n')

        tmpstr_list.append(str('-' * 50 + '\n'))

    result = ''.join(tmpstr_list)

    with utils.output_file(filename, 'w') as fout:
        fout.write(result)

    if filename is not None:
        logger.info("Text output written to file: %s", filename)


def _output_issue_str(issue, color, indent, show_lineno=True, show_code=True,
                      lines=-1):
    # returns a list of lines that should be added to the existing lines list
    tmpstr_list = list()

    tmpstr_list.append("\n%s%s>> Issue: [%s] %s\n" % (
        indent,
        color.get(issue.severity, color['DEFAULT']),
        issue.test,
        issue.text
    ))

    tmpstr_list.append("%s   Severity: %s   Confidence: %s\n" % (
        indent,
        issue.severity.capitalize(),
        issue.confidence.capitalize()
    ))

    tmpstr_list.append("%s   Location: %s:%s\n" % (
        indent,
        issue.fname,
        issue.lineno if show_lineno else ""
    ))

    tmpstr_list.append(color['DEFAULT'])

    if show_code:
        tmpstr_list += list(indent + l + '\n' for l in
                            issue.get_code(lines, True).split('\n'))

    return tmpstr_list
