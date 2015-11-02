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

import collections
import datetime
import logging

from bandit.core import constants
from bandit.core import utils

logger = logging.getLogger(__name__)


def report(manager, filename, sev_level, conf_level, lines=-1,
           out_format='txt'):
    '''Prints issues in Text formt

    :param manager: the bandit manager object
    :param filename: The output file name, or None for stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    :param out_format: The ouput format name
    '''

    tmpstr_list = []

    # use a defaultdict to default to an empty string
    color = collections.defaultdict(str)

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

        for item in zip(manager.files_list, map(utils.sum_scores,
                                                manager.scores)):
            tmpstr_list.append("\t%s (score: %i)\n" % item)

        # print which files were excluded and why
        tmpstr_list.append("\n%sFiles excluded (%s):%s\n" %
                           (color['HEADER'], len(manager.skipped),
                            color['DEFAULT']))
        for fname in manager.skipped:
            tmpstr_list.append("\t%s\n" % fname)

    # print out basic metrics from run
    metrics_summary = ''
    for (label, metric) in [
        ('Total lines of code', 'loc'),
        ('Total lines skipped (#nosec)', 'nosec')
    ]:
        metrics_summary += "\t{0}: {1}\n".format(
            label, manager.metrics.data['_totals'][metric]
        )
    for (criteria, default) in constants.CRITERIA:
        metrics_summary += "\tTotal issues (by {0}):\n".format(
            criteria.lower()
        )
        for rank in constants.RANKING:
            metrics_summary += "\t\t{0}: {1}\n".format(
                rank.capitalize(),
                manager.metrics.data['_totals']['{0}.{1}'.format(criteria,
                                                                 rank)]
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

    for issue in issues:
        tmpstr_list.append("\n%s>> Issue: [%s] %s\n" % (
            color.get(issue.severity, color['DEFAULT']),
            issue.test,
            issue.text
        ))
        tmpstr_list.append("   Severity: %s   Confidence: %s\n" % (
            issue.severity.capitalize(),
            issue.confidence.capitalize()
        ))
        tmpstr_list.append("   Location: %s:%s\n" % (
            issue.fname,
            issue.lineno
        ))
        tmpstr_list.append(color['DEFAULT'])

        tmpstr_list.append(
            issue.get_code(lines, True))

    result = ''.join(tmpstr_list)

    with utils.output_file(filename, 'w') as fout:
        fout.write(result)

    if filename is not None:
        logger.info("Text output written to file: %s", filename)
