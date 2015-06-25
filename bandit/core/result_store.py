# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
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


"""An object to store/access results associated with Bandit tests."""

from collections import OrderedDict
import linecache

from bandit.core import constants
from bandit.core import extension_loader
from bandit.core import utils


class BanditResultStore():
    count = 0
    skipped = None

    def __init__(self, logger, config, agg_type, verbose):
        self.resstore = OrderedDict()
        self.count = 0
        self.skipped = []
        self.logger = logger
        self.config = config
        self.agg_type = agg_type
        self.level = 0
        self.max_lines = -1
        self.format = 'txt'
        self.out_file = None
        self.verbose = verbose

    def skip(self, filename, reason):
        '''Indicates that the specified file was skipped and why

        :param filename: The file that was skipped
        :param reason: Why the file was skipped
        :return: -
        '''
        self.skipped.append((filename, reason))

    def add(self, context, test, issue):
        '''Adds a result, with the context and the issue that was found

        :param context: Context of the node
        :param test: The type (function name) of the test
        :param issue: Which issue was found
        :return: -
        '''
        filename = context['filename']
        lineno = context['lineno']
        linerange = context['statement']['linerange']
        (issue_severity, issue_confidence, issue_text) = issue

        if self.agg_type == 'vuln':
            key = test
        else:
            key = filename

        self.resstore.setdefault(key, []).append(
            {'fname': filename,
             'test': test,
             'lineno': lineno,
             'linerange': linerange,
             'issue_severity': issue_severity,
             'issue_confidence': issue_confidence,
             'issue_text': issue_text})

        self.count += 1

    def _write_report(self, files_list, scores, excluded_files):
        formatters_mgr = extension_loader.MANAGER.formatters_mgr
        try:
            formatter = formatters_mgr[self.format]
        except KeyError:  # Unrecognized format, so use text instead
            formatter = formatters_mgr['txt']

        if self.format == 'csv':
            self.max_lines = 1
        elif formatter.name == 'txt' and self.out_file:
            self.format = 'plain'

        report_func = formatter.plugin
        report_func(self, files_list, scores, excluded_files=excluded_files)

    def report(self, files_list, scores, excluded_files=None, lines=-1,
               level=1, output_filename=None, output_format=None):
        '''Prints the contents of the result store

        :param scope: Which files were inspected
        :param scores: The scores awarded to each file in the scope
        :param lines: # of lines around the issue line to display (optional)
        :param level: What level of severity to display (optional)
        :param output_filename: File to output the results (optional)
        :param output_format: File type to output (json|txt)
        :return: -
        '''

        if not excluded_files:
            excluded_files = []

        if level >= len(constants.RANKING):
            level = len(constants.RANKING) - 1

        self.level = level
        self.max_lines = lines
        self.format = output_format
        self.out_file = output_filename

        try:
            self._write_report(files_list, scores, excluded_files)
        except IOError:
            print("Unable to write to file: %s" % self.out_file)

    def _get_issue_list(self):

        collector = list()

        for group in self.resstore.items():
            issue_list = group[1]
            for issue in issue_list:
                if self._check_severity(issue['issue_severity']):
                    code = self._get_code(issue, True)
                    holder = dict({
                        "filename": issue['fname'],
                        "line_number": issue['lineno'],
                        "line_range": issue['linerange'],
                        "test_name": issue['test'],
                        "issue_severity": issue['issue_severity'],
                        "issue_confidence": issue['issue_confidence'],
                        "code": code,
                        "issue_text": issue['issue_text']
                    })
                    collector.append(holder)

        return collector

    def _get_code(self, issue, tabbed=False):
        '''Gets lines of code from a file

        :param filename: Filename of file with code in it
        :param line_list: A list of integers corresponding to line numbers
        :return: string of code
        '''
        issue_line = []
        prepend = ""

        file_len = self._file_length(issue['fname'])
        lines = utils.lines_with_context(issue['lineno'],
                                         issue['linerange'],
                                         self.max_lines,
                                         file_len)

        for l in lines:
            if l:
                if tabbed:
                    prepend = "%s\t" % l
                issue_line.append(prepend + linecache.getline(
                                  issue['fname'],
                                  l))

        return ''.join(issue_line)

    def _file_length(self, filename):
        with open(filename) as f:
            for line, l in enumerate(f):
                pass
        return line + 1

    def _sum_scores(self, scores):
        '''Get total of all scores

        This just computes the sum of all recorded scores, filtering them
        on the chosen minimum severity level.
        :param score_list: the list of scores to total
        :return: an integer total sum of all scores above the threshold
        '''
        total = 0
        for score_type in scores:
            total = total + sum(scores[score_type][self.level:])
        return total

    def _check_severity(self, severity):
        '''Check severity level

        returns true if the issue severity is above the threshold.
        :param severity: the severity of the issue being checked
        :return: boolean result
        '''
        return constants.RANKING.index(severity) >= self.level
