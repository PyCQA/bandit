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
from datetime import datetime
import json
import linecache
from operator import itemgetter

import constants
import utils


class BanditResultStore():
    resstore = OrderedDict()
    count = 0
    skipped = None

    def __init__(self, logger, config, agg_type):
        self.count = 0
        self.skipped = []
        self.logger = logger
        self.config = config
        self.agg_type = agg_type
        self.level = 0
        self.max_lines = -1

    @property
    def count(self):
        '''Count property - used to get the current number of test results

        :return: The current count of test results
        '''
        return self.count

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
        (issue_type, issue_text) = issue

        if self.agg_type == 'vuln':
            if test in self.resstore:
                self.resstore[test].append({'fname': filename,
                                            'lineno': lineno,
                                            'linerange': linerange,
                                            'issue_type': issue_type,
                                            'issue_text': issue_text})
            else:
                self.resstore[test] = [{'fname': filename,
                                        'lineno': lineno,
                                        'linerange': linerange,
                                        'issue_type': issue_type,
                                        'issue_text': issue_text}]
        else:
            if filename in self.resstore:
                self.resstore[filename].append({'lineno': lineno,
                                                'linerange': linerange,
                                                'test': test,
                                                'issue_type': issue_type,
                                                'issue_text': issue_text})
            else:
                self.resstore[filename] = [{'lineno': lineno,
                                            'linerange': linerange,
                                            'test': test,
                                            'issue_type': issue_type,
                                            'issue_text': issue_text}]
        self.count += 1

    def _report_json(self, file_list, scores, excluded_files):
        '''Prints/returns warnings in JSON format

        :param files_list: Which files were inspected
        :param scores: The scores awarded to each file in the scope
        :param excluded_files: Which files were excluded from the scope
        :param lines: number of lines around the affected code to print
        :return: JSON string
        '''

        stats = dict(zip(file_list, scores))

        machine_output = dict({'results': [], 'errors': [], 'stats': []})
        collector = list()
        for (fname, reason) in self.skipped:
            machine_output['errors'].append({'filename': fname,
                                            'reason': reason})

        for filer, score in stats.iteritems():
            totals = {}
            for i in range(self.level, len(constants.SEVERITY)):
                severity = constants.SEVERITY[i]
                sc = score[i] / constants.SEVERITY_VALUES[severity]
                totals[severity] = sc

            machine_output['stats'].append({'filename': filer,
                                            'score': self._sum_scores(score),
                                            'issue totals': totals})

        # array indeces are determined by order of tuples defined in add()
        if self.agg_type == 'file':
            for item in self.resstore.items():
                filename = item[0]
                filelist = item[1]
                for issue in filelist:
                    issue['fname'] = filename
                    if self._check_severity(issue['issue_type']):
                        line_range = issue['linerange']
                        line_num = issue['lineno']
                        error_label = str(issue['test']).strip()
                        error_type = str(issue['issue_type']).strip()
                        reason = str(issue['issue_text']).strip()
                        code = self._get_code(issue, True)
                        holder = dict({"filename": filename,
                                       "line_num": line_num,
                                       "line_range": line_range,
                                       "error_label": error_label,
                                       "error_type": error_type,
                                       "code": code,
                                       "reason": reason})
                        collector.append(holder)
        else:
            for item in self.resstore.items():
                vuln_label = item[0]
                filelist = item[1]
                for issue in filelist:
                    if self._check_severity(issue['issue_type']):
                        filename = str(issue['fname'])
                        line_range = issue['linerange']
                        line_num = issue['lineno']
                        error_type = str(issue['issue_type']).strip()
                        reason = str(issue['issue_text']).strip()
                        code = self._get_code(issue, True)
                        holder = dict({"filename": filename,
                                       "line_num": line_num,
                                       "line_range": line_range,
                                       "error_label": vuln_label.strip(),
                                       "error_type": error_type,
                                       "code": code,
                                       "reason": reason})
                        collector.append(holder)

        if self.agg_type == 'vuln':
            machine_output['results'] = sorted(collector,
                                               key=itemgetter('error_type'))
        else:
            machine_output['results'] = sorted(collector,
                                               key=itemgetter('filename'))

        return json.dumps(machine_output, sort_keys=True,
                          indent=2, separators=(',', ': '))

    def _report_txt(self, files_list, scores, excluded_files):
        '''Returns TXT string of results

        :param scope: Which files were inspected
        :param scores: The scores awarded to each file in the scope
        :param lines: # of lines around the issue line to display (optional)
        :param level: What level of severity to display (optional)
        :return: TXT string
        '''

        tmpstr_list = []

        # print header
        tmpstr_list.append("Run started:\n\t%s\n" % datetime.utcnow())

        # print which files were inspected
        tmpstr_list.append("Files in scope (%s):\n" % (len(files_list)))

        for item in zip(files_list, map(self._sum_scores, scores)):
            tmpstr_list.append("\t%s (score: %i)\n" % item)

        # print which files were excluded
        tmpstr_list.append("Files excluded (%s):\n" % (len(excluded_files)))
        for item in excluded_files:
            tmpstr_list.append("\n\t%s" % item)

        # print which files were skipped and why
        tmpstr_list.append("Files skipped (%s):" % len(self.skipped))
        for (fname, reason) in self.skipped:
            tmpstr_list.append("\n\t%s (%s)" % (fname, reason))

        # print the results
        tmpstr_list.append("\nTest results:\n")
        if self.count == 0:
            tmpstr_list.append("\tNo issues identified.\n")
        # if aggregating by vulnerability type
        elif self.agg_type == 'vuln':
            for test, issues in self.resstore.items():
                for issue in issues:

                    # if the result in't filtered out by severity
                    if self._check_severity(issue['issue_type']):
                        tmpstr_list.append("\n>> %s\n - %s::%s\n" % (
                            issue['issue_text'],
                            issue['fname'],
                            issue['lineno']
                        ))

                        tmpstr_list.append(
                            self._get_code(issue, True))

        # otherwise, aggregating by filename
        else:
            for filename, issues in self.resstore.items():
                for issue in issues:
                    issue['fname'] = filename

                    # if the result isn't filtered out by severity
                    if self._check_severity(issue['issue_type']):
                        tmpstr_list.append("\n>> %s\n - %s::%s\n" % (
                            issue['issue_text'], filename, issue['lineno']
                        ))

                        tmpstr_list.append(
                            self._get_code(issue, True))
        return "".join(tmpstr_list)

    def _report_tty(self, files_list, scores, excluded_files, lines=0):
        '''Prints the contents of the result store

        :param scope: Which files were inspected
        :param scores: The scores awarded to each file in the scope
        :param lines: # of lines around the issue line to display (optional)
        :param level: What level of severity to display (optional)
        :return: TXT string with appropriate TTY coloring for terminals
        '''

        tmpstr_list = []

        # get text colors from settings
        get_setting = self.config.get_setting
        color = {'HEADER': get_setting('color_HEADER'),
                 'DEFAULT': get_setting('color_DEFAULT'),
                 'INFO': get_setting('color_INFO'),
                 'WARN': get_setting('color_WARN'),
                 'ERROR': get_setting('color_ERROR')
                 }

        # print header
        tmpstr_list.append("%sRun started:%s\n\t%s\n" % (
            color['HEADER'],
            color['DEFAULT'],
            datetime.utcnow()
        ))

        # print which files were inspected
        tmpstr_list.append("\n%sFiles in scope (%s):%s\n" % (
            color['HEADER'], len(files_list),
            color['DEFAULT']
        ))

        for item in zip(files_list, map(self._sum_scores, scores)):
            tmpstr_list.append("\t%s (score: %i)\n" % item)

        # print which files were excluded and why
        tmpstr_list.append("\n%sFiles excluded (%s):%s\n" % (color['HEADER'],
                           len(excluded_files), color['DEFAULT']))
        for fname in excluded_files:
            tmpstr_list.append("\t%s\n" % fname)

        # print which files were skipped and why
        tmpstr_list.append("\n%sFiles skipped (%s):%s\n" % (
            color['HEADER'], len(self.skipped),
            color['DEFAULT']
        ))

        for (fname, reason) in self.skipped:
            tmpstr_list.append("\t%s (%s)\n" % (fname, reason))

        # print the results
        tmpstr_list.append("\n%sTest results:%s\n" % (
            color['HEADER'], color['DEFAULT']
        ))

        if self.count == 0:
            tmpstr_list.append("\tNo issues identified.\n")
        # if aggregating by vulnerability type
        elif self.agg_type == 'vuln':
            for test, issues in self.resstore.items():
                for issue in issues:

                    # if the result in't filtered out by severity
                    if self._check_severity(issue['issue_type']):
                        tmpstr_list.append("\n%s>> %s\n - %s::%s%s\n" % (
                            color.get(issue['issue_type'], color['DEFAULT']),
                            issue['issue_text'],
                            issue['fname'],
                            issue['lineno'],
                            color['DEFAULT']
                        ))

                        tmpstr_list.append(
                            self._get_code(issue, True))

        # otherwise, aggregating by filename
        else:
            for filename, issues in self.resstore.items():
                for issue in issues:
                    issue['fname'] = filename
                    # if the result isn't filtered out by severity
                    if self._check_severity(issue['issue_type']):
                        tmpstr_list.append("\n%s>> %s\n - %s::%s%s\n" % (
                            color.get(
                                issue['issue_type'], color['DEFAULT']
                            ),
                            issue['issue_text'], filename, issue['lineno'],
                            color['DEFAULT']
                        ))

                        tmpstr_list.append(
                            self._get_code(issue, True))
        return ''.join(tmpstr_list)

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

        if level >= len(constants.SEVERITY):
            level = len(constants.SEVERITY) - 1

        self.level = level
        self.max_lines = lines

        if output_filename is None and output_format == 'txt':
            print (self._report_tty(files_list, scores,
                                    excluded_files=excluded_files))  # noqa
            return

        if output_filename is None and output_format == 'json':
            print (self._report_json(files_list, scores,
                                     excluded_files=excluded_files))  # noqa
            return

        if output_format == 'txt':
            outer = self._report_txt(files_list, scores,
                                     excluded_files=excluded_files)
            with open(output_filename, 'w') as fout:
                fout.write(outer)
            print("TXT output written to file: %s" % output_filename)
            return
        else:
            outer = self._report_json(files_list, scores,
                                      excluded_files=excluded_files)
            with open(output_filename, 'w') as fout:
                fout.write(outer)
            print("JSON output written to file: %s" % output_filename)
            return

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

    def _sum_scores(self, score_list):
        '''Get total of all scores

        This just computes the sum of all recorded scores, filtering them
        on the chosen minimum severity level.
        :param score_list: the list of scores to total
        :return: an integer total sum of all scores above the threshold
        '''
        return sum(score_list[self.level:])

    def _check_severity(self, severity):
        '''Check severity level

        returns true if the issue severity is above the threshold.
        :param severity: the severity of the issue being checked
        :return: boolean result
        '''
        return constants.SEVERITY.index(severity) >= self.level
