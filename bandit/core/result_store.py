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
import re

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
                                            'line': lineno,
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

    def report_json(self, output_filename, stats=None, lines=1):
        '''Prints/returns warnings in JSON format

        :param output_filename: File to output the results (optional)
        :param stats: dictionary of stats for each file
        :param lines: number of lines around code to print
        :return: JSON string
        '''
        machine_output = dict({'results': [], 'errors': [], 'stats': []})
        collector = list()
        for (fname, reason) in self.skipped:
            machine_output['errors'].append({'filename': fname,
                                            'reason': reason})

        for filer, score in stats.iteritems():
            machine_output['stats'].append({'filename': filer,
                                            'score': score})

        # array indeces are determined by order of tuples defined in add()
        if self.agg_type == 'file':
            for item in self.resstore.items():
                filename = item[0]
                filelist = item[1]
                for x in filelist:
                    line_range = x['linerange']
                    line_num = x['lineno']
                    error_label = str(x['test']).strip()
                    error_type = str(x['issue_type']).strip()
                    reason = str(x['issue_text']).strip()
                    code = self.get_code(filename, line_range, True)
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
                for x in filelist:
                    filename = str(x['fname'])
                    line_range = x['linerange']
                    line_num = x['lineno']
                    error_type = str(x['issue_type']).strip()
                    reason = str(x['issue_text']).strip()
                    code = self.get_code(filename, line_range, True)
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

    def report_txt(self, files_list, scores, excluded_files, lines=0,
                   level=1):
        '''Returns TXT string of results

        :param scope: Which files were inspected
        :param scores: The scores awarded to each file in the scope
        :param lines: # of lines around the issue line to display (optional)
        :param level: What level of severity to display (optional)
        :return: TXT string
        '''

        if level >= len(constants.SEVERITY):
            level = len(constants.SEVERITY) - 1

        tmpstr_list = []

        # print header
        tmpstr_list.append("Run started:\n\t%s\n" % datetime.utcnow())

        # print which files were inspected
        tmpstr_list.append("Files in scope (%s):\n" % (len(files_list)))
        for item in zip(files_list, scores):
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
                    max_lines = self.file_length(issue['fname'])
                    issue_line = self.get_code(issue['fname'],
                                               issue['linerange'])
                    # if the line doesn't have one of the skip tags, keep going
                    if re.search(constants.SKIP_RE, issue_line):
                        continue
                    # if the result in't filtered out by severity
                    if constants.SEVERITY.index(issue['issue_type']) >= level:
                        tmpstr_list.append("\n>> %s\n - %s::%s\n" % (
                            issue['issue_text'],
                            issue['fname'],
                            issue['lineno']
                        ))

                        tmpstr_list.append(
                            self.get_code(
                                issue['fname'],
                                utils.lines_with_context(issue['linerange'],
                                                         lines,
                                                         max_lines),
                                True))

        # otherwise, aggregating by filename
        else:
            for filename, issues in self.resstore.items():
                for lineno, test, issue_type, issue_text in issues:
                    max_lines = self.file_length(filename)
                    issue_line = self.get_code(filename,
                                               issue['linerange'])
                    # if the line doesn't have one of the skip tags, keep going
                    if re.search(constants.SKIP_RE, issue_line):
                        continue
                    # if the result isn't filtered out by severity
                    if constants.SEVERITY.index(issue['issue_type']) >= level:
                        tmpstr_list.append("\n>> %s\n - %s::%s\n" % (
                            issue['issue_text'], filename, issue['lineno']
                        ))

                        tmpstr_list.append(
                            self.get_code(
                                filename,
                                utils.lines_with_context(issue['linerange'],
                                                         lines,
                                                         max_lines),
                                True))
        return "".join(tmpstr_list)

    def report_tty(self, files_list, scores, excluded_files, lines=0,
                   level=1):
        '''Prints the contents of the result store

        :param scope: Which files were inspected
        :param scores: The scores awarded to each file in the scope
        :param lines: # of lines around the issue line to display (optional)
        :param level: What level of severity to display (optional)
        :return: TXT string with appropriate TTY coloring for terminals
        '''

        if level >= len(constants.SEVERITY):
            level = len(constants.SEVERITY) - 1

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

        for item in zip(files_list, scores):
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
                    max_lines = self.file_length(issue['fname'])
                    issue_line = self.get_code(issue['fname'],
                                               issue['linerange'])
                    # if the line doesn't have one of the skip tags, keep going
                    if re.search(constants.SKIP_RE, issue_line):
                        continue
                    # if the result in't filtered out by severity
                    if constants.SEVERITY.index(issue['issue_type']) >= level:
                        tmpstr_list.append("\n%s>> %s\n - %s::%s%s\n" % (
                            color.get(issue['issue_type'], color['DEFAULT']),
                            issue['issue_text'],
                            issue['fname'],
                            issue['lineno'],
                            color['DEFAULT']
                        ))

                        tmpstr_list.append(
                            self.get_code(
                                issue['fname'],
                                utils.lines_with_context(issue['linerange'],
                                                         lines,
                                                         max_lines),
                                True))

        # otherwise, aggregating by filename
        else:
            for filename, issues in self.resstore.items():
                for issue in issues:
                    max_lines = self.file_length(filename)
                    issue_line = self.get_code(filename, issue['linerange'])
                    # if the line doesn't have one of the skip tags, keep going
                    if re.search(constants.SKIP_RE, issue_line):
                        continue
                    # if the result isn't filtered out by severity
                    if constants.SEVERITY.index(issue['issue_type']) >= level:
                        tmpstr_list.append("\n%s>> %s\n - %s::%s%s\n" % (
                            color.get(
                                issue['issue_type'], color['DEFAULT']
                            ),
                            issue['issue_text'], filename, issue['lineno'],
                            color['DEFAULT']
                        ))

                        tmpstr_list.append(
                            self.get_code(
                                filename,
                                utils.lines_with_context(issue['linerange'],
                                                         lines,
                                                         max_lines),
                                True))
        return ''.join(tmpstr_list)

    def report(self, files_list, scores, excluded_files=None, lines=0, level=1,
               output_filename=None, output_format=None):
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

        scores_dict = dict(zip(files_list, scores))

        if output_filename is None and output_format == 'txt':
            print self.report_tty(files_list, scores,
                                  excluded_files=excluded_files, lines=lines,
                                  level=level)  # noqa
            return

        if output_filename is None and output_format == 'json':
            print self.report_json(output_filename, scores_dict)  # noqa
            return

        if output_format == 'txt':
            outer = self.report_txt(files_list, scores,
                                    excluded_files=excluded_files, lines=lines,
                                    level=level)
            with open(output_filename, 'w') as fout:
                fout.write(outer)
            print("TXT output written to file: %s" % output_filename)
            return
        else:
            outer = self.report_json(output_filename, scores_dict)
            with open(output_filename, 'w') as fout:
                fout.write(outer)
            print("JSON output written to file: %s" % output_filename)
            return

    def get_code(self, filename, line_list, tabbed=False):
        '''Gets lines of code from a file

        :param filename: Filename of file with code in it
        :param line_list: A list of integers corresponding to line numbers
        :return: string of code
        '''
        issue_line = []
        prepend = ""
        for l in line_list:
            if l:
                if tabbed:
                    prepend = "%s\t" % l
                issue_line.append(prepend + linecache.getline(filename, l))
        return ''.join(issue_line)

    def file_length(self, filename):
        with open(filename) as f:
            for line, l in enumerate(f):
                pass
        return line + 1
