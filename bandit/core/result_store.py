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

from collections import defaultdict
from collections import OrderedDict
import csv
from datetime import datetime
import json
import linecache
from operator import itemgetter

from bandit.core import constants
from bandit.core import utils


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
        self.format = 'txt'
        self.out_file = None

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

    def _report_xml(self, file_list, scores, excluded_files):
        '''Prints/returns warnings in XML format (Xunit compatible)

        :param files_list: Which files were inspected
        :param scores: The scores awarded to each file in the scope
        :param excluded_files: Which files were excluded from the scope
        :return: A collection containing the XML data
        '''

        import xml.etree.cElementTree as ET

        if self.out_file is None:
            self.out_file = 'bandit_results.xml'

        items = self.resstore.items()
        root = ET.Element('testsuite', name='bandit', tests=str(len(items)))
        for filename, issues in items:
            for issue in issues:
                test = issue['test']
                testcase = ET.SubElement(root, 'testcase',
                                         classname=filename, name=test)
                if self._check_severity(issue['issue_severity']):
                    text = 'Severity: %s Confidence: %s\n%s\nLocation %s:%s'
                    text = text % (
                        issue['issue_severity'], issue['issue_confidence'],
                        issue['issue_text'], issue['fname'], issue['lineno'])
                    ET.SubElement(testcase, 'error',
                                  type=issue['issue_severity'],
                                  message=issue['issue_text']).text = text

        tree = ET.ElementTree(root)
        tree.write(self.out_file, encoding='utf-8', xml_declaration=True)

        print("XML output written to file: %s" % self.out_file)

    def _report_csv(self, file_list, scores, excluded_files):
        '''Prints/returns warnings in JSON format

        :param files_list: Which files were inspected
        :param scores: The scores awarded to each file in the scope
        :param excluded_files: Which files were excluded from the scope
        :return: A collection containing the CSV data
        '''

        results = self._get_issue_list()

        # Remove the code from all the issues in the list, as we will not
        # be including it in the CSV data.
        def del_code(issue):
            del issue['code']
        map(del_code, results)

        if self.out_file is None:
            self.out_file = 'bandit_results.csv'

        with open(self.out_file, 'w') as fout:
            fieldnames = ['filename',
                          'test_name',
                          'issue_severity',
                          'issue_confidence',
                          'issue_text',
                          'line_number',
                          'line_range']

            writer = csv.DictWriter(fout, fieldnames=fieldnames,
                                    extrasaction='ignore')
            writer.writeheader()
            for result in results:
                writer.writerow(result)

        print("CSV output written to file: %s" % self.out_file)

    def _report_json(self, file_list, scores, excluded_files):
        '''Prints/returns warnings in JSON format

        :param files_list: Which files were inspected
        :param scores: The scores awarded to each file in the scope
        :param excluded_files: Which files were excluded from the scope
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
            for i in range(self.level, len(constants.RANKING)):
                severity = constants.RANKING[i]
                severity_value = constants.RANKING_VALUES[severity]
                try:
                    sc = score['SEVERITY'][i] / severity_value
                except ZeroDivisionError:
                    sc = 0
                totals[severity] = sc

            machine_output['stats'].append({'filename': filer,
                                            'score': self._sum_scores(score),
                                            'issue totals': totals})

        collector = self._get_issue_list()

        if self.agg_type == 'vuln':
            machine_output['results'] = sorted(collector,
                                               key=itemgetter('error_type'))
        else:
            machine_output['results'] = sorted(collector,
                                               key=itemgetter('filename'))

        result = json.dumps(machine_output, sort_keys=True,
                            indent=2, separators=(',', ': '))

        if self.out_file:
            with open(self.out_file, 'w') as fout:
                fout.write(result)
                # XXX: Should this be log output? (ukbelch)
            print("JSON output written to file: %s" % self.out_file)
        else:
            print(result)

    def _report_text(self, files_list, scores, excluded_files):
        '''Prints the contents of the result store

        :param files_list: Which files were inspected
        :param scores: The scores awarded to each file in the scope
        :param excluded_files: List of files excluded from the scope
        :return: TXT string with appropriate TTY coloring for terminals
        '''

        tmpstr_list = []

        # use a defaultdict to default to an empty string
        color = defaultdict(str)

        if self.format == 'txt':
            # get text colors from settings for TTY output
            get_setting = self.config.get_setting
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

        for filename, issues in self.resstore.items():
            for issue in issues:

                # if the result isn't filtered out by severity
                if self._check_severity(issue['issue_severity']):
                    tmpstr_list.append("\n%s>> Issue: %s\n" % (
                        color.get(issue['issue_severity'], color['DEFAULT']),
                        issue['issue_text']
                    ))
                    tmpstr_list.append("   Severity: %s   Confidence: %s\n" % (
                        issue['issue_severity'].capitalize(),
                        issue['issue_confidence'].capitalize()
                    ))
                    tmpstr_list.append("   Location: %s:%s\n" % (
                        issue['fname'],
                        issue['lineno']
                    ))
                    tmpstr_list.append(color['DEFAULT'])

                    tmpstr_list.append(
                        self._get_code(issue, True))

        result = ''.join(tmpstr_list)

        if self.out_file:
            with open(self.out_file, 'w') as fout:
                fout.write(result)
            self.logger.info("Text output written to file: %s" % self.out_file)
        else:
            print(result)

    def _write_report(self, files_list, scores, excluded_files):
        report_name = '_report_{}'.format(self.format)
        report_func = getattr(self, report_name, self._report_text)

        if self.format == 'csv':
            self.max_lines = 1
        elif report_func is self._report_text and self.out_file:
            self.format = 'plain'

        report_func(files_list, scores, excluded_files=excluded_files)

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
