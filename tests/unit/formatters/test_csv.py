# Copyright (c) 2015 VMware, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import csv
import tempfile

import six
import testtools

import bandit
from bandit.core import config
from bandit.core import issue
from bandit.core import manager
from bandit.formatters import csv as b_csv


class CsvFormatterTests(testtools.TestCase):

    def setUp(self):
        super(CsvFormatterTests, self).setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, 'file')
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {'filename': self.tmp_fname,
                        'lineno': 4,
                        'linerange': [4]}
        self.check_name = 'hardcoded_bind_all_interfaces'
        self.issue = issue.Issue(bandit.MEDIUM, bandit.MEDIUM,
                                 'Possible binding to all interfaces.')
        self.manager.out_file = self.tmp_fname

        self.issue.fname = self.context['filename']
        self.issue.lineno = self.context['lineno']
        self.issue.linerange = self.context['linerange']
        self.issue.test = self.check_name

        self.manager.results.append(self.issue)

    def test_report(self):
        tmp_file = open(self.tmp_fname, 'w')
        b_csv.report(self.manager, tmp_file, self.issue.severity,
                     self.issue.confidence)

        with open(self.tmp_fname) as f:
            reader = csv.DictReader(f)
            data = six.next(reader)
            self.assertEqual(self.tmp_fname, data['filename'])
            self.assertEqual(self.issue.severity, data['issue_severity'])
            self.assertEqual(self.issue.confidence, data['issue_confidence'])
            self.assertEqual(self.issue.text, data['issue_text'])
            self.assertEqual(six.text_type(self.context['lineno']),
                             data['line_number'])
            self.assertEqual(six.text_type(self.context['linerange']),
                             data['line_range'])
            self.assertEqual(self.check_name, data['test_name'])
