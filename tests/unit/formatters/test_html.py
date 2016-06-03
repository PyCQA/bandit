# Copyright (c) 2015 Rackspace, Inc.
# Copyright (c) 2015 Hewlett Packard Enterprise
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

from collections import OrderedDict
import tempfile

from bs4 import BeautifulSoup
import mock
import testtools

import bandit
from bandit.core import config
from bandit.core import issue
from bandit.core import manager
from bandit.formatters import html as b_html


class HtmlFormatterTests(testtools.TestCase):

    def setUp(self):
        super(HtmlFormatterTests, self).setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, 'file')

        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()

        self.manager.out_file = self.tmp_fname

    def test_report_with_skipped(self):
        self.manager.skipped = [('abc.py', 'File is bad')]

        tmp_file = open(self.tmp_fname, 'w')
        b_html.report(
            self.manager, tmp_file, bandit.LOW, bandit.LOW)

        with open(self.tmp_fname) as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
            skipped_span = soup.find_all('span', id='skipped')[0]

            self.assertEqual(1, len(soup.find_all('span', id='skipped')))
            self.assertIn('abc.py', skipped_span.text)
            self.assertIn('File is bad', skipped_span.text)

    @mock.patch('bandit.core.issue.Issue.get_code')
    @mock.patch('bandit.core.manager.BanditManager.get_issue_list')
    def test_report_contents(self, get_issue_list, get_code):
        self.manager.metrics.data['_totals'] = {'loc': 1000, 'nosec': 50}

        issue_a = _get_issue_instance(severity=bandit.LOW)
        issue_a.fname = 'abc.py'
        issue_a.test = 'AAAAAAA'
        issue_a.text = 'BBBBBBB'
        issue_a.confidence = 'CCCCCCC'
        # don't need to test severity, it determines the color which we're
        # testing separately

        issue_b = _get_issue_instance(severity=bandit.MEDIUM)
        issue_c = _get_issue_instance(severity=bandit.HIGH)

        issue_x = _get_issue_instance()
        get_code.return_value = 'some code'

        issue_y = _get_issue_instance()

        get_issue_list.return_value = OrderedDict([(issue_a, [issue_x,
                                                              issue_y]),
                                                   (issue_b, [issue_x]),
                                                   (issue_c, [issue_y])])

        tmp_file = open(self.tmp_fname, 'w')
        b_html.report(
            self.manager, tmp_file, bandit.LOW, bandit.LOW)

        with open(self.tmp_fname) as f:
            soup = BeautifulSoup(f.read(), 'html.parser')

            self.assertEqual('1000', soup.find_all('span', id='loc')[0].text)
            self.assertEqual('50', soup.find_all('span', id='nosec')[0].text)

            issue1 = soup.find_all('span', id='issue-0')[0]
            issue2 = soup.find_all('span', id='issue-1')[0]
            issue3 = soup.find_all('span', id='issue-2')[0]

            # make sure the class has been applied properly
            self.assertEqual(1, len(issue1.find_all(
                'div', {'class': 'issue-sev-low'})))

            self.assertEqual(1, len(issue2.find_all(
                'div', {'class': 'issue-sev-medium'})))

            self.assertEqual(1, len(issue3.find_all(
                'div', {'class': 'issue-sev-high'})))

            # issue1 has a candidates section with 2 candidates in it
            self.assertEqual(1, len(issue1.find_all('span', id='candidates')))
            self.assertEqual(2, len(issue1.find_all('span', id='candidate')))

            # issue2 doesn't have candidates
            self.assertEqual(0, len(issue2.find_all('span', id='candidates')))
            self.assertEqual(0, len(issue2.find_all('span', id='candidate')))

            # issue1 doesn't have code issue 2 and 3 do
            self.assertEqual(0, len(issue1.find_all('span', id='code')))
            self.assertEqual(1, len(issue2.find_all('span', id='code')))
            self.assertEqual(1, len(issue3.find_all('span', id='code')))

            # issue2 code and issue1 first candidate have code
            self.assertIn('some code', issue1.find_all('span',
                                                       id='candidate')[0].text)
            self.assertIn('some code', issue2.find_all('span',
                                                       id='code')[0].text)

            # make sure correct things are being output in issues
            self.assertIn('AAAAAAA:', issue1.text)
            self.assertIn('BBBBBBB', issue1.text)
            self.assertIn('CCCCCCC', issue1.text)
            self.assertIn('abc.py', issue1.text)


def _get_issue_instance(severity=bandit.MEDIUM, confidence=bandit.MEDIUM):
    new_issue = issue.Issue(severity, confidence, 'Test issue')
    new_issue.fname = 'code.py'
    new_issue.test = 'bandit_plugin'
    new_issue.lineno = 1
    return new_issue
