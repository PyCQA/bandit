# Copyright (c) 2015 VMware, Inc.
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
import os
import mock
import tempfile

import testtools

import bandit
from bandit.core import config
from bandit.core import manager
from bandit.core import issue
from bandit.formatters import screen


class ScreenFormatterTests(testtools.TestCase):

    def setUp(self):
        super(ScreenFormatterTests, self).setUp()


    @mock.patch('bandit.core.issue.Issue.get_code')
    def test_output_issue(self, get_code):
        issue = _get_issue_instance()
        get_code.return_value = 'DDDDDDD'
        indent_val = 'CCCCCCC'

        def _template(_issue, _indent_val, _code, _color):
            return_val = ["{}{}>> Issue: [{}] {}".
                          format(_indent_val, _color, _issue.test,
                                 _issue.text),
                          "{}   Severity: {}   Confidence: {}".
                          format(_indent_val, _issue.severity.capitalize(),
                                 _issue.confidence.capitalize()),
                          "{}   Location: {}:{}{}".
                          format(_indent_val, _issue.fname, _issue.lineno,
                                 screen.color['DEFAULT'])]
            if _code:
                return_val.append("{}{}".format(_indent_val, _code))
            return '\n'.join(return_val)

        issue_text = screen._output_issue_str(issue, indent_val)
        expected_return = _template(issue, indent_val, 'DDDDDDD',
                                    screen.color['MEDIUM'])
        self.assertEqual(expected_return, issue_text)

        issue_text = screen._output_issue_str(issue, indent_val,
                                              show_code=False)
        expected_return = _template(issue, indent_val, '',
                                    screen.color['MEDIUM'])
        self.assertEqual(expected_return, issue_text)

        issue.lineno = ''
        issue_text = screen._output_issue_str(issue, indent_val,
                                              show_lineno=False)
        expected_return = _template(issue, indent_val, 'DDDDDDD',
                                    screen.color['MEDIUM'])
        self.assertEqual(expected_return, issue_text)


    @mock.patch('bandit.core.manager.BanditManager.get_issue_list')
    def test_no_issues(self, get_issue_list):
        cfg_file = os.path.join(os.getcwd(), 'bandit/config/bandit.yaml')
        conf = config.BanditConfig(cfg_file)
        self.manager = manager.BanditManager(conf, 'file')

        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.manager.out_file = self.tmp_fname

        get_issue_list.return_value = OrderedDict()
        with mock.patch('bandit.formatters.screen.do_print') as m:
            screen.report(self.manager, self.tmp_fname, bandit.LOW, bandit.LOW,
                         lines=5)
            self.assertIn('No issues identified.',
                          '\n'.join([str(a) for a in m.call_args]))


    @mock.patch('bandit.core.manager.BanditManager.get_issue_list')
    def test_report_nobaseline(self, get_issue_list):
        cfg_file = os.path.join(os.getcwd(), 'bandit/config/bandit.yaml')
        conf = config.BanditConfig(cfg_file)
        self.manager = manager.BanditManager(conf, 'file')

        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.manager.out_file = self.tmp_fname

        self.manager.verbose = True
        self.manager.files_list = ['binding.py']

        self.manager.scores = [{'SEVERITY': [0, 0, 0, 1],
                                'CONFIDENCE': [0, 0, 0, 1]}]

        self.manager.skipped = [('abc.py', 'File is bad')]
        self.manager.excluded_files = ['def.py']

        issue_a = _get_issue_instance()
        issue_b = _get_issue_instance()

        get_issue_list.return_value = [issue_a, issue_b]

        self.manager.metrics.data['_totals'] = {'loc': 1000, 'nosec': 50}
        for category in ['SEVERITY', 'CONFIDENCE']:
            for level in ['UNDEFINED', 'LOW', 'MEDIUM', 'HIGH']:
                self.manager.metrics.data['_totals']['%s.%s' %
                                                     (category, level)] = 1

        # Validate that we're outputting the correct issues
        indent_val = ' ' * 10
        output_str_fn = 'bandit.formatters.screen._output_issue_str'
        with mock.patch(output_str_fn) as output_str:
            screen.report(self.manager, self.tmp_fname, bandit.LOW, bandit.LOW, lines=5)

            calls = [mock.call(issue_a, '', lines=5),
                     mock.call(issue_b, '', lines=5)]

            output_str.assert_has_calls(calls, any_order=True)

        # Validate that we're outputting all of the expected fields and the
        # correct values
        with mock.patch('bandit.formatters.screen.do_print') as m:
            screen.report(self.manager, self.tmp_fname, bandit.LOW, bandit.LOW,
                          lines=5)

            data = '\n'.join([str(a) for a in m.call_args[0][0]])

            expected = 'Run started'
            self.assertIn(expected, data)

            expected_items = [
                screen.header('Files in scope (1):'),
                '\n\tbinding.py (score: {SEVERITY: 1, CONFIDENCE: 1})']

            for item in expected_items:
                self.assertIn(item, data)

            expected = screen.header('Files excluded (1):') + '\n\tdef.py'
            self.assertIn(expected, data)

            expected = ('Total lines of code: 1000\n\tTotal lines skipped '
                        '(#nosec): 50')
            self.assertIn(expected, data)

            expected = ('Total issues (by severity):\n\t\tUndefined: 1\n\t\t'
                        'Low: 1\n\t\tMedium: 1\n\t\tHigh: 1')
            self.assertIn(expected, data)

            expected = ('Total issues (by confidence):\n\t\tUndefined: 1\n\t\t'
                        'Low: 1\n\t\tMedium: 1\n\t\tHigh: 1')
            self.assertIn(expected, data)

            expected = (screen.header('Files skipped (1):') +
                        '\n\tabc.py (File is bad)')
            self.assertIn(expected, data)


    @mock.patch('bandit.core.manager.BanditManager.get_issue_list')
    def test_report_baseline(self, get_issue_list):
        cfg_file = os.path.join(os.getcwd(), 'bandit/config/bandit.yaml')
        conf = config.BanditConfig(cfg_file)
        self.manager = manager.BanditManager(conf, 'file')

        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.manager.out_file = self.tmp_fname

        issue_a = _get_issue_instance()
        issue_b = _get_issue_instance()

        issue_x = _get_issue_instance()
        issue_x.fname = 'x'
        issue_y = _get_issue_instance()
        issue_y.fname = 'y'
        issue_z = _get_issue_instance()
        issue_z.fname = 'z'

        get_issue_list.return_value = OrderedDict([(issue_a, [issue_x]),
                                                   (issue_b, [issue_y, issue_z])])

        # Validate that we're outputting the correct issues
        indent_val = ' ' * 10
        output_str_fn = 'bandit.formatters.screen._output_issue_str'
        with mock.patch(output_str_fn) as output_str:
            screen.report(self.manager, self.tmp_fname, bandit.LOW, bandit.LOW, lines=5)

            calls = [mock.call(issue_a, '', lines=5),
                     mock.call(issue_b, '', show_code=False, show_lineno=False),
                     mock.call(issue_y, indent_val, lines=5),
                     mock.call(issue_z, indent_val, lines=5)]

            output_str.assert_has_calls(calls, any_order=True)


def _get_issue_instance(severity=bandit.MEDIUM, confidence=bandit.MEDIUM):
    new_issue = issue.Issue(severity, confidence, 'Test issue')
    new_issue.fname = 'code.py'
    new_issue.test = 'bandit_plugin'
    new_issue.lineno = 1
    return new_issue
