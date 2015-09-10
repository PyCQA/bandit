# -*- coding:utf-8 -*-
#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
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

import testtools

import bandit
from bandit.core import issue


class IssueTests(testtools.TestCase):

    def test_issue_create(self):
        new_issue = _get_issue_instance()
        self.assertIsInstance(new_issue, issue.Issue)

    def test_issue_str(self):
        test_issue = _get_issue_instance()
        self.assertEqual(
            ("Issue: 'Test issue' from bandit_plugin: Severity: MEDIUM "
             "Confidence: MEDIUM at code.py:1"),
            str(test_issue)
        )

    def test_issue_as_dict(self):
        test_issue = _get_issue_instance()
        test_issue_dict = test_issue.as_dict(with_code=False)
        self.assertIsInstance(test_issue_dict, dict)
        for attr in [
            'filename', 'test_name', 'issue_severity', 'issue_confidence',
            'issue_text', 'line_number', 'line_range'
        ]:
            self.assertIn(attr, test_issue_dict)

    def test_issue_filter(self):
        test_issue = _get_issue_instance()
        result = test_issue.filter(bandit.HIGH, bandit.HIGH)
        self.assertFalse(result)
        result = test_issue.filter(bandit.MEDIUM, bandit.MEDIUM)
        self.assertTrue(result)
        result = test_issue.filter(bandit.LOW, bandit.LOW)
        self.assertTrue(result)
        result = test_issue.filter(bandit.LOW, bandit.HIGH)
        self.assertFalse(result)
        result = test_issue.filter(bandit.HIGH, bandit.LOW)
        self.assertFalse(result)

def _get_issue_instance():
    new_issue = issue.Issue(bandit.MEDIUM, bandit.MEDIUM, 'Test issue')
    new_issue.fname = 'code.py'
    new_issue.test = 'bandit_plugin'
    new_issue.lineno = 1
    return new_issue
