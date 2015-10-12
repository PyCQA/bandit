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

import os
import tempfile

import testtools

import bandit
from bandit.core import constants
from bandit.core import config
from bandit.core import manager
from bandit.core import issue
from bandit.formatters import text as b_text

class TextFormatterTests(testtools.TestCase):

    def setUp(self):
        super(TextFormatterTests, self).setUp()
        cfg_file = os.path.join(os.getcwd(), 'bandit/config/bandit.yaml')
        conf = config.BanditConfig(cfg_file)
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

        #mock up the metrics
        self.manager.metrics = {}
        for key in ['_totals', 'binding.py']:
            self.manager.metrics[key] = {'loc':4, 'nosec':2}
            for (criteria, default) in constants.CRITERIA:
                for rank in constants.RANKING:
                    self.manager.metrics[key]['{0}.{1}'.format(
                        criteria, rank
                    )] = 0

    def test_report(self):
        self.manager.verbose = True
        file_list = ['binding.py']
        scores = [{'SEVERITY': [0] * len(constants.RANKING),
                   'CONFIDENCE': [0] * len(constants.RANKING)}]
        exc_files = ['test_binding.py']

        b_text.report(self.manager, self.tmp_fname, self.issue.severity,
                      self.issue.confidence)

        with open(self.tmp_fname) as f:
            data = f.read()
            expected = '>> Issue: %s' % self.issue.text
            self.assertIn(expected, data)
            expected = '   Severity: %s   Confidence: %s' % (
                self.issue.severity.capitalize(),
                self.issue.confidence.capitalize())
            self.assertIn(expected, data)
            expected = '   Location: %s:%d' % (self.tmp_fname,
                                               self.context['lineno'])
            self.assertIn(expected, data)
            expected = 'Total lines of code: {0}'.format(
                self.manager.metrics['_totals']['loc']
            )
            self.assertIn(expected, data)
            expected = 'Total lines skipped (#nosec): {0}'.format(
                self.manager.metrics['_totals']['nosec']
            )
            self.assertIn(expected, data)
