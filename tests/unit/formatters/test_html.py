# Copyright (c) 2015 Rackspace, Inc.
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

from bs4 import BeautifulSoup
import testtools

import bandit
from bandit.core import config
from bandit.core import manager
from bandit.core import issue
from bandit.formatters import html as b_html


class HtmlFormatterTests(testtools.TestCase):

    def setUp(self):
        super(HtmlFormatterTests, self).setUp()
        cfg_file = os.path.join(os.getcwd(), 'bandit/config/bandit.yaml')
        conf = config.BanditConfig(cfg_file)
        self.manager = manager.BanditManager(conf, 'file')
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {'filename': self.tmp_fname,
                        'lineno': 4,
                        'linerange': [4]}
        self.check_name = 'hardcoded_bind_all_interfaces'
        self.issue = issue.Issue(
            bandit.MEDIUM, bandit.MEDIUM, 'Possible binding to all interfaces.'
        )
        self.manager.out_file = self.tmp_fname

        self.issue.fname = self.context['filename']
        self.issue.lineno = self.context['lineno']
        self.issue.linerange = self.context['linerange']
        self.issue.test = self.check_name

        self.manager.results.append(self.issue)

    def test_report(self):
        b_html.report(
            self.manager, self.tmp_fname, self.issue.severity,
            self.issue.confidence)

        with open(self.tmp_fname) as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
            sev_span = soup.find_all('span', class_='severity')[0]
            conf_span = soup.find_all('span', class_='confidence')[0]
            text_h2 = soup.find_all('h2', class_='test_text')[0]
            self.assertEqual(self.issue.severity, sev_span.string)
            self.assertEqual(self.issue.confidence, conf_span.string)
            self.assertEqual(self.issue.text, text_h2.string)
