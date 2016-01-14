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

from collections import defaultdict
import os
import tempfile
from xml.etree import cElementTree as ET

import six
import testtools

import bandit
from bandit.core import config
from bandit.core import issue
from bandit.core import manager
from bandit.formatters import xml as b_xml


class XmlFormatterTests(testtools.TestCase):

    def setUp(self):
        super(XmlFormatterTests, self).setUp()
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

    def _xml_to_dict(self, t):
        d = {t.tag: {} if t.attrib else None}
        children = list(t)
        if children:
            dd = defaultdict(list)
            for dc in map(self._xml_to_dict, children):
                for k, v in six.iteritems(dc):
                    dd[k].append(v)
            d = {t.tag: {k: v[0] if len(v) == 1 else v
                         for k, v in six.iteritems(dd)}}
        if t.attrib:
            d[t.tag].update(('@' + k, v) for k, v in six.iteritems(t.attrib))
        if t.text:
            text = t.text.strip()
            if children or t.attrib:
                if text:
                    d[t.tag]['#text'] = text
            else:
                d[t.tag] = text
        return d

    def test_report(self):
        b_xml.report(self.manager, self.tmp_fname, self.issue.severity,
                     self.issue.confidence)

        with open(self.tmp_fname) as f:
            data = self._xml_to_dict(ET.XML(f.read()))
            self.assertEqual(self.tmp_fname,
                             data['testsuite']['testcase']['@classname'])
            self.assertEqual(
                self.issue.text,
                data['testsuite']['testcase']['error']['@message'])
            self.assertEqual(self.check_name,
                             data['testsuite']['testcase']['@name'])
