# Copyright (c) 2015 VMware, Inc.
#
# SPDX-License-Identifier: Apache-2.0
import collections
import tempfile
from xml.etree import ElementTree as ET

import testtools

import bandit
from bandit.core import config
from bandit.core import issue
from bandit.core import manager
from bandit.formatters import xml as b_xml


class XmlFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "file")
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {
            "filename": self.tmp_fname,
            "lineno": 4,
            "linerange": [4],
        }
        self.check_name = "hardcoded_bind_all_interfaces"
        self.issue = issue.Issue(
            bandit.MEDIUM,
            issue.Cwe.MULTIPLE_BINDS,
            bandit.MEDIUM,
            "Possible binding to all interfaces.",
        )
        self.manager.out_file = self.tmp_fname

        self.issue.fname = self.context["filename"]
        self.issue.lineno = self.context["lineno"]
        self.issue.linerange = self.context["linerange"]
        self.issue.test = self.check_name

        self.manager.results.append(self.issue)

    def _xml_to_dict(self, t):
        d = {t.tag: {} if t.attrib else None}
        children = list(t)
        if children:
            dd = collections.defaultdict(list)
            for dc in map(self._xml_to_dict, children):
                for k, v in dc.items():
                    dd[k].append(v)
            d = {t.tag: {k: v[0] if len(v) == 1 else v for k, v in dd.items()}}
        if t.attrib:
            d[t.tag].update(("@" + k, v) for k, v in t.attrib.items())
        if t.text:
            text = t.text.strip()
            if children or t.attrib:
                if text:
                    d[t.tag]["#text"] = text
            else:
                d[t.tag] = text
        return d

    def test_report(self):
        with open(self.tmp_fname, "wb") as tmp_file:
            b_xml.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            data = self._xml_to_dict(ET.XML(f.read()))
            self.assertEqual(
                self.tmp_fname, data["testsuite"]["testcase"]["@classname"]
            )
            self.assertEqual(
                self.issue.text,
                data["testsuite"]["testcase"]["error"]["@message"],
            )
            self.assertEqual(
                self.check_name, data["testsuite"]["testcase"]["@name"]
            )
            self.assertIsNotNone(
                data["testsuite"]["testcase"]["error"]["@more_info"]
            )
