# Copyright (c) 2015 VMware, Inc.
#
# SPDX-License-Identifier: Apache-2.0
import csv
import tempfile

import testtools

import bandit
from bandit.core import config
from bandit.core import issue
from bandit.core import manager
from bandit.formatters import csv as b_csv


class CsvFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "file")
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {
            "filename": self.tmp_fname,
            "lineno": 4,
            "linerange": [4],
            "col_offset": 8,
            "end_col_offset": 16,
        }
        self.check_name = "hardcoded_bind_all_interfaces"
        self.issue = issue.Issue(
            bandit.MEDIUM,
            123,
            bandit.MEDIUM,
            "Possible binding to all interfaces.",
        )
        self.manager.out_file = self.tmp_fname

        self.issue.fname = self.context["filename"]
        self.issue.lineno = self.context["lineno"]
        self.issue.linerange = self.context["linerange"]
        self.issue.col_offset = self.context["col_offset"]
        self.issue.end_col_offset = self.context["end_col_offset"]
        self.issue.test = self.check_name

        self.manager.results.append(self.issue)

    def test_report(self):
        with open(self.tmp_fname, "w") as tmp_file:
            b_csv.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            reader = csv.DictReader(f)
            data = next(reader)
            self.assertEqual(self.tmp_fname, data["filename"])
            self.assertEqual(self.issue.severity, data["issue_severity"])
            self.assertEqual(self.issue.confidence, data["issue_confidence"])
            self.assertEqual(self.issue.text, data["issue_text"])
            self.assertEqual(str(self.context["lineno"]), data["line_number"])
            self.assertEqual(
                str(self.context["linerange"]), data["line_range"]
            )
            self.assertEqual(self.check_name, data["test_name"])
            self.assertIsNotNone(data["more_info"])
            self.assertEqual(str(self.issue.col_offset), data["col_offset"])
            self.assertEqual(
                str(self.issue.end_col_offset), data["end_col_offset"]
            )
