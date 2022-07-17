# SPDX-License-Identifier: Apache-2.0
import csv
import tempfile

import testtools

import bandit
from bandit.core import config
from bandit.core import issue
from bandit.core import manager
from bandit.formatters import custom


class CustomFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "custom")
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {
            "filename": self.tmp_fname,
            "lineno": 4,
            "linerange": [4],
            "col_offset": 30,
            "end_col_offset": 38,
        }
        self.check_name = "hardcoded_bind_all_interfaces"
        self.issue = issue.Issue(
            bandit.MEDIUM,
            bandit.MEDIUM,
            text="Possible binding to all interfaces.",
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
            custom.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
                template="{line},{col},{end_col},{severity},{msg}",
            )

        with open(self.tmp_fname) as f:
            reader = csv.DictReader(
                f, ["line", "col", "end_col", "severity", "message"]
            )
            data = next(reader)
            self.assertEqual(str(self.context["lineno"]), data["line"])
            self.assertEqual(str(self.context["col_offset"]), data["col"])
            self.assertEqual(
                str(self.context["end_col_offset"]), data["end_col"]
            )
            self.assertEqual(self.issue.severity, data["severity"])
            self.assertEqual(self.issue.text, data["message"])
