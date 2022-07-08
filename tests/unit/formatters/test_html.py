# Copyright (c) 2015 Rackspace, Inc.
# Copyright (c) 2015 Hewlett Packard Enterprise
#
# SPDX-License-Identifier: Apache-2.0
import collections
import tempfile
from unittest import mock

import bs4
import testtools

import bandit
from bandit.core import config
from bandit.core import issue
from bandit.core import manager
from bandit.formatters import html as b_html


class HtmlFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "file")

        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()

        self.manager.out_file = self.tmp_fname

    def test_report_with_skipped(self):
        self.manager.skipped = [("abc.py", "File is bad")]

        with open(self.tmp_fname, "w") as tmp_file:
            b_html.report(self.manager, tmp_file, bandit.LOW, bandit.LOW)

        with open(self.tmp_fname) as f:
            soup = bs4.BeautifulSoup(f.read(), "html.parser")
            skipped = soup.find_all("div", id="skipped")[0]

            self.assertEqual(1, len(soup.find_all("div", id="skipped")))
            self.assertIn("abc.py", skipped.text)
            self.assertIn("File is bad", skipped.text)

    @mock.patch("bandit.core.issue.Issue.get_code")
    @mock.patch("bandit.core.manager.BanditManager.get_issue_list")
    def test_report_contents(self, get_issue_list, get_code):
        self.manager.metrics.data["_totals"] = {"loc": 1000, "nosec": 50}

        issue_a = _get_issue_instance(severity=bandit.LOW)
        issue_a.fname = "abc.py"
        issue_a.test = "AAAAAAA"
        issue_a.text = "BBBBBBB"
        issue_a.confidence = "CCCCCCC"
        # don't need to test severity, it determines the color which we're
        # testing separately

        issue_b = _get_issue_instance(severity=bandit.MEDIUM)
        issue_c = _get_issue_instance(severity=bandit.HIGH)

        issue_x = _get_issue_instance()
        get_code.return_value = "some code"

        issue_y = _get_issue_instance()

        get_issue_list.return_value = collections.OrderedDict(
            [
                (issue_a, [issue_x, issue_y]),
                (issue_b, [issue_x]),
                (issue_c, [issue_y]),
            ]
        )

        with open(self.tmp_fname, "w") as tmp_file:
            b_html.report(self.manager, tmp_file, bandit.LOW, bandit.LOW)

        with open(self.tmp_fname) as f:
            soup = bs4.BeautifulSoup(f.read(), "html.parser")

            self.assertEqual("1000", soup.find_all("span", id="loc")[0].text)
            self.assertEqual("50", soup.find_all("span", id="nosec")[0].text)

            issue1 = soup.find_all("div", id="issue-0")[0]
            issue2 = soup.find_all("div", id="issue-1")[0]
            issue3 = soup.find_all("div", id="issue-2")[0]

            # make sure the class has been applied properly
            self.assertEqual(
                1, len(issue1.find_all("div", {"class": "issue-sev-low"}))
            )

            self.assertEqual(
                1, len(issue2.find_all("div", {"class": "issue-sev-medium"}))
            )

            self.assertEqual(
                1, len(issue3.find_all("div", {"class": "issue-sev-high"}))
            )

            # issue1 has a candidates section with 2 candidates in it
            self.assertEqual(
                1, len(issue1.find_all("div", {"class": "candidates"}))
            )
            self.assertEqual(
                2, len(issue1.find_all("div", {"class": "candidate"}))
            )

            # issue2 doesn't have candidates
            self.assertEqual(
                0, len(issue2.find_all("div", {"class": "candidates"}))
            )
            self.assertEqual(
                0, len(issue2.find_all("div", {"class": "candidate"}))
            )

            # issue1 doesn't have code issue 2 and 3 do
            self.assertEqual(0, len(issue1.find_all("div", {"class": "code"})))
            self.assertEqual(1, len(issue2.find_all("div", {"class": "code"})))
            self.assertEqual(1, len(issue3.find_all("div", {"class": "code"})))

            # issue2 code and issue1 first candidate have code
            element1 = issue1.find_all("div", {"class": "candidate"})
            self.assertIn("some code", element1[0].text)
            element2 = issue2.find_all("div", {"class": "code"})
            self.assertIn("some code", element2[0].text)

            # make sure correct things are being output in issues
            self.assertIn("AAAAAAA:", issue1.text)
            self.assertIn("BBBBBBB", issue1.text)
            self.assertIn("CCCCCCC", issue1.text)
            self.assertIn("abc.py", issue1.text)
            self.assertIn("Line number: 1", issue1.text)

    @mock.patch("bandit.core.issue.Issue.get_code")
    @mock.patch("bandit.core.manager.BanditManager.get_issue_list")
    def test_escaping(self, get_issue_list, get_code):
        self.manager.metrics.data["_totals"] = {"loc": 1000, "nosec": 50}
        marker = "<tag in code>"

        issue_a = _get_issue_instance()
        issue_x = _get_issue_instance()
        get_code.return_value = marker

        get_issue_list.return_value = {issue_a: [issue_x]}

        with open(self.tmp_fname, "w") as tmp_file:
            b_html.report(self.manager, tmp_file, bandit.LOW, bandit.LOW)

        with open(self.tmp_fname) as f:
            contents = f.read()
        self.assertNotIn(marker, contents)


def _get_issue_instance(
    severity=bandit.MEDIUM, cwe=123, confidence=bandit.MEDIUM
):
    new_issue = issue.Issue(severity, cwe, confidence, "Test issue")
    new_issue.fname = "code.py"
    new_issue.test = "bandit_plugin"
    new_issue.lineno = 1
    return new_issue
