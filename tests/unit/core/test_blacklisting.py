#
# Copyright 2016 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import testtools

from bandit.core import blacklisting


class BlacklistingTests(testtools.TestCase):
    def test_report_issue(self):
        data = {"level": "HIGH", "message": "test {name}", "id": "B000"}

        issue = blacklisting.report_issue(data, "name")
        issue_dict = issue.as_dict(with_code=False)
        self.assertIsInstance(issue_dict, dict)
        self.assertEqual("B000", issue_dict["test_id"])
        self.assertEqual("HIGH", issue_dict["issue_severity"])
        self.assertEqual({}, issue_dict["issue_cwe"])
        self.assertEqual("HIGH", issue_dict["issue_confidence"])
        self.assertEqual("test name", issue_dict["issue_text"])

    def test_report_issue_defaults(self):
        data = {"message": "test {name}"}

        issue = blacklisting.report_issue(data, "name")
        issue_dict = issue.as_dict(with_code=False)
        self.assertIsInstance(issue_dict, dict)
        self.assertEqual("LEGACY", issue_dict["test_id"])
        self.assertEqual("MEDIUM", issue_dict["issue_severity"])
        self.assertEqual({}, issue_dict["issue_cwe"])
        self.assertEqual("HIGH", issue_dict["issue_confidence"])
        self.assertEqual("test name", issue_dict["issue_text"])
