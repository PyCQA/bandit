# Copyright (c) 2024 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
import tempfile

import testtools

import bandit
from bandit.core import config
from bandit.core import issue
from bandit.core import manager
from bandit.formatters import github as b_github


class GithubFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "file")
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {
            "filename": "/home/user/project/test.py",
            "lineno": 10,
            "linerange": [10],
            "col_offset": 5,
            "end_col_offset": 15,
        }
        self.manager.out_file = self.tmp_fname

    def test_high_severity_outputs_error(self):
        """Test that HIGH severity issues are formatted as ::error"""
        self.issue = issue.Issue(
            bandit.HIGH,
            123,
            bandit.HIGH,
            "Possible SQL injection.",
        )
        self.issue.fname = self.context["filename"]
        self.issue.lineno = self.context["lineno"]
        self.issue.linerange = self.context["linerange"]
        self.issue.col_offset = self.context["col_offset"]
        self.issue.end_col_offset = self.context["end_col_offset"]
        self.issue.test = "hardcoded_sql_expressions"
        self.issue.test_id = "B608"

        self.manager.results.append(self.issue)

        with open(self.tmp_fname, "w") as tmp_file:
            b_github.report(
                self.manager,
                tmp_file,
                bandit.HIGH,
                bandit.HIGH,
            )

        with open(self.tmp_fname) as f:
            output = f.read()
            self.assertIn("::error", output)
            self.assertIn("file=/home/user/project/test.py", output)
            self.assertIn("line=10", output)
            self.assertIn("col=5", output)
            self.assertIn("title=B608", output)
            self.assertIn("Possible SQL injection.", output)

    def test_medium_severity_outputs_warning(self):
        """Test that MEDIUM severity issues are formatted as ::warning"""
        self.issue = issue.Issue(
            bandit.MEDIUM,
            89,
            bandit.MEDIUM,
            "Use of insecure MD5 hash function.",
        )
        self.issue.fname = "/app/crypto.py"
        self.issue.lineno = 42
        self.issue.linerange = [42]
        self.issue.col_offset = 8
        self.issue.end_col_offset = 20
        self.issue.test = "hashlib_insecure_functions"
        self.issue.test_id = "B324"

        self.manager.results.append(self.issue)

        with open(self.tmp_fname, "w") as tmp_file:
            b_github.report(
                self.manager,
                tmp_file,
                bandit.MEDIUM,
                bandit.MEDIUM,
            )

        with open(self.tmp_fname) as f:
            output = f.read()
            self.assertIn("::warning", output)
            self.assertIn("file=/app/crypto.py", output)
            self.assertIn("line=42", output)
            self.assertIn("col=8", output)
            self.assertIn("title=B324", output)
            self.assertIn("Use of insecure MD5 hash function.", output)

    def test_low_severity_outputs_notice(self):
        """Test that LOW severity issues are formatted as ::notice"""
        self.issue = issue.Issue(
            bandit.LOW,
            0,
            bandit.LOW,
            "Consider possible security implications.",
        )
        self.issue.fname = "/src/utils.py"
        self.issue.lineno = 15
        self.issue.linerange = [15]
        self.issue.col_offset = 0
        self.issue.end_col_offset = 10
        self.issue.test = "assert_used"
        self.issue.test_id = "B101"

        self.manager.results.append(self.issue)

        with open(self.tmp_fname, "w") as tmp_file:
            b_github.report(
                self.manager,
                tmp_file,
                bandit.LOW,
                bandit.LOW,
            )

        with open(self.tmp_fname) as f:
            output = f.read()
            self.assertIn("::notice", output)
            self.assertIn("file=/src/utils.py", output)
            self.assertIn("line=15", output)
            self.assertIn("col=0", output)
            self.assertIn("title=B101", output)
            self.assertIn("Consider possible security implications.", output)

    def test_multiple_issues(self):
        """Test that multiple issues are each formatted on separate lines"""
        issue1 = issue.Issue(
            bandit.HIGH,
            123,
            bandit.HIGH,
            "SQL injection risk.",
        )
        issue1.fname = "/app/db.py"
        issue1.lineno = 10
        issue1.linerange = [10]
        issue1.col_offset = 5
        issue1.test_id = "B608"

        issue2 = issue.Issue(
            bandit.MEDIUM,
            89,
            bandit.MEDIUM,
            "Weak cryptography.",
        )
        issue2.fname = "/app/crypto.py"
        issue2.lineno = 20
        issue2.linerange = [20]
        issue2.col_offset = 8
        issue2.test_id = "B324"

        self.manager.results.append(issue1)
        self.manager.results.append(issue2)

        with open(self.tmp_fname, "w") as tmp_file:
            b_github.report(
                self.manager,
                tmp_file,
                bandit.LOW,
                bandit.LOW,
            )

        with open(self.tmp_fname) as f:
            lines = f.readlines()
            self.assertEqual(2, len(lines))
            self.assertIn("::error", lines[0])
            self.assertIn("B608", lines[0])
            self.assertIn("::warning", lines[1])
            self.assertIn("B324", lines[1])

    def test_missing_col_offset(self):
        """Test handling of missing column offset (default to 0)"""
        self.issue = issue.Issue(
            bandit.MEDIUM,
            0,
            bandit.MEDIUM,
            "Security issue found.",
        )
        self.issue.fname = "/test.py"
        self.issue.lineno = 5
        self.issue.linerange = [5]
        self.issue.col_offset = -1  # Missing/invalid offset
        self.issue.test_id = "B999"

        self.manager.results.append(self.issue)

        with open(self.tmp_fname, "w") as tmp_file:
            b_github.report(
                self.manager,
                tmp_file,
                bandit.MEDIUM,
                bandit.MEDIUM,
            )

        with open(self.tmp_fname) as f:
            output = f.read()
            self.assertIn("col=0", output)

    def test_message_with_special_characters(self):
        """Test that special characters in messages are preserved"""
        self.issue = issue.Issue(
            bandit.HIGH,
            0,
            bandit.HIGH,
            'Use of "eval()" is dangerous: arbitrary code execution.',
        )
        self.issue.fname = "/eval_test.py"
        self.issue.lineno = 1
        self.issue.linerange = [1]
        self.issue.col_offset = 0
        self.issue.test_id = "B307"

        self.manager.results.append(self.issue)

        with open(self.tmp_fname, "w") as tmp_file:
            b_github.report(
                self.manager,
                tmp_file,
                bandit.HIGH,
                bandit.HIGH,
            )

        with open(self.tmp_fname) as f:
            output = f.read()
            self.assertIn('Use of "eval()" is dangerous', output)
            self.assertIn("arbitrary code execution.", output)

    def test_no_issues(self):
        """Test that empty result set produces no output"""
        with open(self.tmp_fname, "w") as tmp_file:
            b_github.report(
                self.manager,
                tmp_file,
                bandit.HIGH,
                bandit.HIGH,
            )

        with open(self.tmp_fname) as f:
            output = f.read()
            self.assertEqual("", output)
