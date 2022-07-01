# SPDX-License-Identifier: Apache-2.0
import sys

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class HashlibInsecureFunctionsTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B324"])

    def test_hashlib_new_md4(self):
        fdata = "hashlib.new('md4')"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        if sys.version_info >= (3, 9):
            self.assertEqual(bandit.HIGH, issue.severity)
        else:
            self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_hashlib_new_md5(self):
        fdata = "hashlib.new('md5')"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        if sys.version_info >= (3, 9):
            self.assertEqual(bandit.HIGH, issue.severity)
        else:
            self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_hashlib_new_sha(self):
        fdata = "hashlib.new('sha')"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        if sys.version_info >= (3, 9):
            self.assertEqual(bandit.HIGH, issue.severity)
        else:
            self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_hashlib_new_sha1(self):
        fdata = "hashlib.new('sha1')"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        if sys.version_info >= (3, 9):
            self.assertEqual(bandit.HIGH, issue.severity)
        else:
            self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_hashlib_new_name_md5(self):
        fdata = "hashlib.new(name='md5', data=b'test')"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        if sys.version_info >= (3, 9):
            self.assertEqual(bandit.HIGH, issue.severity)
        else:
            self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_hashlib_new_sha256(self):
        fdata = "hashlib.new(name='sha256')"
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_hashlib_new_sha512(self):
        fdata = "hashlib.new('SHA512')"
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_hashlib_new_usedforsecurity_true(self):
        fdata = "hashlib.new('sha1', usedforsecurity=True)"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        if sys.version_info >= (3, 9):
            self.assertEqual(bandit.HIGH, issue.severity)
        else:
            self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_hashlib_new_usedforsecurity_false(self):
        fdata = "hashlib.new(name='sha1', usedforsecurity=False)"
        self.visitor.process(fdata)
        if sys.version_info >= (3, 9):
            self.assertEqual(0, len(self.visitor.tester.results))
        else:
            self.assertEqual(1, len(self.visitor.tester.results))
            issue = self.visitor.tester.results[0]
            self.assertEqual(bandit.MEDIUM, issue.severity)
            self.assertEqual(bandit.HIGH, issue.confidence)
            self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
            self.assertEqual(1, issue.lineno)
            self.assertEqual([1], issue.linerange)
            self.assertEqual(0, issue.col_offset)

    def test_hashlib_md4(self):
        if sys.version_info >= (3, 9):
            fdata = "hashlib.md4()"
            self.visitor.process(fdata)
            self.assertEqual(1, len(self.visitor.tester.results))
            issue = self.visitor.tester.results[0]
            self.assertEqual(bandit.HIGH, issue.severity)
            self.assertEqual(bandit.HIGH, issue.confidence)
            self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
            self.assertEqual(1, issue.lineno)
            self.assertEqual([1], issue.linerange)
            self.assertEqual(0, issue.col_offset)

    def test_hashlib_md5(self):
        if sys.version_info >= (3, 9):
            fdata = "hashlib.md5()"
            self.visitor.process(fdata)
            self.assertEqual(1, len(self.visitor.tester.results))
            issue = self.visitor.tester.results[0]
            self.assertEqual(bandit.HIGH, issue.severity)
            self.assertEqual(bandit.HIGH, issue.confidence)
            self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
            self.assertEqual(1, issue.lineno)
            self.assertEqual([1], issue.linerange)
            self.assertEqual(0, issue.col_offset)

    def test_hashlib_sha(self):
        if sys.version_info >= (3, 9):
            fdata = "hashlib.sha()"
            self.visitor.process(fdata)
            self.assertEqual(1, len(self.visitor.tester.results))
            issue = self.visitor.tester.results[0]
            self.assertEqual(bandit.HIGH, issue.severity)
            self.assertEqual(bandit.HIGH, issue.confidence)
            self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
            self.assertEqual(1, issue.lineno)
            self.assertEqual([1], issue.linerange)
            self.assertEqual(0, issue.col_offset)

    def test_hashlib_sha1(self):
        if sys.version_info >= (3, 9):
            fdata = "hashlib.sha1()"
            self.visitor.process(fdata)
            self.assertEqual(1, len(self.visitor.tester.results))
            issue = self.visitor.tester.results[0]
            self.assertEqual(bandit.HIGH, issue.severity)
            self.assertEqual(bandit.HIGH, issue.confidence)
            self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
            self.assertEqual(1, issue.lineno)
            self.assertEqual([1], issue.linerange)
            self.assertEqual(0, issue.col_offset)

    def test_hashlib_sha256(self):
        fdata = "hashlib.sha256()"
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_hashlib_usedforsecurity_false(self):
        if sys.version_info >= (3, 9):
            fdata = "hashlib.md5(usedforsecurity=False)"
            self.visitor.process(fdata)
            self.assertEqual(0, len(self.visitor.tester.results))

    def test_hashlib_usedforsecurity_true(self):
        if sys.version_info >= (3, 9):
            fdata = "hashlib.sha1(usedforsecurity=True)"
            self.visitor.process(fdata)
            self.assertEqual(1, len(self.visitor.tester.results))
            issue = self.visitor.tester.results[0]
            self.assertEqual(bandit.HIGH, issue.severity)
            self.assertEqual(bandit.HIGH, issue.confidence)
            self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
            self.assertEqual(1, issue.lineno)
            self.assertEqual([1], issue.linerange)
            self.assertEqual(0, issue.col_offset)
