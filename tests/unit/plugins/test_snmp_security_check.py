# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class SnmpSecurityCheckTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B508", "B509"])

    def test_communitydata_mpmodel_zero(self):
        fdata = textwrap.dedent(
            """
            from pysnmp import hlapi
            hlapi.CommunityData('public', mpModel=0)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B508", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.CLEARTEXT_TRANSMISSION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_communitydata_mpmodel_one(self):
        fdata = textwrap.dedent(
            """
            from pysnmp import hlapi
            hlapi.CommunityData('public', mpModel=1)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B508", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.CLEARTEXT_TRANSMISSION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_usmuserdata_noauth_nopriv(self):
        fdata = textwrap.dedent(
            """
            from pysnmp import hlapi
            hlapi.UsmUserData("securityName")
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B509", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.CLEARTEXT_TRANSMISSION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_usmuserdata_auth_nopriv(self):
        fdata = textwrap.dedent(
            """
            from pysnmp import hlapi
            hlapi.UsmUserData("securityName", "authName")
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B509", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.CLEARTEXT_TRANSMISSION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_usmuserdata_auth_priv(self):
        fdata = textwrap.dedent(
            """
            from pysnmp import hlapi
            hlapi.UsmUserData("securityName", "authName", "privName")
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
