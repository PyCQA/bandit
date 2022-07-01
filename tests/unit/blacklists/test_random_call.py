# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class RandomCallTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B311"])

    def test_random_random(self):
        fdata = textwrap.dedent(
            """
            import random
            random.random()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B311", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.INSUFFICIENT_RANDOM_VALUES, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_random_randrange(self):
        fdata = textwrap.dedent(
            """
            import random
            random.randrange()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B311", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.INSUFFICIENT_RANDOM_VALUES, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_random_randint(self):
        fdata = textwrap.dedent(
            """
            import random
            random.randint()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B311", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.INSUFFICIENT_RANDOM_VALUES, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_random_choice(self):
        fdata = textwrap.dedent(
            """
            import random
            random.choice()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B311", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.INSUFFICIENT_RANDOM_VALUES, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_random_choices(self):
        fdata = textwrap.dedent(
            """
            import random
            random.choices()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B311", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.INSUFFICIENT_RANDOM_VALUES, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_random_uniform(self):
        fdata = textwrap.dedent(
            """
            import random
            random.uniform()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B311", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.INSUFFICIENT_RANDOM_VALUES, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_random_triangular(self):
        fdata = textwrap.dedent(
            """
            import random
            random.triangular()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B311", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.INSUFFICIENT_RANDOM_VALUES, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_random(self):
        fdata = textwrap.dedent(
            """
            import os
            os.urandom()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_random_systemrandom(self):
        fdata = textwrap.dedent(
            """
            import random
            random.SystemRandom()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_unknown_random(self):
        fdata = textwrap.dedent(
            """
            import random
            random()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_somelib_random(self):
        fdata = textwrap.dedent(
            """
            import somelib
            somelib.a.random()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
