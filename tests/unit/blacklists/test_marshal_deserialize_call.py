# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class MarshalDeserializeCallTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B302"])

    def test_marshal_load(self):
        fdata = textwrap.dedent(
            """
            import marshal
            import tempfile

            file_obj = tempfile.TemporaryFile()
            marshal.dump(range(5), file_obj)
            file_obj.seek(0)
            marshal.load(file_obj)
            file_obj.close()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B302", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA,
            issue.cwe.id,
        )
        self.assertEqual(8, issue.lineno)
        self.assertEqual([8], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_marshal_loads(self):
        fdata = textwrap.dedent(
            """
            import marshal

            serialized = marshal.dumps({'a': 1})
            marshal.loads(serialized)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B302", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA,
            issue.cwe.id,
        )
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(0, issue.col_offset)
