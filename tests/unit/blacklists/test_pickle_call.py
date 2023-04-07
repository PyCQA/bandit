# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class PickleCallTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B301"])

    def test_pickle_loads(self):
        fdata = textwrap.dedent(
            """
            import pickle
            pick = pickle.dumps({'a': 'b', 'c': 'd'})
            pickle.loads(pick)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B301", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pickle_load(self):
        fdata = textwrap.dedent(
            """
            import io
            import pickle
            file_obj = io.BytesIO()
            pickle.dump([1, 2, '3'], file_obj)
            file_obj.seek(0)
            pickle.load(file_obj)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B301", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(7, issue.lineno)
        self.assertEqual([7], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pickle_unpickler(self):
        fdata = textwrap.dedent(
            """
            import io
            import pickle
            file_obj = io.BytesIO()
            pickle.dump([1, 2, '3'], file_obj)
            file_obj.seek(0)
            pickle.Unpickler(file_obj)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B301", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(7, issue.lineno)
        self.assertEqual([7], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_dill_loads(self):
        fdata = textwrap.dedent(
            """
            import dill
            pick = dill.dumps({'a': 'b', 'c': 'd'})
            dill.loads(pick)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B301", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_dill_load(self):
        fdata = textwrap.dedent(
            """
            import io
            import dill
            file_obj = io.BytesIO()
            dill.dump([1, 2, '3'], file_obj)
            file_obj.seek(0)
            dill.load(file_obj)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B301", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(7, issue.lineno)
        self.assertEqual([7], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_dill_unpickler(self):
        fdata = textwrap.dedent(
            """
            import io
            import dill
            file_obj = io.BytesIO()
            dill.dump([1, 2, '3'], file_obj)
            file_obj.seek(0)
            dill.Unpickler(file_obj)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B301", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(7, issue.lineno)
        self.assertEqual([7], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_shelve_open(self):
        fdata = textwrap.dedent(
            """
            import os
            import shelve
            with tempfile.TemporaryDirectory() as d:
                filename = os.path.join(d, 'shelf')
                shelve.open(filename)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B301", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(6, issue.lineno)
        self.assertEqual([6], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_shelve_dbfilenameshelf(self):
        fdata = textwrap.dedent(
            """
            import os
            import shelve
            with tempfile.TemporaryDirectory() as d:
                filename = os.path.join(d, 'shelf')
                shelve.DbfilenameShelf(filename)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B301", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(6, issue.lineno)
        self.assertEqual([6], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_jsonpickle_decode(self):
        fdata = textwrap.dedent(
            """
            import jsonpickle
            pick = jsonpickle.encode({'a': 'b', 'c': 'd'})
            jsonpickle.decode(pick)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B301", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_jsonpickle_unpickler_decode(self):
        fdata = textwrap.dedent(
            """
            import jsonpickle
            pick = jsonpickle.encode({'a': 'b', 'c': 'd'})
            jsonpickle.unpickler.decode(pick)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B301", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_jsonpickle_unpickler_unpickler(self):
        fdata = textwrap.dedent(
            """
            import jsonpickle
            pick = jsonpickle.encode({'a': 'b', 'c': 'd'})
            jsonpickle.unpickler.Unpickler().restore(pick)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B301", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pandas_read_pickle(self):
        fdata = textwrap.dedent(
            """
            import pandas
            df = pandas.DataFrame({"col_A": [1, 2]})
            pick = pickle.dumps(df)
            pandas.read_pickle(pick)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B301", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(0, issue.col_offset)
