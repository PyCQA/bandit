# SPDX-License-Identifier: Apache-2.0
import sys

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class InsecureSqlTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B608"])

    def test_query_select_from_where(self):
        fdata = """query = "SELECT * FROM foo WHERE id = '%s'" % identifier"""
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(8, issue.col_offset)

    def test_query_insert_into_values(self):
        fdata = """query = "INSERT INTO foo VALUES ('a', 'b', '%s')" % value"""
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(8, issue.col_offset)

    def test_query_delete_from_where(self):
        fdata = """query = "DELETE FROM foo WHERE id = '%s'" % identifier"""
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(8, issue.col_offset)

    def test_query_update_set_where(self):
        fdata = (
            """query = "UPDATE foo SET value = 'b' WHERE id = """
            """'%s'" % identifier"""
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(8, issue.col_offset)

    def test_query_with_as_select_from_select_from_where(self):
        fdata = '''query = """WITH cte AS (SELECT x FROM foo)
            SELECT x FROM cte WHERE x = '%s'""" % identifier
        '''
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        if sys.version_info >= (3, 8):
            self.assertEqual(1, issue.lineno)
            self.assertEqual([1, 2], issue.linerange)
            self.assertEqual(8, issue.col_offset)
        else:
            self.assertEqual(2, issue.lineno)
            self.assertEqual([2], issue.linerange)
            # FIXME: col_offset should never be negative
            self.assertEqual(-1, issue.col_offset)

    def test_query_select_from_where_identifier(self):
        fdata = """query = "SELECT * FROM foo WHERE id = '" + identifier + "'"
        """
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(8, issue.col_offset)

    def test_query_select_from_where_format_identifier(self):
        fdata = (
            """query = "SELECT * FROM foo WHERE id = """
            """'{}'".format(identifier)"""
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(8, issue.col_offset)

    def test_execute_select_from_where_identifier(self):
        fdata = (
            """cur.execute("SELECT * FROM foo WHERE id = '%s'" """
            """% identifier)"""
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(12, issue.col_offset)

    def test_execute_insert_values(self):
        fdata = (
            """cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')" """
            """% value)"""
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(12, issue.col_offset)

    def test_execute_delete_from_where_identifier(self):
        fdata = """cur.execute("DELETE FROM foo WHERE id = '%s'" % identifier)
        """
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(12, issue.col_offset)

    def test_execute_update_set_where_identifier(self):
        fdata = (
            """cur.execute("UPDATE foo SET value = 'b' WHERE id = """
            """'%s'" % identifier)"""
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(12, issue.col_offset)

    def test_execute_select_from_where_identifier_2(self):
        fdata = (
            """cur.execute("SELECT * FROM foo WHERE id = """
            """'" + identifier + "'")"""
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(12, issue.col_offset)

    def test_execute_select_from_where_identifier_format(self):
        fdata = (
            """cur.execute("SELECT * FROM foo WHERE id = """
            """'{}'".format(identifier))"""
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(12, issue.col_offset)

    def test_execute_select_from_where_identifier_good(self):
        fdata = """cur.execute("SELECT * FROM foo WHERE id = '%s'", identifier)
        """
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_execute_insert_into_values_good(self):
        fdata = (
            """cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')", """
            """value)"""
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_execute_delete_from_where_good(self):
        fdata = """cur.execute("DELETE FROM foo WHERE id = '%s'", identifier)
        """
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_execute_update_set_where_good(self):
        fdata = (
            """cur.execute("UPDATE foo SET value = 'b' WHERE id = """
            """'%s'", identifier)"""
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_non_sql_select_statement(self):
        fdata = """choices=[('server_list', _("Select from active instances"))]
        """
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_non_sql_delete_statement(self):
        fdata = """print("delete from the cache as the first argument")
        """
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
