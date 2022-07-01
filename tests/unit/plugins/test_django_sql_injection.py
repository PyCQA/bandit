# SPDX-License-Identifier: Apache-2.0
import sys
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class DjangoSqlInjectionTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B610", "B611"])

    def test_django_user_objects_filter_extra_select_where_tables(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            User.objects.filter(username='admin').extra(
                select={'test': 'secure'},
                where=['secure'],
                tables=['secure']
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_user_objects_filter_extra_dict(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            User.objects.filter(username='admin').extra({'test': 'secure'})
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_user_objects_filter_extra_select_dict(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            User.objects.filter(username='admin').extra(
                select={'test': 'secure'}
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_user_objects_filter_extra_where(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            User.objects.filter(username='admin').extra(where=['secure'])
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_user_objects_filter_extra_dict_obj(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            User.objects.filter(username='admin').extra(
                dict(could_be='insecure')
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B610", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([3, 4, 5], issue.linerange)
        else:
            self.assertEqual([3, 4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_user_objects_filter_extra_select_dict_obj(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            User.objects.filter(username='admin').extra(
                select=dict(could_be='insecure')
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B610", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([3, 4, 5], issue.linerange)
        else:
            self.assertEqual([3, 4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_user_objects_filter_extra_select_query_var(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            query = ('"username") AS "username", * FROM "auth_user" '
                     'WHERE 1=1 OR "username"=? --')
            User.objects.filter(username='admin').extra(select={'test': query})
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B610", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_user_objects_filter_extra_select_dict_str_sub(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            User.objects.filter(username='admin').extra(
                select={'test': '%secure' % 'nos'}
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B610", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([3, 4, 5], issue.linerange)
        else:
            self.assertEqual([3, 4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_user_objects_filter_extra_select_dict_str_format(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            User.objects.filter(username='admin').extra(
                select={'test': '{}secure'.format('nos')}
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B610", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([3, 4, 5], issue.linerange)
        else:
            self.assertEqual([3, 4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_user_objects_filter_extra_where_var(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            where_var = ['1=1) OR 1=1 AND (1=1']
            User.objects.filter(username='admin').extra(where=where_var)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B610", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_user_objects_filter_extra_where_str(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            where_str = '1=1) OR 1=1 AND (1=1'
            User.objects.filter(username='admin').extra(where=[where_str])
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B610", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_user_objects_filter_extra_where_str_sub(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            User.objects.filter(username='admin').extra(
                where=['%secure' % 'nos']
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B610", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([3, 4, 5], issue.linerange)
        else:
            self.assertEqual([3, 4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_user_objects_filter_extra_where_str_format(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            User.objects.filter(username='admin').extra(
                where=['{}secure'.format('no')]
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B610", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([3, 4, 5], issue.linerange)
        else:
            self.assertEqual([3, 4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_user_objects_filter_extra_tables_var(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            tables_var = [
                'django_content_type" WHERE "auth_user"."username"="admin'
            ]
            User.objects.all().extra(tables=tables_var).distinct()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B610", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(6, issue.lineno)
        self.assertEqual([6], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_user_objects_filter_extra_tables_str(self):
        fdata = textwrap.dedent(
            """
            from django.contrib.auth.models import User
            tables_str = ('django_content_type" WHERE '
                          '"auth_user"."username"="admin')
            User.objects.all().extra(tables=[tables_str]).distinct()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B610", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_user_objects_annotate_rawsql(self):
        fdata = textwrap.dedent(
            """
            from django.db.models.expressions import RawSQL
            from django.contrib.auth.models import User
            User.objects.annotate(val=RawSQL('secure', []))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_user_objects_annotate_rawsql_str_sub(self):
        fdata = textwrap.dedent(
            """
            from django.db.models.expressions import RawSQL
            from django.contrib.auth.models import User
            User.objects.annotate(val=RawSQL('%secure' % 'nos', []))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B611", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(26, issue.col_offset)

    def test_django_user_objects_annotate_rawsql_str_format(self):
        fdata = textwrap.dedent(
            """
            from django.db.models.expressions import RawSQL
            from django.contrib.auth.models import User
            User.objects.annotate(val=RawSQL('{}secure'.format('no'), []))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B611", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(26, issue.col_offset)

    def test_django_user_objects_annotate_rawsql_raw(self):
        fdata = textwrap.dedent(
            """
            from django.db.models.expressions import RawSQL
            from django.contrib.auth.models import User
            raw = ('"username") AS "val" FROM "auth_user" WHERE'
                   ' "username"="admin" --')
            User.objects.annotate(val=RawSQL(raw, []))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B611", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(6, issue.lineno)
        self.assertEqual([6], issue.linerange)
        self.assertEqual(26, issue.col_offset)

    def test_django_user_objects_annotate_rawsql_raw_sub(self):
        fdata = textwrap.dedent(
            """
            from django.db.models.expressions import RawSQL
            from django.contrib.auth.models import User
            raw = '"username") AS "val" FROM "auth_user"' \
                  ' WHERE "username"="admin" OR 1=%s --'
            User.objects.annotate(val=RawSQL(raw, [0]))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B611", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.SQL_INJECTION, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(26, issue.col_offset)
