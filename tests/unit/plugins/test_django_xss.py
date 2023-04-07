# SPDX-License-Identifier: Apache-2.0
import sys
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class DjangoXssTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B703"])

    def test_django_utils_safestring_mark_safe(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            safestring.mark_safe('<b>secure</b>')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_safestring_safetext(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            safestring.SafeText('<b>secure</b>')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_safestring_safeunicode(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            safestring.SafeUnicode('<b>secure</b>')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_safestring_safestring(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            safestring.SafeString('<b>secure</b>')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_safestring_safebytes(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            safestring.SafeBytes('<b>secure</b>')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_mark_safe_var(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            my_secure_str = '<b>Hello World</b>'
            safestring.mark_safe(my_secure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_mark_safe_tuple_var(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            my_secure_str, _ = ('<b>Hello World</b>', '')
            safestring.mark_safe(my_secure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_mark_safe_var_var(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            my_secure_str, _ = ('<b>Hello World</b>', '')
            also_secure_str = my_secure_str
            safestring.mark_safe(also_secure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_mark_safe_func(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def try_secure():
                try:
                    my_secure_str = 'Secure'
                except Exception:
                    my_secure_str = 'Secure'
                else:
                    my_secure_str = 'Secure'
                finally:
                    my_secure_str = 'Secure'
                safestring.mark_safe(my_secure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_mark_safe_format_secure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def format_secure():
                safestring.mark_safe('<b>{}</b>'.format('secure'))
                my_secure_str = 'secure'
                safestring.mark_safe('<b>{}</b>'.format(my_secure_str))
                safestring.mark_safe('<b>{} {}</b>'.format(my_secure_str, 'a'))
                safestring.mark_safe(
                    '<b>{} {}</b>'.format(*[my_secure_str, 'a'])
                )
                my_secure_str = '<b>{}</b>'.format(my_secure_str)
                safestring.mark_safe(my_secure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_mark_safe_percent_secure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def percent_secure():
                safestring.mark_safe('<b>%s</b>' % 'secure')
                my_secure_str = 'secure'
                safestring.mark_safe('<b>%s</b>' % my_secure_str)
                safestring.mark_safe('<b>%s %s</b>' % (my_secure_str, 'a'))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_mark_safe_with_secure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def with_secure(path):
                with open(path) as f:
                    safestring.mark_safe('Secure')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_mark_safe_loop_secure(self):
        fdata = textwrap.dedent(
            """
            import os
            from django.utils import safestring
            def loop_secure():
                my_secure_str = ''

                for i in range(ord(os.urandom(1))):
                    my_secure_str += ' Secure'
                safestring.mark_safe(my_secure_str)
                while ord(os.urandom(1)) % 2 == 0:
                    my_secure_str += ' Secure'
                safestring.mark_safe(my_secure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_mark_safe_all_secure_case(self):
        fdata = textwrap.dedent(
            """
            import os
            from django.utils import safestring
            def all_secure_case():
                if ord(os.urandom(1)) % 2 == 0:
                    my_secure_str = 'Secure'
                elif ord(os.urandom(1)) % 2 == 0:
                    my_secure_str = 'Secure'
                else:
                    my_secure_str = 'Secure'
                safestring.mark_safe(my_secure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_django_utils_mark_safe_my_insecure_str(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def insecure_function(text, cls=''):
                return '<h1 class="{cls}">{text}</h1>'.format(
                    text=text, cls=cls
                )
            my_insecure_str = insecure_function(
                'insecure', cls='" onload="alert("xss")'
            )
            safestring.mark_safe(my_insecure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(10, issue.lineno)
        self.assertEqual([10], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_utils_safetext_my_insecure_str(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def insecure_function(text, cls=''):
                return '<h1 class="{cls}">{text}</h1>'.format(
                    text=text, cls=cls
                )
            my_insecure_str = insecure_function(
                'insecure', cls='" onload="alert("xss")'
            )
            safestring.SafeText(my_insecure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(10, issue.lineno)
        self.assertEqual([10], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_utils_safeunicode_my_insecure_str(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def insecure_function(text, cls=''):
                return '<h1 class="{cls}">{text}</h1>'.format(
                    text=text, cls=cls
                )
            my_insecure_str = insecure_function(
                'insecure', cls='" onload="alert("xss")'
            )
            safestring.SafeUnicode(my_insecure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(10, issue.lineno)
        self.assertEqual([10], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_utils_safestring_my_insecure_str(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def insecure_function(text, cls=''):
                return '<h1 class="{cls}">{text}</h1>'.format(
                    text=text, cls=cls
                )
            my_insecure_str = insecure_function(
                'insecure', cls='" onload="alert("xss")'
            )
            safestring.SafeString(my_insecure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(10, issue.lineno)
        self.assertEqual([10], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_utils_safebytes_my_insecure_str(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def insecure_function(text, cls=''):
                return '<h1 class="{cls}">{text}</h1>'.format(
                    text=text, cls=cls
                )
            my_insecure_str = insecure_function(
                'insecure', cls='" onload="alert("xss")'
            )
            safestring.SafeBytes(my_insecure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(10, issue.lineno)
        self.assertEqual([10], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_django_utils_mark_safe_try_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def try_insecure(cls='" onload="alert("xss")'):
                try:
                    my_insecure_str = insecure_function('insecure', cls=cls)
                except Exception:
                    my_insecure_str = 'Secure'
                safestring.mark_safe(my_insecure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(8, issue.lineno)
        self.assertEqual([8], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_except_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def except_insecure(cls='" onload="alert("xss")'):
                try:
                    my_insecure_str = 'Secure'
                except Exception:
                    my_insecure_str = insecure_function('insecure', cls=cls)
                safestring.mark_safe(my_insecure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(8, issue.lineno)
        self.assertEqual([8], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_try_else_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def try_else_insecure(cls='" onload="alert("xss")'):
                try:
                    if 1 == random.randint(0, 1):  # nosec
                        raise Exception
                except Exception:
                    my_insecure_str = 'Secure'
                else:
                    my_insecure_str = insecure_function('insecure', cls=cls)
                safestring.mark_safe(my_insecure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(11, issue.lineno)
        self.assertEqual([11], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_finally_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def finally_insecure(cls='" onload="alert("xss")'):
                try:
                    if 1 == random.randint(0, 1):  # nosec
                        raise Exception
                except Exception:
                    print("Exception")
                else:
                    print("No Exception")
                finally:
                    my_insecure_str = insecure_function('insecure', cls=cls)
                safestring.mark_safe(my_insecure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(13, issue.lineno)
        self.assertEqual([13], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_format_arg_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def format_arg_insecure(cls='" onload="alert("xss")'):
                my_insecure_str = insecure_function('insecure', cls=cls)
                safestring.mark_safe('<b>{} {}</b>'.format(
                    my_insecure_str, 'STR')
                )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([5, 6, 7], issue.linerange)
        else:
            self.assertEqual([5, 6], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_format_startarg_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def format_startarg_insecure(cls='" onload="alert("xss")'):
                my_insecure_str = insecure_function('insecure', cls=cls)
                safestring.mark_safe('<b>{}</b>'.format(*[my_insecure_str]))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_format_keywords_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def format_keywords_insecure(cls='" onload="alert("xss")'):
                my_insecure_str = insecure_function('insecure', cls=cls)
                safestring.mark_safe('<b>{b}</b>'.format(b=my_insecure_str))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_format_kwargs_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def format_kwargs_insecure(cls='" onload="alert("xss")'):
                my_insecure_str = insecure_function('insecure', cls=cls)
                safestring.mark_safe('<b>{b}</b>'.format(
                    **{'b': my_insecure_str})
                )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([5, 6, 7], issue.linerange)
        else:
            self.assertEqual([5, 6], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_percent_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def percent_insecure(cls='" onload="alert("xss")'):
                my_insecure_str = insecure_function('insecure', cls=cls)
                safestring.mark_safe('<b>%s</b>' % my_insecure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_percent_list_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def percent_list_insecure(cls='" onload="alert("xss")'):
                my_insecure_str = insecure_function('insecure', cls=cls)
                safestring.mark_safe('<b>%s %s</b>' % (my_insecure_str, 'b'))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_percent_dict_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def percent_dict_insecure(cls='" onload="alert("xss")'):
                my_insecure_str = insecure_function('insecure', cls=cls)
                safestring.mark_safe('<b>%(b)s</b>' % {'b': my_insecure_str})
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_import_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def import_insecure():
                import sre_constants
                safestring.mark_safe(sre_constants.ANY)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_import_as_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def import_as_insecure():
                import sre_constants.ANY as any_str
                safestring.mark_safe(any_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_from_import_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def from_import_insecure():
                from sre_constants import ANY
                safestring.mark_safe(ANY)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_from_import_as_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def from_import_as_insecure():
                from sre_constants import ANY as any_str
                safestring.mark_safe(any_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_with_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def with_insecure(path):
                with open(path) as f:
                    safestring.mark_safe(f.read())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(8, issue.col_offset)

    def test_django_utils_mark_safe_also_with_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def also_with_insecure(path):
                with open(path) as f:
                    safestring.mark_safe(f)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(8, issue.col_offset)

    def test_django_utils_mark_safe_for_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def for_insecure():
                my_secure_str = ''
                for i in range(random.randint(0, 1)):  # nosec
                    my_secure_str += insecure_function(
                        'insecure', cls='" onload="alert("xss")'
                    )
                safestring.mark_safe(my_secure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(9, issue.lineno)
        self.assertEqual([9], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_while_insecure(self):
        fdata = textwrap.dedent(
            """
            import os
            from django.utils import safestring
            def while_insecure():
                my_secure_str = ''
                while ord(os.urandom(1)) % 2 == 0:
                    my_secure_str += insecure_function(
                        'insecure', cls='" onload="alert("xss")'
                    )
                safestring.mark_safe(my_secure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(10, issue.lineno)
        self.assertEqual([10], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_some_insecure_case(self):
        fdata = textwrap.dedent(
            """
            import os
            from django.utils import safestring
            def some_insecure_case():
                if ord(os.urandom(1)) % 2 == 0:
                    my_secure_str = insecure_function(
                        'insecure', cls='" onload="alert("xss")'
                    )
                elif ord(os.urandom(1)) % 2 == 0:
                    my_secure_str = 'Secure'
                else:
                    my_secure_str = 'Secure'
                safestring.mark_safe(my_secure_str)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(13, issue.lineno)
        self.assertEqual([13], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_test_insecure_shadow(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            mystr = 'insecure'
            def test_insecure_shadow():  # var assigned out of scope
                safestring.mark_safe(mystr)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_test_insecure(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def test_insecure(str_arg):
                safestring.mark_safe(str_arg)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_test_insecure_with_assign(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def test_insecure_with_assign(str_arg=None):
                if not str_arg:
                    str_arg = 'could be insecure'
                safestring.mark_safe(str_arg)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(6, issue.lineno)
        self.assertEqual([6], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_django_utils_mark_safe_test_insecure_tuple_assign(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring
            def test_insecure_tuple_assign():
                HTML_CHOICES = (
                    (_('Donate'), 'https://example.org/donate/'),
                    (_('More info'), 'https://example.org/'),
                )
                text, url = choice(HTML_CHOICES)
                safestring.mark_safe('<a href="{0}">{1}</a>'.format(url, text))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B703", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BASIC_XSS, issue.cwe.id)
        self.assertEqual(9, issue.lineno)
        self.assertEqual([9], issue.linerange)
        self.assertEqual(4, issue.col_offset)
