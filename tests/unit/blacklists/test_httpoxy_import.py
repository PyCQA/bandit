# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class HttpoxyImportTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B412"])

    def test_wsgiref_handlers(self):
        fdata = textwrap.dedent(
            """
            import requests
            from wsgiref import handlers

            def application(environ, start_response):
                r = requests.get('https://192.168.0.42/api/foobar', timeout=30)
                start_response('200 OK', [('Content-Type', 'text/plain')])
                return [r.content]

            if __name__ == '__main__':
                wsgiref.handlers.CGIHandler().run(application)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B412", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_ACCESS_CONTROL, issue.cwe.id)
        self.assertEqual(11, issue.lineno)
        self.assertEqual([11], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_twisted_web_twcgi_cgiscript(self):
        fdata = textwrap.dedent(
            """
            from twisted.internet import reactor
            from twisted.web import static, server, twcgi

            root = static.File("/root")
            root.putChild(
                "login.cgi",
                twcgi.CGIScript("/var/www/cgi-bin/login.py"),
            )
            reactor.listenTCP(80, server.Site(root))
            reactor.run()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B412", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_ACCESS_CONTROL, issue.cwe.id)
        self.assertEqual(8, issue.lineno)
        self.assertEqual([8], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_twisted_web_twcgi_cgidirectory(self):
        fdata = textwrap.dedent(
            """
            from twisted.internet import reactor
            from twisted.web import static, server, twcgi

            root = static.File("/root")
            root.putChild(
                "cgi-bin",
                twcgi.CGIDirectory("/var/www/cgi-bin"),
            )
            reactor.listenTCP(80, server.Site(root))
            reactor.run()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B412", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_ACCESS_CONTROL, issue.cwe.id)
        self.assertEqual(8, issue.lineno)
        self.assertEqual([8], issue.linerange)
        self.assertEqual(4, issue.col_offset)
