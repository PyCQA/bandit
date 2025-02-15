# SPDX-License-Identifier: Apache-2.0
import collections
import json
import tempfile
from unittest import mock

import testtools

import bandit
from bandit.core import config
from bandit.core import constants
from bandit.core import issue
from bandit.core import manager
from bandit.core import metrics
from bandit.formatters import sarif


class SarifFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "file")
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {
            "filename": self.tmp_fname,
            "lineno": 4,
            "linerange": [4],
            "code": (
                "import socket\n\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.bind(('0.0.0.0', 31137))"
            ),
        }
        self.check_name = "hardcoded_bind_all_interfaces"
        self.issue = issue.Issue(
            severity=bandit.MEDIUM,
            cwe=issue.Cwe.MULTIPLE_BINDS,
            confidence=bandit.MEDIUM,
            text="Possible binding to all interfaces.",
            test_id="B104",
        )

        self.candidates = [
            issue.Issue(
                issue.Cwe.MULTIPLE_BINDS,
                bandit.LOW,
                bandit.LOW,
                "Candidate A",
                lineno=1,
            ),
            issue.Issue(
                bandit.HIGH,
                issue.Cwe.MULTIPLE_BINDS,
                bandit.HIGH,
                "Candiate B",
                lineno=2,
            ),
        ]

        self.manager.out_file = self.tmp_fname

        self.issue.fname = self.context["filename"]
        self.issue.lineno = self.context["lineno"]
        self.issue.linerange = self.context["linerange"]
        self.issue.code = self.context["code"]
        self.issue.test = self.check_name

        self.manager.results.append(self.issue)
        self.manager.metrics = metrics.Metrics()

        # mock up the metrics
        for key in ["_totals", "binding.py"]:
            self.manager.metrics.data[key] = {"loc": 4, "nosec": 2}
            for criteria, default in constants.CRITERIA:
                for rank in constants.RANKING:
                    self.manager.metrics.data[key][f"{criteria}.{rank}"] = 0

    @mock.patch("bandit.core.manager.BanditManager.get_issue_list")
    def test_report(self, get_issue_list):
        self.manager.files_list = ["binding.py"]
        self.manager.scores = [
            {
                "SEVERITY": [0] * len(constants.RANKING),
                "CONFIDENCE": [0] * len(constants.RANKING),
            }
        ]

        get_issue_list.return_value = collections.OrderedDict(
            [(self.issue, self.candidates)]
        )

        with open(self.tmp_fname, "w") as tmp_file:
            sarif.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            data = json.loads(f.read())
            run = data["runs"][0]
            self.assertEqual(sarif.SCHEMA_URI, data["$schema"])
            self.assertEqual(sarif.SCHEMA_VER, data["version"])
            driver = run["tool"]["driver"]
            self.assertEqual("Bandit", driver["name"])
            self.assertEqual(bandit.__author__, driver["organization"])
            self.assertEqual(bandit.__version__, driver["semanticVersion"])
            self.assertEqual("B104", driver["rules"][0]["id"])
            self.assertEqual(self.check_name, driver["rules"][0]["name"])
            self.assertIn("security", driver["rules"][0]["properties"]["tags"])
            self.assertIn(
                "external/cwe/cwe-605",
                driver["rules"][0]["properties"]["tags"],
            )
            self.assertEqual(
                "medium", driver["rules"][0]["properties"]["precision"]
            )
            invocation = run["invocations"][0]
            self.assertTrue(invocation["executionSuccessful"])
            self.assertIsNotNone(invocation["endTimeUtc"])
            result = run["results"][0]
            # If the level is "warning" like in this case, SARIF will remove
            # from output, as "warning" is the default value.
            self.assertIsNone(result.get("level"))
            self.assertEqual(self.issue.text, result["message"]["text"])
            physicalLocation = result["locations"][0]["physicalLocation"]
            self.assertEqual(
                self.context["linerange"][0],
                physicalLocation["region"]["startLine"],
            )
            self.assertEqual(
                self.context["linerange"][0],
                physicalLocation["region"]["endLine"],
            )
            self.assertIn(
                self.tmp_fname,
                physicalLocation["artifactLocation"]["uri"],
            )
