# Copyright (c) 2015 VMware, Inc.
#
# SPDX-License-Identifier: Apache-2.0
import collections
import tempfile
from xml.etree import ElementTree as ET

import testtools

import bandit
from bandit.core import config
from bandit.core import issue
from bandit.core import manager
from bandit.formatters import xml as b_xml


class XmlFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "file")
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {
            "filename": self.tmp_fname,
            "lineno": 4,
            "linerange": [4],
        }
        self.check_name = "hardcoded_bind_all_interfaces"
        self.issue = issue.Issue(
            bandit.MEDIUM,
            issue.Cwe.MULTIPLE_BINDS,
            bandit.MEDIUM,
            "Possible binding to all interfaces.",
        )
        self.manager.out_file = self.tmp_fname

        self.issue.fname = self.context["filename"]
        self.issue.lineno = self.context["lineno"]
        self.issue.linerange = self.context["linerange"]
        self.issue.test = self.check_name
        self.issue.test_id = "B104"

        self.manager.results.append(self.issue)

    def _xml_to_dict(self, t):
        d = {t.tag: {} if t.attrib else None}
        children = list(t)
        if children:
            dd = collections.defaultdict(list)
            for dc in map(self._xml_to_dict, children):
                for k, v in dc.items():
                    dd[k].append(v)
            d = {t.tag: {k: v[0] if len(v) == 1 else v for k, v in dd.items()}}
        if t.attrib:
            d[t.tag].update(("@" + k, v) for k, v in t.attrib.items())
        if t.text:
            text = t.text.strip()
            if children or t.attrib:
                if text:
                    d[t.tag]["#text"] = text
            else:
                d[t.tag] = text
        return d

    def test_report(self):
        """Test basic XML report generation with JUnit-compliant structure"""
        with open(self.tmp_fname, "wb") as tmp_file:
            b_xml.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            data = self._xml_to_dict(ET.XML(f.read()))

            # Verify root is testsuites (JUnit compliant)
            self.assertIn("testsuites", data)
            testsuites = data["testsuites"]

            # Verify testsuite exists with required attributes
            self.assertIn("testsuite", testsuites)
            testsuite = testsuites["testsuite"]

            # Check required testsuite attributes
            self.assertEqual("bandit", testsuite["@name"])
            self.assertEqual("1", testsuite["@tests"])
            self.assertEqual("0", testsuite["@errors"])
            self.assertEqual("1", testsuite["@failures"])
            self.assertEqual("0", testsuite["@skipped"])
            self.assertIn("@timestamp", testsuite)
            self.assertIn("@hostname", testsuite)

            # Verify testcase exists
            self.assertIn("testcase", testsuite)
            testcase = testsuite["testcase"]

            # Check testcase has file and line attributes (JUnit compliant)
            self.assertEqual(self.tmp_fname, testcase["@file"])
            self.assertEqual(str(self.context["lineno"]), testcase["@line"])

            # Check testcase name is formatted as test_id-test_name
            expected_name = f"{self.issue.test_id}-{self.check_name}"
            self.assertEqual(expected_name, testcase["@name"])

            # Verify it uses failure tag (not error)
            self.assertIn("failure", testcase)
            failure = testcase["failure"]
            self.assertEqual(self.issue.text, failure["@message"])

            # Verify properties exist
            self.assertIn("properties", testcase)

    def test_junit_required_attributes(self):
        """Test that all JUnit-required attributes are present"""
        with open(self.tmp_fname, "wb") as tmp_file:
            b_xml.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            root = ET.XML(f.read())

            # Verify root element
            self.assertEqual("testsuites", root.tag)

            # Get testsuite
            testsuite = root.find("testsuite")
            self.assertIsNotNone(testsuite)

            # Check all required JUnit attributes exist
            required_attrs = ["name", "tests", "errors", "failures", "skipped", "time", "timestamp"]
            for attr in required_attrs:
                self.assertIn(attr, testsuite.attrib, f"Missing required attribute: {attr}")

            # Check testcase attributes
            testcase = testsuite.find("testcase")
            self.assertIsNotNone(testcase)

            testcase_attrs = ["classname", "name", "file", "line", "time"]
            for attr in testcase_attrs:
                self.assertIn(attr, testcase.attrib, f"Missing testcase attribute: {attr}")

    def test_properties_machine_readable(self):
        """Test that properties provide machine-readable metadata"""
        with open(self.tmp_fname, "wb") as tmp_file:
            b_xml.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            root = ET.XML(f.read())
            testcase = root.find(".//testcase")
            properties = testcase.find("properties")

            self.assertIsNotNone(properties)

            # Get all property elements as a dict
            props_dict = {}
            for prop in properties.findall("property"):
                props_dict[prop.get("name")] = prop.get("value")

            # Verify required properties
            self.assertIn("test_id", props_dict)
            self.assertEqual("B104", props_dict["test_id"])

            self.assertIn("severity", props_dict)
            self.assertEqual("MEDIUM", props_dict["severity"])

            self.assertIn("confidence", props_dict)
            self.assertEqual("MEDIUM", props_dict["confidence"])

            self.assertIn("cwe_id", props_dict)
            self.assertEqual("605", props_dict["cwe_id"])

            self.assertIn("cwe_url", props_dict)
            self.assertIn("https://cwe.mitre.org", props_dict["cwe_url"])

            self.assertIn("more_info", props_dict)
            self.assertIn("bandit.readthedocs.io", props_dict["more_info"])

    def test_failure_not_error(self):
        """Test that issues use failure tag, not error tag"""
        with open(self.tmp_fname, "wb") as tmp_file:
            b_xml.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            root = ET.XML(f.read())
            testcase = root.find(".//testcase")

            # Should have failure element
            failure = testcase.find("failure")
            self.assertIsNotNone(failure)

            # Should NOT have error element
            error = testcase.find("error")
            self.assertIsNone(error)

            # Verify failure has message and type attributes
            self.assertIn("message", failure.attrib)
            self.assertIn("type", failure.attrib)

            # Verify no non-standard attributes like more_info
            self.assertNotIn("more_info", failure.attrib)

    def test_multiple_issues_unique_names(self):
        """Test that multiple issues get unique testcase names"""
        # Add a second issue with the same test
        issue2 = issue.Issue(
            bandit.MEDIUM,
            issue.Cwe.MULTIPLE_BINDS,
            bandit.MEDIUM,
            "Another binding issue.",
        )
        issue2.fname = self.tmp_fname
        issue2.lineno = 5
        issue2.test = self.check_name
        issue2.test_id = "B104"
        self.manager.results.append(issue2)

        with open(self.tmp_fname, "wb") as tmp_file:
            b_xml.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            root = ET.XML(f.read())
            testcases = root.findall(".//testcase")

            # Should have 2 testcases
            self.assertEqual(2, len(testcases))

            # Names should be unique
            names = [tc.get("name") for tc in testcases]
            self.assertEqual(len(names), len(set(names)), "Testcase names are not unique")

            # First should be B104-hardcoded_bind_all_interfaces
            # Second should be B104-hardcoded_bind_all_interfaces-1
            self.assertEqual("B104-hardcoded_bind_all_interfaces", names[0])
            self.assertEqual("B104-hardcoded_bind_all_interfaces-1", names[1])

    def test_module_name_extraction(self):
        """Test that classname uses module name, not filename"""
        # Test with a proper module path
        self.issue.fname = "mypackage/submodule.py"

        with open(self.tmp_fname, "wb") as tmp_file:
            b_xml.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            root = ET.XML(f.read())
            testcase = root.find(".//testcase")

            # Classname should be module-style (mypackage.submodule)
            classname = testcase.get("classname")
            self.assertEqual("mypackage.submodule", classname)

            # File should still be the original path
            self.assertEqual("mypackage/submodule.py", testcase.get("file"))

    def test_counts_match_issues(self):
        """Test that testsuite counts accurately reflect issues"""
        # Add more issues
        for i in range(3):
            new_issue = issue.Issue(
                bandit.HIGH,
                issue.Cwe.SQL_INJECTION,
                bandit.HIGH,
                f"SQL injection risk {i}.",
            )
            new_issue.fname = f"module{i}.py"
            new_issue.lineno = i + 1
            new_issue.test = "sql_injection_check"
            new_issue.test_id = f"B60{i}"
            self.manager.results.append(new_issue)

        with open(self.tmp_fname, "wb") as tmp_file:
            b_xml.report(
                self.manager,
                tmp_file,
                bandit.LOW,  # Include all severity levels
                bandit.LOW,
            )

        with open(self.tmp_fname) as f:
            root = ET.XML(f.read())
            testsuite = root.find("testsuite")

            # Should have 4 total tests (1 original + 3 new)
            self.assertEqual("4", testsuite.get("tests"))
            self.assertEqual("4", testsuite.get("failures"))
            self.assertEqual("0", testsuite.get("errors"))
            self.assertEqual("0", testsuite.get("skipped"))

            # Verify actual testcases
            testcases = root.findall(".//testcase")
            self.assertEqual(4, len(testcases))
