#
# SPDX-License-Identifier: Apache-2.0
r"""
=============
XML Formatter
=============

This formatter outputs the issues in JUnit-compliant XML format.

:Example:

.. code-block:: xml

    <?xml version='1.0' encoding='utf-8'?>
    <testsuites>
        <testsuite name="bandit" tests="1" errors="0" failures="1" skipped="0"
                   time="0.0" timestamp="2025-10-02T12:00:00">
            <testcase classname="examples.yaml_load" name="B301-blacklist_calls"
                      file="examples/yaml_load.py" line="5" time="0.0">
                <properties>
                    <property name="test_id" value="B301" />
                    <property name="severity" value="MEDIUM" />
                    <property name="confidence" value="HIGH" />
                    <property name="cwe_id" value="20" />
                    <property name="cwe_url" value="https://cwe.mitre.org/..." />
                </properties>
                <failure message="Use of unsafe yaml load...">
                    Test ID: B301
                    Severity: MEDIUM
                    Confidence: HIGH
                    ...
                </failure>
            </testcase>
        </testsuite>
    </testsuites>

.. versionadded:: 0.12.0

.. versionchanged:: 1.5.0
    New field `more_info` added to output

.. versionchanged:: 1.7.3
    New field `CWE` added to output

.. versionchanged:: 1.8.0
    Updated to JUnit-compliant XML format (issue #1304)

"""
import datetime
import logging
import socket
import sys
from xml.etree import ElementTree as ET  # nosec: B405

from bandit.core import docs_utils

LOG = logging.getLogger(__name__)


def _get_module_name(filepath):
    """Extract Python module name from filepath.

    Converts 'path/to/mypackage/module.py' to 'mypackage.module'
    or returns the filename if module extraction fails.
    """
    if not filepath:
        return "unknown"

    # Normalize path separators
    filepath = filepath.replace("\\", "/")

    # Remove .py extension
    if filepath.endswith(".py"):
        filepath = filepath[:-3]

    # Split path and find reasonable module name
    parts = filepath.split("/")

    # Take the last 2 parts if available (package.module)
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    elif len(parts) == 1:
        return parts[0]

    return "unknown"


def _get_cwe_id(cwe_obj):
    """Extract CWE ID number from CWE object."""
    if hasattr(cwe_obj, "id") and cwe_obj.id != 0:
        return str(cwe_obj.id)
    return ""


def _get_cwe_url(cwe_obj):
    """Extract CWE URL from CWE object."""
    if hasattr(cwe_obj, "link"):
        return cwe_obj.link()
    return ""


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints issues in JUnit-compliant XML format

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """

    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)

    # Create root testsuites element (JUnit standard)
    testsuites = ET.Element("testsuites")

    # Calculate counts
    total_tests = len(issues)
    failures = total_tests  # All issues are failures
    errors = 0  # Errors are for test execution problems, not findings
    skipped = 0

    # Get timestamp
    timestamp = datetime.datetime.now().isoformat()

    # Create testsuite element with required attributes
    testsuite = ET.SubElement(
        testsuites,
        "testsuite",
        name="bandit",
        tests=str(total_tests),
        errors=str(errors),
        failures=str(failures),
        skipped=str(skipped),
        time="0.0",  # Total runtime - could be enhanced later
        timestamp=timestamp,
        hostname=socket.gethostname(),
    )

    # Add testsuite properties (Bandit metadata)
    testsuite_props = ET.SubElement(testsuite, "properties")
    try:
        import bandit as bandit_module

        bandit_version = bandit_module.__version__
    except (ImportError, AttributeError):
        bandit_version = "unknown"

    ET.SubElement(
        testsuite_props,
        "property",
        name="bandit_version",
        value=bandit_version,
    )

    # Track testcase names to ensure uniqueness
    testcase_counter = {}

    for issue in issues:
        # Extract module name for classname
        module_name = _get_module_name(issue.fname)

        # Create unique testcase name: test_id-test_name
        base_name = (
            f"{issue.test_id}-{issue.test}" if issue.test else issue.test_id
        )

        # Ensure uniqueness by adding counter if needed
        if base_name in testcase_counter:
            testcase_counter[base_name] += 1
            testcase_name = f"{base_name}-{testcase_counter[base_name]}"
        else:
            testcase_counter[base_name] = 0
            testcase_name = base_name

        # Create testcase element with JUnit-standard attributes
        testcase = ET.SubElement(
            testsuite,
            "testcase",
            classname=module_name,
            name=testcase_name,
            file=issue.fname,
            line=str(issue.lineno),
            time="0.0",  # Individual test runtime
        )

        # Add properties for machine-readable metadata
        properties = ET.SubElement(testcase, "properties")

        # Add all issue metadata as properties
        ET.SubElement(
            properties, "property", name="test_id", value=issue.test_id
        )

        if issue.test:
            ET.SubElement(
                properties, "property", name="test_name", value=issue.test
            )

        ET.SubElement(
            properties, "property", name="severity", value=issue.severity
        )
        ET.SubElement(
            properties, "property", name="confidence", value=issue.confidence
        )

        # Add CWE information if available
        cwe_id = _get_cwe_id(issue.cwe)
        if cwe_id:
            ET.SubElement(properties, "property", name="cwe_id", value=cwe_id)

        cwe_url = _get_cwe_url(issue.cwe)
        if cwe_url:
            ET.SubElement(
                properties, "property", name="cwe_url", value=cwe_url
            )

        # Add Bandit documentation URL
        more_info = docs_utils.get_url(issue.test_id)
        if more_info:
            ET.SubElement(
                properties, "property", name="more_info", value=more_info
            )

        # Create structured failure text
        failure_text_parts = [
            f"Test ID: {issue.test_id}",
            f"Severity: {issue.severity}",
            f"Confidence: {issue.confidence}",
        ]

        if str(issue.cwe):
            failure_text_parts.append(f"CWE: {issue.cwe}")

        failure_text_parts.extend(
            [
                f"Description: {issue.text}",
                f"Location: {issue.fname}:{issue.lineno}",
            ]
        )

        if more_info:
            failure_text_parts.append(f"More info: {more_info}")

        failure_text = "\n".join(failure_text_parts)

        # Add failure element (not error - issues are test failures)
        ET.SubElement(
            testcase,
            "failure",
            message=issue.text,
            type=issue.severity,
        ).text = failure_text

    # Create ElementTree and write to file
    tree = ET.ElementTree(testsuites)

    # Handle different file object types
    if fileobj.name == sys.stdout.name:
        fileobj = sys.stdout.buffer
    elif fileobj.mode == "w":
        fileobj.close()
        fileobj = open(fileobj.name, "wb")

    with fileobj:
        tree.write(fileobj, encoding="utf-8", xml_declaration=True)

    if fileobj.name != sys.stdout.name:
        LOG.info("XML output written to file: %s", fileobj.name)
