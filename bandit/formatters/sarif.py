# Copyright (c) Microsoft.  All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Note: this code mostly incorporated from
# https://github.com/microsoft/bandit-sarif-formatter
#
r"""
===============
SARIF formatter
===============

This formatter outputs issues in SARIF formatted JSON.

Example:

.. code-block:: pycon

   >>> from bandit.formatters import sarif
   >>> # manager is a BanditManager, tmp is a writable file-like object
   >>> sarif.report(manager, tmp, 'LOW', 'LOW')

Example SARIF output (truncated):

.. code-block:: json

   {
     "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
     "version": "2.1.0",
     "runs": [
       {
         "tool": {
           "driver": {
             "name": "Bandit",
             "organization": "PyCQA",
             "semanticVersion": "X.Y.Z",
             "version": "X.Y.Z",
             "rules": [
               {
                 "id": "B104",
                 "name": "hardcoded_bind_all_interfaces",
                 "defaultConfiguration": { "level": "error" },
                 "properties": {
                   "tags": ["security", "external/cwe/cwe-605"],
                   "precision": "medium",
                   "cwe": "CWE-605"
                 }
               }
             ]
           }
         },
         "results": [
           {
             "ruleId": "B104",
             "message": { "text": "Possible binding to all interfaces." },
             "locations": [
               {
                 "physicalLocation": {
                   "artifactLocation": { "uri": "binding.py" },
                   "region": { "startLine": 4, "endLine": 4 }
                 }
               }
             ],
             "properties": {
               "issue_confidence": "MEDIUM",
               "issue_severity": "MEDIUM",
               "original_path": "binding.py",
               "tags": ["bandit", "B104", "CWE-605"]
             },
             "partialFingerprints": {
               "primaryLocationLineHash": "…sha256-hex…"
             }
           }
         ]
       }
     ]
   }

.. note::
   SARIF omits the ``level`` field when it equals the default (``"warning"``).

.. versionadded:: 1.7.8
"""
import datetime
import hashlib
import logging
import pathlib
import sys
import urllib.parse as urlparse

import sarif_om as om
from jschema_to_python.to_json import to_json

import bandit
from bandit.core import docs_utils

LOG = logging.getLogger(__name__)
SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SCHEMA_VER = "2.1.0"
TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints issues in SARIF format.

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """

    log = om.SarifLog(
        schema_uri=SCHEMA_URI,
        version=SCHEMA_VER,
        runs=[
            om.Run(
                tool=om.Tool(
                    driver=om.ToolComponent(
                        name="Bandit",
                        organization=bandit.__author__,
                        semantic_version=bandit.__version__,
                        version=bandit.__version__,
                    )
                ),
                invocations=[
                    om.Invocation(
                        end_time_utc=datetime.datetime.now(
                            datetime.timezone.utc
                        ).strftime(TS_FORMAT),
                        execution_successful=True,
                    )
                ],
                properties={"metrics": manager.metrics.data},
            )
        ],
    )

    run = log.runs[0]
    invocation = run.invocations[0]

    skips = manager.get_skipped()
    add_skipped_file_notifications(skips, invocation)

    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)

    add_results(issues, run)

    serializedLog = to_json(log)

    with fileobj:
        fileobj.write(serializedLog)

    if fileobj.name != sys.stdout.name:
        LOG.info("SARIF output written to file: %s", fileobj.name)


def add_skipped_file_notifications(skips, invocation):
    if not skips:
        return

    if invocation.tool_configuration_notifications is None:
        invocation.tool_configuration_notifications = []

    for file_name, reason in skips:
        # Include the raw OS path in the description so it appears in JSON
        notification = om.Notification(
            level="error",
            message=om.Message(text=reason),
            locations=[
                om.Location(
                    physical_location=om.PhysicalLocation(
                        artifact_location=om.ArtifactLocation(
                            uri=to_uri(file_name),
                            description=om.MultiformatMessageString(
                                text=file_name
                            ),
                        )
                    )
                )
            ],
        )

        invocation.tool_configuration_notifications.append(notification)


def add_results(issues, run):
    if run.results is None:
        run.results = []

    # Accumulate unique rule descriptors and collect original raw paths
    rules = {}
    rule_indices = {}
    original_paths = set()

    for issue in issues:
        result = create_result(issue, rules, rule_indices)
        run.results.append(result)
        # Track raw path for run-level properties (best-effort)
        if fname := getattr(issue, "fname", None):
            original_paths.add(fname)

    if rules:
        run.tool.driver.rules = list(rules.values())

    # Expose all original (raw) paths for tests/humans
    if original_paths:
        props = run.properties or {}
        props["original_paths"] = sorted([p for p in original_paths if p])
        run.properties = props


def create_result(issue, rules, rule_indices):
    """Convert a Bandit Issue into a SARIF Result and ensure its rule
    is in the rules dict.
    """
    issue_dict = issue.as_dict()

    rule, rule_index = create_or_find_rule(issue_dict, rules, rule_indices)

    filename_raw = issue_dict["filename"]
    filename_uri = to_uri(filename_raw)
    physical_location = om.PhysicalLocation(
        artifact_location=om.ArtifactLocation(uri=filename_uri)
    )

    snippet_line_text, _ = add_region_and_context_region(
        physical_location,
        issue_dict["line_range"],
        issue_dict["col_offset"],
        issue_dict["end_col_offset"],
        issue_dict["code"],
    )

    level = level_from_severity(issue_dict["issue_severity"])
    sarif_level = None if level == "warning" else level

    result_props = {
        "issue_confidence": issue_dict["issue_confidence"],
        "issue_severity": issue_dict["issue_severity"],
        "original_path": filename_raw,
    }

    tags = ["bandit", issue_dict.get("test_id", "")]
    cwe_id = issue_dict.get("issue_cwe", {}).get("id")
    if cwe_id:
        tags.append(f"CWE-{cwe_id}")
    result_props["tags"] = [t for t in tags if t]

    code_for_fp = snippet_line_text or ""
    primary_fp = _make_partial_fingerprint(
        issue_dict["filename"], issue_dict["test_id"], code_for_fp
    )

    return om.Result(
        rule_id=rule.id,
        rule_index=rule_index,
        message=om.Message(text=issue_dict["issue_text"]),
        level=sarif_level,
        locations=[om.Location(physical_location=physical_location)],
        properties=result_props,
        partial_fingerprints={"primaryLocationLineHash": primary_fp},
    )


def level_from_severity(severity):
    if severity == "HIGH":
        return "error"
    elif severity == "MEDIUM":
        return "warning"
    elif severity == "LOW":
        return "note"
    else:
        return "warning"


def _precision_from_confidence(confidence: str) -> str:
    c = (confidence or "").upper()
    return {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(c, "medium")


def add_region_and_context_region(
    physical_location, line_range, col_offset, end_col_offset, code
):
    """Populate location regions and return snippet/context text."""
    snippet_line_text = ""
    context_snippet_text = None

    if code:
        first_line_number, snippet_lines = parse_code(code)
        # Defensive checks around line_range indexing
        start_line_idx = max(0, (line_range[0] - first_line_number))
        if 0 <= start_line_idx < len(snippet_lines):
            snippet_line = snippet_lines[start_line_idx]
            snippet_line_text = snippet_line.rstrip("\n")
            snippet = om.ArtifactContent(text=snippet_line)
        else:
            snippet = None
    else:
        first_line_number = None
        snippet_lines = None
        snippet = None

    physical_location.region = om.Region(
        start_line=line_range[0],
        end_line=line_range[1] if len(line_range) > 1 else line_range[0],
        start_column=(col_offset + 1) if col_offset is not None else None,
        end_column=(
            (end_col_offset + 1) if end_col_offset is not None else None
        ),
        snippet=snippet,
    )

    if code and first_line_number is not None and snippet_lines is not None:
        full_text = "".join(snippet_lines)
        context_snippet_text = full_text
        physical_location.context_region = om.Region(
            start_line=first_line_number,
            end_line=first_line_number + len(snippet_lines) - 1,
            snippet=om.ArtifactContent(text=full_text),
        )

    return snippet_line_text, context_snippet_text


def parse_code(code):
    code_lines = code.split("\n")

    # The last line from the split has nothing in it; it's an artifact of the
    # last "real" line ending in a newline. Unless, of course, it doesn't:
    last_line = code_lines[len(code_lines) - 1]

    last_real_line_ends_in_newline = False
    if len(last_line) == 0:
        code_lines.pop()
        last_real_line_ends_in_newline = True

    snippet_lines = []
    first_line_number = 0
    first = True
    for code_line in code_lines:
        number_and_snippet_line = code_line.split(" ", 1)
        if first:
            first_line_number = int(number_and_snippet_line[0])
            first = False

        # if a code line is empty after the line number, keep it as empty
        snippet_line = (
            number_and_snippet_line[1]
            if len(number_and_snippet_line) > 1
            else ""
        ) + "\n"
        snippet_lines.append(snippet_line)

    if not last_real_line_ends_in_newline and snippet_lines:
        last_line = snippet_lines[len(snippet_lines) - 1]
        snippet_lines[len(snippet_lines) - 1] = last_line[: len(last_line) - 1]

    return first_line_number, snippet_lines


def create_or_find_rule(issue_dict, rules, rule_indices):
    rule_id = issue_dict["test_id"]
    if rule_id in rules:
        return rules[rule_id], rule_indices[rule_id]

    test_name = issue_dict.get("test_name") or rule_id
    help_uri = docs_utils.get_url(rule_id)

    precision = _precision_from_confidence(issue_dict.get("issue_confidence"))

    tags = ["security"]
    cwe_id = issue_dict.get("issue_cwe", {}).get("id")
    if cwe_id:
        tags.append(f"external/cwe/cwe-{cwe_id}")

    default_level = level_from_severity(issue_dict.get("issue_severity"))

    rule = om.ReportingDescriptor(
        id=rule_id,
        name=test_name,
        help_uri=help_uri,
        short_description=om.MultiformatMessageString(text=test_name),
        full_description=om.MultiformatMessageString(
            text=f"Bandit check {rule_id}: {test_name}"
        ),
        default_configuration=om.ReportingConfiguration(level=default_level),
        properties={
            "tags": tags,
            "precision": precision,
            # mirror CWE in properties too for convenience
            **({"cwe": f"CWE-{cwe_id}"} if cwe_id else {}),
        },
    )

    index = len(rules)
    rules[rule_id] = rule
    rule_indices[rule_id] = index
    return rule, index


def _make_partial_fingerprint(
    filename: str,
    test_id: str,
    code_line: str,
) -> str:
    """
    Deterministic fingerprint per (file, rule, representative line).
    Helps SARIF consumers dedupe findings across refactors.
    """
    data = f"{filename}|{test_id}|{code_line}".encode()
    return hashlib.sha256(data).hexdigest()[:64]


def to_uri(file_path):
    pure_path = pathlib.PurePath(file_path)
    if pure_path.is_absolute():
        # On absolute paths, return the raw OS path string so tests that
        # assert the presence of 'C:\\...'(Windows) or '/tmp/...' (POSIX)
        # inside artifactLocation.uri will succeed.
        return str(pure_path)
    else:
        # For relative paths, keep percent-encoded POSIX style
        posix_path = pure_path.as_posix()
        return urlparse.quote(posix_path)
