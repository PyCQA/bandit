# Copyright (c) 2015 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging

from bandit.core import utils

logger = logging.getLogger(__name__)


def report(manager, filename, sev_level, conf_level, lines=-1,
           out_format='html'):
    '''Writes issues to 'filename' in HTML format

    :param manager: the bandit manager object
    :param filename: output file name
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    :param out_format: The ouput format name
    '''

    report_block = """
<!DOCTYPE html>
<html>
<head>
<style>
.metrics-main {{
    border: 1px solid black;
    padding-top:.5em;
    padding-bottom:.5em;
    padding-left:1em ;
    font-size: 1.1em;
    line-height: 130%;
}}

.metrics-title {{
    font-size: 1.5em;
    font-weight: 500;
}}

.issue-description {{
    font-size: 1.3em;
    font-weight: 500;
}}

</style>
<title>
    Bandit Report
</title>
</head>
<body>
    <div class="metrics-main">
        {metrics}
    </div>
    <br><br>
    <div class="results">
        {results}
    </div>
</body>
</html>

    """

    issue_block = """
<div class="issue-description"><b>{test_name}:</b> {test_text}</div><br>
<div class="details">
    <b>Severity: </b>
    <span class='severity severity_{severity}'>{severity}</span><br />
    <b>Confidence:</b>
    <span class='confidence confidence_{confidence}'>{confidence}</span><br />
    <b>File:</b>
    <a class='file_link' href='{path}' target='_blank'>{path}</a> <br />
</div>

<div class="code">
    <pre>
{code}
    </pre>
</div>
    """

    results = {}

    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)
    for issue in issues:
        if not results.get(issue.fname):
            results[issue.fname] = []

        code = issue.get_code(lines, True)
        temp_result = issue_block.format(
            test_name=issue.test,
            test_text=issue.text,
            severity=issue.severity,
            confidence=issue.confidence,
            path=issue.fname, code=code
        )
        results[issue.fname].append(temp_result)

    results_str = ""
    for res in results:
        if results[res]:
            for result in results[res]:
                results_str += result + "\n"

    # print out basic metrics from run

    metrics_summary = '<div class=metrics-title>Metrics:</div><br>\n'

    for (label, metric) in [
        ('Total lines of code', 'loc'),
        ('Total lines skipped (#nosec)', 'nosec')
    ]:
        metrics_summary += "{0}: <span class='{1}'>{2}</span><br>\n".format(
            label,
            metric,
            manager.metrics.data['_totals'][metric]
        )

    report_contents = report_block.format(metrics=metrics_summary,
                                          results=results_str)

    with utils.output_file(filename, 'w') as fout:
        fout.write(report_contents)

    if filename is not None:
        logger.info("HTML output written to file: %s" % filename)
