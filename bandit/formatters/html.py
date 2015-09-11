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
<title>
    Bandit Report
</title>
</head>
<body>
    <div class="results">
        {results}
    </div>
</body>
</html>
    """

    issue_block = """
<h2 class="test_text">{test_text}</h2>
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

    issues = manager.get_issue_list()
    for issue in issues:
        if not results.get(issue.fname):
            results[issue.fname] = []

        if issue.filter(sev_level, conf_level):
            code = issue.get_code(lines, True)
            temp_result = issue_block.format(
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
    report = report_block.format(results=results_str)

    if filename:
        with open(filename, 'w') as fout:
            fout.write(report)
        print("HTML output written to file: %s" % filename)
    else:
        print(report)
