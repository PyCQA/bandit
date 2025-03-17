import io
import logging
import tokenize

from bandit.core import config
from bandit.core import docs_utils
from bandit.core import manager
from bandit.core import meta_ast
from bandit.core import metrics
from bandit.core import node_visitor
from bandit.core import test_set
from pyscript import document


# Disable noisy output from Bandit getting rendered to page
logging.basicConfig(level=logging.ERROR)

ISSUE_BLOCK = """
    <div id="issue-{issue_no}">
        <div class="issue-block {issue_class}">
            <b>[{test_id}:{test_name}]</b> {test_text}<br>
            <b>Severity: </b>{severity}<br>
            <b>Confidence: </b>{confidence}<br>
            <b>CWE: </b><a href="{cwe_link}" target="_blank">{cwe}</a><br>
            <b>More info: </b><a href="{url}" target="_blank">{url}</a><br>
            <b>Location: </b>&lt;stdin&gt;:{line_number}:{col_offset}<br>
        </div>
    </div>
"""

MESSAGE_BLOCK = """
    <div id="no-issues">
        <div class="issue-block">
            <b>{message}</b><br>
        </div>
    </div>
"""

output_element = document.getElementById("output")


def run_analysis(code):
    issue_metrics = metrics.Metrics()
    scores = []
    skipped = []
    filename = "<stdin>"

    # Clear previous output
    output_element.innerHTML = ""

    try:
        fobj = io.BytesIO(code)
        issue_metrics.begin(filename)
        data = fobj.read()
        lines = data.splitlines()
        issue_metrics.count_locs(lines)
        nosec_lines = {}

        try:
            fobj.seek(0)
            tokens = tokenize.tokenize(fobj.readline)
            for toktype, tokval, (lineno, _), _, _ in tokens:
                if toktype == tokenize.COMMENT:
                    nosec_lines[lineno] = manager._parse_nosec_comment(tokval)
        except tokenize.TokenError:
            pass

        visitor = node_visitor.BanditNodeVisitor(
            filename,
            fobj,
            metaast=meta_ast.BanditMetaAst(),
            testset=test_set.BanditTestSet(
                config.BanditConfig(),
                profile={
                    "include": [],
                    "exclude": ["B613"],  # FIXME: issue #1182
                },
            ),
            debug=False,
            nosec_lines=nosec_lines,
            metrics=issue_metrics,
        )
        score = visitor.process(code)
        scores.append(score)
        issue_metrics.count_issues([score])

        for index, issue in enumerate(visitor.tester.results):
            url = docs_utils.get_url(issue.test_id)
            output_element.innerHTML += ISSUE_BLOCK.format(
                issue_no=index,
                issue_class=f"issue-sev-{issue.severity.lower()}",
                test_name=issue.test,
                test_id=issue.test_id,
                test_text=issue.text,
                severity=issue.severity.capitalize(),
                confidence=issue.confidence.capitalize(),
                cwe=str(issue.cwe),
                cwe_link=issue.cwe.link(),
                url=url,
                line_number=issue.lineno,
                col_offset=issue.col_offset,
            )

        if not visitor.tester.results:
            output_element.innerHTML += MESSAGE_BLOCK.format(
                message="No issues identified."
            )
    except SyntaxError:
        output_element.innerHTML += MESSAGE_BLOCK.format(
            message="Syntax error parsing code."
        )
    except Exception:
        output_element.innerHTML += MESSAGE_BLOCK.format(
            message="Exception scanning code."
        )

    issue_metrics.aggregate()


def handle_event(event):
    run_analysis(event.code.encode())

    # prevent default execution
    return False


editor = document.getElementById("editor")
editor.handleEvent = handle_event
