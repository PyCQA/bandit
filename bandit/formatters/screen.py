# Copyright (c) 2015 Hewlett Packard Enterprise
#
# SPDX-License-Identifier: Apache-2.0
r"""
================
Screen formatter
================

This formatter outputs the issues as color coded text to screen.

:Example:

.. code-block:: none

    >> Issue: [B506: yaml_load] Use of unsafe yaml load. Allows
       instantiation of arbitrary objects. Consider yaml.safe_load().

       Severity: Medium   Confidence: High
       CWE: CWE-20 (https://cwe.mitre.org/data/definitions/20.html)
       More Info: https://bandit.readthedocs.io/en/latest/
       Location: examples/yaml_load.py:5
    4       ystr = yaml.dump({'a' : 1, 'b' : 2, 'c' : 3})
    5       y = yaml.load(ystr)
    6       yaml.dump(y)

.. versionadded:: 0.9.0

.. versionchanged:: 1.5.0
    New field `more_info` added to output

.. versionchanged:: 1.7.3
    New field `CWE` added to output

.. versionchanged:: 1.8.6
    Automatic colours configuration with optional override via
    "BANDIT_LIGHT_BG" environment variable.

"""
import datetime
import logging
import os
import select
import sys
import termios
import time
import tty
from typing import Dict
from typing import Union

from bandit.core import constants
from bandit.core import docs_utils
from bandit.core import test_properties

IS_WIN_PLATFORM = sys.platform.startswith("win32")
COLORAMA = False

# This fixes terminal colors not displaying properly on Windows systems.
# Colorama will intercept any ANSI escape codes and convert them to the
# proper Windows console API calls to change text color.
if IS_WIN_PLATFORM:
    try:
        import colorama
    except ImportError:
        pass
    else:
        COLORAMA = True


LOG = logging.getLogger(__name__)


def term_detect_bg() -> Union[bool, None]:
    """Detects if terminal is using dark BG.

    Returns:
        True - Light
        False - Dark
        None - Undetermined
    """
    colorfgbg = os.environ.get("COLORFGBG")
    if colorfgbg and ";" in colorfgbg:
        try:
            parts = colorfgbg.split(";")
            bg_color = int(parts[-1])
            # Ref. https://github.com/rocky/shell-term-background
            if bg_color in {0, 1, 2, 3, 4, 5, 6, 8}:
                return False
            elif bg_color in {7, 9, 10, 11, 12, 13, 14, 15}:
                return True
        except (ValueError, IndexError):
            pass
    if sys.stdin.isatty():
        try:
            result = term_get_osc()
            if result is not None:
                return result
        except Exception:
            pass
    if os.environ.get("BANDIT_LIGHT_BG", "").lower() in (
        "light",
        "bright",
        "white",
        "1",
        "true",
        "yes",
    ):
        return True

    return None


def term_get_osc() -> Union[bool, None]:
    """Query terminal BG colour using OSC11.

    Returns:
        True - Light
        False - Dark
        None - Undetermined
    """
    if not sys.stdin.isatty():
        return None

    old_settings = None

    try:
        old_settings = termios.tcgetattr(sys.stdin)

        _ = tty.setraw(sys.stdin.fileno())
        _ = sys.stdout.write("\x1b]11;?\x1b\\")  # ESC\
        _ = sys.stdout.flush()

        ready, _, _ = select.select([sys.stdin], [], [], 0.2)
        if not ready:
            return None  # Bail out, this term is cursed

        response = ""
        start_time = time.time()
        while time.time() - start_time < 0.5:
            ready, _, _ = select.select([sys.stdin], [], [], 0.01)
            if not ready:
                break
            char = sys.stdin.read(1)
            response += char
            # Break on ESC\, BEL or sufficient data
            if (
                response.endswith("\x1b\\")
                or response.endswith("\x07")
                or len(response) > 50
            ):
                break
            # Bail out if ESC isn't followed by ]
            if (
                len(response) >= 2
                and response.startswith("\x1b")
                and not response.startswith("\x1b]")
            ):
                return None

        if response.startswith("\x1b]11;rgb:"):
            try:
                rgb_start = response.find("rgb:")
                rgb_part = response[rgb_start + 4 :]
                # Find terminator
                for term in ["\x1b\\", "\x07"]:
                    if term in rgb_part:
                        rgb_part = rgb_part[: rgb_part.find(term)]
                        break

                r, g, b = rgb_part.split("/")[:3]

                # HEX -> DEC
                r_val = int(r[:4], 16) if len(r) >= 4 else int(r, 16)
                g_val = int(g[:4], 16) if len(g) >= 4 else int(g, 16)
                b_val = int(b[:4], 16) if len(b) >= 4 else int(b, 16)

                # 16b -> 8b
                if r_val > 255:
                    r_val = r_val >> 8
                if g_val > 255:
                    g_val = g_val >> 8
                if b_val > 255:
                    b_val = b_val >> 8

                # BT601
                lum = 0.299 * r_val + 0.587 * g_val + 0.114 * b_val
                return lum > 128  # Light if luma > 50% grey
            except (ValueError, IndexError):
                pass
        else:
            return None

    except Exception:
        pass
    finally:
        try:
            if old_settings:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        except Exception:
            pass

    return None


def term_serve_colourscheme() -> dict[str, str]:
    """Appropriate colour scheme based on the detected background.

    Returns:
        Dictionary with colour codes
    """
    light = term_detect_bg()

    if light:
        return {
            "DEFAULT": "\033[0m",
            "HEADER": "\033[1;34m",  # Dark blue
            "LOW": "\033[1;32m",  # Dark green
            "MEDIUM": "\033[1;35m",  # Dark magenta
            "HIGH": "\033[1;31m",  # Dark red
        }
    else:
        return {
            "DEFAULT": "\033[0m",
            "HEADER": "\033[1;96m",  # Bright cyan
            "LOW": "\033[1;92m",  # Bright green
            "MEDIUM": "\033[1;93m",  # Bright yellow
            "HIGH": "\033[1;91m",  # Bright red
        }


COLOR = term_serve_colourscheme()


def header(text, *args):
    return f"{COLOR['HEADER']}{text % args}{COLOR['DEFAULT']}"


def get_verbose_details(manager):
    bits = []
    bits.append(header("Files in scope (%i):", len(manager.files_list)))
    tpl = "\t%s (score: {SEVERITY: %i, CONFIDENCE: %i})"
    bits.extend(
        [
            tpl % (item, sum(score["SEVERITY"]), sum(score["CONFIDENCE"]))
            for (item, score) in zip(manager.files_list, manager.scores)
        ]
    )
    bits.append(header("Files excluded (%i):", len(manager.excluded_files)))
    bits.extend([f"\t{fname}" for fname in manager.excluded_files])
    return "\n".join([str(bit) for bit in bits])


def get_metrics(manager):
    bits = []
    bits.append(header("\nRun metrics:"))
    for criteria, _ in constants.CRITERIA:
        bits.append(f"\tTotal issues (by {criteria.lower()}):")
        for rank in constants.RANKING:
            bits.append(
                "\t\t%s: %s"
                % (
                    rank.capitalize(),
                    manager.metrics.data["_totals"][f"{criteria}.{rank}"],
                )
            )
    return "\n".join([str(bit) for bit in bits])


def _output_issue_str(
    issue, indent, show_lineno=True, show_code=True, lines=-1
):
    # returns a list of lines that should be added to the existing lines list
    bits = []
    bits.append(
        "%s%s>> Issue: [%s:%s] %s"
        % (
            indent,
            COLOR[issue.severity],
            issue.test_id,
            issue.test,
            issue.text,
        )
    )

    bits.append(
        "%s   Severity: %s   Confidence: %s"
        % (
            indent,
            issue.severity.capitalize(),
            issue.confidence.capitalize(),
        )
    )

    bits.append(f"{indent}   CWE: {str(issue.cwe)}")

    bits.append(f"{indent}   More Info: {docs_utils.get_url(issue.test_id)}")

    bits.append(
        "%s   Location: %s:%s:%s%s"
        % (
            indent,
            issue.fname,
            issue.lineno if show_lineno else "",
            issue.col_offset if show_lineno else "",
            COLOR["DEFAULT"],
        )
    )

    if show_code:
        bits.extend(
            [indent + line for line in issue.get_code(lines, True).split("\n")]
        )

    return "\n".join([bit for bit in bits])


def get_results(manager, sev_level, conf_level, lines):
    bits = []
    issues = manager.get_issue_list(sev_level, conf_level)
    baseline = not isinstance(issues, list)
    candidate_indent = " " * 10

    if not len(issues):
        return "\tNo issues identified."

    for issue in issues:
        # if not a baseline or only one candidate we know the issue
        if not baseline or len(issues[issue]) == 1:
            bits.append(_output_issue_str(issue, "", lines=lines))

        # otherwise show the finding and the candidates
        else:
            bits.append(
                _output_issue_str(
                    issue, "", show_lineno=False, show_code=False
                )
            )

            bits.append("\n-- Candidate Issues --")
            for candidate in issues[issue]:
                bits.append(
                    _output_issue_str(candidate, candidate_indent, lines=lines)
                )
                bits.append("\n")
        bits.append("-" * 50)

    return "\n".join([bit for bit in bits])


def do_print(bits):
    # needed so we can mock this stuff
    print("\n".join([bit for bit in bits]))


@test_properties.accepts_baseline
def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints discovered issues formatted for screen reading

    This makes use of VT100 terminal codes for colored text.

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """

    if IS_WIN_PLATFORM and COLORAMA:
        colorama.init()

    bits = []
    if not manager.quiet or manager.results_count(sev_level, conf_level):
        bits.append(header("Run started:%s", datetime.datetime.utcnow()))

        if manager.verbose:
            bits.append(get_verbose_details(manager))

        bits.append(header("\nTest results:"))
        bits.append(get_results(manager, sev_level, conf_level, lines))
        bits.append(header("\nCode scanned:"))
        bits.append(
            "\tTotal lines of code: %i"
            % (manager.metrics.data["_totals"]["loc"])
        )

        bits.append(
            "\tTotal lines skipped (#nosec): %i"
            % (manager.metrics.data["_totals"]["nosec"])
        )

        bits.append(get_metrics(manager))
        skipped = manager.get_skipped()
        bits.append(header("Files skipped (%i):", len(skipped)))
        bits.extend(["\t%s (%s)" % skip for skip in skipped])
        do_print(bits)

    if fileobj.name != sys.stdout.name:
        LOG.info(
            "Screen formatter output was not written to file: %s, "
            "consider '-f txt'",
            fileobj.name,
        )

    if IS_WIN_PLATFORM and COLORAMA:
        colorama.deinit()
