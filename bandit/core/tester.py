#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import copy
import logging
import warnings

from bandit.core import constants
from bandit.core import context as b_context
from bandit.core import utils

warnings.formatwarning = utils.warnings_formatter
LOG = logging.getLogger(__name__)


class BanditTester:
    def __init__(self, testset, debug, nosec_lines):
        self.results = []
        self.testset = testset
        self.last_result = None
        self.debug = debug
        self.nosec_lines = nosec_lines

    def run_tests(self, raw_context, checktype):
        """Runs all tests for a certain type of check, for example

        Runs all tests for a certain type of check, for example 'functions'
        store results in results.

        :param raw_context: Raw context dictionary
        :param checktype: The type of checks to run
        :return: a score based on the number and type of test results with
                extra metrics about nosec comments
        """

        scores = {
            "SEVERITY": [0] * len(constants.RANKING),
            "CONFIDENCE": [0] * len(constants.RANKING),
            "nosecs_by_tests": 0,
            "failed_nosecs_by_test": 0,
        }

        tests = self.testset.get_tests(checktype)
        for test in tests:
            name = test.__name__
            # execute test with the an instance of the context class
            temp_context = copy.copy(raw_context)
            context = b_context.Context(temp_context)
            try:
                if hasattr(test, "_config"):
                    result = test(context, test._config)
                else:
                    result = test(context)

                if result is not None:
                    nosec_tests_to_skip = set()
                    base_tests = self.nosec_lines.get(result.lineno, None)
                    context_tests = self.nosec_lines.get(
                        temp_context["lineno"], None
                    )

                    # if both are non there are were no comments
                    # this is explicitly different than being empty
                    # empty set indicates blanket nosec comment without
                    # individual test names or ids
                    if base_tests is None and context_tests is None:
                        nosec_tests_to_skip = None

                    # combine tests from current line and context line
                    if base_tests is not None:
                        nosec_tests_to_skip.update(base_tests)
                    if context_tests is not None:
                        nosec_tests_to_skip.update(context_tests)

                    if isinstance(temp_context["filename"], bytes):
                        result.fname = temp_context["filename"].decode("utf-8")
                    else:
                        result.fname = temp_context["filename"]

                    if result.lineno is None:
                        result.lineno = temp_context["lineno"]
                    result.linerange = temp_context["linerange"]
                    result.col_offset = temp_context["col_offset"]
                    result.test = name
                    if result.test_id == "":
                        result.test_id = test._test_id

                    # don't skip a the test if there was no nosec comment
                    if nosec_tests_to_skip is not None:
                        # if the set is empty or the test id is in the set of
                        # tests to skip, log and increment the skip by test
                        # count
                        if not nosec_tests_to_skip or (
                            result.test_id in nosec_tests_to_skip
                        ):
                            LOG.debug(
                                "skipped, nosec for test %s" % result.test_id
                            )
                            scores["nosecs_by_tests"] += 1
                            continue
                        # otherwise this test was not called out explicitly by
                        # a nosec BXX type comment and should fail. Log and
                        # increment the failed test count
                        else:
                            LOG.debug(
                                "uncaught test %s in nosec comment"
                                % result.test_id
                            )
                            scores["failed_nosecs_by_test"] += 1

                    self.results.append(result)

                    LOG.debug("Issue identified by %s: %s", name, result)
                    sev = constants.RANKING.index(result.severity)
                    val = constants.RANKING_VALUES[result.severity]
                    scores["SEVERITY"][sev] += val
                    con = constants.RANKING.index(result.confidence)
                    val = constants.RANKING_VALUES[result.confidence]
                    scores["CONFIDENCE"][con] += val

            except Exception as e:
                self.report_error(name, context, e)
                if self.debug:
                    raise
        LOG.debug("Returning scores: %s", scores)
        return scores

    @staticmethod
    def report_error(test, context, error):
        what = "Bandit internal error running: "
        what += "%s " % test
        what += "on file %s at line %i: " % (
            context._context["filename"],
            context._context["lineno"],
        )
        what += str(error)
        import traceback

        what += traceback.format_exc()
        LOG.error(what)
