# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
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

import fnmatch
import json
import logging
import os
import sys

import six

from collections import Counter

from bandit.core import constants as b_constants
from bandit.core import extension_loader
from bandit.core import issue
from bandit.core import meta_ast as b_meta_ast
from bandit.core import metrics
from bandit.core import node_visitor as b_node_visitor
from bandit.core import test_set as b_test_set


logger = logging.getLogger(__name__)


class BanditManager():

    scope = []

    def __init__(self, config, agg_type, debug=False, verbose=False,
                 profile_name=None, ignore_nosec=False):
        '''Get logger, config, AST handler, and result store ready

        :param config: config options object
        :type config: bandit.core.BanditConfig
        :param agg_type: aggregation type
        :param debug: Whether to show debug messsages or not
        :param verbose: Whether to show verbose output
        :param profile_name: Optional name of profile to use (from cmd line)
        :param ignore_nosec: Whether to ignore #nosec or not
        :return:
        '''
        self.debug = debug
        self.verbose = verbose
        self.ignore_nosec = ignore_nosec
        self.b_conf = config
        self.files_list = []
        self.excluded_files = []
        self.b_ma = b_meta_ast.BanditMetaAst()
        self.skipped = []
        self.results = []
        self.baseline = []
        self.agg_type = agg_type
        self.metrics = metrics.Metrics()

        # if the profile name was specified, try to find it in the config
        if profile_name:
            if profile_name in self.b_conf.config['profiles']:
                profile = self.b_conf.config['profiles'][profile_name]
                logger.debug(
                    "read in profile '%s': %s",
                    profile_name, profile
                )
            else:
                raise RuntimeError('unable to find profile (%s) in config'
                                   'file: %s' % (profile_name,
                                                 self.b_conf.config_file))
        else:
            profile = None

        self.b_ts = b_test_set.BanditTestSet(config=self.b_conf,
                                             profile=profile)

        # set the increment of after how many files to show progress
        self.progress = self.b_conf.get_setting('progress')
        self.scores = []

    def get_issue_list(self):
        if len(self.baseline):
            return self.filter_results()
        return self.results

    @property
    def has_tests(self):
        return self.b_ts.has_tests

    def populate_baseline(self, data):
        '''Populate a baseline set of issues from a JSON report

        This will populate a list of baseline issues discovered from a previous
        run of bandit. Later this baseline can be used to filter out the result
        set, see filter_results.
        '''
        items = []
        try:
            jdata = json.loads(data)
            items = [issue.issue_from_dict(j) for j in jdata["results"]]
        except Exception as e:
            logger.warn("Failed to load baseline data: %s", e)
        self.baseline = items

    def filter_results(self):
        '''Returns a list of results filtered by the baseline

        This works by checking the number of results returned from each file we
        process. If the number of results is different to the number reported
        for the same file in the baseline, then we return all results for the
        file. We can't reliably return just the new results, as line numbers
        will likely have changed.
        '''
        if len(self.baseline) == 0:
            return self.results

        outs = []
        base = Counter([jd.fname for jd in self.baseline])
        vals = Counter([jd.fname for jd in self.results])
        for key, val in six.iteritems(vals):
            if key not in base or val != base[key]:
                outs.extend([r for r in self.results if r.fname == key])
        return outs

    def results_count(self, sev_filter=b_constants.LOW,
                      conf_filter=b_constants.LOW):
        '''Return the count of results

        :param sev_filter: Severity level to filter lower
        :param conf_filter: Confidence level to filter
        :return: Number of results in the set
        '''
        res = self.filter_results()
        return sum(i.filter(sev_filter, conf_filter) for i in res)

    def output_results(self, lines, sev_level, conf_level, output_filename,
                       output_format):
        '''Outputs results from the result store

        :param lines: How many surrounding lines to show per result
        :param sev_level: Which severity levels to show (LOW, MEDIUM, HIGH)
        :param conf_level: Which confidence levels to show (LOW, MEDIUM, HIGH)
        :param output_filename: File to store results
        :param output_format: output format, 'csv', 'json', 'txt', 'xml', or
            'html'
        :return: -
        '''
        try:
            formatters_mgr = extension_loader.MANAGER.formatters_mgr
            try:
                formatter = formatters_mgr[output_format]
            except KeyError:  # Unrecognized format, so use text instead
                formatter = formatters_mgr['txt']
                output_format = 'txt'

            if output_format == 'csv':
                lines = 1
            elif formatter.name == 'txt' and output_filename:
                output_format = 'plain'

            report_func = formatter.plugin
            report_func(self, filename=output_filename,
                        sev_level=sev_level, conf_level=conf_level,
                        lines=lines, out_format=output_format)

        except IOError:
            print("Unable to write to file: %s" % output_filename)

    def discover_files(self, targets, recursive=False, excluded_paths=''):
        '''Add tests directly and from a directory to the test set

        :param targets: The command line list of files and directories
        :param recursive: True/False - whether to add all files from dirs
        :return:
        '''
        # We'll mantain a list of files which are added, and ones which have
        # been explicitly excluded
        files_list = set()
        excluded_files = set()

        excluded_path_strings = self.b_conf.get_option('exclude_dirs') or []
        included_globs = self.b_conf.get_option('include') or ['*.py']

        # if there are command line provided exclusions add them to the list
        if excluded_paths:
            for path in excluded_paths.split(','):
                excluded_path_strings.append(path)

        # build list of files we will analyze
        for fname in targets:
            # if this is a directory and recursive is set, find all files
            if os.path.isdir(fname):
                if recursive:
                    new_files, newly_excluded = _get_files_from_dir(
                        fname,
                        included_globs=included_globs,
                        excluded_path_strings=excluded_path_strings
                    )
                    files_list.update(new_files)
                    excluded_files.update(newly_excluded)
                else:
                    logger.warn("Skipping directory (%s), use -r flag to "
                                "scan contents", fname)

            else:
                # if the user explicitly mentions a file on command line,
                # we'll scan it, regardless of whether it's in the included
                # file types list
                if _is_file_included(fname, included_globs,
                                     excluded_path_strings,
                                     enforce_glob=False):
                    files_list.add(fname)
                else:
                    excluded_files.add(fname)

        self.files_list = sorted(files_list)
        self.excluded_files = sorted(excluded_files)

    def check_output_destination(self, output_filename):
        # case where file already exists
        if os.path.isfile(output_filename):
            return 'File already exists'
        else:
            # case where specified destination is a directory
            if os.path.isdir(output_filename):
                return 'Specified destination is a directory'
            # case where specified destination is not writable
            try:
                open(output_filename, 'w').close()
            except IOError:
                return 'Specified destination is not writable'
        return True

    def run_tests(self):
        '''Runs through all files in the scope

        :return: -
        '''
        # display progress, if number of files warrants it
        if len(self.files_list) > self.progress:
            sys.stdout.write("%s [" % len(self.files_list))

        # if we have problems with a file, we'll remove it from the files_list
        # and add it to the skipped list instead
        new_files_list = list(self.files_list)

        for count, fname in enumerate(self.files_list):
            logger.debug("working on file : %s", fname)

            if len(self.files_list) > self.progress:
                # is it time to update the progress indicator?
                if count % self.progress == 0:
                    sys.stdout.write("%s.. " % count)
                    sys.stdout.flush()
            try:
                with open(fname, 'rU') as fdata:
                    try:
                        # parse the current file
                        lines = fdata.readlines()
                        self.metrics.begin(fname)
                        self.metrics.count_locs(lines)
                        score = self._execute_ast_visitor(fname, lines)
                        self.scores.append(score)
                        self.metrics.count_issues([score, ])
                    except KeyboardInterrupt as e:
                        sys.exit(2)
            except IOError as e:
                self.skipped.append((fname, e.strerror))
                new_files_list.remove(fname)
            except SyntaxError as e:
                self.skipped.append(
                    (fname, "syntax error while parsing AST from file"))
                new_files_list.remove(fname)

        if len(self.files_list) > self.progress:
            sys.stdout.write("]\n")
            sys.stdout.flush()

        # reflect any files which may have been skipped
        self.files_list = new_files_list

        # do final aggregation of metrics
        self.metrics.aggregate()

    def _execute_ast_visitor(self, fname, lines):
        '''Execute AST parse on each file

        :param fname: The name of the file being parsed
        :param lines: The lines of code to process
        :return: The accumulated test score
        '''
        score = []
        res = b_node_visitor.BanditNodeVisitor(fname, self.b_conf, self.b_ma,
                                               self.b_ts, self.debug,
                                               self.ignore_nosec, self.metrics)

        score = res.process(lines)
        self.results.extend(res.tester.results)
        return score


def _get_files_from_dir(files_dir, included_globs=['*.py'],
                        excluded_path_strings=None):
    if not excluded_path_strings:
        excluded_path_strings = []

    files_list = set()
    excluded_files = set()

    for root, subdirs, files in os.walk(files_dir):
        for filename in files:
            path = os.path.join(root, filename)
            if _is_file_included(path, included_globs, excluded_path_strings):
                files_list.add(path)
            else:
                excluded_files.add(path)

    return files_list, excluded_files


def _is_file_included(path, included_globs, excluded_path_strings,
                      enforce_glob=True):
    '''Determine if a file should be included based on filename

    This utility function determines if a file should be included based
    on the file name, a list of parsed extensions, excluded paths, and a flag
    specifying whether extensions should be enforced.

    :param path: Full path of file to check
    :param parsed_extensions: List of parsed extensions
    :param excluded_paths: List of paths from which we should not include files
    :param enforce_glob: Can set to false to bypass extension check
    :return: Boolean indicating whether a file should be included
    '''
    return_value = False

    # if this is matches a glob of files we look at, and it isn't in an
    # excluded path
    if _matches_glob_list(path, included_globs) or not enforce_glob:
        if not any(x in path for x in excluded_path_strings):
            return_value = True

    return return_value


def _matches_glob_list(filename, glob_list):
    for glob in glob_list:
        if fnmatch.fnmatch(filename, glob):
            return True
    return False
