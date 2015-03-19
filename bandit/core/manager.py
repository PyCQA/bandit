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
import logging
import os
import sys

import config as b_config
import meta_ast as b_meta_ast
import node_visitor as b_node_visitor
import result_store as b_result_store
import test_set as b_test_set


class BanditManager():

    scope = []

    def __init__(self, config_file, agg_type, debug=False, profile_name=None):
        '''Get logger, config, AST handler, and result store ready

        :param config_file: A file to read config from
        :param debug: Whether to show debug messsages or not
        :param profile_name: Optional name of profile to use (from cmd line)
        :return:
        '''
        self.debug = debug
        self.logger = self._init_logger(debug)
        self.b_conf = b_config.BanditConfig(self.logger, config_file)
        self.files_list = []
        self.excluded_files = []

        # if the log format string was set in the options, reinitialize
        if self.b_conf.get_option('log_format'):
            # have to clear old handler
            self.logger.handlers = []
            log_format = self.b_conf.get_option('log_format')
            self.logger = self._init_logger(debug, log_format=log_format)

        self.b_ma = b_meta_ast.BanditMetaAst(self.logger)
        self.b_rs = b_result_store.BanditResultStore(self.logger, self.b_conf,
                                                     agg_type)

        # if the profile name was specified, try to find it in the config
        if profile_name:
            if profile_name in self.b_conf.config['profiles']:
                profile = self.b_conf.config['profiles'][profile_name]
                self.logger.debug(
                    "read in profile '%s': %s",
                    profile_name, profile
                )
            else:
                self.logger.error(
                    'unable to find profile (%s) in config file: '
                    '%s' % (profile_name, config_file)
                )
                sys.exit(2)
        else:
            profile = None

        self.b_ts = b_test_set.BanditTestSet(self.logger, config=self.b_conf,
                                             profile=profile)

        # set the increment of after how many files to show progress
        self.progress = self.b_conf.get_setting('progress')
        self.scores = []

    @property
    def get_logger(self):
        return self.logger

    @property
    def get_resultstore(self):
        return self.b_rs

    @property
    def results_count(self):
        '''Return the count of results

        :return: Number of results in the set
        '''
        return self.b_rs.count

    def output_results(self, lines, level, output_filename, output_format):
        '''Outputs results from the result store

        :param lines: How many surrounding lines to show per result
        :param level: Which levels to show (info, warning, error)
        :param output_filename: File to store results
        :param output_format: output format, either 'json' or 'txt'
        :return: -
        '''

        self.b_rs.report(
            self.files_list, self.scores,
            excluded_files=self.excluded_files, lines=lines,
            level=level, output_filename=output_filename,
            output_format=output_format
        )

    def output_metaast(self):
        '''Outputs all the nodes from the Meta AST.'''
        self.b_ma.report()

    def discover_files(self, targets, recursive=False):
        '''Add tests directly and from a directory to the test set

        :param scope: The command line list of files and directories
        :param recursive: True/False - whether to add all files from dirs
        :return:
        '''
        # We'll mantain a list of files which are added, and ones which have
        # been explicitly excluded
        files_list = set()
        excluded_files = set()

        excluded_path_strings = self.b_conf.get_option('exclude_dirs') or []
        included_globs = self.b_conf.get_option('include') or '*.py'

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
                    self.logger.warn("Skipping directory (%s), use -r flag to "
                                     "scan contents" % fname)

            else:
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

        for count, fname in enumerate(self.files_list):
            self.logger.debug("working on file : %s" % fname)

            if len(self.files_list) > self.progress:
                # is it time to update the progress indicator?
                if count % self.progress == 0:
                    sys.stdout.write("%s.. " % count)
                    sys.stdout.flush()
            try:
                with open(fname, 'rU') as fdata:
                    try:
                        # parse the current file
                        score = self._execute_ast_visitor(
                            fname, fdata, self.b_ma,
                            self.b_rs, self.b_ts
                        )
                        self.scores.append(score)
                    except KeyboardInterrupt as e:
                        sys.exit(2)
            except IOError as e:
                self.b_rs.skip(fname, e.strerror)

        if len(self.files_list) > self.progress:
            sys.stdout.write("]\n")
            sys.stdout.flush()

    def _execute_ast_visitor(self, fname, fdata, b_ma, b_rs, b_ts):
        '''Execute AST parse on each file

        :param fname: The name of the file being parsed
        :param fdata: The file data of the file being parsed
        :param b_ma: The class Meta AST instance
        :param b_rs: The class result store instance
        :param b_ts: The class test set instance
        :return: The accumulated test score
        '''
        score = []
        if fdata is not None:
            res = b_node_visitor.BanditNodeVisitor(
                fname, self.logger, self.b_conf, b_ma, b_rs, b_ts, self.debug
            )
            try:
                score = res.process(fdata)
            except SyntaxError:
                b_rs.skip(fname, "syntax error while parsing AST from file")
        return score

    def _init_logger(self, debug=False, log_format=None):
        '''Initialize the logger

        :param debug: Whether to enable debug mode
        :return: An instantiated logging instance
        '''
        log_level = logging.INFO
        if debug:
            log_level = logging.DEBUG

        if not log_format:
            # default log format
            log_format_string = '[%(module)s]\t%(levelname)s\t%(message)s'
        else:
            log_format_string = log_format

        logger = logging.getLogger()
        logger.setLevel(log_level)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(log_format_string))
        logger.addHandler(handler)
        logger.debug("logging initialized")
        return logger


def _get_files_from_dir(files_dir, included_globs='*.py',
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
    :param do_enforce_extensions: Can set to false to bypass extension check
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
