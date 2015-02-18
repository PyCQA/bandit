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

import ast
import logging
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

    def output_results(self, lines, level, output_filename):
        '''Outputs results from the result store

        :param lines: How many surrounding lines to show per result
        :param level: Which levels to show (info, warning, error)
        :param output_filename: File to store results
        :return: -
        '''
        self.b_rs.report(
            scope=self.scope, scores=self.scores, lines=lines,
            level=level, output_filename=output_filename
        )

    def output_metaast(self):
        '''Outputs all the nodes from the Meta AST.'''
        self.b_ma.report()

    def run_scope(self, scope):
        '''Runs through all files in the scope

        :param scope: A set of all files to inspect
        :return: -
        '''
        self.scope = scope

        # display progress, if number of files warrants it
        if len(scope) > self.progress:
            sys.stdout.write("%s [" % len(scope))

        for i, fname in enumerate(scope):
            self.logger.debug("working on file : %s" % fname)

            if len(scope) > self.progress:
                # is it time to update the progress indicator?
                if i % self.progress == 0:
                    sys.stdout.write("%s.. " % i)
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

        if len(scope) > self.progress:
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
        score = 0
        if fdata is not None:
            res = b_node_visitor.BanditNodeVisitor(
                fname, self.logger, self.b_conf, b_ma, b_rs, b_ts, self.debug
            )
            try:
                score = res.visit(ast.parse("".join(fdata.readlines())))
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
