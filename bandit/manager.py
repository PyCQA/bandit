# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import sys
import logging
import ast
from bandit import config as b_config
from bandit import result_store as b_result_store
from bandit import node_visitor as b_node_visitor
from bandit import test_set as b_test_set
from bandit import meta_ast as b_meta_ast


class BanditManager():

    scope = []
    progress = 50

    def __init__(self, config_file, debug=False, profile_name=None):
        self.logger = self._init_logger(debug)
        self.b_ma = b_meta_ast.BanditMetaAst(self.logger)
        self.b_rs = b_result_store.BanditResultStore(self.logger)
        self.b_conf = b_config.BanditConfig(self.logger, config_file)

        # if the profile name was specified, try to find it in the config
        if profile_name:
            if profile_name in self.b_conf.config['profiles']:
                profile = self.b_conf.config['profiles'][profile_name]
            else:
                self.logger.error('unable to find profile (%s) in config file: '
                                  '%s' % (profile_name, config_file))
                sys.exit(2)
        else:
            profile = None

        self.b_ts = b_test_set.BanditTestSet(self.logger, profile=profile)

    def get_logger(self):
        return self.logger

    def get_resultstore(self):
        return self.b_rs

    def output_results(self, lines, level, output_filename):
        self.b_rs.report(
            scope=self.scope, lines=lines, level=level,
            output_filename=output_filename
        )

    def output_metaast(self):
        self.b_ma.report()

    def run_scope(self, scope):
        if scope:
            self.scope = scope
            if len(scope) > self.progress:
                sys.stdout.write("%s [" % len(scope))
            for i, fname in enumerate(scope):
                self.logger.debug("working on file : %s" % fname)
                if len(scope) > self.progress:
                    if i % self.progress == 0:
                        sys.stdout.write("%s.. " % i)
                        sys.stdout.flush()
                try:
                    with open(fname, 'rU') as fdata:
                        try:
                            self._execute_ast_visitor(
                                fname, fdata, self.b_ma,
                                self.b_rs, self.b_ts
                            )
                        except KeyboardInterrupt as e:
                            sys.exit(2)
                except IOError as e:
                    self.b_rs.skip(fname, e.strerror)
            if len(scope) > self.progress:
                sys.stdout.write("]\n")
                sys.stdout.flush()
        else:
            self.logger.info("no filename/s provided, working from stdin")
            try:
                self._execute_ast_visitor(
                    'STDIN', sys.stdin, self.b_ma, self.b_rs
                )
            except KeyboardInterrupt:
                self.logger.debug("exiting")
                sys.exit(1)

    def _execute_ast_visitor(self, fname, fdata, b_ma, b_rs, b_ts):
        if fdata is not None:
            res = b_node_visitor.BanditNodeVisitor(
                fname, self.logger, b_ma, b_rs, b_ts
            )
            try:
                res.visit(ast.parse("".join(fdata.readlines())))
            except SyntaxError as e:
                b_rs.skip(fname, "syntax error while parsing AST from file")

    def _init_logger(self, debug=False):
        log_level = logging.INFO
        if debug:
            log_level = logging.DEBUG
        log_format = '[%(module)s]\t%(levelname)s\t%(message)s'
        logger = logging.getLogger()
        logger.setLevel(log_level)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(log_format))
        logger.addHandler(handler)
        logger.debug("logging initialized")
        return logger
