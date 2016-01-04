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
import operator

from bandit.core import constants
from bandit.core import tester as b_tester
from bandit.core import utils as b_utils
from bandit.core.utils import InvalidModulePath


logger = logging.getLogger(__name__)


class BanditNodeVisitor(object):
    def __init__(self, fname, config, metaast, testset,
                 debug, nosec_lines, metrics):
        self.debug = debug
        self.nosec_lines = nosec_lines
        self.seen = 0
        self.scores = {
            'SEVERITY': [0] * len(constants.RANKING),
            'CONFIDENCE': [0] * len(constants.RANKING)
        }
        self.depth = 0
        self.fname = fname
        self.config = config
        self.metaast = metaast
        self.testset = testset
        self.imports = set()
        self.import_aliases = {}
        self.tester = b_tester.BanditTester(
            self.config, self.testset, self.debug, nosec_lines,
        )

        # in some cases we can't determine a qualified name
        try:
            self.namespace = b_utils.get_module_qualname_from_path(fname)
        except InvalidModulePath:
            logger.info('Unable to find qualified name for module: %s',
                        self.fname)
            self.namespace = ""
        logger.debug('Module qualified name: %s', self.namespace)
        self.metrics = metrics

    def visit_ClassDef(self, node):
        '''Visitor for AST ClassDef node

        Add class name to current namespace for all descendants.
        :param node: Node being inspected
        :return: -
        '''
        # For all child nodes, add this class name to current namespace
        self.namespace = b_utils.namespace_path_join(self.namespace, node.name)

    def visit_FunctionDef(self, node):
        '''Visitor for AST FunctionDef nodes

        add relevant information about the node to
        the context for use in tests which inspect function definitions.
        Add the function name to the current namespace for all descendants.
        :param node: The node that is being inspected
        :return: -
        '''

        self.context['function'] = node
        qualname = self.namespace + '.' + b_utils.get_func_name(node)
        name = qualname.split('.')[-1]

        self.context['qualname'] = qualname
        self.context['name'] = name

        # For all child nodes and any tests run, add this function name to
        # current namespace
        self.namespace = b_utils.namespace_path_join(self.namespace, name)
        self.update_scores(self.tester.run_tests(self.context, 'FunctionDef'))

    def visit_Call(self, node):
        '''Visitor for AST Call nodes

        add relevant information about the node to
        the context for use in tests which inspect function calls.
        :param node: The node that is being inspected
        :return: -
        '''

        self.context['call'] = node
        qualname = b_utils.get_call_name(node, self.import_aliases)
        name = qualname.split('.')[-1]

        self.context['qualname'] = qualname
        self.context['name'] = name

        self.update_scores(self.tester.run_tests(self.context, 'Call'))

    def visit_Import(self, node):
        '''Visitor for AST Import nodes

        add relevant information about node to
        the context for use in tests which inspect imports.
        :param node: The node that is being inspected
        :return: -
        '''
        for nodename in node.names:
            if nodename.asname:
                self.import_aliases[nodename.asname] = nodename.name
            self.imports.add(nodename.name)
            self.context['module'] = nodename.name
        self.update_scores(self.tester.run_tests(self.context, 'Import'))

    def visit_ImportFrom(self, node):
        '''Visitor for AST ImportFrom nodes

        add relevant information about node to
        the context for use in tests which inspect imports.
        :param node: The node that is being inspected
        :return: -
        '''
        module = node.module
        if module is None:
            return self.visit_Import(node)

        for nodename in node.names:
            # TODO(ljfisher) Names in import_aliases could be overridden
            #      by local definitions. If this occurs bandit will see the
            #      name in import_aliases instead of the local definition.
            #      We need better tracking of names.
            if nodename.asname:
                self.import_aliases[nodename.asname] = (
                    module + "." + nodename.name
                )
            else:
                # Even if import is not aliased we need an entry that maps
                # name to module.name.  For example, with 'from a import b'
                # b should be aliased to the qualified name a.b
                self.import_aliases[nodename.name] = (module + '.' +
                                                      nodename.name)
            self.imports.add(module + "." + nodename.name)
            self.context['module'] = module
            self.context['name'] = nodename.name
        self.update_scores(self.tester.run_tests(self.context, 'ImportFrom'))

    def visit_Str(self, node):
        '''Visitor for AST String nodes

        add relevant information about node to
        the context for use in tests which inspect strings.
        :param node: The node that is being inspected
        :return: -
        '''
        self.context['str'] = node.s
        if not isinstance(node.parent, ast.Expr):  # docstring
            self.context['linerange'] = b_utils.linerange_fix(node.parent)
            self.update_scores(self.tester.run_tests(self.context, 'Str'))

    def visit_Bytes(self, node):
        '''Visitor for AST Bytes nodes

        add relevant information about node to
        the context for use in tests which inspect strings.
        :param node: The node that is being inspected
        :return: -
        '''
        self.context['bytes'] = node.s
        if not isinstance(node.parent, ast.Expr):  # docstring
            self.context['linerange'] = b_utils.linerange_fix(node.parent)
            self.update_scores(self.tester.run_tests(self.context, 'Bytes'))

    def pre_visit(self, node):
        self.context = {}
        self.context['imports'] = self.imports
        self.context['import_aliases'] = self.import_aliases

        if self.debug:
            logger.debug(ast.dump(node))
            self.metaast.add_node(node, '', self.depth)

        if hasattr(node, 'lineno'):
            self.context['lineno'] = node.lineno

            if node.lineno in self.nosec_lines:
                logger.debug("skipped, nosec")
                self.metrics.note_nosec()
                return False

        self.context['node'] = node
        self.context['linerange'] = b_utils.linerange_fix(node)
        self.context['filename'] = self.fname

        self.seen += 1
        logger.debug("entering: %s %s [%s]", hex(id(node)), type(node),
                     self.depth)
        self.depth += 1
        logger.debug(self.context)
        return True

    def visit(self, node):
        name = node.__class__.__name__
        method = 'visit_' + name
        visitor = getattr(self, method, None)
        if visitor is not None:
            if self.debug:
                logger.debug("%s called (%s)", method, ast.dump(node))
            visitor(node)
        else:
            self.update_scores(self.tester.run_tests(self.context, name))

    def post_visit(self, node):
        self.depth -= 1
        logger.debug("%s\texiting : %s", self.depth, hex(id(node)))

        # HACK(tkelsey): this is needed to clean up post-recursion stuff that
        # gets setup in the visit methods for these node types.
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.ClassDef):
            self.namespace = b_utils.namespace_path_split(self.namespace)[0]

    def generic_visit(self, node):
        """Drive the visitor."""
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                max_idx = len(value) - 1
                for idx, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        if idx < max_idx:
                            setattr(item, 'sibling', value[idx + 1])
                        else:
                            setattr(item, 'sibling', None)
                        setattr(item, 'parent', node)

                        if self.pre_visit(item):
                            self.visit(item)
                            self.generic_visit(item)
                            self.post_visit(item)

            elif isinstance(value, ast.AST):
                setattr(value, 'sibling', None)
                setattr(value, 'parent', node)

                if self.pre_visit(value):
                    self.visit(value)
                    self.generic_visit(value)
                    self.post_visit(value)

    def update_scores(self, scores):
        '''Score updater

        Since we moved from a single score value to a map of scores per
        severity, this is needed to update the stored list.
        :param score: The score list to update our scores with
        '''
        # we'll end up with something like:
        # SEVERITY: {0, 0, 0, 10}  where 10 is weighted by finding and level
        for score_type in self.scores:
            self.scores[score_type] = list(map(
                operator.add, self.scores[score_type], scores[score_type]
            ))

    def process(self, data):
        '''Main process loop

        Build and process the AST
        :param lines: lines code to process
        :return score: the aggregated score for the current file
        '''
        f_ast = ast.parse(data)
        self.generic_visit(f_ast)
        return self.scores
