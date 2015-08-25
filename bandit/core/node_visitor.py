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
import copy
import logging

from bandit.core import constants
from bandit.core import tester as b_tester
from bandit.core import utils as b_utils
from bandit.core.utils import InvalidModulePath


logger = logging.getLogger(__name__)


class BanditNodeVisitor(object):
    context_template = {'node': None, 'filename': None,
                        'name': None, 'qualname': None, 'module': None,
                        'imports': None, 'import_aliases': None, 'call': None,
                        'function': None, 'lineno': None, 'skip_lines': None}

    def __init__(self, fname, config, metaast, testset,
                 debug):
        self.debug = debug
        self.seen = 0
        self.scores = {
            'SEVERITY': [0] * len(constants.RANKING),
            'CONFIDENCE': [0] * len(constants.RANKING)
        }
        self.metrics = {'loc': 0, 'nosec': 0}
        self.depth = 0
        self.fname = fname
        self.config = config
        self.metaast = metaast
        self.testset = testset
        self.imports = set()
        self.context_template['imports'] = self.imports
        self.import_aliases = {}
        self.context_template['import_aliases'] = self.import_aliases
        self.tester = b_tester.BanditTester(
            self.config, self.testset, self.debug
        )

        # in some cases we can't determine a qualified name
        try:
            self.namespace = b_utils.get_module_qualname_from_path(fname)
        except InvalidModulePath:
            logger.info('Unable to find qualified name for module: %s',
                        self.fname)
            self.namespace = ""
        logger.debug('Module qualified name: %s', self.namespace)
        self.lines = []

    def visit_ClassDef(self, node):
        '''Visitor for AST ClassDef node

        Add class name to current namespace for all descendants.
        :param node: Node being inspected
        :return: -
        '''

        if self.debug:
            logger.debug("visit_ClassDef called (%s)", ast.dump(node))

        # For all child nodes, add this class name to current namespace
        self.namespace = b_utils.namespace_path_join(self.namespace, node.name)
        self.generic_visit(node)
        self.namespace = b_utils.namespace_path_split(self.namespace)[0]

    def visit_FunctionDef(self, node):
        '''Visitor for AST FunctionDef nodes

        add relevant information about the node to
        the context for use in tests which inspect function definitions.
        Add the function name to the current namespace for all descendants.
        :param node: The node that is being inspected
        :return: -
        '''

        self.context['function'] = node

        if self.debug:
            logger.debug("visit_FunctionDef called (%s)", ast.dump(node))

        qualname = self.namespace + '.' + b_utils.get_func_name(node)
        name = qualname.split('.')[-1]

        self.context['qualname'] = qualname
        self.context['name'] = name

        # For all child nodes and any tests run, add this function name to
        # current namespace
        self.namespace = b_utils.namespace_path_join(self.namespace, name)
        self.update_scores(self.tester.run_tests(self.context, 'FunctionDef'))
        self.generic_visit(node)
        self.namespace = b_utils.namespace_path_split(self.namespace)[0]

    def visit_Call(self, node):
        '''Visitor for AST Call nodes

        add relevant information about the node to
        the context for use in tests which inspect function calls.
        :param node: The node that is being inspected
        :return: -
        '''

        self.context['call'] = node

        if self.debug:
            logger.debug("visit_Call called (%s)", ast.dump(node))

        qualname = b_utils.get_call_name(node, self.import_aliases)
        name = qualname.split('.')[-1]

        self.context['qualname'] = qualname
        self.context['name'] = name

        self.update_scores(self.tester.run_tests(self.context, 'Call'))
        self.generic_visit(node)

    def visit_Import(self, node):
        '''Visitor for AST Import nodes

        add relevant information about node to
        the context for use in tests which inspect imports.
        :param node: The node that is being inspected
        :return: -
        '''
        if self.debug:
            logger.debug("visit_Import called (%s)", ast.dump(node))

        for nodename in node.names:
            if nodename.asname:
                self.context['import_aliases'][nodename.asname] = nodename.name
            self.context['imports'].add(nodename.name)
            self.context['module'] = nodename.name
        self.update_scores(self.tester.run_tests(self.context, 'Import'))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        '''Visitor for AST Import nodes

        add relevant information about node to
        the context for use in tests which inspect imports.
        :param node: The node that is being inspected
        :return: -
        '''
        if self.debug:
            logger.debug("visit_ImportFrom called (%s)", ast.dump(node))

        module = node.module
        if module is None:
            return self.visit_Import(node)

        for nodename in node.names:
            # TODO(ljfisher) Names in import_aliases could be overridden
            #      by local definitions. If this occurs bandit will see the
            #      name in import_aliases instead of the local definition.
            #      We need better tracking of names.
            if nodename.asname:
                self.context['import_aliases'][nodename.asname] = (
                    module + "." + nodename.name
                )
            else:
                # Even if import is not aliased we need an entry that maps
                # name to module.name.  For example, with 'from a import b'
                # b should be aliased to the qualified name a.b
                self.context['import_aliases'][nodename.name] = (module + '.' +
                                                                 nodename.name)
            self.context['imports'].add(module + "." + nodename.name)
            self.context['module'] = module
            self.context['name'] = nodename.name
        self.update_scores(self.tester.run_tests(self.context, 'ImportFrom'))
        self.generic_visit(node)

    def visit_Str(self, node):
        '''Visitor for AST String nodes

        add relevant information about node to
        the context for use in tests which inspect strings.
        :param node: The node that is being inspected
        :return: -
        '''
        self.context['str'] = node.s

        if self.debug:
            logger.debug("visit_Str called (%s)", ast.dump(node))

        if not isinstance(node.parent, ast.Expr):  # docstring
            self.context['linerange'] = b_utils.linerange_fix(node.parent)
            self.update_scores(self.tester.run_tests(self.context, 'Str'))
        self.generic_visit(node)

    def visit_Bytes(self, node):
        '''Visitor for AST Bytes nodes

        add relevant information about node to
        the context for use in tests which inspect strings.
        :param node: The node that is being inspected
        :return: -
        '''
        self.context['bytes'] = node.s

        if self.debug:
            logger.debug("visit_Bytes called (%s)", ast.dump(node))

        if not isinstance(node.parent, ast.Expr):  # docstring
            self.context['linerange'] = b_utils.linerange_fix(node.parent)
            self.update_scores(self.tester.run_tests(self.context, 'Bytes'))
        self.generic_visit(node)

    def visit_Exec(self, node):
        self.context['str'] = 'exec'

        if self.debug:
            logger.debug("visit_Exec called (%s)", ast.dump(node))

        self.update_scores(self.tester.run_tests(self.context, 'Exec'))
        self.generic_visit(node)

    def visit_Assert(self, node):
        self.context['str'] = 'assert'

        if self.debug:
            logger.debug("visit_Assert called (%s)", ast.dump(node))

        self.update_scores(self.tester.run_tests(self.context, 'Assert'))
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        if self.debug:
            logger.debug("visit_ExceptHandler called (%s)",
                         ast.dump(node))

        self.update_scores(self.tester.run_tests(self.context,
                                                 'ExceptHandler'))
        self.generic_visit(node)

    def visit(self, node):
        '''Generic visitor

        add the node to the node collection, and log it
        :param node: The node that is being inspected
        :return: -
        '''
        self.context = copy.copy(self.context_template)

        if self.debug:
            logger.debug(ast.dump(node))

        if self.debug:
            self.metaast.add_node(node, '', self.depth)

        if hasattr(node, 'lineno'):
            self.context['lineno'] = node.lineno
            if ("# nosec" in self.lines[node.lineno - 1] or
                    "#nosec" in self.lines[node.lineno - 1]):
                logger.debug("skipped, nosec")
                self.metrics['nosec'] += 1
                return

        self.context['node'] = node
        self.context['linerange'] = b_utils.linerange_fix(node)
        self.context['filename'] = self.fname

        self.seen += 1
        logger.debug("entering: %s %s [%s]", hex(id(node)), type(node),
                     self.depth)
        self.depth += 1

        method = 'visit_' + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        visitor(node)

        self.depth -= 1
        logger.debug("%s\texiting : %s", self.depth, hex(id(node)))

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
                        self.visit(node=item)

            elif isinstance(value, ast.AST):
                setattr(value, 'sibling', None)
                setattr(value, 'parent', node)
                self.visit(node=value)

    def update_scores(self, scores):
        '''Score updater

        Since we moved from a single score value to a map of scores per
        severity, this is needed to update the stored list.
        :param score: The score list to update our scores with
        '''
        def add(x, y):
            return x + y
        for score_type in self.scores:
            self.scores[score_type] = list(map(
                add, self.scores[score_type], scores[score_type]
            ))

    def process(self, fdata):
        '''Main process loop

        Build and process the AST
        :param fdata: the open filehandle for the code to be processed
        :return score: the aggregated score for the current file
        '''
        fdata.seek(0)
        self.lines = fdata.readlines()
        # only include non-blank lines in the loc metric
        self.metrics['loc'] += len(
            [line for line in self.lines if line.strip()]
        )
        f_ast = ast.parse("".join(self.lines))
        self.generic_visit(f_ast)
        return self.scores, self.metrics
