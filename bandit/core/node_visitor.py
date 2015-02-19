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

import tester as b_tester
import utils as b_utils


class BanditNodeVisitor(ast.NodeVisitor):

    imports = set()
    import_aliases = {}
    logger = None
    results = None
    tester = None
    testset = None
    fname = None
    depth = 0

    context = None
    context_template = {'node': None, 'filename': None, 'lineno': None,
                        'name': None, 'qualname': None, 'module': None,
                        'imports': None, 'import_aliases': None, 'call': None,
                        'function': None}

    def __init__(self, fname, logger, config, metaast, results, testset,
                 debug):
        self.debug = debug
        self.seen = 0
        self.score = 0
        self.fname = fname
        self.logger = logger
        self.config = config
        self.metaast = metaast
        self.results = results
        self.testset = testset
        self.imports = set()
        self.context_template['imports'] = self.imports
        self.import_aliases = {}
        self.context_template['import_aliases'] = self.import_aliases
        self.tester = b_tester.BanditTester(
            self.logger, self.config, self.results, self.testset, self.debug
        )

        self.namespace = b_utils.get_module_qualname_from_path(fname)
        self.logger.debug('Module qualified name: {}'.format(self.namespace))

    def visit_ClassDef(self, node):
        '''Visitor for AST ClassDef node

        Add class name to current namespace for all descendants.
        :param node: Node being inspected
        :return: -
        '''

        # For all child nodes, add this class name to current namespace
        self.namespace = b_utils.namespace_path_join(self.namespace, node.name)
        super(BanditNodeVisitor, self).generic_visit(node)
        self.namespace = b_utils.namespace_path_split(self.namespace)[0]

    def visit_FunctionDef(self, node):
        '''Visitor for AST FunctionDef nodes

        add relevant information about the node to
        the context for use in tests which inspect function definitions.
        Add the function name to the current namespace for all descendants.
        :param node: The node that is being inspected
        :return: -
        '''

        self.context['lineno'] = node.lineno
        self.context['function'] = node

        self.logger.debug("visit_FunctionDef called (%s)" % ast.dump(node))

        qualname = self.namespace + '.' + b_utils.get_func_name(node)
        name = qualname.split('.')[-1]

        self.context['qualname'] = qualname
        self.context['name'] = name

        # For all child nodes and any tests run, add this function name to
        # current namespace
        self.namespace = b_utils.namespace_path_join(self.namespace, name)
        self.score += self.tester.run_tests(self.context, 'FunctionDef')
        super(BanditNodeVisitor, self).generic_visit(node)
        self.namespace = b_utils.namespace_path_split(self.namespace)[0]

    def visit_Call(self, node):
        '''Visitor for AST Call nodes

        add relevant information about the node to
        the context for use in tests which inspect function calls.
        :param node: The node that is being inspected
        :return: -
        '''

        self.context['lineno'] = node.lineno
        self.context['call'] = node

        self.logger.debug("visit_Call called (%s)" % ast.dump(node))

        qualname = b_utils.get_call_name(node, self.import_aliases)
        name = qualname.split('.')[-1]

        self.context['qualname'] = qualname
        self.context['name'] = name

        self.score += self.tester.run_tests(self.context, 'Call')
        super(BanditNodeVisitor, self).generic_visit(node)

    def visit_Import(self, node):
        '''Visitor for AST Import nodes

        add relevant information about node to
        the context for use in tests which inspect imports.
        :param node: The node that is being inspected
        :return: -
        '''

        self.context['lineno'] = node.lineno
        self.logger.debug("visit_Import called (%s)" % ast.dump(node))
        for nodename in node.names:
            if nodename.asname:
                self.context['import_aliases'][nodename.asname] = nodename.name
            self.context['imports'].add(nodename.name)
            self.context['module'] = nodename.name
        self.score += self.tester.run_tests(self.context, 'Import')
        super(BanditNodeVisitor, self).generic_visit(node)

    def visit_ImportFrom(self, node):
        '''Visitor for AST Import nodes

        add relevant information about node to
        the context for use in tests which inspect imports.
        :param node: The node that is being inspected
        :return: -
        '''

        self.context['lineno'] = node.lineno
        self.logger.debug("visit_ImportFrom called (%s)" % ast.dump(node))

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
        self.score += self.tester.run_tests(self.context, 'ImportFrom')
        super(BanditNodeVisitor, self).generic_visit(node)

    def visit_Str(self, node):
        '''Visitor for AST String nodes

        add relevant information about node to
        the context for use in tests which inspect strings.
        :param node: The node that is being inspected
        :return: -
        '''
        self.context['lineno'] = node.lineno
        self.context['str'] = node.s
        self.logger.debug("visit_Str called (%s)" % ast.dump(node))

        self.score += self.tester.run_tests(self.context, 'Str')
        super(BanditNodeVisitor, self).generic_visit(node)

    def visit_Exec(self, node):
        self.context['lineno'] = node.lineno
        self.context['str'] = 'exec'

        self.logger.debug("visit_Exec called (%s)" % ast.dump(node))
        self.score += self.tester.run_tests(self.context, 'Exec')
        super(BanditNodeVisitor, self).generic_visit(node)

    def visit(self, node):
        '''Generic visitor

        add the node to the node collection, and log it
        :param node: The node that is being inspected
        :return: -
        '''
        self.logger.debug(ast.dump(node))
        self.metaast.add_node(node, '', self.depth)

        self.context = copy.copy(self.context_template)
        self.context['node'] = node
        self.context['filename'] = self.fname

        self.seen += 1
        self.logger.debug("entering: %s %s [%s]" % (
            hex(id(node)), type(node), self.depth)
        )
        self.depth += 1
        super(BanditNodeVisitor, self).visit(node)
        self.depth -= 1
        self.logger.debug("%s\texiting : %s" % (self.depth, hex(id(node))))
        return self.score
