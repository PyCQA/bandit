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

import constants
import tester as b_tester
import utils as b_utils
from utils import InvalidModulePath


class StatementBuffer():
    '''Buffer for code statements

    Creates a buffer to store a code file as individual statements
    for AST processing
    '''
    def __init__(self):
        self._buffer = []
        self.skip_lines = []

    def load_buffer(self, fdata):
        '''Buffer initialization

        Read the file as lines, so we can store the length of the file
        so we don't lose multi-line statements at the bottom of the target
        file
        :param fdata: The code to be parsed into the buffer
        '''
        self._buffer = []
        self.skip_lines = []
        lines = fdata.readlines()
        self.file_len = len(lines)

        for lineno in range(self.file_len):
            found = False
            for flag in constants.SKIP_FLAGS:
                if "#" + flag in lines[lineno].replace(" ", "").lower():
                    found = True
            if found:
                self.skip_lines.append(lineno + 1)

        f_ast = ast.parse("".join(lines))
        # We need to expand body blocks within compound statements
        # into our statement buffer so each gets processed in
        # isolation
        tmp_buf = f_ast.body
        while len(tmp_buf):
            # For each statement, if it is one of the special statement
            # types which contain a body, we first update the tmp_buf
            # adding the internal body statements to the beginning of
            # the temporary buffer, then clear the body of the special
            # statement before adding it to the primary buffer
            stmt = tmp_buf.pop(0)
            if (isinstance(stmt, ast.ClassDef)
                    or isinstance(stmt, ast.FunctionDef)
                    or isinstance(stmt, ast.With)
                    or isinstance(stmt, ast.Module)
                    or isinstance(stmt, ast.Interactive)):
                stmt.body.extend(tmp_buf)
                tmp_buf = stmt.body
                stmt.body = []
            elif (isinstance(stmt, ast.For)
                    or isinstance(stmt, ast.While)
                    or isinstance(stmt, ast.If)):
                stmt.body.extend(stmt.orelse)
                stmt.body.extend(tmp_buf)
                tmp_buf = stmt.body
                stmt.body = []
                stmt.orelse = []
            elif (isinstance(stmt, ast.TryExcept)):
                for handler in stmt.handlers:
                    stmt.body.extend(handler.body)
                stmt.body.extend(stmt.orelse)
                stmt.body.extend(tmp_buf)
                tmp_buf = stmt.body
                stmt.body = []
                stmt.orelse = []
                stmt.handlers = []
            elif (isinstance(stmt, ast.TryFinally)):
                stmt.body.extend(stmt.finalbody)
                stmt.body.extend(tmp_buf)
                tmp_buf = stmt.body
                stmt.body = []
                stmt.finalbody = []

            # once we are sure it's either a single statement or that
            # any content in a compound statement body has been removed
            # we can add it to our primary buffer. The compound body
            # must be removed so the ast isn't walked multiple times
            # and isn't included in line-by-line output
            self._buffer.append(stmt)

    def get_next(self):
        '''Statment Retrieval

        Grab the next statement in the buffer for detailed processing
        :return statement: the next statement to be processed, or None
        '''
        if len(self._buffer):
            # Update the context, and shift the next statement off the array
            statement = {}
            statement['node'] = self._buffer.pop(0)
            statement['linerange'] = self.linenumber_range(statement['node'])

            return statement
        return None

    def linenumber_range(self, node):
        '''Get set of line numbers for statement

        Walks the given statement node, and creates a set
        of line numbers covered by the code
        :param node: The statment line numbers are required for
        :return lines: A set of line numbers
        '''
        lines = set()
        for n in ast.walk(node):
            if hasattr(n, 'lineno'):
                lines.add(n.lineno)
        return sorted(lines)

    def get_skip_lines(self):
        return self.skip_lines


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
    context_template = {'node': None, 'filename': None, 'statement': None,
                        'name': None, 'qualname': None, 'module': None,
                        'imports': None, 'import_aliases': None, 'call': None,
                        'function': None, 'lineno': None, 'skip_lines': None}

    def __init__(self, fname, logger, config, metaast, results, testset,
                 debug):
        self.debug = debug
        self.seen = 0
        self.score = [0] * len(constants.SEVERITY)
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

        # in some cases we can't determine a qualified name
        try:
            self.namespace = b_utils.get_module_qualname_from_path(fname)
        except InvalidModulePath:
            self.logger.info('Unable to find qualified name for module: {}'
                             .format(self.fname))
            self.namespace = ""
        self.logger.debug('Module qualified name: {}'.format(self.namespace))
        self.stmt_buffer = StatementBuffer()
        self.statement = {}

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

        self.context['function'] = node

        self.logger.debug("visit_FunctionDef called (%s)" % ast.dump(node))

        qualname = self.namespace + '.' + b_utils.get_func_name(node)
        name = qualname.split('.')[-1]

        self.context['qualname'] = qualname
        self.context['name'] = name

        # For all child nodes and any tests run, add this function name to
        # current namespace
        self.namespace = b_utils.namespace_path_join(self.namespace, name)
        self.update_score(self.tester.run_tests(self.context, 'FunctionDef'))
        super(BanditNodeVisitor, self).generic_visit(node)
        self.namespace = b_utils.namespace_path_split(self.namespace)[0]

    def visit_Call(self, node):
        '''Visitor for AST Call nodes

        add relevant information about the node to
        the context for use in tests which inspect function calls.
        :param node: The node that is being inspected
        :return: -
        '''

        self.context['call'] = node

        self.logger.debug("visit_Call called (%s)" % ast.dump(node))

        qualname = b_utils.get_call_name(node, self.import_aliases)
        name = qualname.split('.')[-1]

        self.context['qualname'] = qualname
        self.context['name'] = name

        self.update_score(self.tester.run_tests(self.context, 'Call'))
        super(BanditNodeVisitor, self).generic_visit(node)

    def visit_Import(self, node):
        '''Visitor for AST Import nodes

        add relevant information about node to
        the context for use in tests which inspect imports.
        :param node: The node that is being inspected
        :return: -
        '''

        self.logger.debug("visit_Import called (%s)" % ast.dump(node))
        for nodename in node.names:
            if nodename.asname:
                self.context['import_aliases'][nodename.asname] = nodename.name
            self.context['imports'].add(nodename.name)
            self.context['module'] = nodename.name
        self.update_score(self.tester.run_tests(self.context, 'Import'))
        super(BanditNodeVisitor, self).generic_visit(node)

    def visit_ImportFrom(self, node):
        '''Visitor for AST Import nodes

        add relevant information about node to
        the context for use in tests which inspect imports.
        :param node: The node that is being inspected
        :return: -
        '''

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
        self.update_score(self.tester.run_tests(self.context, 'ImportFrom'))
        super(BanditNodeVisitor, self).generic_visit(node)

    def visit_Str(self, node):
        '''Visitor for AST String nodes

        add relevant information about node to
        the context for use in tests which inspect strings.
        :param node: The node that is being inspected
        :return: -
        '''
        self.context['str'] = node.s
        self.logger.debug("visit_Str called (%s)" % ast.dump(node))

        # This check is to make sure we aren't running tests against
        # docstrings (any statment that is just a string, nothing else)
        if not isinstance(self.context['statement']['node'], ast.Str):
            self.update_score(self.tester.run_tests(self.context, 'Str'))
            super(BanditNodeVisitor, self).generic_visit(node)

    def visit_Exec(self, node):
        self.context['str'] = 'exec'

        self.logger.debug("visit_Exec called (%s)" % ast.dump(node))
        self.update_score(self.tester.run_tests(self.context, 'Exec'))
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
        self.context['statement'] = self.statement
        self.context['node'] = node
        self.context['filename'] = self.fname
        if hasattr(node, 'lineno'):
            self.context['lineno'] = node.lineno
        self.context['skip_lines'] = self.stmt_buffer.get_skip_lines()

        self.seen += 1
        self.logger.debug("entering: %s %s [%s]" % (
            hex(id(node)), type(node), self.depth)
        )
        self.depth += 1
        super(BanditNodeVisitor, self).visit(node)
        self.depth -= 1
        self.logger.debug("%s\texiting : %s" % (self.depth, hex(id(node))))
        return self.score

    def update_score(self, score):
        '''Score updater

        Since we moved from a single score value to a map of scores per
        severity, this is needed to update the stored list.
        :param score: The score list to update our scores with
        '''
        def add(x, y):
            return x + y
        self.score = map(add, self.score, score)

    def process(self, fdata):
        '''Main process loop

        Iniitalizes the statement buffer, iterates over each statement
        in the buffer testing each AST in turn
        :param fdata: the open filehandle for the code to be processed
        :return score: the aggregated score for the current file
        '''
        self.stmt_buffer.load_buffer(fdata)
        self.statement = self.stmt_buffer.get_next()
        while self.statement is not None:
            self.logger.debug('New statement loaded')
            self.logger.debug('s_node: %s' % ast.dump(self.statement['node']))
            self.logger.debug('s_lineno: %s' % self.statement['linerange'])

            self.visit(self.statement['node'])
            self.statement = self.stmt_buffer.get_next()
        return self.score
