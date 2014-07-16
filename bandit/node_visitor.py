#!/usr/bin/env python

import sys
import ast, _ast
from bandit import tester as b_tester
from bandit import utils as b_utils

class BanditNodeVisitor(ast.NodeVisitor):

    imports = set()
    import_aliases = {}
    callstack = ""
    calldone = False
    callbasenode = None
    logger = None
    results = None
    tester = None
    testset = None
    fname = None
    depth = 0

    def __init__(self, fname, logger, metaast, results, testset):
        self.seen = 0
        self.fname = fname
        self.logger = logger
        self.metaast = metaast
        self.results = results
        self.testset = testset
        self.tester = b_tester.BanditTester(self.logger, self.results, self.testset)

    def _get_Call_name(self, node):
        if type(node.func) == _ast.Name:
            return(b_utils.deepgetattr(node, 'func.id'))
        elif type(node.func) == _ast.Attribute:
            prefix = ""
            if type(node.func.value) == _ast.Name:
                prefix = b_utils.deepgetattr(node, 'func.value.id') + "."
            return("%s%s" % (prefix, b_utils.deepgetattr(node, 'func.attr')))

    def visit_Call(self, node):
        self.tester.test_call(node, name=self.callstack)
        if self.callstack == "":
            self.callbasenode = node
            self.callstack = self._get_Call_name(node)
        #nested calls
        if type(node.func) == _ast.Attribute:
            if type(node.func.value) == _ast.Call:
                self.callstack = ".".join([self._get_Call_name(node.func.value), self.callstack])
            else:
                self.calldone = True
        else:
            self.calldone = True
        #done with nested
        if (self.calldone):
            self.logger.debug("PARSED COMPLETE CALLSTACK: %s" % self.callstack)
            self.logger.debug("\tBASENODE: %s" % ast.dump(self.callbasenode))
            file_detail = (self.fname, node.lineno)
            self.tester.test_call_with_name(file_detail, self.callstack, self.callbasenode, self.imports, self.import_aliases)
            self.callstack = ""
            self.calldone = False
        super(BanditNodeVisitor, self).generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.asname:
                self.import_aliases[alias.asname] = alias.name
            self.imports.add(alias.name)
            file_detail = (self.fname, node.lineno)
            self.tester.test_import_name(file_detail, alias.name)
        super(BanditNodeVisitor, self).generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module
        for alias in node.names:
            if alias.asname:
                self.import_aliases[alias.asname] = module + "." + alias.name
            self.imports.add(module + "." + alias.name)
            file_detail = (self.fname, node.lineno)
            self.tester.test_import_name(file_detail, module + "." + alias.name)

        super(BanditNodeVisitor, self).generic_visit(node)

    def visit(self, node):
        self.seen += 1
        self.logger.debug("entering: %s %s [%s]" % (hex(id(node)), type(node), self.depth))
        self.logger.debug(ast.dump(node))
        self.metaast.add_node(node, '', self.depth)
        self.depth += 1
        super(BanditNodeVisitor, self).visit(node)
        self.depth -= 1
        #run tests for this node - should probably pass more than just the node
        self.testset.run_tests(node)
        self.logger.debug("%s\texiting : %s" % (self.depth, hex(id(node))))

