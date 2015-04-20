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

import os
import ast

import unittest
from bandit.core import node_visitor


class StatementBufferTests(unittest.TestCase):

    def setUp(self):
        super(StatementBufferTests, self).setUp()
        self.test_file = open("./examples/jinja2_templating.py")
        self.buf = node_visitor.StatementBuffer()
        self.buf.load_buffer(self.test_file)

    def tearDown(self):
        pass

    def test_load_buffer(self):
        # Check buffer contains 10 statements
        self.assertEqual(10, len(self.buf._buffer))

    def test_get_next(self):
        # Check get_next returns an AST statement
        stmt = self.buf.get_next()
        self.assertTrue(isinstance(stmt['node'], ast.AST))
        # Check get_next returned the first statement
        self.assertEqual(1, stmt['linerange'][0])
        # Check buffer has been reduced by one
        self.assertEqual(9, len(self.buf._buffer))

    def test_get_next_count(self):
        # Check get_next returns exactly 10 statements
        count = 0
        stmt = self.buf.get_next()
        while stmt is not None:
            count = count + 1
            stmt = self.buf.get_next()

        self.assertEqual(10, count)

    def test_get_next_empty(self):
        # Check get_next on an empty buffer returns None
        # self.test_file has already been read, so is empty file handle
        self.buf.load_buffer(self.test_file)
        stmt = self.buf.get_next()
        self.assertEqual(None, stmt)

    def test_linenumber_range(self):
        # Check linenumber_range returns corrent number of lines
        count = 9
        while count > 0:
            stmt = self.buf.get_next()
            count = count - 1

        # line 9 should be three lines long
        self.assertEqual(3, len(stmt['linerange']))

        # the range should be the correct line numbers
        self.assertEqual([11, 12, 13], stmt['linerange'])
