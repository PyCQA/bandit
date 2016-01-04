# -*- coding:utf-8 -*-
#
# Copyright 2015 Red Hat, Inc.
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

import mock
import six
import testtools

from bandit.core import context


class ContextTests(testtools.TestCase):

    def test_context_create(self):
        ref_context = mock.Mock()
        new_context = context.Context(context_object=ref_context)
        self.assertEqual(ref_context, new_context._context)

        new_context = context.Context()
        self.assertIsInstance(new_context._context, dict)

    def test_repr(self):
        ref_object = dict(spam='eggs')
        expected_repr = '<Context {}>'.format(ref_object)
        new_context = context.Context(context_object=ref_object)
        self.assertEqual(expected_repr, repr(new_context))

    @mock.patch('bandit.core.context.Context._get_literal_value')
    def test_call_args(self, get_literal_value):
        get_literal_value.return_value = 'eggs'
        ref_call = mock.Mock()
        ref_call.args = [mock.Mock(attr='spam'), 'eggs']
        ref_context = dict(call=ref_call)
        new_context = context.Context(context_object=ref_context)
        expected_args = ['spam', 'eggs']
        self.assertListEqual(expected_args, new_context.call_args)

    def test_call_args_count(self):
        ref_call = mock.Mock()
        ref_call.args = ['spam', 'eggs']
        ref_context = dict(call=ref_call)
        new_context = context.Context(context_object=ref_context)
        self.assertEqual(len(ref_call.args), new_context.call_args_count)

        ref_context = dict(call={})
        new_context = context.Context(context_object=ref_context)
        self.assertIsNone(new_context.call_args_count)

        new_context = context.Context()
        self.assertIsNone(new_context.call_args_count)

    def test_call_function_name(self):
        expected_string = 'spam'
        ref_context = dict(name=expected_string)
        new_context = context.Context(context_object=ref_context)
        self.assertEqual(expected_string, new_context.call_function_name)

        new_context = context.Context()
        self.assertIsNone(new_context.call_function_name)

    def test_call_function_name_qual(self):
        expected_string = 'spam'
        ref_context = dict(qualname=expected_string)
        new_context = context.Context(context_object=ref_context)
        self.assertEqual(expected_string, new_context.call_function_name_qual)

        new_context = context.Context()
        self.assertIsNone(new_context.call_function_name_qual)

    @mock.patch('bandit.core.context.Context._get_literal_value')
    def test_call_keywords(self, get_literal_value):
        get_literal_value.return_value = 'eggs'
        ref_keyword1 = mock.Mock(arg='arg1', value=mock.Mock(attr='spam'))
        ref_keyword2 = mock.Mock(arg='arg2', value='eggs')
        ref_call = mock.Mock()
        ref_call.keywords = [ref_keyword1, ref_keyword2]
        ref_context = dict(call=ref_call)
        new_context = context.Context(context_object=ref_context)
        expected_dict = dict(arg1='spam', arg2='eggs')
        self.assertDictEqual(expected_dict, new_context.call_keywords)

        ref_context = dict(call=None)
        new_context = context.Context(context_object=ref_context)
        self.assertIsNone(new_context.call_keywords)

        new_context = context.Context()
        self.assertIsNone(new_context.call_keywords)

    def test_node(self):
        expected_node = 'spam'
        ref_context = dict(node=expected_node)
        new_context = context.Context(context_object=ref_context)
        self.assertEqual(expected_node, new_context.node)

        new_context = context.Context()
        self.assertIsNone(new_context.node)

    def test_string_val(self):
        expected_string = 'spam'
        ref_context = dict(str=expected_string)
        new_context = context.Context(context_object=ref_context)
        self.assertEqual(expected_string, new_context.string_val)

        new_context = context.Context()
        self.assertIsNone(new_context.string_val)

    def test_statement(self):
        expected_string = 'spam'
        ref_context = dict(statement=expected_string)
        new_context = context.Context(context_object=ref_context)
        self.assertEqual(expected_string, new_context.statement)

        new_context = context.Context()
        self.assertIsNone(new_context.statement)

    @mock.patch('bandit.core.utils.get_qual_attr')
    def test_function_def_defaults_qual(self, get_qual_attr):
        get_qual_attr.return_value = 'spam'
        ref_node = mock.Mock(args=mock.Mock(defaults=['spam']))
        ref_context = dict(node=ref_node, import_aliases=None)
        new_context = context.Context(context_object=ref_context)
        self.assertListEqual(['spam'], new_context.function_def_defaults_qual)

        ref_node = mock.Mock(args=mock.Mock(defaults=[]))
        ref_context = dict(node=ref_node, import_aliases=None)
        new_context = context.Context(context_object=ref_context)
        self.assertListEqual([], new_context.function_def_defaults_qual)

        new_context = context.Context()
        self.assertListEqual([], new_context.function_def_defaults_qual)

    def test__get_literal_value(self):
        new_context = context.Context()

        value = ast.Num(42)
        expected = value.n
        self.assertEqual(expected, new_context._get_literal_value(value))

        value = ast.Str('spam')
        expected = value.s
        self.assertEqual(expected, new_context._get_literal_value(value))

        value = ast.List([ast.Str('spam'), ast.Num(42)], ast.Load())
        expected = [ast.Str('spam').s, ast.Num(42).n]
        self.assertListEqual(expected, new_context._get_literal_value(value))

        value = ast.Tuple([ast.Str('spam'), ast.Num(42)], ast.Load())
        expected = (ast.Str('spam').s, ast.Num(42).n)
        self.assertTupleEqual(expected, new_context._get_literal_value(value))

        value = ast.Set([ast.Str('spam'), ast.Num(42)])
        expected = set([ast.Str('spam').s, ast.Num(42).n])
        self.assertSetEqual(expected, new_context._get_literal_value(value))

        value = ast.Dict(['spam', 'eggs'], [42, 'foo'])
        expected = dict(spam=42, eggs='foo')
        self.assertDictEqual(expected, new_context._get_literal_value(value))

        value = ast.Ellipsis()
        self.assertIsNone(new_context._get_literal_value(value))

        value = ast.Name('spam', ast.Load())
        expected = value.id
        self.assertEqual(expected, new_context._get_literal_value(value))

        if six.PY3:
            value = ast.NameConstant(True)
            expected = str(value.value)
            self.assertEqual(expected, new_context._get_literal_value(value))

        if six.PY3:
            value = ast.Bytes(b'spam')
            expected = value.s
            self.assertEqual(expected, new_context._get_literal_value(value))

        self.assertIsNone(new_context._get_literal_value(None))

    @mock.patch('bandit.core.context.Context.call_keywords',
                new_callable=mock.PropertyMock)
    def test_check_call_arg_value(self, call_keywords):
        new_context = context.Context()
        call_keywords.return_value = dict(spam='eggs')
        self.assertTrue(new_context.check_call_arg_value('spam', 'eggs'))
        self.assertTrue(new_context.check_call_arg_value('spam',
                                                         ['spam', 'eggs']))
        self.assertFalse(new_context.check_call_arg_value('spam', 'spam'))
        self.assertFalse(new_context.check_call_arg_value('spam'))
        self.assertFalse(new_context.check_call_arg_value('eggs'))

        new_context = context.Context()
        self.assertIsNone(new_context.check_call_arg_value(None))

    @mock.patch('bandit.core.context.Context.node',
                new_callable=mock.PropertyMock)
    def test_get_lineno_for_call_arg(self, node):
        expected_lineno = 42
        keyword1 = mock.Mock(arg='spam',
                             value=mock.Mock(lineno=expected_lineno))
        node.return_value = mock.Mock(keywords=[keyword1])
        new_context = context.Context()
        actual_lineno = new_context.get_lineno_for_call_arg('spam')
        self.assertEqual(expected_lineno, actual_lineno)

        new_context = context.Context()
        missing_lineno = new_context.get_lineno_for_call_arg('eggs')
        self.assertIsNone(missing_lineno)

    def test_get_call_arg_at_position(self):
        expected_arg = 'spam'
        ref_call = mock.Mock()
        ref_call.args = [ast.Str(expected_arg)]
        ref_context = dict(call=ref_call)
        new_context = context.Context(context_object=ref_context)
        self.assertEqual(expected_arg,
                         new_context.get_call_arg_at_position(0))
        self.assertIsNone(new_context.get_call_arg_at_position(1))

        ref_call = mock.Mock()
        ref_call.args = []
        ref_context = dict(call=ref_call)
        new_context = context.Context(context_object=ref_context)
        self.assertIsNone(new_context.get_call_arg_at_position(0))

        new_context = context.Context()
        self.assertIsNone(new_context.get_call_arg_at_position(0))

    def test_is_module_being_imported(self):
        ref_context = dict(module='spam')
        new_context = context.Context(context_object=ref_context)
        self.assertTrue(new_context.is_module_being_imported('spam'))
        self.assertFalse(new_context.is_module_being_imported('eggs'))

        new_context = context.Context()
        self.assertFalse(new_context.is_module_being_imported('spam'))

    def test_is_module_imported_exact(self):
        ref_context = dict(imports=['spam'])
        new_context = context.Context(context_object=ref_context)
        self.assertTrue(new_context.is_module_imported_exact('spam'))
        self.assertFalse(new_context.is_module_imported_exact('eggs'))

        new_context = context.Context()
        self.assertFalse(new_context.is_module_being_imported('spam'))

    def test_is_module_imported_like(self):
        ref_context = dict(imports=[['spam'], ['eggs']])
        new_context = context.Context(context_object=ref_context)
        self.assertTrue(new_context.is_module_imported_like('spam'))
        self.assertFalse(new_context.is_module_imported_like('bacon'))

        new_context = context.Context()
        self.assertFalse(new_context.is_module_imported_like('spam'))
