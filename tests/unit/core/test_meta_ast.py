# Copyright (c) 2015 VMware, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import six
import testtools

from bandit.core import meta_ast


class BanditMetaAstTests(testtools.TestCase):

    def setUp(self):
        super(BanditMetaAstTests, self).setUp()
        self.b_meta_ast = meta_ast.BanditMetaAst()
        self.node = 'fake_node'
        self.parent_id = 'fake_parent_id'
        self.depth = 1
        self.b_meta_ast.add_node(self.node, self.parent_id, self.depth)
        self.node_id = hex(id(self.node))

    def test_add_node(self):
        expected = {'raw': self.node,
                    'parent_id': self.parent_id,
                    'depth': self.depth}
        self.assertEqual(expected, self.b_meta_ast.nodes[self.node_id])

    def test_str(self):
        node = self.b_meta_ast.nodes[self.node_id]
        expected = 'Node: %s\n\t%s\nLength: 1\n' % (self.node_id, node)
        self.assertEqual(expected, six.text_type(self.b_meta_ast))
