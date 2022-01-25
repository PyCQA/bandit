# Copyright (c) 2015 VMware, Inc.
#
# SPDX-License-Identifier: Apache-2.0
import testtools

from bandit.core import meta_ast


class BanditMetaAstTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.b_meta_ast = meta_ast.BanditMetaAst()
        self.node = "fake_node"
        self.parent_id = "fake_parent_id"
        self.depth = 1
        self.b_meta_ast.add_node(self.node, self.parent_id, self.depth)
        self.node_id = hex(id(self.node))

    def test_add_node(self):
        expected = {
            "raw": self.node,
            "parent_id": self.parent_id,
            "depth": self.depth,
        }
        self.assertEqual(expected, self.b_meta_ast.nodes[self.node_id])

    def test_str(self):
        node = self.b_meta_ast.nodes[self.node_id]
        expected = f"Node: {self.node_id}\n\t{node}\nLength: 1\n"
        self.assertEqual(expected, str(self.b_meta_ast))
