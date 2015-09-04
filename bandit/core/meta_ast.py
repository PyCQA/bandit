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


from collections import OrderedDict
import logging


logger = logging.getLogger(__name__)


class BanditMetaAst():

    nodes = OrderedDict()

    def add_node(self, node, parent_id, depth):
        '''Add a node to the AST node collection

        :param node: The AST node to add
        :param parent_id: The ID of the node's parent
        :param depth: The depth of the node
        :return: -
        '''
        node_id = hex(id(node))
        logger.debug('adding node : %s [%s]', node_id, depth)
        self.nodes[node_id] = {
            'raw': node, 'parent_id': parent_id, 'depth': depth
        }

    def report(self):
        '''Dumps a listing of all of the nodes

        Dumps (prints) a listing of all of the nodes for debugging purposes
        :return: -
        '''
        tmpstr = ""
        for k, v in self.nodes.items():
            tmpstr += "Node: %s\n" % k
            tmpstr += "\t%s\n" % str(v)
        tmpstr += "Length : %s\n" % len(self.nodes)
        print(tmpstr)
