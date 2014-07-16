#!/usr/bin/env python

from collections import OrderedDict

class BanditMetaAst():

    nodes = OrderedDict()

    def __init__(self, logger):
        self.logger = logger

    def add_node(self, node, parent_id, depth):
        node_id = hex(id(node))
        self.logger.debug('adding node : %s [%s]' % (node_id, depth))
        self.nodes[node_id] = {'raw':node, 'parent_id':parent_id, 'depth':depth}

    def report(self):
        tmpstr = ""
        for k,v in self.nodes.items():
            tmpstr += "Node: %s\n" % k
            tmpstr += "\t%s\n" % str(v)
        tmpstr += "Length : %s\n" % len(self.nodes)
        print(tmpstr)

    
