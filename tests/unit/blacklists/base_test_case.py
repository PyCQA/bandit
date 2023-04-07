# SPDX-License-Identifier: Apache-2.0
import testtools

from bandit.core import config
from bandit.core import manager
from bandit.core import meta_ast
from bandit.core import metrics
from bandit.core import node_visitor
from bandit.core import test_set


class BaseTestCase(testtools.TestCase):
    def setUp(self, test_ids):
        super().setUp()
        self.b_config = config.BanditConfig()
        self.b_manager = manager.BanditManager(self.b_config, "file")
        issue_metrics = metrics.Metrics()
        issue_metrics.begin("test.py")
        self.visitor = node_visitor.BanditNodeVisitor(
            "test.py",
            None,
            metaast=meta_ast.BanditMetaAst(),
            testset=test_set.BanditTestSet(
                self.b_config,
                profile={
                    "include": test_ids,
                    "exclude": [],
                },
            ),
            debug=False,
            nosec_lines={},
            metrics=issue_metrics,
        )
