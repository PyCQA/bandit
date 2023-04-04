import ast
import bandit

@bandit.test_id('B123')
def hardcoded_password_typing(context):
    if context.is_module_imported_like("typing"):
        for node in context.node_visitor.pre_order():
            if isinstance(node, ast.Str):
                if "password" in node.s.lower():
                    return bandit.Issue(
                        severity=bandit.HIGH,
                        confidence=bandit.MEDIUM,
                        text="Hardcoded password string in typing module.",
                        lineno=node.lineno,
                    )
