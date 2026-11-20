"""Keep native support fixtures on the maintained conformance distribution."""

import ast
from pathlib import Path


def test_native_support_uses_the_active_conformance_namespace():
    support = Path(__file__).parent / "support"
    assert list(support.glob("*.py"))
    for source in support.glob("*.py"):
        for node in ast.walk(ast.parse(source.read_text("utf-8"))):
            modules = (
                [node.module]
                if isinstance(node, ast.ImportFrom)
                else [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else []
            )
            for module in modules:
                assert not (module or "").startswith(
                    "tba_testkit_workload_credential_conformance"
                ), source
