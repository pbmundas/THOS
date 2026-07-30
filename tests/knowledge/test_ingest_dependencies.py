import ast
from pathlib import Path


def test_knowledge_ingestion_does_not_import_runtime_hunt_clients():
    source = Path("services/knowledge/ingest_knowledge_base.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")

    assert "services.hunting.hearth" not in imported
