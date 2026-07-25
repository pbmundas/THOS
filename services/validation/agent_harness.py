"""Dependency-free contract checks for every registered THOS agent.

Usage:
    python -m services.validation.agent_harness
    python -m services.validation.agent_harness --json
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import asdict
import json
from pathlib import Path

from services.agents.registry import AGENT_SPECS, graph_agent_nodes


REPO_ROOT = Path(__file__).resolve().parents[2]


def _module_path(module: str) -> Path:
    return REPO_ROOT.joinpath(*module.split(".")).with_suffix(".py")


def _defined_callables(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _graph_nodes() -> set[str]:
    path = REPO_ROOT / "services" / "orchestration" / "graph.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    nodes = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_node"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            nodes.add(node.args[0].value)
    return nodes


def run_contract_checks() -> dict:
    checks: list[dict] = []
    tests_packaged = (REPO_ROOT / "tests").is_dir()
    ids = [agent.id for agent in AGENT_SPECS]
    checks.append({
        "name": "unique_agent_ids",
        "passed": len(ids) == len(set(ids)),
        "detail": f"{len(ids)} registered agent(s)",
    })

    for agent in AGENT_SPECS:
        module_path = _module_path(agent.module)
        module_exists = module_path.is_file()
        callables = _defined_callables(module_path) if module_exists else set()
        checks.append({
            "name": f"{agent.id}.runtime_contract",
            "passed": module_exists and agent.callable in callables,
            "detail": f"{agent.module}.{agent.callable}",
        })
        test_path = REPO_ROOT / agent.test_file
        valid_test_mapping = (
            test_path.is_file()
            if tests_packaged
            else agent.test_file.startswith("tests/") and agent.test_file.endswith(".py")
        )
        checks.append({
            "name": f"{agent.id}.test_mapping",
            "passed": valid_test_mapping,
            "detail": (
                agent.test_file
                if tests_packaged
                else f"{agent.test_file} (declared; source tests are not packaged in the production image)"
            ),
        })

    actual_nodes = _graph_nodes()
    expected_nodes = graph_agent_nodes()
    checks.append({
        "name": "langgraph_registry_parity",
        "passed": actual_nodes == expected_nodes,
        "detail": {
            "missing_from_graph": sorted(expected_nodes - actual_nodes),
            "unregistered_graph_nodes": sorted(actual_nodes - expected_nodes),
        },
    })
    failures = [check for check in checks if not check["passed"]]
    return {
        "status": "passed" if not failures else "failed",
        "agents": len(AGENT_SPECS),
        "checks": len(checks),
        "test_files_packaged": tests_packaged,
        "failures": failures,
        "registry": [asdict(agent) for agent in AGENT_SPECS],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate all registered THOS agent contracts")
    parser.add_argument("--json", action="store_true", help="Print machine-readable output")
    args = parser.parse_args()
    result = run_contract_checks()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"THOS agent contracts: {result['status']} "
              f"({result['agents']} agents, {result['checks']} checks)")
        for failure in result["failures"]:
            print(f"FAIL {failure['name']}: {failure['detail']}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
