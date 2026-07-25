from services.agents.registry import AGENT_SPECS, graph_agent_nodes
from services.validation.agent_harness import run_contract_checks


def test_every_registered_agent_has_a_runtime_and_test_contract():
    result = run_contract_checks()

    assert result["status"] == "passed", result["failures"]
    assert result["agents"] == len(AGENT_SPECS)


def test_registry_ids_and_graph_nodes_are_unique():
    ids = [agent.id for agent in AGENT_SPECS]
    nodes = [agent.graph_node for agent in AGENT_SPECS if agent.graph_node]

    assert len(ids) == len(set(ids))
    assert len(nodes) == len(set(nodes))
    assert graph_agent_nodes() == set(nodes)
