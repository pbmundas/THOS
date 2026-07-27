from services.agents.registry import AGENT_SPECS
from services.knowledge.product_knowledge import (
    all_product_topics,
    is_product_question,
    product_context,
    REQUIRED_USER_TOPIC_IDS,
    search_product_knowledge,
)


def test_core_user_questions_retrieve_the_expected_product_topics():
    cases = {
        "How do I test every agent?": "PK-TESTING",
        "Which SIEM and evidence files are supported?": "PK-SOURCES",
        "Can Ask THOS promote a Sigma detection automatically?": "PK-DETECTIONS",
        "How are analyst review, cases, and citations governed?": "PK-GOVERNANCE",
        "Does uploading a runbook retrain the model?": "PK-KNOWLEDGE",
        "How does the forensic evidence chain of custody work?": "PK-FORENSICS",
    }

    for question, expected in cases.items():
        ids = {item["id"] for item in search_product_knowledge(question)}
        assert expected in ids, (question, ids)


def test_every_agent_is_represented_in_product_knowledge():
    topic_ids = {topic.id for topic in all_product_topics()}

    for agent in AGENT_SPECS:
        expected = f"PK-AGENT-{agent.id.upper().replace('_', '-')}"
        assert expected in topic_ids


def test_required_user_product_domains_cannot_be_removed_silently():
    topic_ids = {topic.id for topic in all_product_topics()}

    assert REQUIRED_USER_TOPIC_IDS <= topic_ids


def test_product_context_is_citation_ready_and_bounded():
    context, sources = product_context("Explain Ask THOS knowledge and limits", max_chars=2_000)

    assert len(context) <= 2_000
    assert "[PK-ASK]" in context
    assert any(source["id"] == "PK-ASK" for source in sources)


def test_non_product_investigation_does_not_waste_prompt_budget():
    assert is_product_question("Analyze whether 203.0.113.8 is malicious") is False
    assert product_context("Analyze whether 203.0.113.8 is malicious") == ("", [])
