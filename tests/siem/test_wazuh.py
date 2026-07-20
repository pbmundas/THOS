"""Unit and mocked-HTTP tests for the Wazuh Indexer connector."""
import json

import pytest

from services.siem import wazuh


def _hit(index="wazuh-alerts-4.x-2026.07.20", doc_id="a1", **source):
    return {"_index": index, "_id": doc_id, "_source": source}


def test_build_search_body_owns_scope_and_ignores_model_size_sort():
    supplied = json.dumps({
        "size": 999999,
        "sort": [{"rule.level": "asc"}],
        "query": {"term": {"rule.groups": "purple_team"}},
    })
    body = wazuh._build_search_body(supplied, lookback_minutes=60, limit=25)

    assert body["size"] == 25
    assert body["sort"] == [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]
    assert body["query"]["bool"]["must"] == [
        {"term": {"rule.groups": "purple_team"}}
    ]
    time_range = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert time_range["lte"] == "now"
    assert time_range["gte"].endswith("+00:00")


def test_plain_text_follow_up_uses_safe_simple_query_string():
    clause = wazuh._parse_query_clause("nmap reconnaissance linux-victim")

    assert clause["simple_query_string"]["query"] == \
        "nmap reconnaissance linux-victim"
    assert clause["simple_query_string"]["default_operator"] == "and"
    assert "data.*" not in clause["simple_query_string"]["fields"]


def test_heterogeneous_wildcard_field_is_removed_from_text_search():
    query = json.dumps({
        "query": {
            "simple_query_string": {
                "query": "adversary",
                "fields": ["full_log^3", "data.*"],
            }
        }
    })

    clause = wazuh._parse_query_clause(query)

    assert clause["simple_query_string"]["fields"] == ["full_log^3"]


def test_model_supplied_range_is_rejected_before_indexer_request():
    query = json.dumps({
        "query": {"range": {"@timestamp": {"gte": "adversary"}}}
    })

    with pytest.raises(wazuh.WazuhAPIError, match="THOS owns"):
        wazuh._parse_query_clause(query)


def test_forbidden_script_query_is_rejected():
    query = json.dumps({"query": {"script": {"script": "return true"}}})
    with pytest.raises(wazuh.WazuhAPIError, match="forbidden construct"):
        wazuh._parse_query_clause(query)


def test_cross_index_terms_lookup_is_rejected():
    query = json.dumps({
        "query": {
            "terms": {
                "rule.id": {"index": "other-index", "id": "1", "path": "values"}
            }
        }
    })
    with pytest.raises(wazuh.WazuhAPIError, match="terms lookup"):
        wazuh._parse_query_clause(query)


def test_normalize_wazuh_alert_to_thos_schema():
    hit = _hit(
        **{
            "@timestamp": "2026-07-20T10:00:00.000Z",
            "agent": {"id": "001", "name": "linux-victim", "ip": "10.0.0.10"},
            "rule": {
                "id": "100100",
                "description": "Purple team reconnaissance detected",
                "groups": ["purple_team"],
            },
            "data": {"srcip": "10.0.0.20", "dstip": "10.0.0.10", "srcuser": "kali"},
            "location": "/var/log/suricata/eve.json",
            "full_log": "ET SCAN Possible Nmap User-Agent Observed",
        }
    )
    record = wazuh._normalize_record(hit)

    assert record["timestamp"] == "2026-07-20T10:00:00.000Z"
    assert record["host"] == "linux-victim"
    assert record["user"] == "kali"
    assert record["event"] == "Purple team reconnaissance detected"
    assert record["src_ip"] == "10.0.0.20"
    assert record["dst_ip"] == "10.0.0.10"
    assert record["source_type"] == "wazuh"
    assert "100100" in record["detail"]
    assert record["_raw"] is hit["_source"]


def test_deduplicate_prefers_alert_over_archive_copy():
    common = {
        "@timestamp": "2026-07-20T10:00:00.000Z",
        "agent": {"id": "001", "name": "linux-victim"},
        "location": "/var/log/auth.log",
        "full_log": "purple-lab-rehearsal-marker",
    }
    archive = wazuh._normalize_record(_hit(
        index="wazuh-archives-4.x-2026.07.20", doc_id="r1", **common
    ))
    alert_source = dict(common, rule={"id": "100101", "description": "Purple alert"})
    alert = wazuh._normalize_record(_hit(doc_id="a1", **alert_source))

    records = wazuh._deduplicate([archive, alert])

    assert len(records) == 1
    assert records[0]["event"] == "Purple alert"
    assert records[0]["source_file"].startswith("wazuh-alerts-")


def test_config_requires_all_connection_credentials(monkeypatch):
    monkeypatch.delenv("WAZUH_INDEXER_URL", raising=False)
    monkeypatch.delenv("WAZUH_INDEXER_USERNAME", raising=False)
    monkeypatch.delenv("WAZUH_INDEXER_PASSWORD", raising=False)

    with pytest.raises(wazuh.WazuhConfigError, match="not configured"):
        wazuh._get_config()


def test_fetch_logs_posts_only_to_configured_search_endpoint(monkeypatch):
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200")
    monkeypatch.setenv("WAZUH_INDEXER_USERNAME", "thos_reader")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "secret")
    monkeypatch.setenv("WAZUH_INDEX_SOURCE", "alerts")
    monkeypatch.setenv("WAZUH_VERIFY_SSL", "0")

    captured = {}

    class FakeResponse:
        status_code = 200
        text = ""

        @staticmethod
        def json():
            return {
                "_shards": {"failures": []},
                "hits": {
                    "total": {"value": 1, "relation": "eq"},
                    "hits": [_hit(**{
                        "@timestamp": "2026-07-20T10:00:00Z",
                        "agent": {"name": "linux-victim"},
                        "rule": {"description": "Test alert"},
                    })],
                },
            }

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def post(self, url, **kwargs):
            captured["url"] = url
            captured["request"] = kwargs
            return FakeResponse()

    monkeypatch.setattr(wazuh.httpx, "Client", FakeClient)

    result = wazuh.fetch_logs('{"query":{"match_all":{}}}', limit=25)

    assert captured["url"] == \
        "https://wazuh.indexer:9200/wazuh-alerts-*/_search"
    assert captured["client"]["auth"] == ("thos_reader", "secret")
    assert captured["client"]["verify"] is False
    assert captured["request"]["params"]["ignore_unavailable"] == "true"
    assert result["record_count"] == 1
    assert result["total_hits"] == 1
    assert result["logs"][0]["host"] == "linux-victim"
