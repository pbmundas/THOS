import json

import pytest

from services.siem import elasticsearch


def _configure(monkeypatch, api_key="encoded-key"):
    monkeypatch.setenv("ELASTICSEARCH_URL", "https://elastic.internal:9200")
    monkeypatch.setenv("ELASTICSEARCH_INDEX_PATTERN", "logs-security-*")
    monkeypatch.setenv("ELASTICSEARCH_API_KEY", api_key)
    monkeypatch.setenv("ELASTICSEARCH_VERIFY_SSL", "0")


def test_config_requires_scoped_index_and_authentication(monkeypatch):
    monkeypatch.setenv("ELASTICSEARCH_URL", "https://elastic.internal:9200")
    monkeypatch.setenv("ELASTICSEARCH_INDEX_PATTERN", "*")
    monkeypatch.delenv("ELASTICSEARCH_API_KEY", raising=False)
    monkeypatch.delenv("ELASTICSEARCH_USERNAME", raising=False)
    monkeypatch.delenv("ELASTICSEARCH_PASSWORD", raising=False)

    with pytest.raises(elasticsearch.ElasticsearchConfigError, match="scoped"):
        elasticsearch._get_config()


def test_search_body_owns_time_scope_sort_and_limit():
    supplied = json.dumps({
        "size": 99999,
        "sort": [{"host.name": "asc"}],
        "query": {"term": {"event.action": "process-start"}},
    })
    body = elasticsearch._build_body(supplied, lookback_minutes=30, limit=25)

    assert body["size"] == 25
    assert body["sort"] == [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]
    assert body["query"]["bool"]["must"] == [{"term": {"event.action": "process-start"}}]
    assert body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "now-30m"


def test_forbidden_script_and_model_time_range_are_rejected():
    with pytest.raises(elasticsearch.ElasticsearchAPIError, match="forbidden"):
        elasticsearch._query_clause('{"query":{"script":{"script":"return true"}}}')
    with pytest.raises(elasticsearch.ElasticsearchAPIError, match="owns"):
        elasticsearch._query_clause('{"query":{"range":{"@timestamp":{"gte":"now-1y"}}}}')


def test_fetch_uses_api_key_and_normalizes_ecs(monkeypatch):
    _configure(monkeypatch)
    captured = {}

    class FakeResponse:
        status_code = 200
        text = ""

        @staticmethod
        def json():
            return {
                "_shards": {"failures": []},
                "hits": {
                    "total": {"value": 1},
                    "hits": [{
                        "_index": "logs-security-2026.07.28",
                        "_id": "event-1",
                        "_source": {
                            "@timestamp": "2026-07-28T10:00:00Z",
                            "host": {"name": "server-1"},
                            "user": {"name": "alice"},
                            "event": {"action": "process-start"},
                            "process": {"command_line": "nmap -sV target"},
                            "source": {"ip": "10.0.0.5"},
                        },
                    }],
                },
            }

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def request(self, method, url, **kwargs):
            captured["method"] = method
            captured["url"] = url
            captured["request"] = kwargs
            return FakeResponse()

    monkeypatch.setattr(elasticsearch.httpx, "Client", FakeClient)
    result = elasticsearch.fetch_logs('{"query":{"match_all":{}}}', limit=10)

    assert captured["url"] == "https://elastic.internal:9200/logs-security-*/_search"
    assert captured["client"]["headers"]["Authorization"] == "ApiKey encoded-key"
    assert captured["client"]["verify"] is False
    assert result["record_count"] == 1
    assert result["logs"][0]["host"] == "server-1"
    assert result["logs"][0]["user"] == "alice"
    assert result["logs"][0]["source_type"] == "elasticsearch"


def test_basic_auth_is_supported(monkeypatch):
    _configure(monkeypatch, api_key="")
    monkeypatch.setenv("ELASTICSEARCH_USERNAME", "thos_reader")
    monkeypatch.setenv("ELASTICSEARCH_PASSWORD", "secret")

    cfg = elasticsearch._get_config()
    kwargs = elasticsearch._client_kwargs(cfg)

    assert kwargs["auth"] == ("thos_reader", "secret")
    assert "Authorization" not in kwargs["headers"]
