from services.siem import schema_discovery


def _cache(monkeypatch):
    values = {}
    monkeypatch.setattr(
        schema_discovery.cache,
        "cache_get",
        lambda namespace, payload: values.get((namespace, payload)),
    )
    monkeypatch.setattr(
        schema_discovery.cache,
        "cache_set",
        lambda namespace, payload, value, ttl: values.__setitem__((namespace, payload), value),
    )
    return values


def test_discovers_raw_vendor_fields_and_redacts_sensitive_samples(monkeypatch):
    _cache(monkeypatch)
    monkeypatch.setattr(schema_discovery, "get_value", lambda *_args, **_kwargs: {})
    from services.siem import wazuh
    monkeypatch.setattr(wazuh, "discover_fields", lambda: [
        {"name": "data.win.eventdata.commandLine", "type": "keyword", "sample": None},
    ])
    monkeypatch.setattr(
        schema_discovery.siem_connector,
        "fetch_logs",
        lambda *_args, **_kwargs: {
            "logs": [{
                "_raw": {
                    "@timestamp": "2026-07-25T12:00:00Z",
                    "agent": {"name": "host-01", "ip": "10.0.0.8"},
                    "api_token": "must-not-be-cached",
                    "event": {"code": 4688},
                }
            }]
        },
    )

    result = schema_discovery.discover_siem_fields("wazuh")
    by_name = {item["name"]: item for item in result["fields"]}

    assert by_name["agent.ip"]["type"] == "ip"
    assert by_name["event.code"]["type"] == "int"
    assert by_name["api_token"]["sample"] == "[redacted]"
    assert by_name["data.win.eventdata.commandLine"]["type"] == "keyword"
    assert result["records_sampled"] == 1
    assert result["drift"]["added"] == [
        "@timestamp", "agent.ip", "agent.name", "api_token",
        "data.win.eventdata.commandLine", "event.code"
    ]
    assert result["discovery_method"] == \
        "index_field_capabilities_and_recent_event_sample"


def test_reports_removed_and_type_changed_fields(monkeypatch):
    _cache(monkeypatch)
    responses = iter([
        {"logs": [{"_raw": {"event": {"code": 4688}, "obsolete": "yes"}}]},
        {"logs": [{"_raw": {"event": {"code": "process-created"}, "new": True}}]},
    ])
    monkeypatch.setattr(
        schema_discovery.siem_connector,
        "fetch_logs",
        lambda *_args, **_kwargs: next(responses),
    )

    schema_discovery.discover_siem_fields("splunk")
    result = schema_discovery.discover_siem_fields("splunk")

    assert result["drift"]["added"] == ["new"]
    assert result["drift"]["removed"] == ["obsolete"]
    assert result["drift"]["changed_type"] == [{
        "field": "event.code", "before": "int", "after": "string"
    }]


def test_cached_schema_falls_back_to_persisted_runtime_inventory(monkeypatch):
    monkeypatch.setattr(schema_discovery.cache, "cache_get", lambda *_args: None)
    monkeypatch.setattr(
        schema_discovery,
        "get_value",
        lambda *_args, **_kwargs: {
            "fields": ["EventCode", "host"],
            "uploaded_at": "2026-07-01T00:00:00+00:00",
        },
    )

    result = schema_discovery.get_cached_siem_schema("splunk")

    assert result["hit"] is True
    assert result["stale"] is True
    assert [item["name"] for item in result["fields"]] == ["EventCode", "host"]
