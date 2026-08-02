import asyncio

from services.orchestration import main


def test_translate_log_search_uses_grounded_query_generator(monkeypatch):
    captured = []

    async def call_tool(name, arguments):
        captured.append((name, arguments))
        return {
            "query": "search process_name=powershell.exe",
            "query_generation_mode": "model",
            "query_generation_warnings": [],
        }

    monkeypatch.setattr(main, "call_tool", call_tool)
    request = main.LogSearchTranslateRequest(
        portable_query='process_name == "powershell.exe"',
        siem_type="splunk",
        lookback_minutes=60,
    )

    result = asyncio.run(main.translate_log_search(request))

    assert result["query"] == "search process_name=powershell.exe"
    assert captured[0][0] == "generate_siem_query"
    assert captured[0][1]["hypothesis_text"] == request.portable_query
    assert captured[0][1]["investigation_context"]["lookback_minutes"] == 60


def test_run_log_search_validates_then_fetches_without_cache(monkeypatch):
    calls = []

    async def call_tool(name, arguments):
        calls.append((name, arguments))
        if name == "validate_siem_query":
            return {"query": "search index=main error", "validation_error": None}
        return {
            "logs": [{"host": "endpoint-01", "message": "error"}],
            "record_count": 1,
            "total_hits": 1,
        }

    monkeypatch.setattr(main, "call_tool", call_tool)
    request = main.LogSearchRunRequest(
        portable_query="message contains error",
        query="search index=main error",
        siem_type="splunk",
        lookback_minutes=360,
        limit=500,
    )

    result = asyncio.run(main.run_log_search(request))

    assert [name for name, _arguments in calls] == [
        "validate_siem_query", "fetch_siem_logs",
    ]
    fetch_arguments = calls[1][1]
    assert fetch_arguments["bypass_cache"] is True
    assert fetch_arguments["lookback_minutes"] == 360
    assert fetch_arguments["limit"] == 500
    assert result["record_count"] == 1
    assert result["logs"][0]["host"] == "endpoint-01"
