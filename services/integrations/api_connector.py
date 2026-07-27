"""Bounded read-only connector for direct security telemetry APIs."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any
from urllib.parse import urljoin

import httpx

from services.integrations.catalog import INTEGRATION_CATALOG
from services.runtime_config import get_value

MAX_RESPONSE_BYTES = 20 * 1024 * 1024


class IntegrationConfigError(ValueError):
    pass


def _settings(connector_id: str) -> dict[str, Any]:
    catalog = INTEGRATION_CATALOG.get(connector_id)
    if not catalog:
        raise IntegrationConfigError(f"unknown integration: {connector_id}")
    saved = get_value("integrations", connector_id, "settings", default={}) or {}
    return {**catalog.get("defaults", {}), **saved}


def _bool(value: Any, default: bool = True) -> bool:
    if value in (None, ""):
        return default
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


def _token(settings: dict[str, Any], client: httpx.Client) -> str:
    token_url = str(settings.get("token_url") or "").strip()
    client_id = str(settings.get("client_id") or "").strip()
    client_secret = str(settings.get("client_secret") or "").strip()
    if not token_url or not client_id or not client_secret:
        raise IntegrationConfigError("OAuth2 requires token URL, client ID, and client secret")
    response = client.post(token_url, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": str(settings.get("scope") or "").strip(),
    })
    response.raise_for_status()
    token = str(response.json().get("access_token") or "")
    if not token:
        raise IntegrationConfigError("OAuth token response did not contain access_token")
    return token


def _headers(settings: dict[str, Any], client: httpx.Client) -> dict[str, str]:
    auth_type = str(settings.get("auth_type") or "bearer").strip().lower()
    if auth_type == "oauth2":
        return {"Authorization": f"Bearer {_token(settings, client)}"}
    if auth_type == "bearer":
        token = str(settings.get("api_token") or "").strip()
        if not token:
            raise IntegrationConfigError("Bearer authentication requires an API token")
        return {"Authorization": f"Bearer {token}"}
    if auth_type == "api_key":
        token = str(settings.get("api_token") or "").strip()
        if not token:
            raise IntegrationConfigError("API-key authentication requires an API token")
        return {str(settings.get("api_key_header") or "X-API-Key"): token}
    if auth_type in {"none", "basic"}:
        return {}
    raise IntegrationConfigError(f"unsupported authentication type: {auth_type}")


def _result_list(payload: Any, path: str) -> list[dict]:
    current = payload
    if path:
        for part in path.split("."):
            if not isinstance(current, dict):
                current = []
                break
            current = current.get(part)
    if not path and isinstance(current, dict):
        for key in ("events", "results", "data", "items", "resources", "value", "alerts"):
            candidate = current.get(key)
            if isinstance(candidate, list):
                current = candidate
                break
            if isinstance(candidate, dict):
                nested = next((candidate.get(child) for child in ("events", "results", "items") if isinstance(candidate.get(child), list)), None)
                if nested is not None:
                    current = nested
                    break
    if not isinstance(current, list):
        return [current] if isinstance(current, dict) else []
    return [item for item in current if isinstance(item, dict)]


def _first(raw: dict, *paths: str):
    for path in paths:
        value: Any = raw
        for part in path.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        if value not in (None, ""):
            return value
    return None


def _normalize(raw: dict, connector_id: str) -> dict:
    catalog = INTEGRATION_CATALOG[connector_id]
    detail = _first(raw, "detail", "message", "description", "summary", "name", "title")
    event = _first(raw, "event", "eventType", "event_type", "category", "type", "alertType", "name")
    return {
        "timestamp": _first(raw, "timestamp", "created_at", "createdAt", "eventTime", "time", "@timestamp"),
        "host": _first(raw, "host", "hostname", "device.name", "device.hostname", "computer_name", "agent.name"),
        "user": _first(raw, "user", "username", "user.name", "actor.alternateId", "accountName"),
        "event": str(event or "security_event"),
        "detail": str(detail or json.dumps(raw, ensure_ascii=False, default=str)[:4_000]),
        "src_ip": _first(raw, "src_ip", "source.ip", "sourceIp", "localIP"),
        "dst_ip": _first(raw, "dst_ip", "destination.ip", "destinationIp", "remoteIP"),
        "source_vendor": catalog["vendor"],
        "source_product": catalog["name"],
        "source_type": connector_id,
        "device_type": (catalog.get("device_types") or ["unknown"])[0],
        "_raw": raw,
    }


def fetch_logs(connector_id: str, query: str, limit: int = 25) -> dict:
    settings = _settings(connector_id)
    base_url = str(settings.get("base_url") or "").strip()
    events_path = str(settings.get("events_path") or "").strip()
    if not base_url or not events_path:
        raise IntegrationConfigError("API base URL and read-only events endpoint are required")
    verify = _bool(settings.get("verify_ssl"), True)
    timeout = httpx.Timeout(30, connect=10)
    auth_type = str(settings.get("auth_type") or "bearer").strip().lower()
    basic_auth = None
    if auth_type == "basic":
        username = str(settings.get("username") or "")
        password = str(settings.get("password") or "")
        if not username or not password:
            raise IntegrationConfigError("Basic authentication requires username and password")
        basic_auth = (username, password)
    with httpx.Client(timeout=timeout, verify=verify, follow_redirects=False, auth=basic_auth) as client:
        headers = _headers(settings, client)
        params = {str(settings.get("limit_parameter") or "limit"): max(1, min(int(limit), 1_000))}
        if query and settings.get("query_parameter"):
            params[str(settings["query_parameter"])] = query
        response = client.get(urljoin(base_url.rstrip("/") + "/", events_path.lstrip("/")), headers=headers, params=params)
        response.raise_for_status()
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise IntegrationConfigError("integration response exceeded the 20 MB safety limit")
        payload = response.json()
    raw_items = _result_list(payload, str(settings.get("result_path") or ""))
    logs = [_normalize(item, connector_id) for item in raw_items[:max(1, min(limit, 1_000))]]
    return {
        "siem_type": connector_id,
        "integration_id": connector_id,
        "query": query,
        "record_count": len(logs),
        "total_hits": len(raw_items),
        "logs": logs,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


def test_connection(connector_id: str) -> dict:
    result = fetch_logs(connector_id, "", 1)
    return {
        "connected": True,
        "record_count": result["record_count"],
        "tested_at": datetime.now().astimezone().isoformat(),
    }
