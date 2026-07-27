"""Authoritative catalog for direct telemetry integrations.

SIEM integrations retain their vendor-specific implementations under
``services.siem``. Direct EDR/XDR and other API sources share a bounded,
read-only JSON connector so operators can configure the vendor event endpoint
without exposing credentials to the browser.
"""
from __future__ import annotations

from typing import Any


def _field(name: str, label: str, kind: str = "text", required: bool = False) -> dict[str, Any]:
    return {"name": name, "label": label, "type": kind, "required": required}


COMMON_API_FIELDS = [
    _field("base_url", "API base URL", "url", True),
    _field("events_path", "Read-only events endpoint", "text", True),
    _field("auth_type", "Authentication type (bearer/api_key/basic/oauth2)", "text", True),
    _field("api_token", "API token", "password"),
    _field("api_key_header", "API key header", "text"),
    _field("username", "Username", "text"),
    _field("password", "Password", "password"),
    _field("token_url", "OAuth token URL", "url"),
    _field("client_id", "OAuth client ID", "text"),
    _field("client_secret", "OAuth client secret", "password"),
    _field("scope", "OAuth scope", "text"),
    _field("verify_ssl", "Verify TLS (true/false)", "text"),
    _field("result_path", "Result list path, for example data.events", "text"),
    _field("query_parameter", "Search query parameter", "text"),
    _field("limit_parameter", "Result limit parameter", "text"),
]


def _api_source(
    connector_id: str,
    name: str,
    category: str,
    vendor: str,
    device_types: list[str],
    description: str,
    defaults: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "id": connector_id,
        "name": name,
        "category": category,
        "vendor": vendor,
        "mode": "direct_api",
        "read_only": True,
        "device_types": device_types,
        "description": description,
        "fields": COMMON_API_FIELDS,
        "defaults": {
            "auth_type": "bearer",
            "verify_ssl": "true",
            "result_path": "",
            "query_parameter": "query",
            "limit_parameter": "limit",
            **(defaults or {}),
        },
    }


INTEGRATION_CATALOG: dict[str, dict[str, Any]] = {
    "microsoft_defender_xdr": _api_source(
        "microsoft_defender_xdr", "Microsoft Defender XDR", "EDR / XDR", "Microsoft",
        ["endpoint", "identity", "email", "cloud"],
        "Defender incidents, alerts, devices, and advanced-hunting results.",
        {"auth_type": "oauth2", "events_path": "/api/alerts"},
    ),
    "crowdstrike_falcon": _api_source(
        "crowdstrike_falcon", "CrowdStrike Falcon", "EDR / XDR", "CrowdStrike",
        ["endpoint"], "Falcon detections, incidents, hosts, and endpoint telemetry.",
        {"auth_type": "oauth2"},
    ),
    "sentinelone": _api_source(
        "sentinelone", "SentinelOne", "EDR / XDR", "SentinelOne",
        ["endpoint"], "SentinelOne threats, activities, agents, and Deep Visibility events.",
        {"auth_type": "bearer"},
    ),
    "cortex_xdr": _api_source(
        "cortex_xdr", "Palo Alto Cortex XDR", "EDR / XDR", "Palo Alto Networks",
        ["endpoint", "network"], "Cortex XDR incidents, alerts, and endpoint events.",
        {"auth_type": "api_key"},
    ),
    "carbon_black": _api_source(
        "carbon_black", "VMware Carbon Black", "EDR / XDR", "Broadcom",
        ["endpoint"], "Carbon Black alerts, processes, devices, and investigative events.",
        {"auth_type": "api_key"},
    ),
    "sophos_central": _api_source(
        "sophos_central", "Sophos Central", "EDR / XDR", "Sophos",
        ["endpoint"], "Sophos endpoint alerts, cases, and XDR query results.",
        {"auth_type": "oauth2"},
    ),
    "trend_micro_vision_one": _api_source(
        "trend_micro_vision_one", "Trend Micro Vision One", "EDR / XDR", "Trend Micro",
        ["endpoint", "email", "network"], "Vision One alerts, workbench events, and observed attack techniques.",
    ),
    "trellix_edr": _api_source(
        "trellix_edr", "Trellix EDR", "EDR / XDR", "Trellix",
        ["endpoint"], "Trellix endpoint detections and investigation events.",
    ),
    "microsoft_entra": _api_source(
        "microsoft_entra", "Microsoft Entra ID", "Identity", "Microsoft",
        ["identity"], "Sign-in, audit, risk, and directory activity logs.",
        {"auth_type": "oauth2"},
    ),
    "okta": _api_source(
        "okta", "Okta System Log", "Identity", "Okta",
        ["identity"], "Authentication, policy, lifecycle, and administrative events.",
        {"events_path": "/api/v1/logs", "auth_type": "api_key", "api_key_header": "Authorization"},
    ),
    "aws_security": _api_source(
        "aws_security", "AWS Security Telemetry", "Cloud", "Amazon Web Services",
        ["cloud"], "CloudTrail, GuardDuty, and other exported AWS security events.",
    ),
    "azure_activity": _api_source(
        "azure_activity", "Azure Activity Logs", "Cloud", "Microsoft",
        ["cloud"], "Azure control-plane and resource activity events.",
        {"auth_type": "oauth2"},
    ),
    "google_cloud_audit": _api_source(
        "google_cloud_audit", "Google Cloud Audit Logs", "Cloud", "Google",
        ["cloud"], "Google Cloud administrative, data-access, and system events.",
        {"auth_type": "oauth2"},
    ),
    "microsoft_365": _api_source(
        "microsoft_365", "Microsoft 365 Audit", "Email / SaaS", "Microsoft",
        ["email", "saas"], "Exchange, SharePoint, Teams, and unified audit events.",
        {"auth_type": "oauth2"},
    ),
    "google_workspace": _api_source(
        "google_workspace", "Google Workspace Audit", "Email / SaaS", "Google",
        ["email", "saas"], "Admin, login, Drive, Gmail, and application audit events.",
        {"auth_type": "oauth2"},
    ),
    "network_sensor": _api_source(
        "network_sensor", "Network Sensor / NDR API", "Network", "Generic",
        ["network", "ids", "dns", "proxy", "firewall"],
        "Read-only JSON endpoint for NDR, Zeek, Suricata, DNS, proxy, VPN, firewall, or IDS telemetry.",
    ),
    "generic_security_api": _api_source(
        "generic_security_api", "Generic Security JSON API", "Other telemetry", "Generic",
        ["unknown"], "Bounded read-only JSON API connector for supported security-event sources.",
    ),
}

SECRET_SETTING_NAMES = {
    field["name"]
    for item in INTEGRATION_CATALOG.values()
    for field in item["fields"]
    if field["type"] == "password"
}


def public_catalog() -> list[dict[str, Any]]:
    return [INTEGRATION_CATALOG[key] for key in sorted(
        INTEGRATION_CATALOG,
        key=lambda item: (
            INTEGRATION_CATALOG[item]["category"],
            INTEGRATION_CATALOG[item]["name"],
        ),
    )]

