"""SIEM-KB tool: field mappings, log source metadata, API quirks.

This is the tool the query_generator relies on so the LLM doesn't have
to guess field names per-vendor.

Phase 1: static dict for LogRhythm + Splunk + QRadar core fields.
Phase 2 extension point: load this from /data/knowledge_base/siem_kb/*.yaml
and index into a 'siem_kb' Chroma collection for semantic field lookup
across large schemas.
"""

from services.runtime_config import get_value

SIEM_FIELD_MAP = {
    "logrhythm": {
        "process_name": "vProcessName",
        "command_line": "vObjectName",  # LogRhythm's general-purpose "Object" field
        "src_ip": "srcIP",
        "dst_ip": "destIP",
        "user": "login",
        "dns_query": "subject",
        "event_time": "normalDateMin",
    },
    "splunk": {
        "process_name": "process_name",
        "command_line": "process",
        "src_ip": "src_ip",
        "dst_ip": "dest_ip",
        "user": "user",
        "dns_query": "query",
        "event_time": "_time",
    },
    "qradar": {
        "process_name": "Process Name",
        "command_line": "Command",
        "src_ip": "Source IP",
        "dst_ip": "Destination IP",
        "user": "Username",
        "dns_query": "DNS Query",
        "event_time": "Start Time",
    },
    "wazuh": {
        "process_name": "data.process.name / data.win.eventdata.image",
        "command_line": "data.command / data.win.eventdata.commandLine / full_log",
        "src_ip": "data.srcip",
        "dst_ip": "data.dstip",
        "user": "data.srcuser / data.dstuser",
        "dns_query": "data.query / data.win.eventdata.queryName",
        "event_time": "@timestamp",
        "host": "agent.name",
        "rule_id": "rule.id",
        "rule_description": "rule.description",
        "rule_groups": "rule.groups",
        "mitre_technique": "rule.mitre.id",
    },
    "elasticsearch": {
        "process_name": "process.name",
        "command_line": "process.command_line",
        "src_ip": "source.ip",
        "dst_ip": "destination.ip",
        "user": "user.name",
        "dns_query": "dns.question.name",
        "event_time": "@timestamp",
        "host": "host.name",
        "rule_id": "rule.id",
        "rule_description": "rule.name",
        "mitre_technique": "threat.technique.id",
    },
    # "folder" — normalized field names already used by file_log_parser
    # for every locally-parsed format (evtx/log/syslog/csv/CEF/JSON/ECS/
    # xml/txt/pcap), so the mapping is effectively an identity map. This
    # is here mainly so generate_query's field_map lookup doesn't fall
    # back to "no field map available" for folder-backed hunts.
    "folder": {
        "process_name": "event",
        "command_line": "detail",
        "src_ip": "src_ip",
        "dst_ip": "dst_ip",
        "user": "user",
        "dns_query": "detail",
        "event_time": "timestamp",
    },
}


def get_field_mapping(siem_type: str) -> dict:
    """Return the normalized-field -> vendor-field mapping for a given SIEM."""
    key = siem_type.lower()
    mapping = dict(SIEM_FIELD_MAP.get(key, {}))
    custom = get_value("siem_field_mappings", key, default={})
    if isinstance(custom, dict):
        mapping.update({str(field): str(value) for field, value in custom.items() if str(field) and str(value)})
    inventory = get_value("siem_field_inventory", key, default={})
    fields = inventory.get("fields", []) if isinstance(inventory, dict) else []
    if isinstance(fields, list) and fields:
        # Keep the return shape string-valued for existing MCP consumers while
        # grounding query generation in the exact uploaded vendor schema.
        mapping["available_fields"] = ", ".join(str(field) for field in fields if str(field).strip())
    return mapping


def normalize_field(siem_type: str, normalized_field: str) -> str | None:
    mapping = get_field_mapping(siem_type)
    return mapping.get(normalized_field)
