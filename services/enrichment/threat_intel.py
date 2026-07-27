import json
import ipaddress
import os
from services.orchestration.state import HuntState
from services.enrichment import ioc_management

_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value) for value in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7",
    )
)


def _suppress_private_indicator(value: str) -> bool:
    if os.environ.get("THOS_IOC_MATCH_PRIVATE", "").strip().lower() in {"1", "true", "yes"}:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in _PRIVATE_NETWORKS
               if address.version == network.version)


async def enrich_iocs_node(state: HuntState) -> dict:
    """Match observable IOCs to a locally managed JSON blocklist only."""
    data = ioc_management.load_blocklist()
    blocklist = {str(value).lower(): meta for value, meta in (data.get("indicators", data) or {}).items()}
    networks = []
    for value, metadata in blocklist.items():
        if not isinstance(metadata, dict) or metadata.get("type") != "network":
            continue
        try:
            networks.append((ipaddress.ip_network(value, strict=False), value, metadata))
        except ValueError:
            continue
        if len(networks) >= 10_000:
            break
    hits = []
    for index, log in enumerate(state.get("processed_logs") or []):
        text = json.dumps(log, default=str)
        observed = ioc_management.extract_indicators(text.encode("utf-8"), "record.json")
        for indicator_type, values in observed.items():
            for value in values:
                # Public reputation feeds often include broad bogon/private
                # ranges. Treating an internal RFC1918 address as malicious
                # solely because of that overlap creates noisy false positives.
                if indicator_type in {"ipv4", "ipv6"} and _suppress_private_indicator(value):
                    continue
                metadata = blocklist.get(value.lower())
                matched = value
                if not isinstance(metadata, dict) and indicator_type in {"ipv4", "ipv6"}:
                    try:
                        address = ipaddress.ip_address(value)
                        network_hit = next(
                            ((network_value, item) for network, network_value, item in networks if address in network),
                            None,
                        )
                    except ValueError:
                        network_hit = None
                    if network_hit:
                        matched, metadata = network_hit
                if isinstance(metadata, dict):
                    hit = {
                        "indicator": value,
                        "record_index": index,
                        "source": "local_blocklist",
                        "metadata": metadata,
                    }
                    if matched != value:
                        hit["matched_indicator"] = matched
                        hit["indicator_type"] = indicator_type
                    hits.append(hit)
                if len(hits) >= 100:
                    return {"enrichment_hits": hits}
    return {"enrichment_hits": hits[:100]}
