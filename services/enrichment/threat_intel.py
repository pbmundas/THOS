import ipaddress
import json
import os
import re
from pathlib import Path
from services.orchestration.state import HuntState

_IOC = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-fA-F0-9]{64}\b|\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


async def enrich_iocs_node(state: HuntState) -> dict:
    """Match observable IOCs to a locally managed JSON blocklist only."""
    path = Path(os.environ.get("THOS_IOC_BLOCKLIST_PATH", "/data/threat_intel/blocklist.json"))
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, json.JSONDecodeError):
        data = {}
    blocklist = {str(value).lower(): meta for value, meta in (data.get("indicators", data) or {}).items()}
    hits = []
    for index, log in enumerate(state.get("processed_logs") or []):
        text = " ".join(str(log.get(key, "")) for key in ("detail", "src_ip", "dst_ip"))
        for value in set(_IOC.findall(text)):
            try:
                if value.count(".") == 3:
                    ipaddress.ip_address(value)
            except ValueError:
                continue
            if value.lower() in blocklist:
                hits.append({"indicator": value, "record_index": index, "source": "local_blocklist", "metadata": blocklist[value.lower()]})
    return {"enrichment_hits": hits[:100]}
