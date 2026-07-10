"""
MITRE ATT&CK mapping tool — full-fledged version.

Loads the complete technique table (services/knowledge/data/mitre_full.json)
covering every technique ID referenced by the ingested HEARTH hypothesis
set (233 techniques), instead of the old 3-entry hardcoded stub.

Table provenance (see data/_generate_mitre_full.py):
  - "curated"                         — hand-written name/description,
                                         taken from services/knowledge/seeds/mitre_seed.json.
  - "base-technique-table+hearth-grounded" — canonical MITRE ATT&CK base
                                         technique name, tactic voted from
                                         the actual hunting-hypothesis data.
  - "hearth-grounded-only"            — no curated name available; tactic
                                         and description are still grounded
                                         in real hypothesis data (never
                                         invented).

Phase 4 extension point: replace/augment this file-backed table by loading
the full Enterprise ATT&CK STIX bundle (https://github.com/mitre/cti) into
the 'mitre_kb' Chroma collection at container startup for semantic lookup
by name/description instead of exact ID only. The public API below
(map_technique / suggest_data_sources) stays the same either way, so
nothing else in the codebase needs to change when that lands.
"""
import json
import os

DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "mitre_full.json")

with open(DATA_PATH, "r", encoding="utf-8") as _f:
    TECHNIQUE_TABLE: dict[str, dict] = json.load(_f)


def map_technique(technique_id: str) -> dict | None:
    """Return MITRE ATT&CK technique details for a given technique ID
    (e.g. T1059.001). Falls back to the base technique (e.g. T1059) if
    the exact sub-technique ID isn't in the table, so callers still get
    a usable tactic/name instead of a hard miss."""
    if not technique_id:
        return None
    tech = TECHNIQUE_TABLE.get(technique_id)
    if tech:
        return tech
    base = technique_id.split(".")[0]
    return TECHNIQUE_TABLE.get(base)


def suggest_data_sources(technique_id: str) -> list[str]:
    tech = map_technique(technique_id)
    return tech["data_sources"] if tech else []


def coverage_stats() -> dict:
    """Summary of table coverage, useful for a report's MITRE ATT&CK
    Coverage section: how many techniques are curated vs. name-known
    vs. grounded-only-no-name."""
    by_source: dict[str, int] = {}
    by_tactic: dict[str, int] = {}
    for tech in TECHNIQUE_TABLE.values():
        by_source[tech["source"]] = by_source.get(tech["source"], 0) + 1
        by_tactic[tech["tactic"]] = by_tactic.get(tech["tactic"], 0) + 1
    return {
        "total_techniques": len(TECHNIQUE_TABLE),
        "by_source": by_source,
        "by_tactic": by_tactic,
    }


def list_techniques_for_tactic(tactic: str) -> list[dict]:
    """All techniques mapped to a given MITRE ATT&CK tactic name."""
    return [t for t in TECHNIQUE_TABLE.values() if t["tactic"].lower() == tactic.lower()]
