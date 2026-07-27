#!/usr/bin/env python3
"""Generate THOS hypotheses for observable ATT&CK coverage gaps.

The generator deliberately creates hypotheses only when all three conditions
hold:
  1. the technique exists in the supplied official Enterprise ATT&CK STIX;
  2. no HEARTH hypothesis maps to that exact technique ID; and
  3. the live Wazuh schema has at least one runnable Sigma query for it.

This prevents a large catalog of unobservable "paper hypotheses" while closing
every hypothesis-side gap that THOS can currently execute.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import re


TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TACTIC_NAMES = {
    "command-and-control": "Command and Control",
    "credential-access": "Credential Access",
    "defense-evasion": "Defense Evasion",
    "defense-impairment": "Defense Impairment",
    "initial-access": "Initial Access",
    "lateral-movement": "Lateral Movement",
    "privilege-escalation": "Privilege Escalation",
    "resource-development": "Resource Development",
    "stealth": "Stealth",
}
SEVERITY = {
    "Credential Access": "critical",
    "Defense Impairment": "critical",
    "Exfiltration": "critical",
    "Impact": "critical",
    "Collection": "medium",
    "Discovery": "medium",
    "Reconnaissance": "low",
    "Resource Development": "low",
}


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _title_tactic(slug: str) -> str:
    return TACTIC_NAMES.get(slug, slug.replace("-", " ").title())


def _official_techniques(bundle: dict) -> dict[str, dict]:
    output: dict[str, dict] = {}
    for item in bundle.get("objects", []):
        if (
            item.get("type") != "attack-pattern"
            or item.get("revoked")
            or item.get("x_mitre_deprecated")
        ):
            continue
        external = next((
            ref for ref in item.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
            and TECHNIQUE_ID.fullmatch(str(ref.get("external_id", "")))
        ), None)
        if not external:
            continue
        tactics = sorted({
            _title_tactic(phase["phase_name"])
            for phase in item.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
            and phase.get("phase_name")
        })
        output[external["external_id"]] = {
            "id": external["external_id"],
            "name": item.get("name", external["external_id"]),
            "description": str(item.get("description", "")).strip(),
            "tactics": tactics,
        }
    return output


def _hearth_techniques(items: list[dict]) -> set[str]:
    output: set[str] = set()
    for item in items:
        output.update(str(value) for value in item.get("all_techniques", []) if value)
        if item.get("technique"):
            output.add(str(item["technique"]))
    return output


def _sigma_by_technique(catalog: dict) -> dict[str, list[dict]]:
    output: dict[str, list[dict]] = defaultdict(list)
    for item in catalog.get("entries", []):
        if item.get("backend") != "wazuh":
            continue
        for tag in item.get("tags", []):
            value = str(tag).lower()
            if value.startswith("attack."):
                technique = value.removeprefix("attack.").upper()
                if TECHNIQUE_ID.fullmatch(technique):
                    output[technique].append(item)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hearth", type=Path, required=True)
    parser.add_argument("--attack-stix", type=Path, required=True)
    parser.add_argument("--attack-version", default="19.1")
    parser.add_argument("--sigma-catalog", type=Path, required=True)
    parser.add_argument("--sigma-ready", type=Path, required=True)
    parser.add_argument("--hypotheses-out", type=Path, required=True)
    parser.add_argument("--mitre-out", type=Path, required=True)
    parser.add_argument("--audit-out", type=Path, required=True)
    args = parser.parse_args()

    hearth = _read(args.hearth)
    official = _official_techniques(_read(args.attack_stix))
    sigma = _sigma_by_technique(_read(args.sigma_catalog))
    readiness = _read(args.sigma_ready)
    covered = _hearth_techniques(hearth)

    gaps = [
        technique for technique in sorted(sigma)
        if technique in official
        and technique not in covered
        and int(readiness.get(technique, {}).get("ready", 0)) > 0
    ]

    hypotheses: list[dict] = []
    mitre: dict[str, dict] = {}
    tactic_counts: Counter[str] = Counter()
    for technique in gaps:
        attack = official[technique]
        rules = sigma[technique]
        ready = int(readiness[technique]["ready"])
        tactic = attack["tactics"][0] if attack["tactics"] else "Unknown"
        tactic_counts[tactic] += 1
        titles = list(dict.fromkeys(
            str(item.get("title") or item.get("rule_id"))
            for item in rules
        ))[:4]
        title_text = "; ".join(titles)
        hypotheses.append({
            "id": f"THOS-GAP-{technique.replace('.', '-')}",
            "title": f"{attack['name']} activity ({technique})",
            "tactic": tactic,
            "technique": technique,
            "text": (
                f"An adversary may be exhibiting {attack['name']} ({technique}) "
                f"behavior in this environment. Hunt the connected Wazuh telemetry "
                f"with the {ready} live-schema-compatible Sigma detection"
                f"{'s' if ready != 1 else ''} tagged {technique}; prioritize evidence "
                f"patterns represented by: {title_text}. Correlate every match by "
                "host, user, process lineage, timestamp, and adjacent authentication, "
                "network, registry, file, or event-log activity before disposition."
            ),
            "category": "THOS Required Coverage Gap",
            "severity": SEVERITY.get(tactic, "high"),
            "all_tactics": attack["tactics"],
            "all_techniques": [technique],
            "tags": ["thos-required-gap", technique.lower()],
            "source": f"MITRE ATT&CK v{args.attack_version} + live Wazuh Sigma catalog",
            "runnable_sigma_rules": ready,
        })
        mitre[technique] = {
            "id": technique,
            "name": attack["name"],
            "tactic": tactic,
            "description": attack["description"],
            "data_sources": [],
            "source": f"official-mitre-attack-v{args.attack_version}",
        }

    args.hypotheses_out.parent.mkdir(parents=True, exist_ok=True)
    args.mitre_out.parent.mkdir(parents=True, exist_ok=True)
    args.audit_out.parent.mkdir(parents=True, exist_ok=True)
    args.hypotheses_out.write_text(
        json.dumps(hypotheses, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    args.mitre_out.write_text(
        json.dumps(mitre, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    audit = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "attack_version": args.attack_version,
        "hearth_hypotheses": len(hearth),
        "hearth_exact_techniques_before": len(covered),
        "official_enterprise_techniques": len(official),
        "sigma_tagged_techniques": len(sigma),
        "runnable_sigma_hypothesis_gaps_closed": len(gaps),
        "exact_techniques_after": len(covered | set(gaps)),
        "remaining_official_techniques_without_hypotheses": len(
            set(official) - covered - set(gaps)
        ),
        "remaining_classification": (
            "Detection/telemetry gap: no live-schema-compatible Sigma query; "
            "not an executable hypothesis-side gap."
        ),
        "added_by_tactic": dict(sorted(tactic_counts.items())),
        "added_techniques": gaps,
    }
    args.audit_out.write_text(
        json.dumps(audit, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(audit, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
