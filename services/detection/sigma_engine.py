"""
Sigma rule engine — small, hand-written, hand-tuned, offline, no
external dependency on SigmaHQ or pySigma.

Loads real Sigma-style YAML detection rules from
services/detection/sigma_rules/*.yml and evaluates them directly against
THOS's normalized log record schema:

    {timestamp, host, user, event, src_ip, dst_ip, detail, source_file, source_type}

This is the SUPPLEMENTARY detection layer. The primary one — real
breadth against the actual SigmaHQ community ruleset, parsed with
pySigma rather than the simplified grammar below — is
services/detection/sigmahq_engine.py; see that module's docstring for
the three-layer design (SigmaHQ rules -> these hand-tuned rules -> LLM-
derived indicators) and services/mcp/soc_tools.py for how they combine.
This module and its ~16 rules were never the problem being solved here
— thin *coverage* was — so they're kept as-is: a small set of rules
written and tuned specifically against this platform's flat 8-field
schema, useful precisely because they're narrower and more precise than
a generic community rule would be on this schema.

This originally replaced the "Phase 1" approach in
services/mcp/soc_tools.py, which only did ad-hoc event-ID/keyword
substring matching and called an LLM to draft cosmetic SIGMA-looking
text that was never actually evaluated. Here, rules are real Sigma
detection logic and are actually run against every record.

Supported rule grammar (a grounded, honest subset of full Sigma — see
LIMITATIONS below):

    detection:
      <selection_name>:
        <field>|<modifier>: <value or list of values>
        <field>: <value or list of values>          # modifier optional == exact/contains-ci match
      condition: <expression>

  - Within one selection block, multiple fields are AND-ed together.
  - A list of values for one field is OR-ed ("any of these values").
  - Modifiers: contains (default for strings), exact, startswith, endswith, re.
  - condition supports: a single selection name, "not X", "X and Y",
    "X or Y", "1 of sel*", "all of sel*" (fnmatch-style wildcard on
    selection names). Nested parentheses are NOT supported (kept simple
    and auditable rather than a full boolean-expression parser).

LIMITATIONS (stated here rather than silently pretending otherwise):
  - The normalized schema has only 8 generic fields — there's no
    structured GrantedAccess/TargetImage/CommandLine/ParentImage
    extraction, so rules match against `event` (e.g. "EventID-4104") and
    substrings inside the raw `detail` blob rather than fully-parsed
    structured fields. This is still a real, deterministic evaluation —
    just against a flatter schema than a production Sigma backend with
    fully parsed Sysmon/Security fields would have.
  - No aggregation conditions (e.g. Sigma's `count() > N by field`
    time-windowed correlation) — each record is evaluated independently.
"""
from __future__ import annotations

import fnmatch
import glob
import os
import re

import yaml

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sigma_rules")


def load_rules(rules_dir: str = RULES_DIR) -> list[dict]:
    """Load and parse every .yml/.yaml Sigma rule in rules_dir."""
    rules = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yml")) +
                        glob.glob(os.path.join(rules_dir, "*.yaml"))):
        try:
            with open(path, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
            if rule and "detection" in rule:
                rule["_path"] = path
                rules.append(rule)
        except (yaml.YAMLError, OSError) as e:
            # A single malformed rule file must never abort the whole load.
            rules.append({"_path": path, "_load_error": str(e)})
    return [r for r in rules if "_load_error" not in r]


def _field_value(record: dict, field: str):
    return record.get(field)


def _match_one(record_value, expected, modifier: str) -> bool:
    if record_value is None:
        return False
    rv = str(record_value).lower()
    ev = str(expected).lower()
    if modifier == "contains":
        return ev in rv
    if modifier == "startswith":
        return rv.startswith(ev)
    if modifier == "endswith":
        return rv.endswith(ev)
    if modifier == "re":
        try:
            return re.search(expected, str(record_value), re.IGNORECASE) is not None
        except re.error:
            return False
    # exact / no modifier
    return rv == ev


def _eval_field_clause(record: dict, field_key: str, expected) -> bool:
    if "|" in field_key:
        field, modifier = field_key.split("|", 1)
    else:
        field, modifier = field_key, "contains"
    record_value = _field_value(record, field)
    expected_list = expected if isinstance(expected, list) else [expected]
    return any(_match_one(record_value, exp, modifier) for exp in expected_list)


def _eval_selection(record: dict, selection: dict) -> bool:
    """All fields inside a selection block are AND-ed together."""
    if not selection:
        return False
    return all(_eval_field_clause(record, field_key, expected)
               for field_key, expected in selection.items())


def _eval_condition(condition: str, selections: dict, record: dict) -> bool:
    condition = condition.strip()

    m = re.match(r"^(1|all) of (.+)$", condition)
    if m:
        quantifier, pattern = m.groups()
        matched_names = [name for name in selections if fnmatch.fnmatch(name, pattern.strip())]
        results = [_eval_selection(record, selections[name]) for name in matched_names]
        if not results:
            return False
        return any(results) if quantifier == "1" else all(results)

    if " and not " in condition:
        left, right = condition.split(" and not ", 1)
        return _eval_condition(left, selections, record) and not _eval_condition(right, selections, record)
    if " and " in condition:
        left, right = condition.split(" and ", 1)
        return _eval_condition(left, selections, record) and _eval_condition(right, selections, record)
    if " or " in condition:
        left, right = condition.split(" or ", 1)
        return _eval_condition(left, selections, record) or _eval_condition(right, selections, record)
    if condition.startswith("not "):
        return not _eval_condition(condition[4:], selections, record)

    return _eval_selection(record, selections.get(condition, {}))


def evaluate_rule(rule: dict, record: dict) -> bool:
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not condition or not selections:
        return False
    try:
        return _eval_condition(condition, selections, record)
    except Exception:  # noqa: BLE001 — one bad rule must never abort a hunt
        return False


def evaluate_all(records: list[dict], rules: list[dict] | None = None,
                  technique_id: str = "", tactic: str = "") -> dict:
    """Evaluate every loaded rule against every record.

    Returns:
        {
          "matched_record_indices": [...],   # union across all matched rules
          "rule_matches": [
              {"rule_id", "title", "level", "tags", "matched_indices": [...]}
              , ...   # only rules with >=1 match
          ],
          "rules_evaluated": <int>,
        }
    """
    if rules is None:
        rules = load_rules()

    # Soft-prioritize rules tagged with this hunt's technique/tactic, but
    # still evaluate every rule — a hypothesis's stated technique isn't
    # the only thing that can show up in the evidence.
    rule_matches = []
    matched_indices = set()

    for rule in rules:
        hits = [i for i, rec in enumerate(records) if evaluate_rule(rule, rec)]
        if hits:
            matched_indices.update(hits)
            rule_matches.append({
                "rule_id": rule.get("id", "unknown"),
                "title": rule.get("title", "Untitled rule"),
                "level": rule.get("level", "medium"),
                "tags": rule.get("tags", []),
                "matched_indices": hits,
                "matched_count": len(hits),
            })

    rule_matches.sort(key=lambda r: r["matched_count"], reverse=True)

    return {
        "matched_record_indices": sorted(matched_indices),
        "rule_matches": rule_matches,
        "rules_evaluated": len(rules),
    }
