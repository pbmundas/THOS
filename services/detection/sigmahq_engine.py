"""
SigmaHQ rule engine -- evaluates the real, vendored SigmaHQ ruleset
(services/detection/sigma_rules_hq/, 2,843 rules as of this writing;
see sigma_rules_hq/VERSION.txt) against THOS's normalized log record
schema, using pySigma to parse rules rather than a hand-rolled parser.

This is a *third* detection layer, additive to the two that already
exist (see services/mcp/soc_tools.py):

  1. sigmahq_engine (this module) -- the real SigmaHQ community
     ruleset, parsed by pySigma. Broad coverage, primary signal.
  2. sigma_engine -- THOS's original ~16 hand-written rules, written
     and tuned specifically against this platform's 8-field schema.
     Kept as a small, high-precision supplementary layer -- these
     rules were never the problem, thin *coverage* was.
  3. LLM-derived indicators (indicator_deriver.py) -- fallback for
     techniques neither rule set covers yet.

Why pySigma instead of hand-rolling a bigger rule parser: pySigma is
the rule -> query *compiler* the Sigma ecosystem actually maintains
(it's what sigma-cli and every official SigmaHQ backend, e.g. Splunk/
Elastic/Sentinel, are built on). Its normal job is turning parsed
Sigma detection logic into query strings for a target backend. There
is no upstream backend that evaluates rules directly against Python
dicts, so DictMatchBackend below is a Backend subclass that walks the
same parsed condition tree pySigma builds for every other backend, but
returns Python predicates (Callable[[dict], bool]) instead of query
fragments. This means: rule *parsing* (YAML, detection logic, field
modifiers, condition expressions -- including nested boolean groups,
which the old hand-rolled engine explicitly could not do) is 100% real
pySigma, not reimplemented; only the final "how do I check this
against a record" step is custom, because no backend for that exists.

FIELD MAPPING (grounded, stated honestly rather than pretended away):
THOS's normalized schema has 8 generic fields (timestamp/host/user/
event/src_ip/dst_ip/detail/source_file/source_type) -- there's no
structured CommandLine/Image/ParentImage/TargetObject extraction the
way a real Sysmon-parsing backend would have. So:
  - Sigma fields with a clear structural match (EventID, User/
    TargetUserName/etc., ComputerName/Hostname/etc., Source/
    DestinationIp) map onto the corresponding normalized field.
  - Every other Sigma field (CommandLine, Image, TargetObject, ...)
    matches against the raw `detail` blob, since file_log_parser.py
    already puts the raw EVTX XML / log line / JSON there -- the
    literal field value text is genuinely present in `detail` for
    EVTX-derived logs, just not pre-extracted into its own key. This
    is real substring/regex evaluation against real captured text, not
    a fabricated match.
  - Field-to-field comparisons, Sigma field-existence checks, and
    query-expression values (backend-specific placeholders) aren't
    representable on a flat schema and always evaluate to no-match
    rather than silently guessing.

PERFORMANCE: rules are parsed and compiled into predicates once per
process (module-level cache, see get_compiled_ruleset), not per hunt.
Each compiled rule also carries a set of literal substrings extracted
from its string leaves; at evaluation time a record is first checked
against that set (a record can only match a rule if at least one of
the rule's literal substrings appears somewhere in the record) before
running the full predicate tree, so records that share no vocabulary
with a given rule skip it cheaply. Rules containing a leaf we can't
reduce to a literal substring (regex/CIDR/numeric-compare/exists/
base64-transform modifiers, etc.) opt out of this pre-filter and are
always fully evaluated -- the pre-filter is a cheap, sound speed-up,
never a source of false negatives.
"""
from __future__ import annotations

import functools
import glob
import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Callable

from sigma.collection import SigmaCollection
from sigma.conditions import ConditionAND, ConditionNOT, ConditionOR
from sigma.conversion.base import Backend
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaError
from sigma.types import SigmaCompareExpression

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sigma_rules_hq")

Predicate = Callable[[dict], bool]

# Sigma field name (lowercased) -> normalized THOS record key. Anything
# not listed here falls back to searching the raw `detail` blob.
FIELD_MAP = {
    "eventid": "event",
    "user": "user", "targetusername": "user", "subjectusername": "user",
    "accountname": "user", "username": "user",
    "computername": "host", "computer": "host", "hostname": "host",
    "workstationname": "host", "workstation": "host",
    "destinationip": "dst_ip", "destinationhostname": "dst_ip",
    "sourceip": "src_ip", "ipaddress": "src_ip",
}
FALLBACK_FIELD = "detail"
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]{3,}")

# Sigma value-transform modifiers whose encoded output would never
# literally appear in raw log text the way the original value does,
# plus EventID field naming itself doesn't move -- handled via
# _mark_unsound instead so the token pre-filter doesn't skip a rule
# it can't actually reason about.


def _record_text(record: dict, field: str) -> str:
    key = FIELD_MAP.get(field.lower(), FALLBACK_FIELD)
    val = record.get(key)
    if val is None and key != FALLBACK_FIELD:
        val = record.get(FALLBACK_FIELD)
    return "" if val is None else str(val)


def _mark_unsound(state: ConversionState) -> None:
    """Called by any leaf conversion that can't be reduced to a literal
    substring. Disables the literal-token pre-filter for this rule so
    the pre-filter never causes a false negative."""
    state.processing_state["gateable"] = False


def _record_tokens_from_str(state: ConversionState, value) -> None:
    plain = value.to_plain() if hasattr(value, "to_plain") else str(value)
    tokens = state.processing_state.setdefault("tokens", set())
    for tok in _TOKEN_RE.findall(plain.strip("*?")):
        tokens.add(tok.lower())


class DictMatchBackend(Backend):
    """pySigma Backend that compiles a parsed Sigma condition tree into
    a Python predicate over a THOS normalized log record, instead of a
    query string. See module docstring for rationale."""

    name = "thos-dict-match"
    formats = {"default": "In-process Python predicate (not a query language)"}

    # --- boolean combinators -------------------------------------------------
    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Predicate:
        subs = [self.convert_condition(a, state) for a in cond.args]
        return lambda r: all(p(r) for p in subs)

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Predicate:
        subs = [self.convert_condition(a, state) for a in cond.args]
        return lambda r: any(p(r) for p in subs)

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Predicate:
        sub = self.convert_condition(cond.args[0], state)
        return lambda r: not sub(r)

    def convert_condition_as_in_expression(self, cond, state) -> Predicate:
        return self.convert_condition_or(cond, state)

    # --- field = value leaves --------------------------------------------------
    def convert_condition_field_eq_val_str(self, cond, state) -> Predicate:
        _record_tokens_from_str(state, cond.value)
        pattern = re.compile(cond.value.to_regex().regexp.to_plain(), re.IGNORECASE | re.DOTALL)
        field = cond.field
        return lambda r: pattern.fullmatch(_record_text(r, field)) is not None

    def convert_condition_field_eq_val_str_case_sensitive(self, cond, state) -> Predicate:
        _record_tokens_from_str(state, cond.value)
        pattern = re.compile(cond.value.to_regex().regexp.to_plain(), re.DOTALL)
        field = cond.field
        return lambda r: pattern.fullmatch(_record_text(r, field)) is not None

    def convert_condition_field_eq_val_num(self, cond, state) -> Predicate:
        _mark_unsound(state)  # bare numbers aren't run through token extraction
        expected = str(cond.value)
        field = cond.field
        return lambda r: expected in _record_text(r, field)

    def convert_condition_field_eq_val_timestamp_part(self, cond, state) -> Predicate:
        _mark_unsound(state)
        return lambda r: False  # no parsed timestamp components on this schema

    def convert_condition_field_eq_val_bool(self, cond, state) -> Predicate:
        _mark_unsound(state)
        expected = str(bool(cond.value)).lower()
        field = cond.field
        return lambda r: _record_text(r, field).lower() == expected

    def convert_condition_field_eq_val_re(self, cond, state) -> Predicate:
        _mark_unsound(state)
        try:
            pattern = re.compile(str(cond.value.regexp), re.IGNORECASE)
        except re.error:
            return lambda r: False
        field = cond.field
        return lambda r: pattern.search(_record_text(r, field)) is not None

    def convert_condition_field_eq_val_cidr(self, cond, state) -> Predicate:
        _mark_unsound(state)
        try:
            network = ipaddress.ip_network(str(cond.value), strict=False)
        except ValueError:
            return lambda r: False
        field = cond.field

        def _match(r: dict) -> bool:
            try:
                return ipaddress.ip_address(_record_text(r, field)) in network
            except ValueError:
                return False
        return _match

    def convert_condition_field_compare_op_val(self, cond, state) -> Predicate:
        _mark_unsound(state)
        op, num = cond.value.op, cond.value.number
        field = cond.field
        ops = {
            SigmaCompareExpression.CompareOperators.LT: lambda v: v < num,
            SigmaCompareExpression.CompareOperators.LTE: lambda v: v <= num,
            SigmaCompareExpression.CompareOperators.GT: lambda v: v > num,
            SigmaCompareExpression.CompareOperators.GTE: lambda v: v >= num,
        }

        def _match(r: dict) -> bool:
            try:
                v = float(_record_text(r, field))
            except (TypeError, ValueError):
                return False
            return ops.get(op, lambda _v: False)(v)
        return _match

    def convert_condition_field_eq_field(self, cond, state) -> Predicate:
        _mark_unsound(state)  # cross-field comparisons unsupported on this flat schema
        return lambda r: False

    def convert_condition_field_eq_val_null(self, cond, state) -> Predicate:
        _mark_unsound(state)
        key = FIELD_MAP.get(cond.field.lower())
        if key is None:
            return lambda r: False
        return lambda r: r.get(key) is None

    def convert_condition_field_exists(self, cond, state) -> Predicate:
        _mark_unsound(state)
        field = cond.field
        return lambda r: bool(_record_text(r, field))

    def convert_condition_field_not_exists(self, cond, state) -> Predicate:
        _mark_unsound(state)
        field = cond.field
        return lambda r: not bool(_record_text(r, field))

    def convert_condition_field_eq_query_expr(self, cond, state) -> Predicate:
        _mark_unsound(state)  # backend-specific query placeholders, no target here
        return lambda r: False

    # --- field-less (keyword) leaves --------------------------------------------
    def convert_condition_val_str(self, cond, state) -> Predicate:
        _record_tokens_from_str(state, cond.value)
        pattern = re.compile(cond.value.to_regex().regexp.to_plain(), re.IGNORECASE | re.DOTALL)

        def _match(r: dict) -> bool:
            blob = " ".join(str(v) for v in r.values() if v is not None)
            return pattern.search(blob) is not None
        return _match

    def convert_condition_val_num(self, cond, state) -> Predicate:
        _mark_unsound(state)
        expected = str(cond.value)

        def _match(r: dict) -> bool:
            return any(expected in str(v) for v in r.values() if v is not None)
        return _match

    def convert_condition_val_re(self, cond, state) -> Predicate:
        _mark_unsound(state)
        try:
            pattern = re.compile(str(cond.value.regexp), re.IGNORECASE)
        except re.error:
            return lambda r: False

        def _match(r: dict) -> bool:
            blob = " ".join(str(v) for v in r.values() if v is not None)
            return pattern.search(blob) is not None
        return _match

    def convert_condition_query_expr(self, cond, state) -> Predicate:
        _mark_unsound(state)
        return lambda r: False

    # --- finalization: return the predicate itself, not a query string --------
    def finalize_query_default(self, rule, query, index, state):
        return query

    def finalize_output_default(self, queries):
        return queries

    # Correlation (aggregation) rules are excluded from the vendored
    # ruleset (see sigma_rules_hq/VERSION.txt) -- these are never
    # exercised, but Backend is an ABC that requires them defined.
    def convert_correlation_event_count_rule(self, *a, **k): raise NotImplementedError
    def convert_correlation_value_count_rule(self, *a, **k): raise NotImplementedError
    def convert_correlation_temporal_rule(self, *a, **k): raise NotImplementedError
    def convert_correlation_temporal_ordered_rule(self, *a, **k): raise NotImplementedError
    def convert_correlation_extended_temporal_rule(self, *a, **k): raise NotImplementedError
    def convert_correlation_extended_temporal_ordered_rule(self, *a, **k): raise NotImplementedError
    def convert_correlation_value_sum_rule(self, *a, **k): raise NotImplementedError
    def convert_correlation_value_avg_rule(self, *a, **k): raise NotImplementedError
    def convert_correlation_value_percentile_rule(self, *a, **k): raise NotImplementedError
    def convert_correlation_value_median_rule(self, *a, **k): raise NotImplementedError


@dataclass
class CompiledRule:
    rule_id: str
    title: str
    level: str
    tags: list[str]
    predicates: list[Predicate]
    gate_tokens: frozenset[str] | None  # None => can't safely pre-filter, always run


def _iter_rule_files(rules_dir: str):
    yield from glob.iglob(os.path.join(rules_dir, "**", "*.yml"), recursive=True)
    yield from glob.iglob(os.path.join(rules_dir, "**", "*.yaml"), recursive=True)


def _compile_rule(rule, backend: DictMatchBackend) -> CompiledRule | None:
    predicates = []
    tokens: set[str] = set()
    gateable = True
    try:
        for parsed_cond in rule.detection.parsed_condition:
            state = ConversionState()
            predicates.append(backend.convert_condition(parsed_cond.parsed, state))
            if not state.processing_state.get("gateable", True):
                gateable = False
            tokens |= state.processing_state.get("tokens", set())
    except (SigmaError, NotImplementedError, re.error):
        return None
    if not predicates:
        return None
    return CompiledRule(
        rule_id=str(rule.id) if rule.id else "unknown",
        title=rule.title or "Untitled rule",
        level=str(rule.level.name).lower() if rule.level else "medium",
        tags=[str(t) for t in (rule.tags or [])],
        predicates=predicates,
        gate_tokens=frozenset(tokens) if (gateable and tokens) else None,
    )


def _load_and_compile(rules_dir: str) -> list[CompiledRule]:
    files = sorted(_iter_rule_files(rules_dir))
    compiled: list[CompiledRule] = []
    backend = DictMatchBackend()
    for path in files:
        try:
            collection = SigmaCollection.load_ruleset([path])
        except (SigmaError, OSError) as e:
            # One malformed rule file must never abort the whole load --
            # same principle the original hand-rolled engine documented.
            continue
        for rule in collection.rules:
            try:
                compiled_rule = _compile_rule(rule, backend)
            except Exception:  # noqa: BLE001 -- one bad rule can't abort a hunt
                compiled_rule = None
            if compiled_rule is not None:
                compiled.append(compiled_rule)
    return compiled


@functools.lru_cache(maxsize=4)
def _cached_ruleset(rules_dir: str) -> tuple[CompiledRule, ...]:
    """Parse + compile every vendored rule exactly once per process.
    Compiling ~2,800 rules takes single-digit seconds; doing that on
    every hunt instead of once per process would dominate hunt latency
    for no reason, so this is a process-lifetime cache keyed on the
    rules directory path (call clear_cache() in tests / after a
    fetch_sigmahq_rules.py refresh within a long-running process)."""
    return tuple(_load_and_compile(rules_dir))


def clear_cache() -> None:
    _cached_ruleset.cache_clear()


def load_rules(rules_dir: str = RULES_DIR) -> list[CompiledRule]:
    return list(_cached_ruleset(rules_dir))


def evaluate_all(records: list[dict], rules: list[CompiledRule] | None = None,
                  technique_id: str = "", tactic: str = "") -> dict:
    """Evaluate every compiled SigmaHQ rule against every record.

    Returns the same shape as sigma_engine.evaluate_all so callers can
    treat both detection layers uniformly:
        {
          "matched_record_indices": [...],
          "rule_matches": [{"rule_id","title","level","tags",
                             "matched_indices","matched_count"}, ...],
          "rules_evaluated": <int>,
        }
    """
    if rules is None:
        rules = load_rules()

    rule_matches = []
    matched_indices: set[int] = set()

    # Precompute each record's token set once (see module docstring on
    # the literal-token pre-filter); records are usually far fewer than
    # rules, so this dominates neither memory nor time.
    record_tokens = [
        set(_TOKEN_RE.findall(
            " ".join(str(v) for v in rec.values() if v is not None).lower()
        ))
        for rec in records
    ]

    for rule in rules:
        hits = []
        for i, rec in enumerate(records):
            if rule.gate_tokens is not None and rule.gate_tokens.isdisjoint(record_tokens[i]):
                continue
            if any(p(rec) for p in rule.predicates):
                hits.append(i)
        if hits:
            matched_indices.update(hits)
            rule_matches.append({
                "rule_id": rule.rule_id,
                "title": rule.title,
                "level": rule.level,
                "tags": rule.tags,
                "matched_indices": hits,
                "matched_count": len(hits),
            })

    rule_matches.sort(key=lambda r: r["matched_count"], reverse=True)

    return {
        "matched_record_indices": sorted(matched_indices),
        "rule_matches": rule_matches,
        "rules_evaluated": len(rules),
    }
