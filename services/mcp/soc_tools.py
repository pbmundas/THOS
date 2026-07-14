import asyncio

from services.mcp.mcp_client import call_tool
from services.orchestration.state import HuntState
from services.detection import sigma_engine, sigmahq_engine
from services.detection.anomaly_scoring import score_rare_events


def _keyword_matches(log: dict, event_ids: list[str], keywords: list[str]) -> bool:
    event = str(log.get("event", "")).lower()
    detail = str(log.get("detail", "")).lower()
    if any(event == eid.lower() or event.endswith(f":{eid.lower()}") for eid in event_ids):
        return True
    return any(kw in detail for kw in keywords)


def _merge_rule_matches(hq_matches: list[dict], local_matches: list[dict]) -> list[dict]:
    """Combine rule_matches from both Sigma layers into one sorted list,
    tagging each with its source engine so the reasoning node (and the
    text summary below) can tell a broad SigmaHQ hit apart from one of
    THOS's own hand-tuned rules."""
    combined = [{**rm, "source": "sigmahq"} for rm in hq_matches]
    combined += [{**rm, "source": "thos"} for rm in local_matches]
    combined.sort(key=lambda r: r["matched_count"], reverse=True)
    return combined


async def run_soc_tools_node(state: HuntState) -> dict:
    """
    Runs the SOC tool suite against the processed logs before handing off
    to the reasoning node — full-fledged version.

    Three matching layers, all real (deterministic) evaluations against
    every processed log record, not cosmetic LLM-drafted text:

    1. SigmaHQ rule engine (services/detection/sigmahq_engine.py): loads
       the vendored SigmaHQ community ruleset in
       services/detection/sigma_rules_hq/ (parsed with pySigma, not a
       hand-rolled parser — see that module's docstring for why) and
       evaluates every rule's real detection logic against every record.
       This is the primary signal and the one with actual breadth —
       thousands of community-maintained rules vs. a handful of
       hand-written ones, so "did we miss something" has real coverage
       behind it.

    2. THOS's own Sigma rule engine (services/detection/sigma_engine.py):
       a small set of hand-written, hand-tuned rules aimed specifically
       at this platform's 8-field normalized schema. Kept as a
       supplementary high-precision layer — these were never the
       problem, thin *coverage* was, and SigmaHQ doesn't replace
       platform-specific tuning, it complements it.

    3. LLM-derived indicator matcher (derive_detection_indicators): for
       hypotheses/techniques neither static rule set covers yet, falls
       back to LLM-grounded event-IDs/keywords, substring-matched the
       same deterministic way.

    Records matched by ANY layer are tagged so the reasoning node sees
    exactly which layer(s) — and which specific rule(s) — flagged them.

    LIMITATION (unchanged from Phase 1, now shared by all three layers):
    the normalized log schema here only has 8 generic fields (timestamp/
    host/user/event/src_ip/dst_ip/detail/source_file) — there's no
    structured GrantedAccess/TargetImage/CommandLine extraction, so every
    layer matches on `event` + substring/regex search inside the raw
    `detail` blob rather than fully parsed structured fields. See
    sigmahq_engine.py's and sigma_engine.py's module docstrings for the
    full grounded limitations list.
    """
    processed_logs = state.get("processed_logs", [])
    hypothesis_text = state.get("hypothesis_text", "")
    technique_id = state.get("technique_id", "") or ""
    technique_name = state.get("technique_name", "") or ""
    tactic = state.get("tactic", "") or ""

    # --- All three layers are independent of each other — the two Sigma
    # engines are CPU-bound and synchronous (sigmahq_engine's rule count is
    # ~2 orders of magnitude larger, so it gets its own thread rather than
    # sharing one with sigma_engine), the indicator call is a network-bound
    # LLM call — so run them concurrently instead of paying their
    # latencies sequentially.
    sigmahq_result, sigma_result, indicators = await asyncio.gather(
        asyncio.to_thread(
            sigmahq_engine.evaluate_all, processed_logs, technique_id=technique_id, tactic=tactic
        ),
        asyncio.to_thread(
            sigma_engine.evaluate_all, processed_logs, technique_id=technique_id, tactic=tactic
        ),
        call_tool("derive_detection_indicators", {
            "hypothesis_text": hypothesis_text,
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
        }),
    )
    indicators = indicators or {}
    sigmahq_matched_set = set(sigmahq_result["matched_record_indices"])
    sigma_matched_set = set(sigma_result["matched_record_indices"])

    event_ids = indicators.get("event_ids", [])
    keywords = indicators.get("keywords", [])

    llm_matched_set = {i for i, log in enumerate(processed_logs)
                       if _keyword_matches(log, event_ids, keywords)}

    all_matched = sorted(sigmahq_matched_set | sigma_matched_set | llm_matched_set)

    # Tag every matched record in place so the reasoning node can see,
    # per-record, which layer(s) flagged it and by which rule.
    rule_titles_by_index: dict[int, list[str]] = {}
    for source, result in (("sigmahq", sigmahq_result), ("thos", sigma_result)):
        for rm in result["rule_matches"]:
            for idx in rm["matched_indices"]:
                rule_titles_by_index.setdefault(idx, []).append(
                    f"[{source}] {rm['rule_id']}:{rm['title']}"
                )

    for i in all_matched:
        if 0 <= i < len(processed_logs):
            processed_logs[i]["_sigma_match"] = True
            processed_logs[i]["_sigma_rules"] = rule_titles_by_index.get(i, [])
            processed_logs[i]["_sigmahq_match"] = i in sigmahq_matched_set
            processed_logs[i]["_llm_indicator_match"] = i in llm_matched_set

    sigma_rule_summary = _merge_rule_matches(
        [{"rule_id": rm["rule_id"], "title": rm["title"], "level": rm["level"],
          "matched_count": rm["matched_count"]} for rm in sigmahq_result["rule_matches"]],
        [{"rule_id": rm["rule_id"], "title": rm["title"], "level": rm["level"],
          "matched_count": rm["matched_count"]} for rm in sigma_result["rule_matches"]],
    )

    total_matched_records = len(sigmahq_matched_set | sigma_matched_set)
    total_rules_evaluated = sigmahq_result["rules_evaluated"] + sigma_result["rules_evaluated"]
    total_rules_matched = len(sigmahq_result["rule_matches"]) + len(sigma_result["rule_matches"])

    sigma_rule_text = (
        f"# Sigma rule evaluation — {sigmahq_result['rules_evaluated']} SigmaHQ rule(s) + "
        f"{sigma_result['rules_evaluated']} THOS rule(s) loaded "
        f"({total_rules_evaluated} total), {total_rules_matched} rule(s) matched, "
        f"{total_matched_records} of {len(processed_logs)} record(s) matched.\n"
    )
    if sigmahq_result["rules_evaluated"] == 0:
        sigma_rule_text += (
            "#   NOTE: services/detection/sigma_rules_hq/ is empty — run "
            "services/detection/fetch_sigmahq_rules.py to vendor the SigmaHQ ruleset "
            "before relying on this layer.\n"
        )
    for rm in sigma_rule_summary:
        sigma_rule_text += (
            f"#   [{rm['source']}][{rm['level']}] {rm['rule_id']} — {rm['title']}: "
            f"{rm['matched_count']} match(es)\n"
        )
    sigma_rule_text += (
        f"# Supplementary LLM-derived indicator layer (for techniques with no "
        f"static rule hit): event IDs {event_ids or '(none)'}, keywords {keywords or '(none)'}, "
        f"{len(llm_matched_set)} additional record(s) matched.\n"
    )

    return {
        "sigma_rule": sigma_rule_text,
        "sigma_matched_count": len(all_matched),
        "sigma_matched_refs": all_matched,
        "sigma_rule_matches": sigma_rule_summary,
        "enrichment": {
            "technique_id": technique_id,
            "log_count_analyzed": len(processed_logs),
            "sigmahq_rules_evaluated": sigmahq_result["rules_evaluated"],
            "sigmahq_rules_matched": len(sigmahq_result["rule_matches"]),
            "sigmahq_matched_records": len(sigmahq_matched_set),
            "thos_rules_evaluated": sigma_result["rules_evaluated"],
            "thos_rules_matched": len(sigma_result["rule_matches"]),
            "thos_matched_records": len(sigma_matched_set),
            "sigma_rules_evaluated": total_rules_evaluated,
            "sigma_rules_matched": total_rules_matched,
            "sigma_matched_records": total_matched_records,
            "llm_indicator_event_ids": event_ids,
            "llm_indicator_keywords": keywords,
            "llm_indicator_matched_records": len(llm_matched_set),
        },
        "anomaly_scores": score_rare_events(processed_logs),
    }
