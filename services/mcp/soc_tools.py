import asyncio

from services.mcp.mcp_client import call_tool
from services.orchestration.state import HuntState
from services.detection import sigma_engine


def _keyword_matches(log: dict, event_ids: list[str], keywords: list[str]) -> bool:
    event = str(log.get("event", "")).lower()
    detail = str(log.get("detail", "")).lower()
    if any(event == eid.lower() or event.endswith(f":{eid.lower()}") for eid in event_ids):
        return True
    return any(kw in detail for kw in keywords)


async def run_soc_tools_node(state: HuntState) -> dict:
    """
    Runs the SOC tool suite against the processed logs before handing off
    to the reasoning node — full-fledged version.

    Two matching layers, both real (deterministic) evaluations against
    every processed log record, not cosmetic LLM-drafted text:

    1. Sigma rule engine (services/detection/sigma_engine.py): loads the
       real Sigma-style YAML rules in services/detection/sigma_rules/ and
       evaluates each one's actual detection logic (field selections +
       condition) against every record. This is the primary signal.

    2. LLM-derived indicator matcher (derive_detection_indicators): for
       hypotheses/techniques the static Sigma rule set doesn't cover yet,
       falls back to LLM-grounded event-IDs/keywords, substring-matched
       the same deterministic way. Records matched by EITHER layer are
       tagged so the reasoning node sees exactly which layer(s) flagged
       them.

    LIMITATION (unchanged from Phase 1): the normalized log schema here
    only has 8 generic fields (timestamp/host/user/event/src_ip/dst_ip/
    detail/source_file) — there's no structured GrantedAccess/TargetImage/
    CommandLine extraction, so both layers match on `event` + substring
    search inside the raw `detail` blob rather than fully parsed
    structured fields. See sigma_engine.py's module docstring for the
    full grounded limitations list.
    """
    processed_logs = state.get("processed_logs", [])
    hypothesis_text = state.get("hypothesis_text", "")
    technique_id = state.get("technique_id", "") or ""
    technique_name = state.get("technique_name", "") or ""
    tactic = state.get("tactic", "") or ""

    # --- Layer 1 (deterministic Sigma) and Layer 2 (LLM-derived indicators) are
    # independent of each other — the Sigma engine is CPU-bound and synchronous,
    # the indicator call is a network-bound LLM call, so run them concurrently
    # instead of paying their latencies sequentially.
    sigma_result, indicators = await asyncio.gather(
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
    sigma_matched_set = set(sigma_result["matched_record_indices"])

    event_ids = indicators.get("event_ids", [])
    keywords = indicators.get("keywords", [])

    llm_matched_set = {i for i, log in enumerate(processed_logs)
                       if _keyword_matches(log, event_ids, keywords)}

    all_matched = sorted(sigma_matched_set | llm_matched_set)

    # Tag every matched record in place so the reasoning node can see,
    # per-record, which layer(s) flagged it and by which rule.
    rule_titles_by_index: dict[int, list[str]] = {}
    for rm in sigma_result["rule_matches"]:
        for idx in rm["matched_indices"]:
            rule_titles_by_index.setdefault(idx, []).append(f"{rm['rule_id']}:{rm['title']}")

    for i in all_matched:
        if 0 <= i < len(processed_logs):
            processed_logs[i]["_sigma_match"] = True
            processed_logs[i]["_sigma_rules"] = rule_titles_by_index.get(i, [])
            processed_logs[i]["_llm_indicator_match"] = i in llm_matched_set

    sigma_rule_summary = [
        {"rule_id": rm["rule_id"], "title": rm["title"], "level": rm["level"],
         "matched_count": rm["matched_count"]}
        for rm in sigma_result["rule_matches"]
    ]

    sigma_rule_text = (
        f"# Sigma rule evaluation — {sigma_result['rules_evaluated']} rules loaded, "
        f"{len(sigma_result['rule_matches'])} rule(s) matched, "
        f"{len(sigma_matched_set)} of {len(processed_logs)} record(s) matched.\n"
    )
    for rm in sigma_result["rule_matches"]:
        sigma_rule_text += f"#   [{rm['level']}] {rm['rule_id']} — {rm['title']}: {rm['matched_count']} match(es)\n"
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
            "sigma_rules_evaluated": sigma_result["rules_evaluated"],
            "sigma_rules_matched": len(sigma_result["rule_matches"]),
            "sigma_matched_records": len(sigma_matched_set),
            "llm_indicator_event_ids": event_ids,
            "llm_indicator_keywords": keywords,
            "llm_indicator_matched_records": len(llm_matched_set),
        },
    }
