"""SOC enrichment node with SIEM-side Sigma query pushdown."""
from __future__ import annotations

import asyncio
import json

from services.detection import sigma_engine, sigmahq_engine
from services.detection.anomaly_scoring import score_rare_events
from services.detection.sigma_detection_agent import LOCAL_SOURCES, query_sigma_for_hunt
from services.mcp.mcp_client import call_tool
from services.orchestration.state import HuntState


def _keyword_matches(log: dict, event_ids: list[str], keywords: list[str]) -> bool:
    event = str(log.get("event", "")).lower()
    detail = str(log.get("detail", "")).lower()
    return (any(event == eid.lower() or event.endswith(f":{eid.lower()}") for eid in event_ids)
            or any(keyword in detail for keyword in keywords))


def _record_key(record: dict) -> str:
    return json.dumps({key: record.get(key) for key in
                       ("timestamp", "host", "user", "event", "src_ip", "dst_ip", "detail")},
                      sort_keys=True, default=str)


def _merge_query_records(existing: list[dict], queried: list[dict], matches: list[dict]) -> tuple[list[dict], list[dict]]:
    by_key = {_record_key(record): index for index, record in enumerate(existing)}
    local_to_merged: dict[int, int] = {}
    for local_index, record in enumerate(queried):
        key = _record_key(record)
        merged_index = by_key.get(key)
        if merged_index is None:
            merged_index = len(existing)
            existing.append(record)
            by_key[key] = merged_index
        else:
            target = existing[merged_index]
            target["_sigma_match"] = target.get("_sigma_match") or record.get("_sigma_match")
            target["_sigmahq_match"] = target.get("_sigmahq_match") or record.get("_sigmahq_match")
            target["_sigma_rules"] = sorted(set(target.get("_sigma_rules", [])) |
                                                   set(record.get("_sigma_rules", [])))
        local_to_merged[local_index] = merged_index
    for match in matches:
        match["matched_indices"] = [local_to_merged[index] for index in match.get("matched_indices", [])
                                    if index in local_to_merged]
    return existing, matches


async def run_soc_tools_node(state: HuntState) -> dict:
    processed_logs = list(state.get("processed_logs", []) or [])
    hypothesis_text = state.get("hypothesis_text", "") or ""
    technique_id = state.get("technique_id", "") or ""
    technique_name = state.get("technique_name", "") or ""
    tactic = state.get("tactic", "") or ""
    siem_type = (state.get("siem_type", "mock") or "mock").lower()

    indicator_call = call_tool("derive_detection_indicators", {
        "hypothesis_text": hypothesis_text, "technique_id": technique_id,
        "technique_name": technique_name, "tactic": tactic,
    })

    if siem_type in LOCAL_SOURCES:
        # A folder has no query engine. Keep the deterministic in-process
        # evaluator as the explicit local compatibility path.
        sigmahq_result, sigma_result, indicators = await asyncio.gather(
            asyncio.to_thread(sigmahq_engine.evaluate_all, processed_logs,
                              technique_id=technique_id, tactic=tactic),
            asyncio.to_thread(sigma_engine.evaluate_all, processed_logs,
                              technique_id=technique_id, tactic=tactic),
            indicator_call,
        )
        rule_matches = ([{**match, "source": "sigmahq"} for match in sigmahq_result["rule_matches"]] +
                        [{**match, "source": "thos"} for match in sigma_result["rule_matches"]])
        rules_evaluated = sigmahq_result["rules_evaluated"] + sigma_result["rules_evaluated"]
        coverage = {"mode": "local", "unsupported": 0, "truncated": 0}
        sigma_refs = set(sigmahq_result["matched_record_indices"]) | set(sigma_result["matched_record_indices"])
        for match in rule_matches:
            for index in match.get("matched_indices", []):
                if 0 <= index < len(processed_logs):
                    record = processed_logs[index]
                    record["_sigma_match"] = True
                    record.setdefault("_sigma_rules", []).append(
                        f"[{match['source']}] {match['rule_id']}:{match['title']}"
                    )
                    record["_sigmahq_match"] = (
                        record.get("_sigmahq_match", False) or match["source"] == "sigmahq"
                    )
    else:
        # Sigma SIEM queries and the model indicator call are independent I/O.
        # Run them concurrently; only events matched by a targeted query cross
        # the SIEM boundary.
        pushed, indicators = await asyncio.gather(
            query_sigma_for_hunt(siem_type=siem_type, technique_id=technique_id, tactic=tactic),
            indicator_call,
        )
        processed_logs, rule_matches = _merge_query_records(
            processed_logs, pushed["processed_logs"], pushed["rule_matches"]
        )
        sigma_refs = {index for match in rule_matches for index in match.get("matched_indices", [])}
        rules_evaluated = pushed["rules_evaluated"]
        coverage = {**pushed["coverage"], "mode": "siem_query_pushdown", "errors": pushed["errors"]}

    indicators = indicators or {}
    event_ids = [str(value) for value in indicators.get("event_ids", [])]
    keywords = [str(value).lower() for value in indicators.get("keywords", [])]
    llm_refs = {index for index, log in enumerate(processed_logs)
                if _keyword_matches(log, event_ids, keywords)}
    for index, record in enumerate(processed_logs):
        record["_llm_indicator_match"] = index in llm_refs
    all_refs = sorted(sigma_refs | llm_refs)
    rule_matches.sort(key=lambda item: item.get("matched_count", 0), reverse=True)

    mode_text = ("locally evaluated because the source has no query engine" if siem_type in LOCAL_SOURCES
                 else "precompiled and executed in the SIEM; only matched events were returned")
    sigma_rule_text = (
        f"# Detection query execution — {rules_evaluated} applicable rule query/rules(s) {mode_text}; "
        f"{len(rule_matches)} rule(s) matched {len(sigma_refs)} record(s).\n"
    )
    if coverage.get("unsupported") or coverage.get("truncated") or coverage.get("errors"):
        sigma_rule_text += (
            f"# Coverage — unsupported={coverage.get('unsupported', 0)}, "
            f"truncated={coverage.get('truncated', 0)}, execution_errors={len(coverage.get('errors', []))}.\n"
        )
    for match in rule_matches:
        sigma_rule_text += (
            f"#   [{match['source']}][{match['level']}] {match['rule_id']} — {match['title']}: "
            f"{match['matched_count']} match(es)\n"
        )
    sigma_rule_text += (
        f"# Supplementary model-derived indicators: event IDs {event_ids or '(none)'}, "
        f"keywords {keywords or '(none)'}, {len(llm_refs)} record(s) matched.\n"
    )

    sigmahq_matches = [item for item in rule_matches if item.get("source") == "sigmahq"]
    thos_matches = [item for item in rule_matches if item.get("source") == "thos"]
    return {
        "processed_logs": processed_logs,
        "sigma_rule": sigma_rule_text,
        "sigma_matched_count": len(all_refs), "sigma_matched_refs": all_refs,
        "sigma_rule_matches": [{key: value for key, value in item.items() if key != "matched_indices"}
                               for item in rule_matches],
        "enrichment": {
            "technique_id": technique_id, "log_count_analyzed": len(processed_logs),
            "sigma_execution_mode": coverage.get("mode"), "sigma_query_coverage": coverage,
            "sigmahq_rules_evaluated": rules_evaluated if siem_type not in LOCAL_SOURCES else
                                       sigmahq_result["rules_evaluated"],
            "sigmahq_rules_matched": len(sigmahq_matches),
            "sigmahq_matched_records": len({i for m in sigmahq_matches for i in m.get("matched_indices", [])}),
            "thos_rules_evaluated": 0 if siem_type not in LOCAL_SOURCES else sigma_result["rules_evaluated"],
            "thos_rules_matched": len(thos_matches),
            "thos_matched_records": len({i for m in thos_matches for i in m.get("matched_indices", [])}),
            "sigma_rules_evaluated": rules_evaluated, "sigma_rules_matched": len(rule_matches),
            "sigma_matched_records": len(sigma_refs), "llm_indicator_event_ids": event_ids,
            "llm_indicator_keywords": keywords, "llm_indicator_matched_records": len(llm_refs),
        },
        "anomaly_scores": score_rare_events(processed_logs),
    }
