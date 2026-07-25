import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowPathIcon, ExclamationTriangleIcon, MagnifyingGlassIcon, ShieldExclamationIcon } from "@heroicons/react/24/outline";


async function api(path) {
  const response = await fetch(path);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || payload.error || `Request failed (${response.status})`);
  return payload;
}

function displaySource(value) {
  return String(value || "Local").replace(/SigmaHQ/gi, "Community").replace(/Sigma/gi, "Detection rule");
}


export default function Detections() {
  const [items, setItems] = useState([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState("");
  const load = useCallback(async () => {
    setLoading(true); setError("");
    try { const payload = await api("/api/detections?limit=200"); setItems(Array.isArray(payload) ? payload : []); }
    catch (reason) { setError(reason.message); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return items.filter((item) => !needle || `${item.rule_id} ${item.rule_title} ${displaySource(item.rule_source)} ${item.siem_type}`.toLowerCase().includes(needle));
  }, [items, query]);

  return <div className="page-wrap detections-page">
    <section className="page-heading"><div><span className="status-pill status-red"><ShieldExclamationIcon /> Scheduled detection monitoring</span><h1>Detection Operations</h1><p>Review matched events from enabled scheduled detection-rule executions. Hypothesis-hunt observations remain separated from operational detections.</p></div><button className="secondary-button" onClick={load} disabled={loading}><ArrowPathIcon className={loading ? "spinning" : ""} /> Refresh detections</button></section>
    <section className="detection-filter panel"><MagnifyingGlassIcon /><input aria-label="Search detections" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search rule ID, title, source, or SIEM…" /><span>{filtered.length} detection run(s)</span></section>
    {error && <div className="alert error-alert"><ExclamationTriangleIcon />{error}</div>}
    <div className="detection-list">
      {filtered.map((item) => {
        const runId = String(item.run_id);
        const events = Array.isArray(item.matched_events) ? item.matched_events : [];
        const analysis = item.analysis || {};
        return <article className="detection-card panel" key={runId}>
          <header><span className={`detection-level level-${String(item.level || "medium").toLowerCase()}`}>{item.level || "medium"}</span><div><h2>{item.rule_title || item.rule_id}</h2><p>{displaySource(item.rule_source)} · {item.rule_id}</p></div><div className="detection-run-meta"><strong>{item.events_matched} matched event(s)</strong><small>{new Date(item.created_at).toLocaleString()} · {item.siem_type}</small></div></header>
          <div className="detection-analysis"><strong>Scheduled-rule analysis</strong><p>{analysis.summary}</p><span>{analysis.distinct_hosts || 0} host(s)</span><span>{analysis.distinct_users || 0} user(s)</span><span>{analysis.first_event_at || "No timestamp"} → {analysis.last_event_at || "No timestamp"}</span></div>
          <button className="detection-expand" onClick={() => setExpanded(expanded === runId ? "" : runId)}>{expanded === runId ? "Hide matched events" : "Show matched events"}</button>
          {expanded === runId && <div className="detection-events"><table><thead><tr><th>Time</th><th>Host</th><th>User</th><th>Event</th><th>Source / detail</th></tr></thead><tbody>{events.map((event, index) => <tr key={`${event.record_ref}-${index}`}><td>{event.timestamp || "—"}</td><td>{event.host || "—"}</td><td>{event.user || "—"}</td><td>{event.event || "—"}</td><td><strong>{event.source_file || "Telemetry"}</strong><span>{event.detail || `${event.src_ip || ""} ${event.dst_ip || ""}`.trim() || "—"}</span></td></tr>)}</tbody></table></div>}
        </article>;
      })}
      {!loading && !filtered.length && <div className="empty-state panel"><span className="empty-icon"><ShieldExclamationIcon /></span><h3>No scheduled detections</h3><p>Only scheduled rules that matched one or more events are displayed.</p></div>}
    </div>
  </div>;
}
