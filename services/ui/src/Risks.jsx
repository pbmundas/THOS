import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowDownTrayIcon,
  ArrowPathIcon,
  ChevronRightIcon,
  ExclamationTriangleIcon,
  MagnifyingGlassIcon,
  ShieldExclamationIcon,
} from "@heroicons/react/24/outline";


async function api(path) {
  const response = await fetch(path);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || payload.error || `Request failed (${response.status})`);
  return payload;
}

function displayDetectionText(value) {
  return String(value || "")
    .replace(/SigmaHQ/gi, "Community")
    .replace(/Sigma/gi, "Detection rule");
}

function age(value) {
  const milliseconds = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "just now";
  const days = Math.floor(milliseconds / 86_400_000);
  if (days < 1) {
    const hours = Math.max(1, Math.floor(milliseconds / 3_600_000));
    return `${hours} hour${hours === 1 ? "" : "s"} old`;
  }
  if (days < 31) return `${days} day${days === 1 ? "" : "s"} old`;
  const months = Math.floor(days / 30.44);
  if (months < 12) return `${months} month${months === 1 ? "" : "s"} old`;
  const years = Math.floor(days / 365.25);
  return `${years} year${years === 1 ? "" : "s"} old`;
}

export default function Risks({ onOpenRisk }) {
  const [payload, setPayload] = useState({ summary: {}, items: [] });
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async (force = false) => {
    setLoading(true);
    setError("");
    try {
      setPayload(await api(`/api/risks?limit=1000${force ? "&refresh=true" : ""}`));
    } catch (reason) {
      setError(reason.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = window.setInterval(() => load(false), 15_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const items = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (payload.items || []).filter((item) => {
      if (severity !== "all" && item.severity !== severity) return false;
      if (source !== "all" && item.source_type !== source) return false;
      if (!needle) return true;
      return `${displayDetectionText(item.name)} ${displayDetectionText(item.description)} ${item.entity?.type} ${item.entity?.name} ${displayDetectionText(item.source_label)}`
        .toLowerCase().includes(needle);
    });
  }, [payload.items, query, severity, source]);

  const summary = payload.summary || {};
  const exportRisks = () => {
    const columns = [
      ["Risk ID", (item) => item.id],
      ["Name", (item) => displayDetectionText(item.name)],
      ["Description", (item) => displayDetectionText(item.description)],
      ["Entity type", (item) => item.entity?.type],
      ["Entity", (item) => item.entity?.name],
      ["Score", (item) => item.score],
      ["Severity", (item) => item.severity],
      ["Identified at", (item) => item.identified_at],
      ["Age", (item) => age(item.identified_at)],
      ["Evidence source", (item) => displayDetectionText(item.source_label)],
      ["Source ID", (item) => item.detection_run_id || item.hunt_id || ""],
    ];
    const csv = [columns.map(([label]) => label), ...items.map((item) => columns.map(([, read]) => read(item) ?? ""))]
      .map((row) => row.map((value) => `"${String(value).replaceAll("\"", "\"\"")}"`).join(","))
      .join("\r\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `thos-risks-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return <div className="page-wrap risks-page">
    <section className="page-heading">
      <div>
        <span className="status-pill status-red"><ShieldExclamationIcon /> Evidence-correlated exposure</span>
        <h1>Actionable security risks</h1>
        <p>Prioritized risks produced from verifier-supported hunt findings and detections with matched events.</p>
      </div>
      <div className="page-heading-actions"><button className="secondary-button" onClick={exportRisks} disabled={!items.length}><ArrowDownTrayIcon /> Export risks</button><button className="secondary-button" onClick={() => load(true)} disabled={loading}><ArrowPathIcon className={loading ? "spinning" : ""} /> Re-analyze risks</button></div>
    </section>

    <section className="risk-summary-grid">
      <article className="panel"><small>Open risks</small><strong>{Number(summary.total || 0).toLocaleString()}</strong><span>Across reports and detections</span></article>
      <article className="panel critical"><small>Critical / high</small><strong>{Number(summary.critical || 0) + Number(summary.high || 0)}</strong><span>Prioritize analyst review</span></article>
      <article className="panel"><small>Affected entities</small><strong>{Number(summary.affected_entities || 0).toLocaleString()}</strong><span>Hosts, users, IPs, and techniques</span></article>
      <article className="panel"><small>Average score</small><strong>{Number(summary.average_score || 0).toFixed(1)}</strong><span>Out of 100</span></article>
    </section>

    <section className="risk-controls panel">
      <label className="risk-search"><MagnifyingGlassIcon /><input aria-label="Search risks" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search risk, entity, evidence, or source" /></label>
      <label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
      <label>Evidence source<select value={source} onChange={(event) => setSource(event.target.value)}><option value="all">All sources</option><option value="hunt_report">Hunt reports</option><option value="detection">Detections</option></select></label>
      <span>{items.length.toLocaleString()} visible risk{items.length === 1 ? "" : "s"}</span>
    </section>

    {error && <div className="alert error-alert"><ExclamationTriangleIcon />{error}</div>}
    {(["pending", "refreshing"].includes(payload.refresh?.status)) && <div className="alert"><ArrowPathIcon className="spinning" />The Risk Analysis Agent is processing newly persisted reports and detections. Existing results remain available and this page refreshes automatically.</div>}
    {payload.refresh?.status === "failed" && <div className="alert error-alert"><ExclamationTriangleIcon />The latest risk refresh failed. The previous verified snapshot remains available. {payload.refresh?.error}</div>}

    <section className="risk-register panel">
      <div className="risk-register-head"><span>Risk</span><span>Description and rationale</span><span>Entity</span><span>Score</span><span>Severity</span><span>Age</span><span /></div>
      {items.map((item) => <button className="risk-entry" key={item.id} onClick={() => onOpenRisk(item)}>
        <span className="risk-name"><strong>{displayDetectionText(item.name)}</strong><small>{item.source_type === "hunt_report" ? "Hunt report" : "Detection"} · {item.evidence_count} evidence item{item.evidence_count === 1 ? "" : "s"}</small></span>
        <span className="risk-description"><strong>{displayDetectionText(item.what)}</strong><small><b>Why:</b> {displayDetectionText(item.why)}</small><small><b>Discovered:</b> {displayDetectionText(item.discovery)}</small></span>
        <span className="risk-entity"><strong>{item.entity?.name || "Unknown"}</strong><small>{item.entity?.type || "Entity"}</small></span>
        <span className="risk-score"><strong>{item.score}</strong><i><b style={{ width: `${item.score}%` }} /></i></span>
        <span><em className={`risk-severity severity-${item.severity}`}>{item.severity}</em></span>
        <span className="risk-age"><strong>{age(item.identified_at)}</strong><small>{new Date(item.identified_at).toLocaleString()}</small></span>
        <ChevronRightIcon />
      </button>)}
      {!loading && !items.length && <div className="risk-empty"><ShieldExclamationIcon /><h3>No actionable risks match</h3><p>Change the filters, or run hunts and scheduled detections to generate evidence.</p></div>}
      {loading && !items.length && <div className="risk-empty"><ArrowPathIcon className="spinning" /><h3>Analyzing persisted evidence</h3><p>The Risk Analysis Agent is correlating reports and detections.</p></div>}
    </section>
  </div>;
}
