import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowDownTrayIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  ChevronRightIcon,
  ExclamationTriangleIcon,
  MagnifyingGlassIcon,
  ShieldExclamationIcon,
} from "@heroicons/react/24/outline";


async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  });
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

function timestamp(value, fallback = "Not available") {
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toLocaleString() : fallback;
}

function valueOrFallback(value, fallback = "Not available") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

const ACTIVE_REFRESH_MS = 2_000;
const IDLE_REFRESH_MS = 15_000;

export default function Risks({ onOpenRisk, session }) {
  const [payload, setPayload] = useState({ summary: {}, items: [] });
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");
  const [status, setStatus] = useState("active");
  const [periodDays, setPeriodDays] = useState("30");
  const [loading, setLoading] = useState(true);
  const [resolvingId, setResolvingId] = useState("");
  const [error, setError] = useState("");
  const requestVersionRef = useRef(0);

  const load = useCallback((force = false, background = false) => {
    const requestVersion = ++requestVersionRef.current;
    if (!background) setLoading(true);
    const hours = Number(periodDays) > 0 ? Number(periodDays) * 24 : 0;
    const request = api(`/api/risks?limit=1000&hours=${hours}${force ? "&refresh=true" : ""}`)
      .then((nextPayload) => {
        if (requestVersion === requestVersionRef.current) {
          setPayload(nextPayload);
          setError("");
        }
        return nextPayload;
      })
      .catch((reason) => {
        if (requestVersion === requestVersionRef.current) setError(reason.message);
        return null;
      })
      .finally(() => {
        if (!background && requestVersion === requestVersionRef.current) setLoading(false);
      });
    return request;
  }, [periodDays]);

  useEffect(() => {
    let cancelled = false;
    let timer;
    const schedule = (nextPayload) => {
      if (cancelled) return;
      const isActive = ["pending", "refreshing"].includes(nextPayload?.refresh?.status);
      timer = window.setTimeout(async () => {
        const refreshed = await load(false, true);
        schedule(refreshed || nextPayload);
      }, isActive ? ACTIVE_REFRESH_MS : IDLE_REFRESH_MS);
    };
    load().then(schedule);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [load]);

  const items = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (payload.items || []).filter((item) => {
      if (severity !== "all" && item.severity !== severity) return false;
      if (source !== "all" && item.source_type !== source) return false;
      const isActive = item.active !== false && item.status !== "resolved";
      if (status === "active" && !isActive) return false;
      if (status === "inactive" && isActive) return false;
      if (!needle) return true;
      return `${displayDetectionText(item.name)} ${displayDetectionText(item.description)} ${displayDetectionText(item.what)} ${displayDetectionText(item.why)} ${displayDetectionText(item.discovery)} ${item.entity?.type} ${item.entity?.name} ${displayDetectionText(item.source_label)} ${item.source_id} ${(item.evidence_refs || []).join(" ")}`
        .toLowerCase().includes(needle);
    });
  }, [payload.items, query, severity, source, status]);

  const summary = payload.summary || {};
  const canResolve = ["Admin", "SME"].includes(session?.role);
  const resolveRisk = async (item, event) => {
    event.stopPropagation();
    if (!canResolve || item.active === false || item.status === "resolved") return;
    setResolvingId(item.id);
    try {
      const resolution = await api(`/api/risks/${encodeURIComponent(item.id)}/resolve`, {
        method: "PATCH",
        body: JSON.stringify({ note: "Resolved from the Risks page" }),
      });
      setPayload((current) => ({
        ...current,
        items: (current.items || []).map((risk) => risk.id === item.id ? {
          ...risk,
          ...resolution,
          status: "resolved",
          active: false,
        } : risk),
        summary: {
          ...(current.summary || {}),
          total: Math.max(0, Number(current.summary?.total || 0) - 1),
          inactive: Number(current.summary?.inactive || 0) + 1,
          [item.severity]: Math.max(0, Number(current.summary?.[item.severity] || 0) - 1),
        },
      }));
      setError("");
      await load(false, true);
    } catch (reason) {
      setError(reason.message);
    } finally {
      setResolvingId("");
    }
  };
  const exportRisks = () => {
    const columns = [
      ["Risk ID", (item) => item.id],
      ["Name", (item) => displayDetectionText(item.name)],
      ["Description", (item) => displayDetectionText(item.description)],
      ["What", (item) => displayDetectionText(item.what)],
      ["Why", (item) => displayDetectionText(item.why)],
      ["Discovery", (item) => displayDetectionText(item.discovery)],
      ["Entity type", (item) => item.entity?.type],
      ["Entity", (item) => item.entity?.name],
      ["Score", (item) => item.score],
      ["Severity", (item) => item.severity],
      ["Status", (item) => item.status],
      ["Identified at", (item) => item.identified_at],
      ["Last seen at", (item) => item.last_seen_at],
      ["Age", (item) => age(item.identified_at)],
      ["Evidence source", (item) => displayDetectionText(item.source_label)],
      ["Source ID", (item) => item.source_id],
      ["Evidence references", (item) => (item.evidence_refs || []).join("; ")],
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
      <article className="panel"><small>Open risks</small><strong>{Number(summary.total || 0).toLocaleString()}</strong><span>{Number(summary.critical || 0)} critical · {Number(summary.high || 0)} high · {Number(summary.medium || 0)} medium · {Number(summary.low || 0)} low</span><span>{Number(summary.reviewed_candidates || 0)} evidence candidates reviewed · {Number(summary.excluded_candidates || 0)} excluded</span></article>
      <article className="panel critical"><small>Critical / high</small><strong>{Number(summary.critical || 0) + Number(summary.high || 0)}</strong><span>Prioritize analyst review</span></article>
      <article className="panel"><small>Affected entities</small><strong>{Number(summary.affected_entities || 0).toLocaleString()}</strong><span>Hosts, users, IPs, and techniques</span></article>
      <article className="panel"><small>Average score</small><strong>{Number(summary.average_score || 0).toFixed(1)}</strong><span>Out of 100</span></article>
      <article className="panel"><small>Inactive risks</small><strong>{Number(summary.inactive || 0).toLocaleString()}</strong><span>Resolved by an Admin or SME</span></article>
      <article className="panel"><small>Last analyzed</small><strong className="risk-summary-time">{payload.generated_at ? age(payload.generated_at) : "Processing"}</strong><span>{timestamp(payload.generated_at, "Waiting for the first automatic analysis")}</span></article>
    </section>

    <section className="risk-controls panel">
      <label className="risk-search"><MagnifyingGlassIcon /><input aria-label="Search risks" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search risk, entity, evidence, or source" /></label>
      <label>Period<select aria-label="Risk period" value={periodDays} onChange={(event) => setPeriodDays(event.target.value)}><option value="1">Last 1 day</option><option value="7">Last 7 days</option><option value="14">Last 14 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option><option value="180">Last 180 days</option><option value="365">Last 365 days</option><option value="0">All time</option></select></label>
      <label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
      <label>Evidence source<select value={source} onChange={(event) => setSource(event.target.value)}><option value="all">All sources</option><option value="hunt_report">Hunt reports</option><option value="detection">Detections</option></select></label>
      <label>Status<select value={status} onChange={(event) => setStatus(event.target.value)}><option value="active">Active</option><option value="inactive">Inactive / resolved</option><option value="all">All statuses</option></select></label>
      <span>{items.length.toLocaleString()} visible risk{items.length === 1 ? "" : "s"}</span>
    </section>

    {error && <div className="alert error-alert"><ExclamationTriangleIcon />{error}</div>}
    {(["pending", "refreshing"].includes(payload.refresh?.status)) && <div className="alert"><ArrowPathIcon className="spinning" />The Risk Analysis Agent is processing newly persisted reports and detections. Existing results remain available and this page refreshes automatically.</div>}
    {payload.refresh?.status === "failed" && <div className="alert error-alert"><ExclamationTriangleIcon />The latest risk refresh failed. The previous verified snapshot remains available. {payload.refresh?.error}</div>}

    <section className="risk-register panel">
      <div className="risk-register-head"><span>Risk</span><span>Required details and rationale</span><span>Entity</span><span>Score</span><span>Severity</span><span>Timeline</span><span>Evidence source</span><span>Action</span></div>
      {items.map((item) => <article className={`risk-entry ${item.active === false ? "inactive" : ""}`} key={item.id} role="button" tabIndex={0} onClick={() => onOpenRisk(item)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") onOpenRisk(item); }}>
        <span className="risk-name"><strong>{valueOrFallback(displayDetectionText(item.name))}</strong><small>{item.active === false ? "Inactive / resolved" : "Open / active"} · {item.source_type === "hunt_report" ? "Hunt report" : "Detection"} · {Number(item.evidence_count || 0)} evidence item{Number(item.evidence_count || 0) === 1 ? "" : "s"}</small><small>ID: {valueOrFallback(item.id)}</small>{item.resolved_at && <small>Resolved {timestamp(item.resolved_at)} by {valueOrFallback(item.resolved_by)}</small>}</span>
        <span className="risk-description"><strong>{valueOrFallback(displayDetectionText(item.description))}</strong><small><b>What:</b> {valueOrFallback(displayDetectionText(item.what))}</small><small><b>Why:</b> {valueOrFallback(displayDetectionText(item.why))}</small><small><b>Discovered:</b> {valueOrFallback(displayDetectionText(item.discovery))}</small></span>
        <span className="risk-entity"><strong>{item.entity?.name || "Unknown"}</strong><small>{item.entity?.type || "Entity"}</small></span>
        <span className="risk-score"><strong>{item.score}</strong><i><b style={{ width: `${item.score}%` }} /></i></span>
        <span><em className={`risk-severity severity-${item.severity}`}>{item.severity}</em></span>
        <span className="risk-age"><strong>Identified {age(item.identified_at)}</strong><small>{timestamp(item.identified_at)}</small><small>Last seen: {timestamp(item.last_seen_at)}</small></span>
        <span className="risk-source"><strong>{valueOrFallback(displayDetectionText(item.source_label))}</strong><small>{item.source_type === "hunt_report" ? "Report" : "Detection"} ID: {valueOrFallback(item.source_id)}</small><small>Refs: {(item.evidence_refs || []).map(displayDetectionText).join(", ") || "Not available"}</small></span>
        <span className="risk-action">{item.active === false ? <em className="risk-state-resolved"><CheckCircleIcon /> Inactive</em> : canResolve ? <button type="button" onClick={(event) => resolveRisk(item, event)} disabled={resolvingId === item.id}>{resolvingId === item.id ? <ArrowPathIcon className="spinning" /> : <CheckCircleIcon />} Resolve</button> : <ChevronRightIcon />}</span>
      </article>)}
      {!loading && !items.length && <div className="risk-empty"><ShieldExclamationIcon /><h3>No actionable risks match</h3><p>Change the filters, or run hunts and scheduled detections to generate evidence.</p></div>}
      {loading && !items.length && <div className="risk-empty"><ArrowPathIcon className="spinning" /><h3>Analyzing persisted evidence</h3><p>The Risk Analysis Agent is correlating reports and detections.</p></div>}
    </section>
  </div>;
}
