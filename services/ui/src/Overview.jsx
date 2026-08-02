import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowPathIcon,
  BoltIcon,
  ChartBarSquareIcon,
  CheckCircleIcon,
  CircleStackIcon,
  ClockIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon,
  FingerPrintIcon,
  GlobeAltIcon,
  QueueListIcon,
  ShieldExclamationIcon,
  SparklesIcon,
} from "@heroicons/react/24/outline";

const PERIODS = [
  { value: 24, label: "Last 24 hours" },
  { value: 168, label: "Last 7 days" },
  { value: 720, label: "Last 30 days" },
  { value: 2160, label: "Last 90 days" },
];

async function api(path) {
  const response = await fetch(path);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || payload.error || `Request failed (${response.status})`);
  return payload;
}

function number(value) {
  return Number(value || 0).toLocaleString();
}

function duration(value) {
  const milliseconds = Number(value || 0);
  if (!milliseconds) return "0m";
  if (milliseconds < 60_000) return `${Math.round(milliseconds / 1000)}s`;
  if (milliseconds < 3_600_000) return `${Math.round(milliseconds / 60_000)}m`;
  return `${(milliseconds / 3_600_000).toFixed(1)}h`;
}

function shortTime(value, hours) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return hours <= 48
    ? date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : date.toLocaleDateString([], { month: "short", day: "numeric" });
}

function activityTone(level) {
  const normalized = String(level || "INFO").toLowerCase();
  if (normalized === "error") return "error";
  if (normalized === "warning") return "warning";
  return "info";
}

function displayOperationalText(value) {
  return String(value || "")
    .replace(/SigmaHQ/gi, "Community")
    .replace(/sigma[_\s-]*detection/gi, "detection monitoring")
    .replace(/Sigma/gi, "detection rule");
}

function MetricCard({ icon: Icon, label, value, note, tone = "indigo", onClick }) {
  const content = <>
    <span className={`overview-metric-icon ${tone}`}><Icon /></span>
    <span><small>{label}</small><strong>{value}</strong><em>{note}</em></span>
  </>;
  return onClick
    ? <button className="overview-metric panel" onClick={onClick}>{content}</button>
    : <article className="overview-metric panel">{content}</article>;
}

export default function Overview({ onNavigate }) {
  const [hours, setHours] = useState(24);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [operationsResult, risksResult] = await Promise.allSettled([
        api(`/api/dashboard/operations?hours=${hours}`),
        api(`/api/risks?limit=1000&hours=${hours}`),
      ]);
      const operations = operationsResult.status === "fulfilled" ? operationsResult.value : {};
      const risks = risksResult.status === "fulfilled" ? risksResult.value : { summary: {}, items: [] };
      setData((current) => ({ ...(current || {}), ...operations, risks }));
      const failures = [operationsResult, risksResult]
        .filter((result) => result.status === "rejected")
        .map((result) => result.reason?.message || "Data source unavailable");
      if (failures.length) setError(failures.join(" · "));
    } catch (reason) {
      setError(reason.message);
    } finally {
      setLoading(false);
    }
  }, [hours]);

  useEffect(() => {
    load();
    const timer = window.setInterval(load, 30_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const summary = data?.summary || {};
  const riskSummary = data?.risks?.summary || {};
  const platform = data?.platform || {};
  const trend = data?.trend || [];
  const maxTrend = Math.max(1, ...trend.flatMap((item) => [
    Number(item.hunts || 0), Number(item.detections || 0), Number(item.events || 0),
  ]));
  const totalOutcomes = Math.max(1, Number(summary.hunts_total || 0));
  const completedAngle = Number(summary.hunts_completed || 0) * 360 / totalOutcomes;
  const failedAngle = completedAngle + Number(summary.hunts_failed || 0) * 360 / totalOutcomes;
  const outcomeStyle = {
    background: `conic-gradient(#12b76a 0deg ${completedAngle}deg, #f04438 ${completedAngle}deg ${failedAngle}deg, #6366f1 ${failedAngle}deg 360deg)`,
  };
  const maxAgent = Math.max(1, ...(data?.agent_performance || []).map((item) => Number(item.total_duration_ms || 0)));
  const severityTotal = Math.max(1, ...(data?.detection_severity || []).map((item) => Number(item.events || 0)));
  const latestGenerated = useMemo(
    () => data?.generated_at ? new Date(data.generated_at).toLocaleString() : "Not loaded",
    [data?.generated_at],
  );

  return <div className="page-wrap overview-page">
    <section className="overview-heading">
      <div>
        <span className="status-pill status-indigo"><SparklesIcon /> Daily operations</span>
        <h1>Security operations overview</h1>
        <p>Live hunt, detection, forensic, workflow, and platform health for the selected operating window.</p>
      </div>
      <div className="overview-period">
        <label htmlFor="overview-period">Time period</label>
        <select id="overview-period" value={hours} onChange={(event) => setHours(Number(event.target.value))}>
          {PERIODS.map((period) => <option key={period.value} value={period.value}>{period.label}</option>)}
        </select>
        <button onClick={load} disabled={loading} aria-label="Refresh overview"><ArrowPathIcon className={loading ? "spinning" : ""} /></button>
        <small>Updated {latestGenerated}</small>
      </div>
    </section>

    {error && <div className="alert error-alert"><ExclamationTriangleIcon />{error}</div>}

    <section className="overview-metrics" aria-label="Operational metrics">
      <MetricCard icon={ShieldExclamationIcon} label="Actionable risks" value={number(riskSummary.total)} note={`${number(Number(riskSummary.critical || 0) + Number(riskSummary.high || 0))} critical / high`} tone={(riskSummary.critical || riskSummary.high) ? "red" : "green"} onClick={() => onNavigate("risks")} />
      <MetricCard icon={BoltIcon} label="Hunts completed" value={number(summary.hunts_completed)} note={`${number(summary.hunts_running)} running · ${number(summary.hunts_failed)} failed`} tone={summary.hunts_failed ? "red" : "green"} onClick={() => onNavigate("reports")} />
      <MetricCard icon={CheckCircleIcon} label="Completion rate" value={`${Number(summary.completion_rate || 0).toFixed(1)}%`} note={`${number(summary.hypotheses_hunted)} unique hypotheses`} tone="green" />
      <MetricCard icon={ShieldExclamationIcon} label="Detection events" value={number(summary.matched_events)} note={`${number(summary.detections_triggered)} triggered rules`} tone={summary.matched_events ? "red" : "slate"} onClick={() => onNavigate("detections")} />
      <MetricCard icon={CircleStackIcon} label="Records analyzed" value={number(summary.records_analyzed)} note={`${duration(summary.avg_hunt_duration_ms)} average hunt`} tone="cyan" />
      <MetricCard icon={SparklesIcon} label="Model work avoided" value={number(summary.model_reasoning_skipped)} note={`${number(summary.degraded_hunts)} degraded completions`} tone="purple" />
      <MetricCard icon={DocumentTextIcon} label="Reports created" value={number(platform.report_library_created ?? summary.reports_created)} note="Hunt and forensic library" tone="indigo" onClick={() => onNavigate("reports")} />
      <MetricCard icon={FingerPrintIcon} label="Forensic cases" value={number(summary.forensic_cases)} note={`${number(summary.forensics_running)} currently running`} tone="amber" onClick={() => onNavigate("forensics")} />
      <MetricCard icon={ExclamationTriangleIcon} label="Workflow errors" value={number(summary.tool_errors)} note={`${number(platform.schedule_failures)} failed schedules`} tone={(summary.tool_errors || platform.schedule_failures) ? "red" : "green"} />
    </section>

    <section className="operating-kpi-framework">
      <article className="kpi-domain impact panel">
        <header><span><ShieldExclamationIcon /></span><div><h2>Security impact KPIs</h2><p>Current exposure requiring analyst decisions</p></div><button onClick={() => onNavigate("risks")}>View risks</button></header>
        <div className="kpi-domain-grid">
          <span><small>Risk exposure</small><strong>{Number(riskSummary.average_score || 0).toFixed(1)}<em>/100</em></strong></span>
          <span><small>Affected entities</small><strong>{number(riskSummary.affected_entities)}</strong></span>
          <span><small>Report findings</small><strong>{number(riskSummary.report_findings)}</strong></span>
          <span><small>Detection findings</small><strong>{number(riskSummary.detection_findings)}</strong></span>
        </div>
      </article>
      <article className="kpi-domain efficiency panel">
        <header><span><BoltIcon /></span><div><h2>Operational efficiency</h2><p>How effectively THOS converts telemetry into decisions</p></div></header>
        <div className="kpi-domain-grid">
          <span><small>Workflow success</small><strong>{Number(summary.completion_rate || 0).toFixed(1)}<em>%</em></strong></span>
          <span><small>Average hunt</small><strong>{duration(summary.avg_hunt_duration_ms)}</strong></span>
          <span><small>Reasoning avoided</small><strong>{number(summary.model_reasoning_skipped)}</strong></span>
          <span><small>Records reviewed</small><strong>{number(summary.records_analyzed)}</strong></span>
        </div>
      </article>
      <article className="kpi-domain communication panel">
        <header><span><DocumentTextIcon /></span><div><h2>Communication framework</h2><p>One evidence set, tailored for each operating audience</p></div></header>
        <div className="communication-lanes">
          <span><strong>Leadership</strong><small>Risk score, affected entities, and security impact trend</small></span>
          <span><strong>SOC operations</strong><small>Detection evidence, hunt outcomes, and response priorities</small></span>
          <span><strong>Governance</strong><small>Reports, audit trail, degraded runs, and control assurance</small></span>
        </div>
      </article>
    </section>

    <section className="overview-grid">
      <article className="overview-card overview-trend panel">
        <header><div><span><ChartBarSquareIcon /></span><div><h2>Operations trend</h2><p>Hunts, triggered detections, and matched events over time</p></div></div><div className="overview-legend"><span className="hunt">Hunts</span><span className="detect">Detections</span><span className="event">Events</span></div></header>
        <div className="trend-chart" role="img" aria-label="Operations trend bar chart">
          {trend.map((item, index) => <div className="trend-column" key={item.bucket || index}>
            <div className="trend-bars">
              <i className="hunt" style={{ height: `${Math.max(2, Number(item.hunts || 0) * 100 / maxTrend)}%` }} title={`${item.hunts} hunts`} />
              <i className="detect" style={{ height: `${Math.max(2, Number(item.detections || 0) * 100 / maxTrend)}%` }} title={`${item.detections} detections`} />
              <i className="event" style={{ height: `${Math.max(2, Number(item.events || 0) * 100 / maxTrend)}%` }} title={`${item.events} events`} />
            </div>
            {(trend.length <= 16 || index % Math.ceil(trend.length / 12) === 0) && <small>{shortTime(item.bucket, hours)}</small>}
          </div>)}
          {!trend.length && <p className="overview-empty">No trend data in this period.</p>}
        </div>
      </article>

      <article className="overview-card overview-outcomes panel">
        <header><div><span><CheckCircleIcon /></span><div><h2>Hunt outcomes</h2><p>Workflow reliability in this period</p></div></div></header>
        <div className="outcome-body">
          <div className="outcome-ring" style={outcomeStyle}><span><strong>{number(summary.hunts_total)}</strong><small>total hunts</small></span></div>
          <div className="outcome-list">
            <span className="green"><i />Completed<strong>{number(summary.hunts_completed)}</strong></span>
            <span className="red"><i />Failed<strong>{number(summary.hunts_failed)}</strong></span>
            <span className="indigo"><i />Running<strong>{number(summary.hunts_running)}</strong></span>
          </div>
        </div>
      </article>

      <article className="overview-card panel">
        <header><div><span><ShieldExclamationIcon /></span><div><h2>Detection severity</h2><p>Matched event volume by rule severity</p></div></div></header>
        <div className="severity-bars">
          {(data?.detection_severity || []).map((item) => <div key={item.severity}>
            <span><strong>{item.severity}</strong><small>{number(item.runs)} runs · {number(item.events)} events</small></span>
            <div><i className={`severity-${item.severity}`} style={{ width: `${Math.max(2, Number(item.events || 0) * 100 / severityTotal)}%` }} /></div>
          </div>)}
          {!data?.detection_severity?.length && <p className="overview-empty">No scheduled detection activity.</p>}
        </div>
      </article>

      <article className="overview-card panel">
        <header><div><span><ClockIcon /></span><div><h2>Agent workload</h2><p>Total execution time and average latency</p></div></div></header>
        <div className="agent-bars">
          {(data?.agent_performance || []).slice(0, 8).map((item) => <div key={item.node_name}>
            <span><strong>{item.agent_name || item.node_name}</strong><small>{number(item.executions)} runs · avg {duration(item.avg_duration_ms)}</small></span>
            <div><i style={{ width: `${Math.max(2, Number(item.total_duration_ms || 0) * 100 / maxAgent)}%` }} /></div>
          </div>)}
          {!data?.agent_performance?.length && <p className="overview-empty">No agent timing data.</p>}
        </div>
      </article>
    </section>

    <section className="overview-detail-grid">
      <article className="overview-card panel">
        <header><div><span><QueueListIcon /></span><div><h2>Most active hypotheses</h2><p>Highest hunt frequency in the selected period</p></div></div></header>
        <div className="overview-table">
          <div className="overview-table-head"><span>Hypothesis</span><span>Runs</span><span>Success</span><span>Last run</span></div>
          {(data?.top_hypotheses || []).map((item) => <div key={item.hypothesis_id}>
            <span><strong>{item.hypothesis_id}</strong><small>{item.title}</small></span>
            <span>{number(item.runs)}</span>
            <span className={item.failed ? "text-red" : "text-green"}>{number(item.completed)} / {number(item.runs)}</span>
            <span>{new Date(item.last_run_at).toLocaleString()}</span>
          </div>)}
          {!data?.top_hypotheses?.length && <p className="overview-empty">No hypothesis runs in this period.</p>}
        </div>
      </article>

      <article className="overview-card overview-platform panel">
        <header><div><span><GlobeAltIcon /></span><div><h2>Platform readiness</h2><p>Services supporting daily operations</p></div></div></header>
        <div className="readiness-grid">
          <span><strong>{number(platform.telemetry_sources)}</strong><small>Active telemetry sources</small></span>
          <span><strong>{number(platform.enabled_schedules)}</strong><small>Enabled schedules</small></span>
          <span className={platform.schedule_failures ? "danger" : ""}><strong>{number(platform.schedule_failures)}</strong><small>Failed schedules</small></span>
          <span><strong>{number(platform.connected_integrations)}</strong><small>Connected integrations</small></span>
        </div>
      </article>
    </section>

    <article className="overview-card overview-activity panel">
      <header><div><span><QueueListIcon /></span><div><h2>Recent operational activity</h2><p>Timestamped workflow, detection, forensic, and error events</p></div></div><button onClick={() => onNavigate("settings", "audit")}>Open audit logs</button></header>
      <div className="activity-list">
        {(data?.recent_activity || []).slice(0, 12).map((item) => <div key={item.id}>
          <i className={activityTone(item.level)} />
          <time>{new Date(item.timestamp).toLocaleString()}</time>
          <span><strong>{displayOperationalText(item.message)}</strong><small>{displayOperationalText(item.service)} · {displayOperationalText(item.category)} · {item.actor || "system"}</small></span>
          <em>{item.duration_ms != null ? duration(item.duration_ms) : item.level}</em>
        </div>)}
        {!data?.recent_activity?.length && <p className="overview-empty">No recent activity was recorded.</p>}
      </div>
    </article>
  </div>;
}
