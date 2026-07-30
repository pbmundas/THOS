import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowPathIcon, BeakerIcon, BookOpenIcon, CheckCircleIcon, ClockIcon,
  CloudArrowUpIcon, Cog6ToothIcon, CpuChipIcon, ExclamationTriangleIcon,
  GlobeAltIcon, KeyIcon, MagnifyingGlassIcon, PencilSquareIcon, PlusIcon, QueueListIcon, ShieldCheckIcon, TrashIcon,
  UserCircleIcon, UserGroupIcon,
} from "@heroicons/react/24/outline";

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = payload.detail || payload.error;
    throw new Error(
      typeof detail === "object"
        ? detail.message || JSON.stringify(detail)
        : detail || `Request failed (${response.status})`
    );
  }
  return payload;
}

const jsonOptions = (method, body) => ({ method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const displayDetectionText = (value) => String(value || "")
  .replace(/SigmaHQ/gi, "Community")
  .replace(/sigma[_\s-]*detection/gi, "detection monitoring")
  .replace(/Sigma/gi, "Detection rule");
const CONNECTION_SIEMS = ["wazuh", "elasticsearch", "logrhythm", "splunk", "qradar", "folder"];
const ALL_FEATURES = ["hunts", "forensics", "reports", "chat", "knowledge", "threat_intel", "settings"];
const DETECTION_RULE_TEMPLATE = `title: New detection rule
status: experimental
description: Describe the behavior and intended evidence.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: "\\\\example.exe"
  condition: selection
level: medium
tags:
  - attack.execution
`;
const YARA_RULE_TEMPLATE = `rule New_Local_Rule {
  meta:
    title = "New local rule"
    description = "Describe the matched artifact"
    severity = "medium"
    status = "experimental"
  strings:
    $indicator = "replace_me" ascii wide nocase
  condition:
    $indicator
}
`;

function scheduleLabel(item) {
  const count = Number(item.interval || 1);
  if (item.frequency === "minutes") return `Every ${count} minute${count === 1 ? "" : "s"}, anchored at ${item.time}`;
  if (item.frequency === "hourly") return `Every ${count} hour${count === 1 ? "" : "s"} at minute ${String(item.time || "00:00").slice(3)}`;
  return count === 1 ? `Once a day at ${item.time}` : `${count} times a day, starting at ${item.time}`;
}

function schedulePerformance(item) {
  const stats = Object.values(item.last_result?.target_duration_stats || {});
  const p50 = Math.max(0, ...stats.map((entry) => Number(entry.p50_duration_ms || 0)));
  const p95 = Math.max(0, ...stats.map((entry) => Number(entry.p95_duration_ms || 0)));
  const plan = item.last_result?.adaptive_plan;
  const duration = (milliseconds) => {
    const minutes = Math.round(milliseconds / 60000);
    return minutes < 1 ? "<1m" : `${minutes}m`;
  };
  const parts = [];
  if (p50) parts.push(`p50 ${duration(p50)}`);
  if (p95) parts.push(`p95 ${duration(p95)}`);
  if (plan) {
    parts.push(`adaptive batch ${plan.adaptive_batch_size}`);
    parts.push(`${plan.maintenance_window_minutes}m window`);
  }
  return parts.length ? ` · ${parts.join(" · ")}` : "";
}

function RuleAuthoringPanel({ title, content, onChange, onSave, onCancel, working }) {
  return <section className="rule-authoring">
    <header><div><h4>{title}</h4><p>Only locally managed rules can be edited. Content is validated before it is saved.</p></div></header>
    <textarea value={content} onChange={(event) => onChange(event.target.value)} spellCheck="false" />
    <div className="settings-actions"><button className="primary-button" disabled={working || !content.trim()} onClick={onSave}>{working ? <ArrowPathIcon className="spinning" /> : <CheckCircleIcon />} Validate and save</button><button className="secondary-button" disabled={working} onClick={onCancel}>Cancel</button></div>
  </section>;
}

function Notice({ type = "success", children }) {
  return <div className={`settings-notice ${type}`}><span>{type === "error" ? <ExclamationTriangleIcon /> : <CheckCircleIcon />}</span>{children}</div>;
}

function DayPicker({ value, onChange }) {
  const selected = new Set(value);
  return <div className="day-picker">{DAYS.map((day, index) => <button type="button" className={selected.has(index) ? "active" : ""} key={day} onClick={() => onChange(selected.has(index) ? value.filter((item) => item !== index) : [...value, index].sort())}>{day}</button>)}</div>;
}

function GeneralTab({ activeSources }) {
  const [models, setModels] = useState([]);
  const [form, setForm] = useState({ default_model: "", default_iterations: 2, default_siem: "folder" });
  const [timezone, setTimezone] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [general, available] = await Promise.all([api("/api/settings/general"), api("/api/settings/models")]);
      setForm({ default_model: general.default_model || available.models?.[0]?.name || "", default_iterations: general.default_iterations, default_siem: general.default_siem });
      setTimezone(general.timezone);
      setModels(available.models || []);
    } catch (error) { setNotice(error.message); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);
  const save = async () => {
    try { await api("/api/settings/general", jsonOptions("PUT", form)); setNotice("Runtime defaults saved. New hunts and model calls use them immediately."); }
    catch (error) { setNotice(error.message); }
  };
  return <div className="settings-stack"><section className="settings-card">
    <div className="settings-card-title"><span><CpuChipIcon /></span><div><h3>Model and hunt defaults</h3><p>Models are discovered from the local inference service. No hosted endpoint is used.</p></div></div>
    {notice && <Notice type={notice.includes("saved") ? "success" : "error"}>{notice}</Notice>}
    <div className="settings-form-grid">
      <label>Default local model<select disabled={loading} value={form.default_model} onChange={(event) => setForm({ ...form, default_model: event.target.value })}>{models.map((item) => <option key={item.name} value={item.name}>{item.name} · {(Number(item.size || 0) / 1024 ** 3).toFixed(1)} GB</option>)}</select></label>
      <label>Default hunt iterations<select value={form.default_iterations} onChange={(event) => setForm({ ...form, default_iterations: Number(event.target.value) })}>{[1, 2, 3, 4, 5].map((value) => <option key={value} value={value}>{value}{value === 2 ? " · recommended" : ""}</option>)}</select></label>
      <label>Default telemetry source<select value={form.default_siem} onChange={(event) => setForm({ ...form, default_siem: event.target.value })}>{activeSources.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label>
      <label>Scheduler timezone<input value={timezone} disabled /></label>
    </div>
    <div className="settings-actions"><button className="secondary-button" onClick={load}><ArrowPathIcon /> Refresh models</button><button className="primary-button" onClick={save}><CheckCircleIcon /> Save defaults</button></div>
  </section></div>;
}

function DetectionRulesTab({ activeSources }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [data, setData] = useState({ items: [], total: 0, schedules: [] });
  const [time, setTime] = useState("02:00");
  const [frequency, setFrequency] = useState("daily");
  const [interval, setInterval] = useState(1);
  const [siem, setSiem] = useState(activeSources[0]?.id || "folder");
  const [days, setDays] = useState([0, 1, 2, 3, 4, 5, 6]);
  const [notice, setNotice] = useState("");
  const [editingSchedule, setEditingSchedule] = useState(null);
  const [authoring, setAuthoring] = useState(null);
  const [authoringWorking, setAuthoringWorking] = useState(false);
  const load = useCallback(async () => {
    try { setData(await api(`/api/settings/sigma?query=${encodeURIComponent(query)}&severity=${severity}&page_size=100`)); }
    catch (error) { setNotice(error.message); }
  }, [query, severity]);
  useEffect(() => { const timer = setTimeout(load, 250); return () => clearTimeout(timer); }, [load]);
  useEffect(() => { if (!activeSources.some((item) => item.id === siem)) setSiem(activeSources[0]?.id || "folder"); }, [activeSources, siem]);
  const toggle = async (rule) => {
    try { await api(`/api/settings/sigma/${encodeURIComponent(rule.id)}`, jsonOptions("PUT", { enabled: !rule.enabled })); load(); }
    catch (error) { setNotice(error.message); }
  };
  const editRule = async (rule) => {
    try {
      const result = await api(`/api/settings/sigma/authoring/${encodeURIComponent(rule.id)}`);
      setAuthoring({ id: rule.id, content: result.content, mode: "edit" });
    } catch (error) { setNotice(error.message); }
  };
  const saveRule = async () => {
    if (!authoring) return;
    setAuthoringWorking(true);
    try {
      const target = authoring.mode === "edit"
        ? `/api/settings/sigma/authoring/${encodeURIComponent(authoring.id)}`
        : "/api/settings/sigma/authoring";
      const result = await api(target, jsonOptions(authoring.mode === "edit" ? "PUT" : "POST", { content: authoring.content }));
      setNotice(`Detection rule ${result.id} saved successfully.`);
      setAuthoring(null);
      await load();
    } catch (error) { setNotice(error.message); }
    finally { setAuthoringWorking(false); }
  };
  const intervalMax = frequency === "minutes" ? 59 : 24;
  const schedule = async (rule) => {
    try {
      const bounded = Math.max(1, Math.min(intervalMax, Number(interval) || 1));
      await api("/api/settings/schedules/sigma", jsonOptions("POST", { target_id: rule.id, title: rule.title, time, frequency, interval: bounded, days, enabled: true, siem_type: siem }));
      setNotice(`Scheduled ${displayDetectionText(rule.title)}: ${scheduleLabel({ frequency, interval: bounded, time })} on ${siem}.`);
      load();
    } catch (error) { setNotice(error.message); }
  };
  const scheduleCatalog = async () => {
    try {
      const bounded = Math.max(1, Math.min(intervalMax, Number(interval) || 1));
      await api("/api/settings/schedules/sigma", jsonOptions("POST", {
        target_id: "__all_compatible__", title: "All schema-compatible detection rules",
        schedule_scope: "catalog", time, frequency, interval: bounded, days,
        enabled: true, siem_type: siem,
      }));
      setNotice(`Scheduled all schema-compatible detection rules in rotating batches on ${siem}.`);
      load();
    } catch (error) { setNotice(error.message); }
  };
  const beginEdit = (item) => {
    setEditingSchedule(item);
    setTime(item.time || "02:00");
    setFrequency(item.frequency || "daily");
    setInterval(Number(item.interval || 1));
    setSiem(item.siem_type || activeSources[0]?.id || "folder");
    setDays(item.days || []);
  };
  const saveEdit = async () => {
    if (!editingSchedule) return;
    const bounded = Math.max(1, Math.min(intervalMax, Number(interval) || 1));
    try {
      await api(`/api/settings/schedules/sigma/${editingSchedule.id}`, jsonOptions("PUT", {
        ...editingSchedule, time, frequency, interval: bounded, days,
        enabled: editingSchedule.enabled !== false, siem_type: siem,
      }));
      setNotice(`Updated ${displayDetectionText(editingSchedule.title) || "detection schedule"}.`);
      setEditingSchedule(null);
      load();
    } catch (error) { setNotice(error.message); }
  };
  const remove = async (id) => { await api(`/api/settings/schedules/sigma/${id}`, { method: "DELETE" }); load(); };
  return <div className="settings-stack">
    <section className="settings-card">
      <div className="settings-card-title"><span><ShieldCheckIcon /></span><div><h3>Detection rule catalog</h3><p>{data.total.toLocaleString()} community and local rules. Admins and SMEs can create or edit locally managed rules.</p></div></div>
      {notice && <Notice type={/Scheduled|saved successfully|Updated/.test(notice) ? "success" : "error"}>{notice}</Notice>}
      <div className="settings-actions"><button className="secondary-button" onClick={() => setAuthoring({ id: "", content: DETECTION_RULE_TEMPLATE, mode: "create" })}><PlusIcon /> Create detection rule</button></div>
      {authoring && <RuleAuthoringPanel title={authoring.mode === "edit" ? `Edit ${authoring.id}` : "Create detection rule"} content={authoring.content} onChange={(content) => setAuthoring({ ...authoring, content })} onSave={saveRule} onCancel={() => setAuthoring(null)} working={authoringWorking} />}
      <div className="sigma-controls">
        <input className="sigma-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search rule ID, title, or ATT&CK tag…" />
        <label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></label>
        <label>Frequency<select value={frequency} onChange={(event) => { setFrequency(event.target.value); setInterval(1); }}><option value="minutes">Every N minutes</option><option value="hourly">Every N hours</option><option value="daily">N times per day</option></select></label>
        <label>{frequency === "daily" ? "Runs per day" : "Every"}<input type="number" min="1" max={intervalMax} value={interval} onChange={(event) => setInterval(event.target.value)} /></label>
        <label>First run time<input type="time" value={time} onChange={(event) => setTime(event.target.value)} /></label>
        <label>Active SIEM<select value={siem} onChange={(event) => setSiem(event.target.value)}>{activeSources.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label>
        <DayPicker value={days} onChange={setDays} />
      </div>
      <div className="settings-actions">{editingSchedule ? <><button className="primary-button" disabled={!days.length} onClick={saveEdit}><CheckCircleIcon /> Save schedule changes</button><button className="secondary-button" onClick={() => setEditingSchedule(null)}>Cancel edit</button></> : <button className="primary-button" disabled={!days.length || !["wazuh", "splunk"].includes(siem)} onClick={scheduleCatalog}><ClockIcon /> Schedule all compatible rules</button>}</div>
      <div className="rule-list">{data.items.map((rule) => <div className="rule-row" key={rule.id}><div><strong>{displayDetectionText(rule.title)}</strong><small>{displayDetectionText(rule.source)} · {rule.severity || rule.level} severity · {rule.id}</small></div>{rule.editable && <button className="secondary-button compact" onClick={() => editRule(rule)}><PencilSquareIcon /> Edit</button>}<button className={`switch ${rule.enabled ? "on" : ""}`} onClick={() => toggle(rule)} aria-label={`${rule.enabled ? "Disable" : "Enable"} ${displayDetectionText(rule.title)}`}><span /></button><button className="secondary-button compact" disabled={!rule.enabled || !days.length} onClick={() => schedule(rule)}><ClockIcon /> Schedule</button></div>)}</div>
    </section>
    <section className="settings-card"><h3>Scheduled detection validations</h3><div className="schedule-list">{data.schedules?.map((item) => <div key={item.id}><span><strong>{displayDetectionText(item.title || item.target_id)}</strong><small>{item.severity || "medium"} severity · {scheduleLabel(item)} · {item.siem_type} · {(item.days || []).map((day) => DAYS[day]).join(", ")} · {item.last_status}</small></span><button title="Edit schedule" onClick={() => beginEdit(item)}><PencilSquareIcon /></button><button title="Delete schedule" onClick={() => remove(item.id)}><TrashIcon /></button></div>)}{!data.schedules?.length && <p className="settings-muted">No detection schedules configured.</p>}</div></section>
  </div>;
}

function YaraRulesTab() {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [data, setData] = useState({ items: [], total: 0, schedules: [] });
  const [path, setPath] = useState("/data/log_sources");
  const [time, setTime] = useState("03:00");
  const [days, setDays] = useState([0, 1, 2, 3, 4, 5, 6]);
  const [notice, setNotice] = useState("");
  const [working, setWorking] = useState(false);
  const [editingSchedule, setEditingSchedule] = useState(null);
  const [authoring, setAuthoring] = useState(null);
  const [authoringWorking, setAuthoringWorking] = useState(false);
  const load = useCallback(async () => {
    try { setData(await api(`/api/settings/yara?query=${encodeURIComponent(query)}&severity=${severity}&page_size=100`)); }
    catch (error) { setNotice(error.message); }
  }, [query, severity]);
  useEffect(() => { const timer = setTimeout(load, 250); return () => clearTimeout(timer); }, [load]);
  const toggle = async (rule) => {
    try { await api(`/api/settings/yara/${encodeURIComponent(rule.id)}`, jsonOptions("PUT", { enabled: !rule.enabled })); load(); }
    catch (error) { setNotice(error.message); }
  };
  const editRule = async (rule) => {
    try {
      const result = await api(`/api/settings/yara/authoring/${encodeURIComponent(rule.id)}`);
      setAuthoring({ id: rule.id, content: result.content, mode: "edit" });
    } catch (error) { setNotice(error.message); }
  };
  const saveRule = async () => {
    if (!authoring) return;
    setAuthoringWorking(true);
    try {
      const target = authoring.mode === "edit"
        ? `/api/settings/yara/authoring/${encodeURIComponent(authoring.id)}`
        : "/api/settings/yara/authoring";
      const result = await api(target, jsonOptions(authoring.mode === "edit" ? "PUT" : "POST", { content: authoring.content }));
      setNotice(`YARA rule ${result.id} saved successfully.`);
      setAuthoring(null);
      await load();
    } catch (error) { setNotice(error.message); }
    finally { setAuthoringWorking(false); }
  };
  const scan = async (ruleId = null) => {
    setWorking(true);
    try {
      const result = await api("/api/yara/scan", jsonOptions("POST", { path, recursive: true, rule_id: ruleId }));
      setNotice(`YARA scanned ${result.files_scanned} file(s); ${result.match_count} match(es) found.`);
    } catch (error) { setNotice(error.message); }
    finally { setWorking(false); }
  };
  const schedule = async (rule) => {
    try {
      await api("/api/settings/schedules/yara", jsonOptions("POST", {
        target_id: rule.id, title: rule.title, time, frequency: "daily",
        interval: 1, days, enabled: true, siem_type: "folder", log_source_path: path,
      }));
      setNotice(`Scheduled ${displayDetectionText(rule.title)} against ${path}.`);
      load();
    } catch (error) { setNotice(error.message); }
  };
  const scheduleBundle = async () => {
    try {
      await api("/api/settings/schedules/yara", jsonOptions("POST", {
        target_id: "__all_enabled__", title: "All enabled YARA rules",
        schedule_scope: "catalog", time, frequency: "daily", interval: 1,
        days, enabled: true, siem_type: "folder", log_source_path: path,
      }));
      setNotice(`Scheduled the enabled YARA bundle against changed files under ${path}.`);
      load();
    } catch (error) { setNotice(error.message); }
  };
  const beginEdit = (item) => {
    setEditingSchedule(item);
    setPath(item.log_source_path || "/data/log_sources");
    setTime(item.time || "03:00");
    setDays(item.days || []);
  };
  const saveEdit = async () => {
    if (!editingSchedule) return;
    try {
      await api(`/api/settings/schedules/yara/${editingSchedule.id}`, jsonOptions("PUT", {
        ...editingSchedule, time, days,
        frequency: editingSchedule.frequency || "daily",
        interval: Number(editingSchedule.interval || 1),
        enabled: editingSchedule.enabled !== false,
        siem_type: editingSchedule.siem_type || "folder",
        log_source_path: path,
      }));
      setNotice(`Updated ${editingSchedule.title || "YARA schedule"}.`);
      setEditingSchedule(null);
      load();
    } catch (error) { setNotice(error.message); }
  };
  const remove = async (id) => { await api(`/api/settings/schedules/yara/${id}`, { method: "DELETE" }); load(); };
  return <div className="settings-stack">
    <section className="settings-card">
      <div className="settings-card-title"><span><ShieldCheckIcon /></span><div><h3>YARA rule catalog and scanning</h3><p>Admins and SMEs can create or edit locally managed rules, then scan evidence with bounded resource controls.</p></div></div>
      {notice && <Notice type={/scanned|Scheduled|saved successfully|Updated/.test(notice) ? "success" : "error"}>{notice}</Notice>}
      <div className="settings-actions"><button className="secondary-button" onClick={() => setAuthoring({ id: "", content: YARA_RULE_TEMPLATE, mode: "create" })}><PlusIcon /> Create YARA rule</button></div>
      {authoring && <RuleAuthoringPanel title={authoring.mode === "edit" ? `Edit ${authoring.id}` : "Create YARA rule"} content={authoring.content} onChange={(content) => setAuthoring({ ...authoring, content })} onSave={saveRule} onCancel={() => setAuthoring(null)} working={authoringWorking} />}
      <p className="settings-muted">
        Managed community catalog: {data.catalog?.ready_rules || 0} ready rules from {data.catalog?.ready_files || 0} compatible files
        {data.catalog?.invalid_files ? ` · ${data.catalog.invalid_files} incompatible upstream files quarantined` : ""}
        {data.catalog?.compiled_at ? ` · compiled ${new Date(data.catalog.compiled_at).toLocaleString()}` : ""}.
      </p>
    <div className="sigma-controls"><input className="sigma-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search rule, ATT&CK ID, or title…" /><label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></label><label>Managed evidence path<input value={path} onChange={(event) => setPath(event.target.value)} /></label><label>Schedule time<input type="time" value={time} onChange={(event) => setTime(event.target.value)} /></label><DayPicker value={days} onChange={setDays} /><button className="primary-button" disabled={working || !path} onClick={() => scan()}>{working ? <ArrowPathIcon className="spinning" /> : <BeakerIcon />} Scan enabled rules</button>{editingSchedule ? <><button className="primary-button" disabled={!path || !days.length} onClick={saveEdit}><CheckCircleIcon /> Save schedule changes</button><button className="secondary-button" onClick={() => setEditingSchedule(null)}>Cancel edit</button></> : <button className="secondary-button" disabled={!path || !days.length} onClick={scheduleBundle}><ClockIcon /> Schedule enabled bundle</button>}</div>
    <div className="rule-list">{data.items.map((rule) => <div className="rule-row" key={rule.id}><div><strong>{displayDetectionText(rule.title)}</strong><small>{displayDetectionText(rule.source)} · {rule.category || "local"} · {rule.severity} severity · {rule.compilation_status === "ready" ? "Ready" : "Incompatible"} · {rule.attack || "Unmapped"} · {rule.id}</small>{rule.compilation_error && <small title={rule.compilation_error}>Quarantined: {rule.compilation_error}</small>}</div>{rule.editable && <button className="secondary-button compact" onClick={() => editRule(rule)}><PencilSquareIcon /> Edit</button>}<button disabled={rule.compilation_status !== "ready"} className={`switch ${rule.enabled ? "on" : ""}`} onClick={() => toggle(rule)} aria-label={`${rule.enabled ? "Disable" : "Enable"} ${displayDetectionText(rule.title)}`}><span /></button><button className="secondary-button compact" disabled={!rule.enabled || working} onClick={() => scan(rule.id)}><BeakerIcon /> Scan</button><button className="secondary-button compact" disabled={!rule.enabled || !days.length || !path} onClick={() => schedule(rule)}><ClockIcon /> Schedule</button></div>)}</div>
    </section>
    <section className="settings-card"><h3>Scheduled YARA scans</h3><div className="schedule-list">{data.schedules?.map((item) => <div key={item.id}><span><strong>{displayDetectionText(item.title || item.target_id)}</strong><small>{item.severity || "medium"} severity · {item.time} · {item.log_source_path} · {item.last_status}</small></span><button title="Edit schedule" onClick={() => beginEdit(item)}><PencilSquareIcon /></button><button title="Delete schedule" onClick={() => remove(item.id)}><TrashIcon /></button></div>)}{!data.schedules?.length && <p className="settings-muted">No YARA schedules configured.</p>}</div></section>
  </div>;
}

function KnowledgeTab() {
  const [documents, setDocuments] = useState([]);
  const [file, setFile] = useState(null);
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => { try { setDocuments(await api("/api/knowledge/documents")); } catch (error) { setNotice(error.message); } }, []);
  useEffect(() => { load(); }, [load]);
  const upload = async () => {
    if (!file) return;
    setLoading(true);
    const form = new FormData();
    form.append("file", file);
    try {
      const result = await api("/api/knowledge/upload", { method: "POST", body: form });
      if (result.error) throw new Error(result.error);
      setNotice(`Ingested ${result.filename} into ${result.chunk_count} retrieval chunks.`);
      setFile(null);
      load();
    } catch (error) { setNotice(error.message); }
    finally { setLoading(false); }
  };
  const remove = async (id) => { await api(`/api/knowledge/documents/${id}`, { method: "DELETE" }); load(); };
  return <div className="settings-stack">
    <section className="settings-card"><div className="settings-card-title"><span><BookOpenIcon /></span><div><h3>Organizational knowledge base</h3><p>Files are extracted, chunked, embedded, and used as grounded retrieval context. This does not retrain model weights.</p></div></div>
      {notice && <Notice type={notice.startsWith("Ingested") ? "success" : "error"}>{notice}</Notice>}
      <div className="upload-zone"><CloudArrowUpIcon /><div><strong>{file?.name || "Choose a reference document"}</strong><small>TXT, Markdown, CSV, JSON, logs, HTML, PDF, or DOCX · maximum 25 MB</small></div><label className="secondary-button">Browse<input type="file" hidden onChange={(event) => setFile(event.target.files?.[0] || null)} /></label><button className="primary-button" disabled={!file || loading} onClick={upload}>{loading ? <ArrowPathIcon className="spinning" /> : <CloudArrowUpIcon />} Ingest knowledge</button></div>
    </section>
    <section className="settings-card"><h3>Ingested documents</h3><div className="document-list">{documents.map((item) => <div key={item.doc_id}><span className="doc-badge">{String(item.content_type || "DOC").replace(".", "").toUpperCase()}</span><span><strong>{item.filename}</strong><small>{item.chunk_count} chunks · {item.ingested_at}</small></span><button onClick={() => remove(item.doc_id)}><TrashIcon /></button></div>)}{!documents.length && <p className="settings-muted">No organizational documents have been ingested.</p>}</div></section>
  </div>;
}

function HypothesisScheduleTab({ hypotheses, activeSources, isAdmin }) {
  const [schedules, setSchedules] = useState([]);
  const [severity, setSeverity] = useState("all");
  const [selectedTargets, setSelectedTargets] = useState([]);
  const [time, setTime] = useState("01:00");
  const [days, setDays] = useState([0, 1, 2, 3, 4]);
  const [siemTypes, setSiemTypes] = useState([activeSources[0]?.id || "folder"]);
  const [notice, setNotice] = useState("");
  const [editingSchedule, setEditingSchedule] = useState(null);
  const load = useCallback(async () => { try { setSchedules(await api("/api/settings/schedules/hypothesis")); } catch (error) { setNotice(error.message); } }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const active = new Set(activeSources.map((item) => item.id));
    setSiemTypes((current) => {
      const valid = current.filter((source) => active.has(source));
      return valid.length ? valid : [activeSources[0]?.id || "folder"];
    });
  }, [activeSources]);
  const severityHypotheses = useMemo(
    () => hypotheses.filter((item) => severity === "all" || (item.severity || "medium") === severity),
    [hypotheses, severity],
  );
  const severitySchedules = useMemo(
    () => schedules.filter((item) => severity === "all" || (item.severity || "medium") === severity),
    [schedules, severity],
  );
  const hypothesisGroups = useMemo(
    () => ["critical", "high", "medium", "low", "unrated"]
      .map((type) => ({
        severity: type,
        items: severityHypotheses.filter((item) => (item.severity || "medium") === type),
      }))
      .filter((group) => group.items.length),
    [severityHypotheses],
  );
  useEffect(() => {
    const available = new Set(severityHypotheses.map((item) => item.id));
    setSelectedTargets((current) => current.filter((id) => available.has(id)));
  }, [severityHypotheses]);
  const toggleTarget = (id) => setSelectedTargets((current) => (
    current.includes(id) ? current.filter((item) => item !== id) : [...current, id]
  ));
  const toggleSource = (id) => setSiemTypes((current) => (
    current.includes(id)
      ? (current.length === 1 ? current : current.filter((item) => item !== id))
      : [...current, id]
  ));
  const allListedSelected = severityHypotheses.length > 0 && selectedTargets.length === severityHypotheses.length;
  const toggleAllListed = () => setSelectedTargets(
    allListedSelected ? [] : severityHypotheses.map((item) => item.id),
  );
  const create = async () => {
    const first = hypotheses.find((item) => item.id === selectedTargets[0]);
    const groupSelected = selectedTargets.length > 1;
    const selectedSeverities = new Set(
      hypotheses
        .filter((item) => selectedTargets.includes(item.id))
        .map((item) => item.severity || "medium"),
    );
    const scheduleSeverity = selectedSeverities.size === 1
      ? Array.from(selectedSeverities)[0]
      : "all";
    try {
      await api("/api/settings/schedules/hypothesis", jsonOptions("POST", {
        target_id: selectedTargets[0],
        target_ids: selectedTargets,
        title: first?.title || selectedTargets[0],
        schedule_scope: groupSelected ? "severity" : "individual",
        severity: scheduleSeverity,
        time,
        days,
        enabled: true,
        siem_type: siemTypes[0],
        siem_types: siemTypes,
      }));
      setNotice(`${groupSelected ? `${scheduleSeverity === "all" ? "Cross-severity" : scheduleSeverity[0].toUpperCase() + scheduleSeverity.slice(1)} group` : "Hypothesis"} schedule created in system local time.`);
      load();
    } catch (error) { setNotice(error.message); }
  };
  const remove = async (id) => { await api(`/api/settings/schedules/hypothesis/${id}`, { method: "DELETE" }); load(); };
  const beginEdit = (item) => {
    setEditingSchedule(item);
    setTime(item.time || "01:00");
    setDays(item.days || []);
    setSiemTypes(
      item.siem_types?.length
        ? item.siem_types
        : [item.siem_type || activeSources[0]?.id || "folder"],
    );
  };
  const saveEdit = async () => {
    if (!editingSchedule) return;
    try {
      await api(`/api/settings/schedules/hypothesis/${editingSchedule.id}`, jsonOptions("PUT", {
        ...editingSchedule, time, days,
        frequency: editingSchedule.frequency || "daily",
        interval: Number(editingSchedule.interval || 1),
        enabled: editingSchedule.enabled !== false,
        siem_type: siemTypes[0],
        siem_types: siemTypes,
      }));
      setNotice(`Updated ${editingSchedule.title || "hypothesis schedule"}.`);
      setEditingSchedule(null);
      load();
    } catch (error) { setNotice(error.message); }
  };
  const applyRecommended = async () => {
    try {
      const result = await api("/api/settings/schedules/recommended", { method: "POST" });
      setNotice(`Recommended load-balanced schedule created for ${result.hypothesis_count} hypotheses, detection rules, and YARA.`);
      load();
    } catch (error) { setNotice(error.message); }
  };
  return <div className="settings-stack">
    <section className="settings-card"><div className="settings-card-title"><span><ClockIcon /></span><div><h3>Hypothesis scheduler</h3><p>Filter by severity, review the resulting hypotheses, select any subset or every listed item, then create one sequential group schedule.</p></div></div>
      {notice && <Notice type={notice.includes("created") ? "success" : "error"}>{notice}</Notice>}
      <div className="settings-form-grid"><label>Severity<select value={severity} onChange={(event) => { setSeverity(event.target.value); setSelectedTargets([]); }}><option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unrated">Unrated</option></select></label><label>Run time<input type="time" value={time} onChange={(event) => setTime(event.target.value)} /></label><div className="source-scope-field"><strong>Telemetry sources</strong><div className="source-scope-options">{activeSources.map((item) => <label key={item.id}><input type="checkbox" checked={siemTypes.includes(item.id)} onChange={() => toggleSource(item.id)} /><span>{item.label}</span></label>)}</div><small>The first selected source is primary; the hunt investigates every selected source.</small></div></div>
      <div className="severity-selection-header"><div><strong>{severity === "all" ? "All severity groups" : `${severity[0].toUpperCase() + severity.slice(1)} severity hypotheses`}</strong><small>{selectedTargets.length} of {severityHypotheses.length} listed hypotheses selected</small></div><span><button className="secondary-button compact" type="button" onClick={toggleAllListed} disabled={!severityHypotheses.length}>{allListedSelected ? "Clear all listed" : "Select all listed"}</button></span></div>
      <div className="hypothesis-schedule-selector">{hypothesisGroups.map((group) => <section className="hypothesis-schedule-group" key={group.severity}><header><span className={`detection-level level-${group.severity}`}>{group.severity}</span><small>{group.items.length}</small></header>{group.items.map((item) => <label key={item.id} className={selectedTargets.includes(item.id) ? "selected" : ""}><input type="checkbox" checked={selectedTargets.includes(item.id)} onChange={() => toggleTarget(item.id)} /><span><strong>{item.id} · {item.title}</strong><small>{item.tactic || "Unassigned tactic"} · {item.technique || "Unmapped"}</small></span></label>)}</section>)}{!severityHypotheses.length && <p className="settings-muted">No hypotheses are assigned to this severity type.</p>}</div>
      <DayPicker value={days} onChange={setDays} />
      <div className="settings-actions">{editingSchedule ? <><button className="primary-button" disabled={!days.length} onClick={saveEdit}><CheckCircleIcon /> Save schedule changes</button><button className="secondary-button" onClick={() => setEditingSchedule(null)}>Cancel edit</button></> : <button className="primary-button" disabled={!selectedTargets.length || !days.length} onClick={create}><PlusIcon /> Schedule selected ({selectedTargets.length})</button>}{isAdmin && !editingSchedule && <button className="secondary-button" onClick={applyRecommended}><ClockIcon /> Apply recommended schedule</button>}</div>
    </section>
    <section className="settings-card"><h3>{severity === "all" ? "All severity schedules" : `${severity[0].toUpperCase() + severity.slice(1)} severity schedules`}</h3><div className="schedule-list">{severitySchedules.map((item) => <div key={item.id}><span><strong>{displayDetectionText(item.title || item.target_id)}</strong><small>Severity: {item.severity || "medium"} · {item.target_count || 1} hypothesis{(item.target_count || 1) === 1 ? "" : "es"} · {item.time} · {(item.siem_types || [item.siem_type]).join(", ")} · {item.days.map((day) => DAYS[day]).join(", ")} · {item.last_status}{schedulePerformance(item)}</small></span><button title="Edit schedule" onClick={() => beginEdit(item)}><PencilSquareIcon /></button><button title="Delete schedule" onClick={() => remove(item.id)}><TrashIcon /></button></div>)}{!severitySchedules.length && <p className="settings-muted">No schedules are configured for this severity view.</p>}</div></section>
  </div>;
}

export function SiemTab({ activeSources, onTelemetryChange }) {
  const [siem, setSiem] = useState("wazuh");
  const [schema, setSchema] = useState({});
  const [values, setValues] = useState({});
  const [configuredSecrets, setConfiguredSecrets] = useState([]);
  const [statuses, setStatuses] = useState([]);
  const [fieldSiem, setFieldSiem] = useState(activeSources[0]?.id || "folder");
  const [fieldFile, setFieldFile] = useState(null);
  const [inventory, setInventory] = useState({ fields: [], field_count: 0 });
  const [notice, setNotice] = useState("");
  const load = useCallback(async () => {
    try {
      const [schemas, saved, state] = await Promise.all([api("/api/settings/siem/schema"), api(`/api/settings/siem/${siem}`), api("/api/settings/siem-status")]);
      setSchema(schemas); setValues(saved.settings || {}); setConfiguredSecrets(saved.configured_secrets || []); setStatuses(state || []);
    } catch (error) { setNotice(error.message); }
  }, [siem]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (!activeSources.some((item) => item.id === fieldSiem)) setFieldSiem(activeSources[0]?.id || "folder"); }, [activeSources, fieldSiem]);
  useEffect(() => { api(`/api/settings/siem/${fieldSiem}`).then((saved) => setInventory(saved.field_inventory || { fields: [], field_count: 0 })).catch((error) => setNotice(error.message)); }, [fieldSiem]);
  const save = async () => { try { await api(`/api/settings/siem/${siem}`, jsonOptions("PUT", { settings: values })); setNotice(`${siem} configuration saved. Test it successfully to make it active.`); await Promise.all([load(), onTelemetryChange()]); } catch (error) { setNotice(error.message); } };
  const test = async () => { try { await api(`/api/settings/siem/${siem}`, jsonOptions("PUT", { settings: values })); const result = await api(`/api/settings/siem/${siem}/test`, { method: "POST" }); setNotice(`${siem} connection succeeded; ${result.record_count} test record(s).`); await Promise.all([load(), onTelemetryChange()]); } catch (error) { setNotice(error.message); } };
  const uploadFields = async () => { if (!fieldFile) return; const form = new FormData(); form.append("file", fieldFile); try { const result = await api(`/api/settings/siem/${fieldSiem}/fields-csv`, { method: "POST", body: form }); setInventory(result); setFieldFile(null); setNotice(`Uploaded ${result.field_count} available fields for ${fieldSiem}.`); } catch (error) { setNotice(error.message); } };
  const discoverFields = async () => { try { setNotice(`Discovering ${fieldSiem} fields and compiling compatible detection rules…`); const result = await api(`/api/settings/siem/${fieldSiem}/discover`, { method: "POST" }); setInventory(result.inventory); setNotice(`Discovered ${result.inventory.field_count} fields; ${result.compilation.ready || 0} detection queries are ready and ${result.compilation.uncompilable || 0} need mapping.`); } catch (error) { setNotice(error.message); } };
  const clearFields = async () => { try { await api(`/api/settings/siem/${fieldSiem}/fields-csv`, { method: "DELETE" }); setInventory({ fields: [], field_count: 0 }); setNotice(`Cleared the field inventory for ${fieldSiem}.`); } catch (error) { setNotice(error.message); } };
  const selectedStatus = statuses.find((item) => item.id === siem);
  return <div className="settings-stack">
    <section className="settings-card"><div className="settings-card-title"><span><BeakerIcon /></span><div><h3>SIEM connection</h3><p>Credentials remain server-side and are never returned to browser JavaScript.</p></div></div>
      {notice && <Notice type={notice.includes("saved") || notice.includes("succeeded") || notice.startsWith("Uploaded") || notice.startsWith("Discovered") ? "success" : "error"}>{notice}</Notice>}
      <div className="settings-form-grid"><label>SIEM platform<select value={siem} onChange={(event) => { setSiem(event.target.value); setNotice(""); }}>{CONNECTION_SIEMS.map((item) => <option key={item}>{item}</option>)}</select></label><label>Connection state<input disabled value={selectedStatus?.active ? "Active · connection tested" : selectedStatus?.status || "Not tested"} /></label>{(schema[siem] || []).map((field) => <label key={field.name}>{field.label}{field.type === "password" && configuredSecrets.includes(field.name) && <small>Stored · leave blank to keep</small>}<input type={field.type} required={field.required} value={values[field.name] || ""} onChange={(event) => setValues({ ...values, [field.name]: event.target.value })} /></label>)}</div>
      <div className="settings-actions"><button className="secondary-button" onClick={save}><CheckCircleIcon /> Save configuration</button><button className="primary-button" onClick={test}><BeakerIcon /> Save, test & activate</button></div>
    </section>
    <section className="settings-card"><div className="settings-card-title"><span><CloudArrowUpIcon /></span><div><h3>Available SIEM log fields</h3><p>Discover from a bounded live sample or upload a one-column CSV. Weekly refresh recompiles compatible detection queries.</p></div></div>
      <div className="settings-form-grid"><label>Active SIEM<select value={fieldSiem} onChange={(event) => { setFieldSiem(event.target.value); setFieldFile(null); }}>{activeSources.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label><label>Current field inventory<input disabled value={inventory.field_count ? `${inventory.field_count} fields · ${inventory.source === "automatic_discovery" ? "live discovery" : inventory.filename || "CSV uploaded"}` : "No field inventory"} /></label></div>
      <div className="field-csv-upload">{fieldSiem !== "folder" && <button className="secondary-button" onClick={discoverFields}><BeakerIcon /> Discover & compile</button>}<label className="secondary-button"><CloudArrowUpIcon /> Choose one-column CSV<input type="file" accept=".csv,text/csv" hidden onChange={(event) => setFieldFile(event.target.files?.[0] || null)} /></label><span>{fieldFile?.name || "No CSV selected"}</span>{inventory.field_count ? <button className="secondary-button" onClick={clearFields}><TrashIcon /> Clear inventory</button> : null}<button className="primary-button" disabled={!fieldFile} onClick={uploadFields}><CloudArrowUpIcon /> Upload fields</button></div>
      {!!inventory.fields?.length && <div className="field-preview">{inventory.fields.slice(0, 18).map((field) => <span key={field}>{field}</span>)}{inventory.fields.length > 18 && <em>+{inventory.fields.length - 18} more</em>}</div>}
    </section>
  </div>;
}

function IOCSourcesTab({ isAdmin }) {
  const initial = { name: "", kind: "remote", location: "", category: "uncategorized", severity: "medium", confidence: "medium", enabled: true, time: "00:00", frequency: "daily", interval: 1, days: [0, 1, 2, 3, 4, 5, 6] };
  const [sources, setSources] = useState([]);
  const [form, setForm] = useState(initial);
  const [file, setFile] = useState(null);
  const [notice, setNotice] = useState("");
  const [working, setWorking] = useState("");
  const [editingSource, setEditingSource] = useState(null);
  const load = useCallback(async () => { try { setSources(await api("/api/settings/ioc-sources")); } catch (error) { setNotice(error.message); } }, []);
  useEffect(() => { load(); }, [load]);
  const create = async () => {
    try {
      if (editingSource) {
        await api(`/api/settings/ioc-sources/${editingSource.id}`, jsonOptions("PUT", form));
        setNotice(`Updated ${form.name}.`);
      } else {
        await api("/api/settings/ioc-sources", jsonOptions("POST", form));
        setNotice(`Added ${form.name}.`);
      }
      setEditingSource(null);
      setForm(initial);
      load();
    }
    catch (error) { setNotice(error.message); }
  };
  const beginEdit = (source) => {
    setEditingSource(source);
    setForm(Object.fromEntries(
      Object.keys(initial).map((key) => [key, source[key] ?? initial[key]]),
    ));
  };
  const upload = async () => {
    if (!file || !form.name.trim()) return;
    const payload = new FormData();
    payload.append("file", file); payload.append("name", form.name); payload.append("category", form.category); payload.append("severity", form.severity); payload.append("confidence", form.confidence);
    try { await api("/api/settings/ioc-sources/upload", { method: "POST", body: payload }); setNotice(`Uploaded ${file.name}. Use Refresh to normalize its indicators.`); setFile(null); load(); }
    catch (error) { setNotice(error.message); }
  };
  const refresh = async (id) => {
    setWorking(id);
    try { const result = await api(`/api/settings/ioc-sources/${id}/refresh`, { method: "POST" }); setNotice(`IOC index updated with ${result.extracted_count || 0} indicator(s).`); load(); }
    catch (error) { setNotice(error.message); }
    finally { setWorking(""); }
  };
  const refreshAll = async () => {
    setWorking("all");
    try { await api("/api/settings/ioc-sources/refresh-all", { method: "POST" }); setNotice("All configured IOC sources were processed."); load(); }
    catch (error) { setNotice(error.message); }
    finally { setWorking(""); }
  };
  const update = async (source, patch) => {
    const payload = Object.fromEntries(["name", "kind", "location", "category", "severity", "confidence", "enabled", "time", "frequency", "interval", "days"].map((key) => [key, patch[key] ?? source[key]]));
    try { await api(`/api/settings/ioc-sources/${source.id}`, jsonOptions("PUT", payload)); load(); }
    catch (error) { setNotice(error.message); }
  };
  const remove = async (id) => {
    if (!window.confirm("Remove this IOC source configuration? Preserved source snapshots remain available to administrators on the server.")) return;
    try { await api(`/api/settings/ioc-sources/${id}`, { method: "DELETE" }); setNotice("IOC source configuration removed."); load(); }
    catch (error) { setNotice(error.message); }
  };
  return <div className="settings-stack">
    <section className="settings-card"><div className="settings-card-title"><span><GlobeAltIcon /></span><div><h3>Threat intelligence IOC sources</h3><p>Configure remote file pulls or upload any source file. The IOC Management Agent preserves each snapshot and normalizes common indicator types into the local index.</p></div></div>
      {notice && <Notice type={notice.includes("updated") || notice.includes("Added") || notice.includes("processed") || notice.includes("Uploaded") || notice.includes("removed") ? "success" : "error"}>{notice}</Notice>}
      <div className="settings-form-grid">
        <label>Source name<input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Approved intelligence feed" /></label>
        <label>Source type<select value={form.kind} onChange={(event) => setForm({ ...form, kind: event.target.value })}><option value="remote">Remote file URL</option><option value="local">Managed local path</option></select></label>
        <label>Location<input value={form.location} onChange={(event) => setForm({ ...form, location: event.target.value })} placeholder={form.kind === "remote" ? "https://provider.example/feed.json" : "/data/ioc_sources/source.dat"} /></label>
        <label>Category<input value={form.category} onChange={(event) => setForm({ ...form, category: event.target.value })} placeholder="phishing, botnet-c2, malware" /></label>
        <label>Severity<select value={form.severity} onChange={(event) => setForm({ ...form, severity: event.target.value })}><option>informational</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
        <label>Confidence<select value={form.confidence} onChange={(event) => setForm({ ...form, confidence: event.target.value })}><option>low</option><option>medium</option><option>high</option></select></label>
        <label>Frequency<select value={form.frequency} onChange={(event) => setForm({ ...form, frequency: event.target.value, interval: 1 })}><option value="minutes">Every N minutes</option><option value="hourly">Every N hours</option><option value="daily">N times per day</option></select></label>
        <label>{form.frequency === "daily" ? "Runs per day" : "Every"}<input type="number" min="1" max={form.frequency === "minutes" ? 59 : 24} value={form.interval} onChange={(event) => setForm({ ...form, interval: Number(event.target.value) })} /></label>
        <label>Schedule anchor<input type="time" value={form.time} onChange={(event) => setForm({ ...form, time: event.target.value })} /></label>
      </div>
      <DayPicker value={form.days} onChange={(days) => setForm({ ...form, days })} />
      <div className="settings-actions"><button className="secondary-button" disabled={!sources.length || working} onClick={refreshAll}><ArrowPathIcon className={working === "all" ? "spinning" : ""} /> Fetch all now</button><button className="primary-button" disabled={!form.name.trim() || !form.location.trim() || !form.days.length} onClick={create}>{editingSource ? <CheckCircleIcon /> : <PlusIcon />}{editingSource ? "Save source schedule" : "Add source"}</button>{editingSource && <button className="secondary-button" onClick={() => { setEditingSource(null); setForm(initial); }}>Cancel edit</button>}</div>
      <div className="upload-zone"><CloudArrowUpIcon /><div><strong>{file?.name || "Upload any IOC source file"}</strong><small>Text, CSV, JSON, STIX, XML, archives, or other provider file formats · bounded by server policy</small></div><label className="secondary-button">Choose file<input type="file" hidden onChange={(event) => setFile(event.target.files?.[0] || null)} /></label><button className="primary-button" disabled={!file || !form.name.trim()} onClick={upload}><CloudArrowUpIcon /> Upload source</button></div>
    </section>
    <section className="settings-card"><h3>Configured intelligence sources</h3><div className="schedule-list">{sources.map((source) => <div key={source.id}><span><strong>{source.name}</strong><small>{source.category || "uncategorized"} · {source.severity || "medium"} severity · {source.confidence} confidence · {scheduleLabel(source)} · {source.last_status || "never"}{source.last_result?.extracted_count != null ? ` · ${source.last_result.extracted_count} indicators` : ""}</small><code>{source.location}</code></span><button className={`switch ${source.enabled ? "on" : ""}`} onClick={() => update(source, { enabled: !source.enabled })} aria-label={`${source.enabled ? "Disable" : "Enable"} ${source.name}`}><span /></button><button title="Edit source and schedule" onClick={() => beginEdit(source)}><PencilSquareIcon /></button><button className="secondary-button compact" disabled={Boolean(working)} onClick={() => refresh(source.id)}><ArrowPathIcon className={working === source.id ? "spinning" : ""} /> Refresh</button>{isAdmin && <button onClick={() => remove(source.id)}><TrashIcon /></button>}</div>)}{!sources.length && <p className="settings-muted">No IOC sources configured.</p>}</div></section>
  </div>;
}

function AccountTab({ session, onSessionChange }) {
  const [profile, setProfile] = useState({ display_name: session.display_name || "", email: session.email || "" });
  const [passwords, setPasswords] = useState({ current_password: "", new_password: "", confirm: "" });
  const [avatar, setAvatar] = useState(null);
  const [platformLogo, setPlatformLogo] = useState(null);
  const [notice, setNotice] = useState("");
  useEffect(() => { api("/api/account").then((item) => setProfile({ display_name: item.display_name || "", email: item.email || "" })).catch((error) => setNotice(error.message)); }, []);
  const save = async () => {
    try { const item = await api("/api/account", jsonOptions("PUT", profile)); setNotice("Account profile updated."); onSessionChange?.(item); }
    catch (error) { setNotice(error.message); }
  };
  const upload = async () => {
    if (!avatar) return;
    const form = new FormData(); form.append("file", avatar);
    try { const item = await api("/api/account/avatar", { method: "POST", body: form }); setNotice("Account avatar updated."); setAvatar(null); onSessionChange?.({ ...item, avatar_url: `${item.avatar_url}?v=${Date.now()}` }); }
    catch (error) { setNotice(error.message); }
  };
  const changePassword = async () => {
    if (passwords.new_password !== passwords.confirm) { setNotice("New password confirmation does not match."); return; }
    try { await api("/api/account/password", jsonOptions("PUT", { current_password: passwords.current_password, new_password: passwords.new_password })); setPasswords({ current_password: "", new_password: "", confirm: "" }); setNotice("Account password changed."); }
    catch (error) { setNotice(error.message); }
  };
  const uploadPlatformLogo = async () => {
    if (!platformLogo || session.role !== "Admin") return;
    const form = new FormData(); form.append("file", platformLogo);
    try {
      const branding = await api("/api/account/platform-logo", { method: "POST", body: form });
      const next = { ...branding, logo_url: `${branding.logo_url}?v=${Date.now()}` };
      setPlatformLogo(null); setNotice("Platform logo updated."); onSessionChange?.({ branding: next });
    } catch (error) { setNotice(error.message); }
  };
  const resetPlatformLogo = async () => {
    if (session.role !== "Admin") return;
    try {
      await api("/api/account/platform-logo", { method: "DELETE" });
      setNotice("Platform logo reset."); onSessionChange?.({ branding: { logo_url: "" } });
    } catch (error) { setNotice(error.message); }
  };
  return <div className="settings-stack">
    <section className="settings-card"><div className="settings-card-title"><span><UserCircleIcon /></span><div><h3>Account profile</h3><p>Update the account name shown in the platform, email address, and avatar. The sign-in username remains unchanged.</p></div></div>
      {notice && <Notice type={notice.includes("updated") || notice.includes("changed") || notice.includes("reset") ? "success" : "error"}>{notice}</Notice>}
      <div className="account-profile-row">{session.avatar_url ? <img className="account-avatar" src={session.avatar_url} alt="" /> : <span className="avatar">{(profile.display_name || session.username || "U")[0].toUpperCase()}</span>}<div><strong>{session.username}</strong><small>Username cannot be changed · {session.role}</small></div></div>
      <div className="settings-form-grid"><label>Account name<input value={profile.display_name} onChange={(event) => setProfile({ ...profile, display_name: event.target.value })} /></label><label>Email address<input type="email" value={profile.email} onChange={(event) => setProfile({ ...profile, email: event.target.value })} /></label></div>
      <div className="settings-actions"><label className="secondary-button">Choose avatar<input type="file" accept="image/png,image/jpeg,image/gif,image/webp" hidden onChange={(event) => setAvatar(event.target.files?.[0] || null)} /></label><button className="secondary-button" disabled={!avatar} onClick={upload}><CloudArrowUpIcon /> Upload avatar</button><button className="primary-button" disabled={!profile.display_name.trim()} onClick={save}><CheckCircleIcon /> Save profile</button></div>
    </section>
    <section className="settings-card"><div className="settings-card-title"><span><KeyIcon /></span><div><h3>Change password</h3><p>Confirm the current password and choose a new password with at least 10 characters.</p></div></div>
      <div className="settings-form-grid"><label>Current password<input type="password" autoComplete="current-password" value={passwords.current_password} onChange={(event) => setPasswords({ ...passwords, current_password: event.target.value })} /></label><label>New password<input type="password" autoComplete="new-password" value={passwords.new_password} onChange={(event) => setPasswords({ ...passwords, new_password: event.target.value })} /></label><label>Confirm new password<input type="password" autoComplete="new-password" value={passwords.confirm} onChange={(event) => setPasswords({ ...passwords, confirm: event.target.value })} /></label></div>
      <div className="settings-actions"><button className="primary-button" disabled={!passwords.current_password || passwords.new_password.length < 10 || !passwords.confirm} onClick={changePassword}><KeyIcon /> Change password</button></div>
    </section>
    {session.role === "Admin" && <section className="settings-card"><div className="settings-card-title"><span><ShieldCheckIcon /></span><div><h3>Platform logo</h3><p>Choose the compact logo shown in the top status area for every signed-in user.</p></div></div>
      <div className="account-profile-row">{session.branding?.logo_url ? <img className="platform-logo-preview" src={session.branding.logo_url} alt="Current platform logo" /> : <span className="platform-logo-fallback"><ShieldCheckIcon /></span>}<div><strong>{platformLogo?.name || "Current platform identity"}</strong><small>PNG, JPEG, or WebP · maximum 2 MB</small></div></div>
      <div className="settings-actions"><label className="secondary-button">Choose logo<input type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={(event) => setPlatformLogo(event.target.files?.[0] || null)} /></label><button className="primary-button" disabled={!platformLogo} onClick={uploadPlatformLogo}><CloudArrowUpIcon /> Upload logo</button>{session.branding?.logo_url && <button className="secondary-button" onClick={resetPlatformLogo}><TrashIcon /> Reset logo</button>}</div>
    </section>}
  </div>;
}

function AuditLogsTab() {
  const [hours, setHours] = useState(24);
  const [level, setLevel] = useState("all");
  const [query, setQuery] = useState("");
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState("");
  const [expanded, setExpanded] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setNotice("");
    try {
      const params = new URLSearchParams({ hours: String(hours), limit: "1000", level, query });
      const payload = await api(`/api/audit/logs?${params.toString()}`);
      setRows(Array.isArray(payload) ? payload : payload.items || []);
    } catch (error) {
      setNotice(error.message);
    } finally {
      setLoading(false);
    }
  }, [hours, level, query]);

  useEffect(() => {
    const timer = window.setTimeout(load, 300);
    return () => window.clearTimeout(timer);
  }, [load]);

  useEffect(() => {
    const timer = window.setInterval(load, 30_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const localTime = (value) => {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? "Unknown" : parsed.toLocaleString();
  };

  return <div className="settings-stack">
    <section className="settings-card audit-log-card">
      <div className="settings-card-title">
        <span><QueueListIcon /></span>
        <div><h3>Audit logs</h3><p>Timestamped request, hunt, detection, forensic, and tool events for troubleshooting and workflow reconstruction.</p></div>
      </div>
      <div className="audit-toolbar">
        <label className="audit-search"><span><MagnifyingGlassIcon /></span><input aria-label="Search audit logs" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search service, action, actor, resource, or message" /></label>
        <label>Period<select value={hours} onChange={(event) => setHours(Number(event.target.value))}><option value={24}>24 hours</option><option value={168}>7 days</option><option value={720}>30 days</option><option value={2160}>90 days</option></select></label>
        <label>Level<select value={level} onChange={(event) => setLevel(event.target.value)}><option value="all">All levels</option><option value="info">Info</option><option value="warning">Warning</option><option value="error">Error</option></select></label>
        <button className="secondary-button" onClick={load} disabled={loading}><ArrowPathIcon className={loading ? "spinning" : ""} /> Refresh</button>
      </div>
      {notice && <Notice type="error">{notice}</Notice>}
      <div className="audit-summary"><strong>{rows.length.toLocaleString()}</strong> events in the selected period <span>Auto-refreshes every 30 seconds</span></div>
      <div className="audit-table-wrap">
        <div className="audit-table audit-table-head"><span>Timestamp</span><span>Level</span><span>Source</span><span>Action and resource</span><span>Actor</span><span>Status / duration</span></div>
        {rows.map((item) => {
          const levelName = String(item.level || "INFO").toLowerCase();
          const open = expanded === item.id;
          return <div className={`audit-row-wrap ${open ? "expanded" : ""}`} key={`${item.service}-${item.id}-${item.timestamp}`}>
            <button className="audit-table audit-row" onClick={() => setExpanded(open ? "" : item.id)}>
              <time>{localTime(item.timestamp)}</time>
              <span><i className={`audit-level ${levelName}`} />{levelName}</span>
              <span><strong>{displayDetectionText(item.service)}</strong><small>{displayDetectionText(item.category)}</small></span>
              <span><strong>{displayDetectionText(item.message || item.action)}</strong><small>{displayDetectionText(item.action)}{item.resource ? ` · ${displayDetectionText(item.resource)}` : ""}</small></span>
              <span>{item.actor || "system"}</span>
              <span>{item.status_code || "—"}<small>{item.duration_ms != null ? `${Number(item.duration_ms).toLocaleString()} ms` : "No timing"}</small></span>
            </button>
            {open && <div className="audit-detail"><div><strong>Event ID</strong><code>{item.id}</code></div><div><strong>Context</strong><pre>{displayDetectionText(JSON.stringify(item.context || {}, null, 2))}</pre></div></div>}
          </div>;
        })}
        {!loading && !rows.length && <div className="audit-empty">No audit events match these filters.</div>}
        {loading && !rows.length && <div className="audit-empty"><ArrowPathIcon className="spinning" /> Loading audit timeline…</div>}
      </div>
    </section>
  </div>;
}

function UsersTab() {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ username: "", display_name: "", email: "", password: "", role: "Expert", permissions: ["hunts", "forensics", "reports", "chat", "knowledge"] });
  const [notice, setNotice] = useState("");
  const load = useCallback(async () => { try { setUsers(await api("/api/settings/users")); } catch (error) { setNotice(error.message); } }, []);
  useEffect(() => { load(); }, [load]);
  const create = async () => {
    const payload = { ...form, permissions: ["Admin", "SME"].includes(form.role) ? ALL_FEATURES : form.permissions };
    try { await api("/api/settings/users", jsonOptions("POST", payload)); setNotice(`Created ${form.role} account ${form.username}.`); setForm({ username: "", display_name: "", email: "", password: "", role: "Expert", permissions: ["hunts", "forensics", "reports", "chat", "knowledge"] }); load(); }
    catch (error) { setNotice(error.message); }
  };
  const update = async (user, patch) => { try { await api(`/api/settings/users/${encodeURIComponent(user.username)}`, jsonOptions("PUT", patch)); load(); } catch (error) { setNotice(error.message); } };
  const remove = async (user) => { if (!window.confirm(`Delete account ${user.username}?`)) return; try { await api(`/api/settings/users/${encodeURIComponent(user.username)}`, { method: "DELETE" }); setNotice(`Deleted account ${user.username}.`); load(); } catch (error) { setNotice(error.message); } };
  return <div className="settings-stack">
    <section className="settings-card"><div className="settings-card-title"><span><UserGroupIcon /></span><div><h3>User and role administration</h3><p>Admins control the platform and destructive actions. SMEs use all operational UI features. Experts receive hunting, investigation, reports, chat, and knowledge access.</p></div></div>
      {notice && <Notice type={notice.startsWith("Created") || notice.startsWith("Deleted") ? "success" : "error"}>{notice}</Notice>}
      <div className="settings-form-grid"><label>Username<input value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} /></label><label>Account name<input value={form.display_name} onChange={(event) => setForm({ ...form, display_name: event.target.value })} /></label><label>Email address<input type="email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} /></label><label>Temporary password<input type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} /></label><label>Role<select value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })}><option>Admin</option><option>SME</option><option>Expert</option></select></label></div>
      <div className="settings-actions"><button className="primary-button" disabled={!form.username || !form.display_name || form.password.length < 10} onClick={create}><PlusIcon /> Create user</button></div>
    </section>
    <section className="settings-card"><h3>Local accounts</h3><div className="user-list">{users.map((user) => <div key={user.username}>{user.avatar_url ? <img className="avatar small" src={user.avatar_url} alt="" /> : <span className="avatar small">{user.display_name?.[0] || user.username[0]}</span>}<span><strong>{user.display_name}</strong><small>{user.username} · {user.email || "No email"} · {user.role}</small></span><select aria-label={`Role for ${user.username}`} value={user.role} onChange={(event) => update(user, { role: event.target.value })}><option>Admin</option><option>SME</option><option>Expert</option></select><button className={`switch ${user.enabled ? "on" : ""}`} onClick={() => update(user, { enabled: !user.enabled })}><span /></button><button className="user-delete" onClick={() => remove(user)} title="Delete user"><TrashIcon /></button></div>)}</div></section>
  </div>;
}

export default function Settings({ initialTab = "account", onTabChange, hypotheses, session, activeSources, onTelemetryChange, onSessionChange }) {
  const isAdmin = session.role === "Admin";
  const canConfigure = ["Admin", "SME"].includes(session.role);
  const canKnowledge = canConfigure || session.permissions?.includes("knowledge");
  const tabs = useMemo(() => [
    { id: "account", label: "My account", icon: UserCircleIcon },
    ...(canConfigure ? [
      { id: "general", label: "General", icon: Cog6ToothIcon },
      { id: "rules", label: "Detection rules", icon: ShieldCheckIcon },
      { id: "yara", label: "YARA rules", icon: ShieldCheckIcon },
      { id: "ioc", label: "IOC sources", icon: GlobeAltIcon },
      { id: "schedules", label: "Hunt schedules", icon: ClockIcon },
      { id: "audit", label: "Audit logs", icon: QueueListIcon },
    ] : []),
    ...(canKnowledge ? [{ id: "knowledge", label: "Knowledge base", icon: BookOpenIcon }] : []),
    ...(isAdmin ? [{ id: "users", label: "Users & roles", icon: UserGroupIcon }] : []),
  ], [canConfigure, canKnowledge, isAdmin]);
  const [tab, setTab] = useState("account");
  useEffect(() => {
    if (tabs.some((item) => item.id === initialTab)) {
      setTab(initialTab);
    } else {
      setTab("account");
      onTabChange?.("account");
    }
    // Route correction runs only when the requested tab or authorized tabs change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialTab, tabs]);
  useEffect(() => { if (!tabs.some((item) => item.id === tab)) setTab("account"); }, [tabs, tab]);
  return <div className="page-wrap settings-page">
    <section className="page-heading"><div><span className="status-pill status-indigo"><Cog6ToothIcon /> Governed administration</span><h1>Platform configuration</h1><p>Manage account details, intelligence sources, runtime behavior, schedules, telemetry, knowledge, and role-based access.</p></div></section>
    <div className="settings-layout"><aside className="settings-tabs panel">{tabs.map((item) => <button key={item.id} className={tab === item.id ? "active" : ""} onClick={() => { setTab(item.id); onTabChange?.(item.id); }}><item.icon />{item.label}</button>)}</aside><main className="settings-content">
      {tab === "account" && <AccountTab session={session} onSessionChange={onSessionChange} />}
      {tab === "general" && <GeneralTab activeSources={activeSources} />}
      {tab === "rules" && <DetectionRulesTab activeSources={activeSources} />}
      {tab === "yara" && <YaraRulesTab />}
      {tab === "ioc" && <IOCSourcesTab isAdmin={isAdmin} />}
      {tab === "knowledge" && <KnowledgeTab />}
      {tab === "schedules" && <HypothesisScheduleTab hypotheses={hypotheses} activeSources={activeSources} isAdmin={isAdmin} />}
      {tab === "audit" && <AuditLogsTab />}
      {tab === "users" && <UsersTab />}
    </main></div>
  </div>;
}
