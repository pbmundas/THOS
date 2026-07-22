import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowPathIcon, BeakerIcon, BookOpenIcon, CheckCircleIcon, ClockIcon,
  CloudArrowUpIcon, Cog6ToothIcon, CpuChipIcon, ExclamationTriangleIcon,
  PlusIcon, ShieldCheckIcon, TrashIcon, UserGroupIcon,
} from "@heroicons/react/24/outline";


async function api(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || payload.error || `Request failed (${response.status})`);
  return payload;
}
const jsonOptions = (method, body) => ({ method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const CONNECTION_SIEMS = ["wazuh", "logrhythm", "splunk", "qradar", "folder"];

function sigmaScheduleLabel(item) {
  const count = Number(item.interval || 1);
  if (item.frequency === "minutes") return `Every ${count} minute${count === 1 ? "" : "s"}, anchored at ${item.time}`;
  if (item.frequency === "hourly") return `Every ${count} hour${count === 1 ? "" : "s"} at minute ${String(item.time || "00:00").slice(3)}`;
  return count === 1 ? `Once a day at ${item.time}` : `${count} times a day, starting at ${item.time}`;
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
  const [form, setForm] = useState({ default_model: "", default_iterations: 1, default_siem: "folder" });
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
    } catch (error) { setNotice(error.message); } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);
  const save = async () => {
    try { await api("/api/settings/general", jsonOptions("PUT", form)); setNotice("Runtime defaults saved. New hunts and model calls use them immediately."); }
    catch (error) { setNotice(error.message); }
  };
  return <div className="settings-stack">
    <section className="settings-card"><div className="settings-card-title"><span><CpuChipIcon /></span><div><h3>Model and hunt defaults</h3><p>Models are discovered from the local Ollama service. No hosted endpoint is used.</p></div></div>
      {notice && <Notice type={notice.includes("saved") ? "success" : "error"}>{notice}</Notice>}
      <div className="settings-form-grid">
        <label>Default local model<select disabled={loading} value={form.default_model} onChange={(event) => setForm({ ...form, default_model: event.target.value })}>{models.map((item) => <option key={item.name} value={item.name}>{item.name} · {(Number(item.size || 0) / 1024 ** 3).toFixed(1)} GB</option>)}</select></label>
        <label>Default hunt iterations<select value={form.default_iterations} onChange={(event) => setForm({ ...form, default_iterations: Number(event.target.value) })}>{[1, 2, 3, 4, 5].map((value) => <option key={value} value={value}>{value}{value === 1 ? " · recommended" : ""}</option>)}</select></label>
        <label>Default telemetry source<select value={form.default_siem} onChange={(event) => setForm({ ...form, default_siem: event.target.value })}>{activeSources.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label>
        <label>Scheduler timezone<input value={timezone} disabled /></label>
      </div>
      <div className="settings-actions"><button className="secondary-button" onClick={load}><ArrowPathIcon /> Refresh models</button><button className="primary-button" onClick={save}><CheckCircleIcon /> Save defaults</button></div>
    </section>
  </div>;
}

function SigmaTab({ activeSources }) {
  const [query, setQuery] = useState("");
  const [data, setData] = useState({ items: [], total: 0, schedules: [] });
  const [loading, setLoading] = useState(false);
  const [time, setTime] = useState("02:00");
  const [frequency, setFrequency] = useState("daily");
  const [interval, setInterval] = useState(1);
  const [siem, setSiem] = useState(activeSources[0]?.id || "folder");
  const [days, setDays] = useState([0, 1, 2, 3, 4, 5, 6]);
  const [notice, setNotice] = useState("");
  const load = useCallback(async () => { setLoading(true); try { setData(await api(`/api/settings/sigma?query=${encodeURIComponent(query)}&page_size=100`)); } catch (error) { setNotice(error.message); } finally { setLoading(false); } }, [query]);
  useEffect(() => { const timer = setTimeout(load, 250); return () => clearTimeout(timer); }, [load]);
  useEffect(() => { if (!activeSources.some((item) => item.id === siem)) setSiem(activeSources[0]?.id || "folder"); }, [activeSources, siem]);
  const toggle = async (rule) => { try { await api(`/api/settings/sigma/${encodeURIComponent(rule.id)}`, jsonOptions("PUT", { enabled: !rule.enabled })); setData((current) => ({ ...current, items: current.items.map((item) => item.id === rule.id ? { ...item, enabled: !item.enabled } : item) })); } catch (error) { setNotice(error.message); } };
  const intervalMax = frequency === "minutes" ? 59 : 24;
  const schedule = async (rule) => { try { const bounded = Math.max(1, Math.min(intervalMax, Number(interval) || 1)); await api("/api/settings/schedules/sigma", jsonOptions("POST", { target_id: rule.id, title: rule.title, time, frequency, interval: bounded, days, enabled: true, siem_type: siem })); setNotice(`Scheduled ${rule.title}: ${sigmaScheduleLabel({ frequency, interval: bounded, time })} on ${siem}.`); load(); } catch (error) { setNotice(error.message); } };
  const remove = async (id) => { await api(`/api/settings/schedules/sigma/${id}`, { method: "DELETE" }); load(); };
  return <div className="settings-stack"><section className="settings-card"><div className="settings-card-title"><span><ShieldCheckIcon /></span><div><h3>Sigma rule catalogue</h3><p>{data.total.toLocaleString()} matching community and THOS rules. Disabled rules are excluded from every hunt.</p></div></div>
    {notice && <Notice type={notice.startsWith("Scheduled") ? "success" : "error"}>{notice}</Notice>}
    <div className="sigma-controls"><input className="sigma-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search rule ID, title, or ATT&CK tag…" /><label>Frequency<select aria-label="Sigma schedule frequency" value={frequency} onChange={(event) => { setFrequency(event.target.value); setInterval(1); }}><option value="minutes">Every N minutes</option><option value="hourly">Every N hours</option><option value="daily">N times per day</option></select></label><label>{frequency === "daily" ? "Runs per day" : "Every"}<input aria-label="Sigma schedule interval" type="number" min="1" max={intervalMax} value={interval} onChange={(event) => setInterval(event.target.value)} /></label><label>First run time<input type="time" value={time} onChange={(event) => setTime(event.target.value)} /></label><label>Active SIEM<select aria-label="Sigma schedule SIEM" value={siem} onChange={(event) => setSiem(event.target.value)}>{activeSources.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label><DayPicker value={days} onChange={setDays} /></div>
    <div className="rule-list">{loading ? <p className="settings-muted">Loading Sigma catalogue…</p> : data.items.map((rule) => <div className="rule-row" key={rule.id}><div><strong>{rule.title}</strong><small>{rule.source} · {rule.level} · {rule.id}</small></div><button className={`switch ${rule.enabled ? "on" : ""}`} onClick={() => toggle(rule)} aria-label={`${rule.enabled ? "Disable" : "Enable"} ${rule.title}`}><span /></button><button className="secondary-button compact" disabled={!rule.enabled || !days.length} onClick={() => schedule(rule)}><ClockIcon /> Schedule</button></div>)}</div>
  </section>
  <section className="settings-card"><h3>Scheduled Sigma validations</h3><div className="schedule-list">{data.schedules?.map((item) => <div key={item.id}><span><strong>{item.title || item.target_id}</strong><small>{sigmaScheduleLabel(item)} · {item.siem_type} · {(item.days || []).map((day) => DAYS[day]).join(", ")} · {item.last_status}</small></span><button onClick={() => remove(item.id)}><TrashIcon /></button></div>)}{!data.schedules?.length && <p className="settings-muted">No Sigma schedules configured.</p>}</div></section></div>;
}

function KnowledgeTab() {
  const [documents, setDocuments] = useState([]);
  const [file, setFile] = useState(null);
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => { try { setDocuments(await api("/api/knowledge/documents")); } catch (error) { setNotice(error.message); } }, []);
  useEffect(() => { load(); }, [load]);
  const upload = async () => { if (!file) return; setLoading(true); const form = new FormData(); form.append("file", file); try { const result = await api("/api/knowledge/upload", { method: "POST", body: form }); if (result.error) throw new Error(result.error); setNotice(`Ingested ${result.filename} into ${result.chunk_count} RAG chunks.`); setFile(null); load(); } catch (error) { setNotice(error.message); } finally { setLoading(false); } };
  const remove = async (id) => { await api(`/api/knowledge/documents/${id}`, { method: "DELETE" }); load(); };
  return <div className="settings-stack"><section className="settings-card"><div className="settings-card-title"><span><BookOpenIcon /></span><div><h3>Organizational knowledge base</h3><p>Files are extracted, chunked, embedded, and used as RAG context. This grounds the model; it does not retrain model weights.</p></div></div>
    {notice && <Notice type={notice.startsWith("Ingested") ? "success" : "error"}>{notice}</Notice>}
    <div className="upload-zone"><CloudArrowUpIcon /><div><strong>{file?.name || "Choose a reference document"}</strong><small>TXT, Markdown, CSV, JSON, logs, HTML, PDF, or DOCX · maximum 25 MB</small></div><label className="secondary-button">Browse<input type="file" hidden onChange={(event) => setFile(event.target.files?.[0] || null)} /></label><button className="primary-button" disabled={!file || loading} onClick={upload}>{loading ? <ArrowPathIcon className="spinning" /> : <CloudArrowUpIcon />} Ingest for RAG</button></div>
  </section><section className="settings-card"><h3>Ingested documents</h3><div className="document-list">{documents.map((item) => <div key={item.doc_id}><span className="doc-badge">{String(item.content_type || "DOC").replace(".", "").toUpperCase()}</span><span><strong>{item.filename}</strong><small>{item.chunk_count} chunks · {item.ingested_at}</small></span><button onClick={() => remove(item.doc_id)}><TrashIcon /></button></div>)}{!documents.length && <p className="settings-muted">No organizational documents have been ingested.</p>}</div></section></div>;
}

function HypothesisScheduleTab({ hypotheses, activeSources }) {
  const [schedules, setSchedules] = useState([]);
  const [target, setTarget] = useState(hypotheses[0]?.id || "");
  const [time, setTime] = useState("01:00");
  const [days, setDays] = useState([0, 1, 2, 3, 4]);
  const [siem, setSiem] = useState(activeSources[0]?.id || "folder");
  const [notice, setNotice] = useState("");
  const load = useCallback(async () => { try { setSchedules(await api("/api/settings/schedules/hypothesis")); } catch (error) { setNotice(error.message); } }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (!target && hypotheses[0]) setTarget(hypotheses[0].id); }, [hypotheses, target]);
  useEffect(() => { if (!activeSources.some((item) => item.id === siem)) setSiem(activeSources[0]?.id || "folder"); }, [activeSources, siem]);
  const create = async () => { const hypothesis = hypotheses.find((item) => item.id === target); try { await api("/api/settings/schedules/hypothesis", jsonOptions("POST", { target_id: target, title: hypothesis?.title || target, time, days, enabled: true, siem_type: siem })); setNotice("Hypothesis schedule created in system local time."); load(); } catch (error) { setNotice(error.message); } };
  const remove = async (id) => { await api(`/api/settings/schedules/hypothesis/${id}`, { method: "DELETE" }); load(); };
  return <div className="settings-stack"><section className="settings-card"><div className="settings-card-title"><span><ClockIcon /></span><div><h3>Hypothesis scheduler</h3><p>Schedules are evaluated in the system-local timezone and launch the same governed hunt pipeline as an analyst run.</p></div></div>{notice && <Notice type={notice.startsWith("Hypothesis") ? "success" : "error"}>{notice}</Notice>}
    <div className="settings-form-grid"><label>Hypothesis<select value={target} onChange={(event) => setTarget(event.target.value)}>{hypotheses.map((item) => <option key={item.id} value={item.id}>{item.id} · {item.title}</option>)}</select></label><label>Run time<input type="time" value={time} onChange={(event) => setTime(event.target.value)} /></label><label>Active telemetry source<select value={siem} onChange={(event) => setSiem(event.target.value)}>{activeSources.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label></div><DayPicker value={days} onChange={setDays} /><div className="settings-actions"><button className="primary-button" disabled={!target || !days.length} onClick={create}><PlusIcon /> Add schedule</button></div>
  </section><section className="settings-card"><h3>Scheduled hunts</h3><div className="schedule-list">{schedules.map((item) => <div key={item.id}><span><strong>{item.title || item.target_id}</strong><small>{item.time} · {item.siem_type} · {item.days.map((day) => DAYS[day]).join(", ")} · {item.last_status}</small></span><button onClick={() => remove(item.id)}><TrashIcon /></button></div>)}{!schedules.length && <p className="settings-muted">No hypothesis schedules configured.</p>}</div></section></div>;
}

function SiemTab({ activeSources, onTelemetryChange }) {
  const [siem, setSiem] = useState("wazuh");
  const [schema, setSchema] = useState({});
  const [values, setValues] = useState({});
  const [configuredSecrets, setConfiguredSecrets] = useState([]);
  const [statuses, setStatuses] = useState([]);
  const [fieldSiem, setFieldSiem] = useState(activeSources[0]?.id || "folder");
  const [fieldFile, setFieldFile] = useState(null);
  const [inventory, setInventory] = useState({ fields: [], field_count: 0 });
  const [notice, setNotice] = useState("");
  const load = useCallback(async () => { try { const [schemas, saved, state] = await Promise.all([api("/api/settings/siem/schema"), api(`/api/settings/siem/${siem}`), api("/api/settings/siem-status")]); setSchema(schemas); setValues(saved.settings || {}); setConfiguredSecrets(saved.configured_secrets || []); setStatuses(state || []); } catch (error) { setNotice(error.message); } }, [siem]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (!activeSources.some((item) => item.id === fieldSiem)) setFieldSiem(activeSources[0]?.id || "folder"); }, [activeSources, fieldSiem]);
  useEffect(() => { api(`/api/settings/siem/${fieldSiem}`).then((saved) => setInventory(saved.field_inventory || { fields: [], field_count: 0 })).catch((error) => setNotice(error.message)); }, [fieldSiem]);
  const save = async () => { try { await api(`/api/settings/siem/${siem}`, jsonOptions("PUT", { settings: values })); setNotice(`${siem} configuration saved. Test it successfully to make it active.`); await Promise.all([load(), onTelemetryChange()]); } catch (error) { setNotice(error.message); } };
  const test = async () => { try { await api(`/api/settings/siem/${siem}`, jsonOptions("PUT", { settings: values })); const result = await api(`/api/settings/siem/${siem}/test`, { method: "POST" }); setNotice(`${siem} connection succeeded and is now active; ${result.record_count} test record(s).`); await Promise.all([load(), onTelemetryChange()]); } catch (error) { setNotice(error.message); await Promise.all([load(), onTelemetryChange()]); } };
  const uploadFields = async () => { if (!fieldFile) return; const form = new FormData(); form.append("file", fieldFile); try { const result = await api(`/api/settings/siem/${fieldSiem}/fields-csv`, { method: "POST", body: form }); setInventory(result); setFieldFile(null); setNotice(`Uploaded ${result.field_count} available fields for ${fieldSiem}.`); } catch (error) { setNotice(error.message); } };
  const clearFields = async () => { try { await api(`/api/settings/siem/${fieldSiem}/fields-csv`, { method: "DELETE" }); setInventory({ fields: [], field_count: 0 }); setNotice(`Cleared the field inventory for ${fieldSiem}.`); } catch (error) { setNotice(error.message); } };
  const selectedStatus = statuses.find((item) => item.id === siem);
  return <div className="settings-stack"><section className="settings-card"><div className="settings-card-title"><span><BeakerIcon /></span><div><h3>SIEM connection</h3><p>Credentials remain server-side in the on-prem runtime configuration and are never returned to browser JavaScript.</p></div></div>{notice && <Notice type={notice.includes("saved") || notice.includes("succeeded") || notice.startsWith("Uploaded") ? "success" : "error"}>{notice}</Notice>}
    <div className="settings-form-grid"><label>SIEM platform<select value={siem} onChange={(event) => { setSiem(event.target.value); setNotice(""); }}>{CONNECTION_SIEMS.map((item) => <option key={item}>{item}</option>)}</select></label><label>Connection state<input disabled value={selectedStatus?.active ? "Active · connection tested" : selectedStatus?.status || "Not tested"} /></label>{(schema[siem] || []).map((field) => <label key={field.name}>{field.label}{field.type === "password" && configuredSecrets.includes(field.name) && <small>Stored · leave blank to keep</small>}<input type={field.type} required={field.required} value={values[field.name] || ""} onChange={(event) => setValues({ ...values, [field.name]: event.target.value })} /></label>)}</div>
    <div className="settings-actions"><button className="secondary-button" onClick={save}><CheckCircleIcon /> Save configuration</button><button className="primary-button" onClick={test}><BeakerIcon /> Save, test & activate</button></div>
  </section><section className="settings-card"><div className="settings-card-title"><span><CloudArrowUpIcon /></span><div><h3>Available SIEM log fields</h3><p>Upload a CSV with all available field names in one populated column. The selected active SIEM owns this field inventory.</p></div></div>
    <div className="settings-form-grid"><label>Active SIEM<select value={fieldSiem} onChange={(event) => { setFieldSiem(event.target.value); setFieldFile(null); }}>{activeSources.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label><label>Current field inventory<input disabled value={inventory.field_count ? `${inventory.field_count} fields · ${inventory.filename || "CSV uploaded"}` : "No field CSV uploaded"} /></label></div>
    <div className="field-csv-upload"><label className="secondary-button"><CloudArrowUpIcon /> Choose one-column CSV<input type="file" accept=".csv,text/csv" hidden onChange={(event) => setFieldFile(event.target.files?.[0] || null)} /></label><span>{fieldFile?.name || "No CSV selected"}</span>{inventory.field_count ? <button className="secondary-button" onClick={clearFields}><TrashIcon /> Clear inventory</button> : null}<button className="primary-button" disabled={!fieldFile} onClick={uploadFields}><CloudArrowUpIcon /> Upload fields</button></div>
    {!!inventory.fields?.length && <div className="field-preview">{inventory.fields.slice(0, 18).map((field) => <span key={field}>{field}</span>)}{inventory.fields.length > 18 && <em>+{inventory.fields.length - 18} more</em>}</div>}
  </section></div>;
}

function UsersTab() {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ username: "", display_name: "", password: "", role: "Analyst", permissions: ["hunts", "reports"] });
  const [notice, setNotice] = useState("");
  const load = useCallback(async () => { try { setUsers(await api("/api/settings/users")); } catch (error) { setNotice(error.message); } }, []);
  useEffect(() => { load(); }, [load]);
  const togglePermission = (permission) => setForm({ ...form, permissions: form.permissions.includes(permission) ? form.permissions.filter((item) => item !== permission) : [...form.permissions, permission] });
  const create = async () => { try { await api("/api/settings/users", jsonOptions("POST", form)); setNotice(`Created ${form.role} account ${form.username}.`); setForm({ username: "", display_name: "", password: "", role: "Analyst", permissions: ["hunts", "reports"] }); load(); } catch (error) { setNotice(error.message); } };
  const toggle = async (user) => { try { await api(`/api/settings/users/${encodeURIComponent(user.username)}`, jsonOptions("PUT", { enabled: !user.enabled })); load(); } catch (error) { setNotice(error.message); } };
  const remove = async (user) => { try { await api(`/api/settings/users/${encodeURIComponent(user.username)}`, { method: "DELETE" }); setNotice(`Deleted account ${user.username}.`); load(); } catch (error) { setNotice(error.message); } };
  return <div className="settings-stack"><section className="settings-card"><div className="settings-card-title"><span><UserGroupIcon /></span><div><h3>User creation and role access</h3><p>SMEs administer every feature. Analysts see only features explicitly assigned here.</p></div></div>{notice && <Notice type={notice.startsWith("Created") ? "success" : "error"}>{notice}</Notice>}
    <div className="settings-form-grid"><label>Username<input value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} /></label><label>Display name<input value={form.display_name} onChange={(event) => setForm({ ...form, display_name: event.target.value })} /></label><label>Temporary password<input type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} /></label><label>Role<select value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value, permissions: event.target.value === "SME" ? ["hunts", "reports", "chat", "knowledge", "settings"] : form.permissions })}><option>Analyst</option><option>SME</option></select></label></div>
    <div className="permission-picker">{["hunts", "reports", "chat", "knowledge"].map((permission) => <label key={permission}><input type="checkbox" checked={form.role === "SME" || form.permissions.includes(permission)} disabled={form.role === "SME"} onChange={() => togglePermission(permission)} />{permission}</label>)}</div><div className="settings-actions"><button className="primary-button" disabled={!form.username || !form.display_name || form.password.length < 10} onClick={create}><PlusIcon /> Create user</button></div>
  </section><section className="settings-card"><h3>Local accounts</h3><div className="user-list">{users.map((user) => <div key={user.username}><span className="avatar small">{user.display_name?.[0] || user.username[0]}</span><span><strong>{user.display_name}</strong><small>{user.username} · {user.role} · {user.permissions.join(", ")}</small></span><button className={`switch ${user.enabled ? "on" : ""}`} onClick={() => toggle(user)}><span /></button><button className="user-delete" onClick={() => remove(user)} title="Delete user"><TrashIcon /></button></div>)}</div></section></div>;
}

export default function Settings({ hypotheses, session, activeSources, onTelemetryChange }) {
  const isSme = session.role === "SME";
  const tabs = useMemo(() => [
    ...(isSme ? [{ id: "general", label: "General", icon: Cog6ToothIcon }, { id: "sigma", label: "Sigma rules", icon: ShieldCheckIcon }] : []),
    ...(session.permissions.includes("knowledge") ? [{ id: "knowledge", label: "Knowledge base", icon: BookOpenIcon }] : []),
    ...(isSme ? [{ id: "schedules", label: "Hypothesis schedule", icon: ClockIcon }, { id: "siem", label: "SIEM & fields", icon: BeakerIcon }, { id: "users", label: "Users & roles", icon: UserGroupIcon }] : []),
  ], [isSme, session.permissions]);
  const [tab, setTab] = useState(tabs[0]?.id || "knowledge");
  useEffect(() => { if (!tabs.some((item) => item.id === tab) && tabs[0]) setTab(tabs[0].id); }, [tabs, tab]);
  return <div className="page-wrap settings-page"><section className="page-heading"><div><span className="status-pill status-indigo"><Cog6ToothIcon /> Governed control plane</span><h1>{isSme ? "Platform settings" : "Knowledge workspace"}</h1><p>Configure runtime behavior without exposing model, SIEM, or orchestration secrets to the browser.</p></div></section><div className="settings-layout"><aside className="settings-tabs panel">{tabs.map((item) => <button key={item.id} className={tab === item.id ? "active" : ""} onClick={() => setTab(item.id)}><item.icon />{item.label}</button>)}</aside><main className="settings-content">{tab === "general" && <GeneralTab activeSources={activeSources} />}{tab === "sigma" && <SigmaTab activeSources={activeSources} />}{tab === "knowledge" && <KnowledgeTab />}{tab === "schedules" && <HypothesisScheduleTab hypotheses={hypotheses} activeSources={activeSources} />}{tab === "siem" && <SiemTab activeSources={activeSources} onTelemetryChange={onTelemetryChange} />}{tab === "users" && <UsersTab />}</main></div></div>;
}
