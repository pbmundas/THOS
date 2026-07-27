import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowPathIcon, BeakerIcon, CheckCircleIcon, CircleStackIcon,
  LinkIcon, ShieldCheckIcon, TrashIcon,
} from "@heroicons/react/24/outline";
import { SiemTab } from "./Settings";

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || payload.error || `Request failed (${response.status})`);
  return payload;
}

const jsonOptions = (method, body) => ({
  method,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

function Notice({ success, children }) {
  return <div className={`settings-notice ${success ? "success" : "error"}`}><span>{success ? <CheckCircleIcon /> : <ShieldCheckIcon />}</span>{children}</div>;
}

function DirectIntegrations({ session, onTelemetryChange }) {
  const [items, setItems] = useState([]);
  const [category, setCategory] = useState("EDR / XDR");
  const [selectedId, setSelectedId] = useState("");
  const [values, setValues] = useState({});
  const [configuredSecrets, setConfiguredSecrets] = useState([]);
  const [notice, setNotice] = useState("");
  const [working, setWorking] = useState(false);
  const load = useCallback(async () => {
    try {
      const catalog = await api("/api/integrations");
      setItems(catalog);
      setSelectedId((current) => current || catalog.find((item) => item.category === "EDR / XDR")?.id || catalog[0]?.id || "");
    } catch (error) { setNotice(error.message); }
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!selectedId) return;
    api(`/api/integrations/${selectedId}`).then((saved) => {
      const catalog = items.find((item) => item.id === selectedId);
      setValues({ ...(catalog?.defaults || {}), ...(saved.settings || {}) });
      setConfiguredSecrets(saved.configured_secrets || []);
    }).catch((error) => setNotice(error.message));
  }, [items, selectedId]);
  const categories = useMemo(() => [...new Set(items.map((item) => item.category))], [items]);
  const visible = items.filter((item) => item.category === category);
  const selected = items.find((item) => item.id === selectedId);
  const save = async (activate = false) => {
    if (!selectedId) return;
    setWorking(true);
    try {
      await api(`/api/integrations/${selectedId}`, jsonOptions("PUT", { settings: values }));
      if (activate) {
        const result = await api(`/api/integrations/${selectedId}/test`, { method: "POST" });
        setNotice(`${selected?.name} connected; ${result.record_count} bounded test record(s) returned.`);
      } else {
        setNotice(`${selected?.name} configuration saved. Test it to make it available to hunts.`);
      }
      await Promise.all([load(), onTelemetryChange()]);
    } catch (error) { setNotice(error.message); }
    finally { setWorking(false); }
  };
  const remove = async () => {
    if (session.role !== "Admin" || !selectedId || !window.confirm(`Remove the ${selected?.name} integration configuration?`)) return;
    try {
      await api(`/api/integrations/${selectedId}`, { method: "DELETE" });
      setNotice(`${selected?.name} configuration removed.`);
      await Promise.all([load(), onTelemetryChange()]);
    } catch (error) { setNotice(error.message); }
  };
  return <div className="integration-layout">
    <aside className="integration-catalog panel">
      <div className="integration-categories">{categories.map((item) => <button key={item} className={category === item ? "active" : ""} onClick={() => { setCategory(item); setSelectedId(items.find((entry) => entry.category === item)?.id || ""); }}>{item}</button>)}</div>
      <div className="integration-list">{visible.map((item) => <button key={item.id} className={selectedId === item.id ? "active" : ""} onClick={() => setSelectedId(item.id)}><span><strong>{item.name}</strong><small>{item.vendor} · {item.device_types.join(", ")}</small></span><i className={`integration-state ${item.connection_status === "connected" ? "connected" : ""}`}>{item.connection_status}</i></button>)}</div>
    </aside>
    <main className="settings-stack">
      {selected ? <section className="settings-card">
        <div className="settings-card-title"><span><LinkIcon /></span><div><h3>{selected.name}</h3><p>{selected.description} All collection is bounded and read-only.</p></div></div>
        {notice && <Notice success={/saved|connected|removed/i.test(notice)}>{notice}</Notice>}
        <div className="integration-meta"><span>{selected.category}</span><span>{selected.vendor}</span><span>{selected.device_types.join(" · ")}</span><span>{selected.connection_status}</span></div>
        <div className="settings-form-grid">{selected.fields.map((field) => <label key={field.name}>{field.label}{field.type === "password" && configuredSecrets.includes(field.name) && <small>Stored · leave blank to keep</small>}<input type={field.type === "password" ? "password" : field.type === "number" ? "number" : "text"} required={field.required} value={values[field.name] || ""} onChange={(event) => setValues({ ...values, [field.name]: event.target.value })} /></label>)}</div>
        <div className="settings-actions">{session.role === "Admin" && <button className="danger-button" onClick={remove}><TrashIcon /> Remove</button>}<button className="secondary-button" disabled={working} onClick={() => save(false)}>Save configuration</button><button className="primary-button" disabled={working} onClick={() => save(true)}>{working ? <ArrowPathIcon className="spinning" /> : <BeakerIcon />} Save, test & activate</button></div>
      </section> : <section className="settings-card"><p>Select an integration.</p></section>}
    </main>
  </div>;
}

export default function Integrations({ session, activeSources, onTelemetryChange }) {
  const [mode, setMode] = useState("siem");
  return <div className="page-wrap integrations-page">
    <section className="page-heading"><div><span className="status-pill status-indigo"><LinkIcon /> Governed connectors</span><h1>Security integrations</h1><p>Connect SIEM, EDR/XDR, identity, cloud, email, network, and other security telemetry through one governed workspace.</p></div></section>
    <div className="integration-mode panel"><button className={mode === "siem" ? "active" : ""} onClick={() => setMode("siem")}><CircleStackIcon /> SIEM</button><button className={mode === "direct" ? "active" : ""} onClick={() => setMode("direct")}><LinkIcon /> EDR and log sources</button></div>
    {mode === "siem" ? <SiemTab activeSources={activeSources} onTelemetryChange={onTelemetryChange} /> : <DirectIntegrations session={session} onTelemetryChange={onTelemetryChange} />}
  </div>;
}
