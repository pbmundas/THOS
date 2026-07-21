import { useCallback, useEffect, useState } from "react";
import {
  BeakerIcon, CheckCircleIcon, LightBulbIcon, PlusIcon, ShieldCheckIcon, TrashIcon,
} from "@heroicons/react/24/outline";

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`);
  return payload;
}

const EMPTY = { title: "", text: "", tactic: "Execution", technique: "" };

export default function HypothesisCreate({ onCreated }) {
  const [form, setForm] = useState(EMPTY);
  const [items, setItems] = useState([]);
  const [notice, setNotice] = useState("");
  const [saving, setSaving] = useState(false);
  const load = useCallback(async () => {
    try { setItems(await api("/api/settings/hypotheses")); }
    catch (error) { setNotice(error.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const create = async () => {
    setSaving(true);
    try {
      const item = await api("/api/settings/hypotheses", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form),
      });
      setNotice(`Created ${item.id}. It is now available on the hypothesis board.`);
      setForm(EMPTY);
      await Promise.all([load(), onCreated()]);
    } catch (error) { setNotice(error.message); }
    finally { setSaving(false); }
  };
  const remove = async (id) => {
    try {
      await api(`/api/settings/hypotheses/${encodeURIComponent(id)}`, { method: "DELETE" });
      setNotice(`Deleted ${id}.`);
      await Promise.all([load(), onCreated()]);
    } catch (error) { setNotice(error.message); }
  };

  return <div className="page-wrap create-hypothesis-page">
    <section className="page-heading"><div><span className="status-pill status-indigo"><LightBulbIcon /> SME authoring</span><h1>Create a hunting hypothesis</h1><p>Publish a reviewed organizational hypothesis into the shared catalogue. Analysts can read and run it from the board.</p></div></section>
    <section className="settings-card hypothesis-author-card">
      <div className="settings-card-title"><span><ShieldCheckIcon /></span><div><h3>Hypothesis definition</h3><p>Use observable behavior and identify the ATT&CK context. THOS assigns the next custom ID automatically.</p></div></div>
      {notice && <div className={`settings-notice ${notice.startsWith("Created") || notice.startsWith("Deleted") ? "success" : "error"}`}><span>{notice.startsWith("Created") ? <CheckCircleIcon /> : <BeakerIcon />}</span>{notice}</div>}
      <div className="settings-form-grid">
        <label>Title<input value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} placeholder="Concise behavior being investigated" /></label>
        <label>MITRE tactic<input value={form.tactic} onChange={(event) => setForm({ ...form, tactic: event.target.value })} placeholder="Execution" /></label>
        <label>Technique ID (optional)<input value={form.technique} onChange={(event) => setForm({ ...form, technique: event.target.value.toUpperCase() })} placeholder="T1059.001" /></label>
      </div>
      <label className="hypothesis-body-field">Hypothesis and investigation guidance<textarea value={form.text} onChange={(event) => setForm({ ...form, text: event.target.value })} placeholder="Describe the suspicious behavior, expected telemetry, useful baselines, and important limitations…" /></label>
      <div className="settings-actions"><button className="primary-button" disabled={saving || form.title.trim().length < 8 || form.text.trim().length < 20 || form.tactic.trim().length < 2} onClick={create}><PlusIcon /> {saving ? "Creating…" : "Create hypothesis"}</button></div>
    </section>
    <section className="settings-card"><h3>Organizational hypotheses</h3><div className="custom-hypothesis-list">{items.map((item) => <div key={item.id}><span className="status-pill status-indigo">{item.id}</span><span><strong>{item.title}</strong><small>{item.tactic} · {item.technique || "Unmapped"} · created {new Date(item.created_at).toLocaleString()}</small></span><button aria-label={`Delete ${item.id}`} onClick={() => remove(item.id)}><TrashIcon /></button></div>)}{!items.length && <p className="settings-muted">No custom hypotheses have been created.</p>}</div></section>
  </div>;
}
