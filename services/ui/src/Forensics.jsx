import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowPathIcon,
  CheckCircleIcon,
  ClockIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon,
  FingerPrintIcon,
  FolderArrowDownIcon,
} from "@heroicons/react/24/outline";

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || `Request failed (${response.status})`);
  }
  return response.json();
}

function elapsed(value) {
  const ms = Number(value);
  if (!Number.isFinite(ms)) return "—";
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
}

function localTimestamp(value) {
  const parsed = value ? new Date(value) : new Date();
  if (Number.isNaN(parsed.getTime())) return "—";
  const pad = (number) => String(number).padStart(2, "0");
  return `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())} ${pad(parsed.getHours())}:${pad(parsed.getMinutes())}:${pad(parsed.getSeconds())}`;
}

function reportFilename(path) {
  return String(path || "").split(/[\\/]/).pop();
}

export default function Forensics({ onOpenReport }) {
  const [cases, setCases] = useState([]);
  const [selected, setSelected] = useState(null);
  const [title, setTitle] = useState("");
  const [acquiredFrom, setAcquiredFrom] = useState("");
  const [legalAuthority, setLegalAuthority] = useState("");
  const [notes, setNotes] = useState("");
  const [files, setFiles] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [notice, setNotice] = useState("");
  const fileInput = useRef(null);

  const load = useCallback(async () => {
    try {
      const items = await api("/api/forensics");
      setCases(Array.isArray(items) ? items : []);
      if (selected?.case_id) {
        const detail = await api(`/api/forensics/${selected.case_id}`);
        setSelected(detail);
      }
    } catch (error) {
      setNotice(error.message);
    }
  }, [selected?.case_id]);

  useEffect(() => {
    load();
    const timer = window.setInterval(load, 3000);
    return () => window.clearInterval(timer);
  }, [load]);

  const openCase = async (caseId) => {
    setNotice("");
    try {
      setSelected(await api(`/api/forensics/${caseId}`));
    } catch (error) {
      setNotice(error.message);
    }
  };

  const submit = async (event) => {
    event.preventDefault();
    if (!title.trim() || !files.length || submitting) return;
    setSubmitting(true);
    setNotice("");
    const body = new FormData();
    body.append("case_title", title.trim());
    body.append("acquired_from", acquiredFrom.trim());
    body.append("legal_authority", legalAuthority.trim());
    body.append("notes", notes.trim());
    files.forEach((file) => body.append("files", file));
    try {
      const result = await api("/api/forensics/cases", { method: "POST", body });
      setNotice(`Case ${result.case_id} was preserved and queued for analysis.`);
      setTitle("");
      setAcquiredFrom("");
      setLegalAuthority("");
      setNotes("");
      setFiles([]);
      if (fileInput.current) fileInput.current.value = "";
      await load();
      await openCase(result.case_id);
    } catch (error) {
      setNotice(error.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="page-wrap forensics-page">
      <section className="page-heading">
        <div>
          <span className="status-pill status-indigo"><FingerPrintIcon /> Evidence examination</span>
          <h1>Digital Forensics</h1>
          <p>Preserve one or more evidence files, verify full-file hashes, correlate artifacts, and produce a technical legal-review report.</p>
        </div>
        <button className="secondary-button" onClick={load}><ArrowPathIcon /> Refresh cases</button>
      </section>

      {notice && <div className={`alert ${notice.includes("queued") ? "" : "error-alert"}`}>{notice.includes("queued") ? <CheckCircleIcon /> : <ExclamationTriangleIcon />}{notice}</div>}

      <section className="forensic-intake panel">
        <div className="settings-card-title">
          <span><FolderArrowDownIcon /></span>
          <div><h3>New evidence intake</h3><p>Files are stored once under the dated forensic evidence root; SHA-256 is recorded during upload and recomputed before examination.</p></div>
        </div>
        <form onSubmit={submit}>
          <div className="forensic-form-grid">
            <label>Case title<input value={title} maxLength={300} onChange={(event) => setTitle(event.target.value)} required /></label>
            <label>Collection source / tool<input value={acquiredFrom} onChange={(event) => setAcquiredFrom(event.target.value)} placeholder="e.g. EnCase, FTK Imager, Velociraptor" /></label>
            <label>Legal authority / authorization<input value={legalAuthority} onChange={(event) => setLegalAuthority(event.target.value)} placeholder="Warrant, consent, ticket, or internal authorization" /></label>
            <label className="forensic-files">Evidence files<input ref={fileInput} type="file" multiple onChange={(event) => setFiles(Array.from(event.target.files || []))} required /><small>{files.length ? `${files.length} file(s) selected · ${files.reduce((sum, file) => sum + file.size, 0).toLocaleString()} bytes` : "Select single or multiple logs, archives, documents, captures, or forensic images."}</small></label>
            <label className="forensic-notes">Scope and examination notes<textarea rows={4} value={notes} onChange={(event) => setNotes(event.target.value)} /></label>
          </div>
          <button className="primary-button" disabled={submitting || !title.trim() || !files.length}>{submitting ? <ArrowPathIcon className="spinning" /> : <FingerPrintIcon />} Preserve and analyze</button>
        </form>
      </section>

      <div className="forensic-layout">
        <aside className="forensic-cases panel">
          <header><h2>Forensic cases</h2><span>{cases.length}</span></header>
          {cases.map((item) => (
            <button key={item.case_id} className={selected?.case_id === item.case_id ? "active" : ""} onClick={() => openCase(item.case_id)}>
              <span className={`run-status run-${item.status}`}>{item.status}</span>
              <strong>{item.case_title}</strong>
              <small>{new Date(item.created_at).toLocaleString()} · {item.examiner}</small>
              <code>{item.case_id}</code>
            </button>
          ))}
          {!cases.length && <p className="muted-list">No forensic cases have been submitted.</p>}
        </aside>

        <section className="forensic-detail panel">
          {selected ? (
            <>
              <header>
                <div><span className={`run-status run-${selected.status}`}>{selected.status}</span><h2>{selected.case_title}</h2><code>{selected.case_id}</code></div>
                {selected.report_path && <button className="primary-button" onClick={() => onOpenReport(reportFilename(selected.report_path))}><DocumentTextIcon /> View forensic report</button>}
              </header>
              {selected.error_msg && <div className="alert error-alert"><ExclamationTriangleIcon />{selected.error_msg}</div>}
              {selected.current_stage && <div className="forensic-current"><ClockIcon /><div><strong>Agent working now</strong><span>{selected.current_stage.replaceAll("_", " ")}</span></div></div>}
              <div className="forensic-agent-list">
                {(selected.steps || []).map((step) => (
                  <article key={step.step_id}>
                    <span><CheckCircleIcon /></span>
                    <div><strong>{step.agent_name}</strong><p>{step.activity}</p><small>{step.model_name ? `${step.model_name} (${step.model_tier} tier)` : "Deterministic evidence stage · no model"}</small></div>
                    <time title={`Execution duration: ${elapsed(step.duration_ms)}`}>{localTimestamp(step.created_at)}</time>
                  </article>
                ))}
                {!selected.steps?.length && <p className="muted-list">Waiting for the first integrity stage to complete.</p>}
              </div>
              {selected.summary && <div className="result-summary"><h3>Case output</h3><p>{selected.summary}</p></div>}
            </>
          ) : <div className="empty-state"><span className="empty-icon"><FingerPrintIcon /></span><h3>Select a forensic case</h3><p>Open a case to inspect named agent stages, local completion timestamps, limitations, and report status.</p></div>}
        </section>
      </div>
    </div>
  );
}
