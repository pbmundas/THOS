import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowPathIcon,
  CheckCircleIcon,
  CircleStackIcon,
  ClockIcon,
  CpuChipIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon,
  FingerPrintIcon,
  FolderArrowDownIcon,
  ShieldCheckIcon,
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

function bytes(value) {
  const amount = Number(value || 0);
  if (!Number.isFinite(amount)) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = amount;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(unit ? 2 : 0)} ${units[unit]}`;
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

function readyForensicTools(payload) {
  const tools = Array.isArray(payload?.tools) ? payload.tools : [];
  return tools.filter(
    (tool) => tool?.available === true && tool?.status === "available"
  );
}

function MemoryResult({ scan }) {
  if (!scan) {
    return (
      <div className="empty-state">
        <span className="empty-icon"><CpuChipIcon /></span>
        <h3>Select a file or memory scan</h3>
        <p>Open a scan to inspect integrity metadata, YARA matches, offsets, tags, and execution limits.</p>
      </div>
    );
  }
  const result = scan.scan_result || {};
  const fileResult = (result.results || [])[0] || {};
  const matches = fileResult.matches || [];
  const staticAnalysis = scan.static_analysis || {};
  const toolResults = staticAnalysis.results || [];
  return (
    <>
      <header>
        <div>
          <span className={`run-status run-${scan.status}`}>{scan.status}</span>
          <h2>{scan.scan_title}</h2>
          <code>{scan.scan_id}</code>
        </div>
        <div className="memory-agent-badge"><CpuChipIcon /><span><strong>File and Memory Static Analysis Agent</strong><small>Deterministic, non-executing triage · no model reasoning</small></span></div>
      </header>

      {scan.error && <div className="alert error-alert"><ExclamationTriangleIcon />{scan.error}</div>}
      <div className="memory-summary-grid">
        <article><small>Rule matches</small><strong>{Number(result.match_count || 0).toLocaleString()}</strong><span>{Number(result.matched_files || 0)} matched file{Number(result.matched_files || 0) === 1 ? "" : "s"}</span></article>
        <article><small>Artifact size</small><strong>{bytes(scan.size_bytes)}</strong><span>{scan.artifact_type === "process_dump" ? "Process dump" : scan.artifact_type === "memory_dump" ? "Memory dump" : "Suspicious file"}</span></article>
        <article><small>Scan duration</small><strong>{elapsed(result.duration_ms)}</strong><span>Timeout {result.scan_timeout_seconds || "—"} seconds</span></article>
        <article><small>Rules evaluated</small><strong>{Number(result.catalog?.enabled_rules || result.catalog?.enabled || 0).toLocaleString()}</strong><span>Actionable enabled bundle</span></article>
      </div>

      <div className="memory-integrity">
        <ShieldCheckIcon />
        <div><strong>Preserved artifact integrity</strong><code>{scan.sha256 || fileResult.sha256 || "Hash unavailable"}</code></div>
        <span>{scan.original_name} · received {localTimestamp(scan.received_at)}</span>
      </div>

      {(result.errors || []).map((error, index) => (
        <div className="alert error-alert" key={`${error.path}-${index}`}><ExclamationTriangleIcon />{error.error}</div>
      ))}

      {toolResults.length > 0 && (
        <div className="forensic-tool-results">
          <div className="memory-section-heading">
            <h3>Static forensic triage</h3>
            <span>{Number(staticAnalysis.finding_count || 0)} deterministic finding{Number(staticAnalysis.finding_count || 0) === 1 ? "" : "s"}</span>
          </div>
          <div className="forensic-tool-result-grid">
            {toolResults.map((tool, index) => (
              <details key={`${tool.tool_id}-${index}`}>
                <summary>
                  <strong>{tool.tool_id}</strong>
                  <span className={`tool-state tool-state-${tool.status}`}>{String(tool.status || "unknown").replaceAll("_", " ")}</span>
                  <small>{elapsed(tool.duration_ms)}</small>
                </summary>
                {tool.note && <p>{tool.note}</p>}
                {tool.error && <div className="alert error-alert"><ExclamationTriangleIcon />{tool.error}</div>}
                {tool.data && <pre>{JSON.stringify(tool.data, null, 2)}</pre>}
                {tool.output && <pre>{tool.output}</pre>}
                {tool.truncated && <small>Output was truncated at the configured safety limit.</small>}
              </details>
            ))}
          </div>
        </div>
      )}

      {matches.length ? (
        <div className="memory-matches">
          <div className="memory-section-heading"><h3>Matched rules</h3><span>{matches.length} result{matches.length === 1 ? "" : "s"}</span></div>
          {matches.map((match, index) => (
            <article key={`${match.rule_id}-${index}`}>
              <header>
                <div><strong>{match.meta?.description || match.meta?.name || match.raw_rule_id}</strong><code>{match.rule_id}</code></div>
                <span className={`severity severity-${String(match.meta?.severity || "medium").toLowerCase()}`}>{match.meta?.severity || "review"}</span>
              </header>
              <p>{match.meta?.description || "The rule matched byte patterns in the submitted dump. Validate the process, memory region, and surrounding artifacts before concluding malicious activity."}</p>
              <div className="memory-rule-meta"><span>Namespace: {match.namespace}</span>{(match.tags || []).map((tag) => <span key={tag}>{tag}</span>)}</div>
              {(match.strings || []).length > 0 && (
                <details>
                  <summary>Matched byte locations ({match.strings.length})</summary>
                  <div className="memory-offsets">
                    {(match.strings || []).slice(0, 50).map((item, itemIndex) => (
                      <div key={`${item.identifier}-${item.offset}-${itemIndex}`}><code>{item.identifier}</code><span>Offset {Number(item.offset).toLocaleString()}</span><code>{item.matched_data_hex}</code></div>
                    ))}
                  </div>
                </details>
              )}
            </article>
          ))}
        </div>
      ) : scan.status === "clean" ? (
        <div className="memory-clean"><CheckCircleIcon /><div><h3>No enabled YARA rule matched this artifact</h3><p>{scan.artifact_type === "suspicious_file" ? "The current actionable rule bundle found no match. This does not prove that the file is benign; continue with static, behavioral, reputation, and sandbox analysis when the case requires it." : "The current actionable rule bundle found no match. This does not prove that the memory image is clean; continue with process, module, network, timeline, and volatility-style examination when the case requires it."}</p></div></div>
      ) : null}
    </>
  );
}

export default function Forensics({
  onOpenReport,
  initialTab = "evidence",
  focusId = "",
  onRouteChange,
}) {
  const [activeTab, setActiveTab] = useState(
    initialTab === "yara" ? "memory" : "evidence"
  );
  const [cases, setCases] = useState([]);
  const [selected, setSelected] = useState(null);
  const [title, setTitle] = useState("");
  const [acquiredFrom, setAcquiredFrom] = useState("");
  const [legalAuthority, setLegalAuthority] = useState("");
  const [notes, setNotes] = useState("");
  const [files, setFiles] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [memoryScans, setMemoryScans] = useState([]);
  const [selectedMemory, setSelectedMemory] = useState(null);
  const [memoryTitle, setMemoryTitle] = useState("");
  const [dumpType, setDumpType] = useState("suspicious_file");
  const [memorySource, setMemorySource] = useState("");
  const [memoryNotes, setMemoryNotes] = useState("");
  const [memoryFile, setMemoryFile] = useState(null);
  const [memorySubmitting, setMemorySubmitting] = useState(false);
  const [notice, setNotice] = useState("");
  const [noticeError, setNoticeError] = useState(false);
  const [forensicTools, setForensicTools] = useState(null);
  const visibleForensicTools = readyForensicTools(forensicTools);
  const fileInput = useRef(null);
  const memoryInput = useRef(null);

  const loadEvidence = useCallback(async () => {
    try {
      const items = await api("/api/forensics");
      setCases(Array.isArray(items) ? items : []);
      if (selected?.case_id) setSelected(await api(`/api/forensics/${selected.case_id}`));
    } catch (error) {
      setNotice(error.message);
      setNoticeError(true);
    }
  }, [selected?.case_id]);

  const loadMemory = useCallback(async () => {
    try {
      const items = await api("/api/forensics/yara-scans");
      setMemoryScans(Array.isArray(items) ? items : []);
      if (selectedMemory?.scan_id) setSelectedMemory(await api(`/api/forensics/yara-scans/${selectedMemory.scan_id}`));
    } catch (error) {
      setNotice(error.message);
      setNoticeError(true);
    }
  }, [selectedMemory?.scan_id]);

  const loadTools = useCallback(async () => {
    try {
      setForensicTools(await api("/api/forensics/tools"));
    } catch (error) {
      setNotice(error.message);
      setNoticeError(true);
    }
  }, []);

  useEffect(() => {
    loadTools();
  }, [loadTools]);

  useEffect(() => {
    const loader = activeTab === "evidence" ? loadEvidence : loadMemory;
    loader();
    const timer = window.setInterval(loader, 3000);
    return () => window.clearInterval(timer);
  }, [activeTab, loadEvidence, loadMemory]);

  const openCase = async (caseId) => {
    setNotice("");
    try {
      setSelected(await api(`/api/forensics/${caseId}`));
      onRouteChange?.("evidence", caseId);
    } catch (error) {
      setNotice(error.message);
      setNoticeError(true);
    }
  };

  const openMemoryScan = async (scanId) => {
    setNotice("");
    try {
      setSelectedMemory(await api(`/api/forensics/yara-scans/${scanId}`));
      onRouteChange?.("yara", scanId);
    } catch (error) {
      setNotice(error.message);
      setNoticeError(true);
    }
  };

  useEffect(() => {
    const nextTab = initialTab === "yara" ? "memory" : "evidence";
    setActiveTab(nextTab);
    if (!focusId) return;
    if (initialTab === "yara") openMemoryScan(focusId);
    else openCase(focusId);
    // The focus is a validated URL identifier; reload only when it changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialTab, focusId]);

  const submit = async (event) => {
    event.preventDefault();
    if (!title.trim() || !files.length || submitting) return;
    setSubmitting(true);
    setNotice("");
    setNoticeError(false);
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
      await loadEvidence();
      await openCase(result.case_id);
    } catch (error) {
      setNotice(error.message);
      setNoticeError(true);
    } finally {
      setSubmitting(false);
    }
  };

  const submitMemory = async (event) => {
    event.preventDefault();
    if (!memoryTitle.trim() || !memoryFile || memorySubmitting) return;
    setMemorySubmitting(true);
    setNotice("");
    setNoticeError(false);
    const body = new FormData();
    body.append("scan_title", memoryTitle.trim());
    body.append("artifact_type", dumpType);
    body.append("acquired_from", memorySource.trim());
    body.append("notes", memoryNotes.trim());
    body.append("sample", memoryFile);
    try {
      const result = await api("/api/forensics/yara-scans", { method: "POST", body });
      setSelectedMemory(result);
      setNotice(`Static analysis ${result.scan_id} completed with ${(result.scan_result?.match_count || 0) + (result.static_analysis?.finding_count || 0)} deterministic findings.`);
      setMemoryTitle("");
      setMemorySource("");
      setMemoryNotes("");
      setMemoryFile(null);
      if (memoryInput.current) memoryInput.current.value = "";
      await loadMemory();
    } catch (error) {
      setNotice(error.message);
      setNoticeError(true);
    } finally {
      setMemorySubmitting(false);
    }
  };

  const refresh = activeTab === "evidence" ? loadEvidence : loadMemory;

  return (
    <div className="page-wrap forensics-page">
      <section className="page-heading">
        <div>
          <span className="status-pill status-indigo"><FingerPrintIcon /> Evidence examination</span>
          <h1>Digital Forensics</h1>
          <p>Preserve evidence and run content-routed, non-executing analysis across suspicious files, executables, documents, registry hives, disk images, memory images, and process dumps.</p>
        </div>
        <button className="secondary-button" onClick={refresh}><ArrowPathIcon /> Refresh {activeTab === "evidence" ? "cases" : "scans"}</button>
      </section>

      <div className="forensic-tabs" role="tablist" aria-label="Forensic analysis type">
        <button role="tab" aria-selected={activeTab === "evidence"} className={activeTab === "evidence" ? "active" : ""} onClick={() => { setActiveTab("evidence"); onRouteChange?.("evidence"); }}><FolderArrowDownIcon /><span><strong>Evidence Analysis</strong><small>Evidence-based forensic reasoning</small></span></button>
        <button role="tab" aria-selected={activeTab === "memory"} className={activeTab === "memory" ? "active" : ""} onClick={() => { setActiveTab("memory"); onRouteChange?.("yara"); }}><CpuChipIcon /><span><strong>File &amp; Memory Analysis</strong><small>Suspicious files, executables, and dumps</small></span></button>
      </div>

      {visibleForensicTools.length > 0 && (
        <details className="forensic-tool-coverage panel">
          <summary>
            <span><ShieldCheckIcon /></span>
            <div><strong>Ready forensic tools</strong><small>{visibleForensicTools.length} tools available for agent-selected analysis · samples are never executed</small></div>
            <span>View tools</span>
          </summary>
          <div className="forensic-tool-grid">
            {visibleForensicTools.map((tool) => (
              <article key={tool.tool_id}>
                <header><strong>{tool.name}</strong></header>
                <p>{tool.purpose}</p>
                <small>{(tool.capabilities || []).join(" · ")}</small>
              </article>
            ))}
          </div>
          <p className="forensic-safety-note">Timeout {forensicTools.safety?.timeout_seconds}s per tool · output capped at {bytes(forensicTools.safety?.output_byte_limit)} · submitted samples are never executed</p>
        </details>
      )}

      {notice && <div className={`alert ${noticeError ? "error-alert" : ""}`}>{noticeError ? <ExclamationTriangleIcon /> : <CheckCircleIcon />}{notice}</div>}

      {activeTab === "evidence" ? (
        <>
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
        </>
      ) : (
        <>
          <section className="forensic-intake memory-intake panel">
            <div className="settings-card-title">
              <span><CircleStackIcon /></span>
              <div><h3>Submit a suspicious file, memory image, or process dump</h3><p>The artifact is streamed to managed forensic storage, hashed, made read-only, classified by content, and routed through applicable static-analysis tools and YARA.</p></div>
            </div>
            <form onSubmit={submitMemory}>
              <div className="forensic-form-grid">
                <label>Scan title<input value={memoryTitle} maxLength={300} onChange={(event) => setMemoryTitle(event.target.value)} required /></label>
                <label>Artifact type<select value={dumpType} onChange={(event) => setDumpType(event.target.value)}><option value="suspicious_file">Suspicious file / executable</option><option value="memory_dump">Full memory dump</option><option value="process_dump">Process dump</option></select></label>
                <label>Acquisition agent / tool<input value={memorySource} maxLength={1000} onChange={(event) => setMemorySource(event.target.value)} placeholder="e.g. WinPmem, DumpIt, LiME, ProcDump, Velociraptor" /></label>
                <label className="forensic-files">File to analyze<input ref={memoryInput} type="file" onChange={(event) => setMemoryFile(event.target.files?.[0] || null)} required /><small>{memoryFile ? `${memoryFile.name} · ${bytes(memoryFile.size)}` : "Any file can be submitted, including PE/ELF executables, DLLs, scripts, documents, archives, raw/VM/LiME memory, core files, minidumps, and process dumps."}</small></label>
                <label className="forensic-notes">Acquisition and investigation notes<textarea rows={4} value={memoryNotes} onChange={(event) => setMemoryNotes(event.target.value)} placeholder="Host, process, acquisition time, incident reference, and scope." /></label>
              </div>
              <button className="primary-button" disabled={memorySubmitting || !memoryTitle.trim() || !memoryFile}>{memorySubmitting ? <ArrowPathIcon className="spinning" /> : <CpuChipIcon />} {memorySubmitting ? "Preserving and analyzing…" : "Preserve and analyze"}</button>
            </form>
          </section>

          <div className="forensic-layout">
            <aside className="forensic-cases memory-scan-list panel">
              <header><h2>File and memory scans</h2><span>{memoryScans.length}</span></header>
              {memoryScans.map((item) => (
                <button key={item.scan_id} className={selectedMemory?.scan_id === item.scan_id ? "active" : ""} onClick={() => openMemoryScan(item.scan_id)}>
                  <span className={`run-status run-${item.status}`}>{item.status}</span>
                  <strong>{item.scan_title}</strong>
                  <small>{localTimestamp(item.received_at)} · {(item.match_count || 0) + (item.static_finding_count || 0)} finding{(item.match_count || 0) + (item.static_finding_count || 0) === 1 ? "" : "s"}</small>
                  <code>{item.original_name}</code>
                </button>
              ))}
              {!memoryScans.length && <p className="muted-list">No suspicious files, memory images, or process dumps have been scanned.</p>}
            </aside>
            <section className="forensic-detail memory-detail panel"><MemoryResult scan={selectedMemory} /></section>
          </div>
        </>
      )}
    </div>
  );
}
