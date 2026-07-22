import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowDownTrayIcon,
  ArrowLeftOnRectangleIcon,
  ArrowPathIcon,
  Bars3Icon,
  CheckCircleIcon,
  ChevronRightIcon,
  ClockIcon,
  Cog6ToothIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon,
  EyeIcon,
  LightBulbIcon,
  MagnifyingGlassIcon,
  PlayIcon,
  QueueListIcon,
  RadioIcon,
  ShieldExclamationIcon,
  ShieldCheckIcon,
  SparklesIcon,
  Squares2X2Icon,
  XMarkIcon,
} from "@heroicons/react/24/outline";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import logo from "./assets/appLogo.svg";
import ChatPage from "./ChatPage";
import HypothesisCreate from "./HypothesisCreate";
import Settings from "./Settings";
import Detections from "./Detections";

const NODE_LABELS = {
  refresh_hearth_kb: "Refreshing hypothesis knowledge",
  supervisor: "Planning adaptive hunt workflow",
  hypothesis: "Selecting hypothesis & MITRE context",
  hunt_memory: "Recalling relevant completed hunts",
  query_gen: "Generating SIEM query",
  siem_fetch: "Fetching logs from SIEM",
  log_processing: "Normalizing and deduplicating logs",
  guardrail: "Screening untrusted telemetry",
  soc_tools: "Running SOC tools (Sigma and enrichment)",
  coverage_gap: "Checking telemetry coverage gaps",
  threat_intel: "Enriching indicators with threat intelligence",
  reasoning: "Reasoning over evidence",
  verifier: "Verifying citations and confidence",
  detection_engineering: "Drafting detection-rule proposal",
  communication: "Preparing audience-aware brief",
  report: "Writing hunt report",
};

const NODE_REASONS = {
  hypothesis: "resolves hunt scope and ATT&CK context",
  hunt_memory: "recalls lessons from comparable hunts",
  supervisor: "selects the analysis stages required",
  query_gen: "creates deterministic, validated SIEM syntax",
  siem_fetch: "retrieves bounded telemetry from the selected source",
  log_processing: "normalizes evidence and removes duplicates",
  guardrail: "screens untrusted log text before model use",
  soc_tools: "runs SigmaHQ, local Sigma, and enrichment concurrently",
  coverage_gap: "checks whether available telemetry supports a conclusion",
  threat_intel: "compares observed indicators with local intelligence",
  reasoning: "turns evidence into cited findings",
  verifier: "validates citations before findings are trusted",
  report: "persists evidence and governance status",
};

function formatDuration(value) {
  const milliseconds = Number(value);
  if (!Number.isFinite(milliseconds)) return "—";
  return milliseconds < 1000 ? `${Math.max(0, Math.round(milliseconds))} ms` : `${(milliseconds / 1000).toFixed(2)} s`;
}

function eventReason(node, data = {}) {
  if (node === "siem_fetch") return `retrieved ${data.record_count || 0} matching records`;
  if (node === "log_processing") return `retained ${(data.processed_logs || []).length} normalized records`;
  if (node === "soc_tools") {
    return `evaluated ${(data.enrichment || {}).sigma_rules_evaluated || 0} rules; flagged ${data.sigma_matched_count || 0} records`;
  }
  if (node === "coverage_gap") return `identified ${(data.coverage_gaps || []).length} coverage gaps`;
  if (node === "threat_intel") return `found ${(data.enrichment_hits || []).length} local IOC matches`;
  if (node === "reasoning" && data.reasoning_failed) return `failed after ${data.reasoning_attempts || 3} attempts; report generation was stopped`;
  if (node === "reasoning" && data.reasoning_degraded) return `model attempts exhausted; completed with deterministic evidence fallback and human approval`;
  if (node === "reasoning" && data.reasoning_cache_hit) return "reused a previously validated reasoning result";
  if (node === "reasoning" && data.reasoning_attempts) return `returned a complete validated result on attempt ${data.reasoning_attempts}`;
  return NODE_REASONS[node] || "completed this hunt stage";
}

function moduleDetails(data = {}) {
  const details = {};
  Object.entries(data).forEach(([key, value]) => {
    if (["logs", "processed_logs", "findings"].includes(key) && Array.isArray(value)) details[key] = `${value.length} item(s)`;
    else if (Array.isArray(value)) details[key] = value.length <= 8 ? value : `${value.length} item(s)`;
    else if (value && typeof value === "object") details[key] = Object.keys(value).length <= 12 ? value : `${Object.keys(value).length} field(s)`;
    else if (typeof value === "string") details[key] = value.length > 500 ? `${value.slice(0, 500)}…` : value;
    else details[key] = value;
  });
  return details;
}

function progressItem(step) {
  const data = step?.output && typeof step.output === "object" ? step.output : {};
  return {
    id: step?.step_id || `${step?.node_name}-${step?.created_at || ""}`,
    node: step?.node_name || "unknown",
    label: NODE_LABELS[step?.node_name] || step?.node_name || "Unknown module",
    duration: formatDuration(step?.duration_ms),
    reason: eventReason(step?.node_name, data),
    details: moduleDetails(data),
  };
}

function readableHypothesisText(value) {
  if (!value) return "No hypothesis description supplied.";
  return String(value).replace(/<\/?br\s*\/?>/gi, "\n").trim();
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) {
    if (response.status === 401) window.dispatchEvent(new Event("thos:unauthorized"));
    let detail = `Request failed (${response.status})`;
    try {
      const payload = await response.json();
      detail = payload.detail || payload.error || detail;
    } catch {
      // Keep the status-based message when a proxy returns non-JSON.
    }
    throw new Error(detail);
  }
  return response.json();
}

function StatusPill({ children, tone = "slate" }) {
  return <span className={`status-pill status-${tone}`}>{children}</span>;
}

function EmptyState({ icon: Icon, title, body }) {
  return (
    <div className="empty-state">
      <span className="empty-icon"><Icon /></span>
      <h3>{title}</h3>
      <p>{body}</p>
    </div>
  );
}

function LoginPage({ onAuthenticated, checking = false }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [loginError, setLoginError] = useState("");

  const submit = async (event) => {
    event.preventDefault();
    if (!username.trim() || !password || submitting) return;
    setSubmitting(true);
    setLoginError("");
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.detail || "Sign-in failed");
      onAuthenticated(payload);
    } catch (error) {
      setLoginError(error.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="login-page">
      <section className="login-story" aria-label="THOS platform overview">
        <div className="login-brand"><span className="brand-mark"><img src={logo} alt="" /></span><div><strong>THOS</strong><small>Threat Hunting OS</small></div></div>
        <div className="login-story-copy">
          <StatusPill tone="cyan"><ShieldCheckIcon /> On-prem intelligence</StatusPill>
          <h1>Turn hypotheses into<br />defensible evidence.</h1>
          <p>Run governed threat hunts, inspect each analysis stage, and publish verified investigation reports without moving telemetry outside your environment.</p>
          <div className="login-assurances">
            <span><CheckCircleIcon /> Local model inference</span>
            <span><CheckCircleIcon /> Approval-gated detections</span>
            <span><CheckCircleIcon /> Auditable hunt reports</span>
          </div>
        </div>
        <p className="login-footnote">SECURITY OPERATIONS WORKSPACE</p>
      </section>
      <section className="login-form-side">
        <form className="login-card" onSubmit={submit}>
          <div className="login-mobile-brand"><span className="brand-mark"><img src={logo} alt="" /></span><strong>THOS</strong></div>
          <StatusPill tone="indigo"><RadioIcon /> Analyst access</StatusPill>
          <h2>{checking ? "Checking session…" : "Welcome back"}</h2>
          <p>Sign in to open the threat hunting workspace.</p>
          <label htmlFor="login-username">Username</label>
          <input id="login-username" name="username" autoComplete="username" autoFocus={!checking} value={username} onChange={(event) => setUsername(event.target.value)} disabled={checking || submitting} />
          <label htmlFor="login-password">Password</label>
          <input id="login-password" name="password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} disabled={checking || submitting} />
          {loginError && <div className="login-error" role="alert"><ExclamationTriangleIcon /> {loginError}</div>}
          <button className="login-submit" type="submit" disabled={checking || submitting || !username.trim() || !password}>
            {checking || submitting ? <ArrowPathIcon className="spinning" /> : <ShieldCheckIcon />}
            {checking ? "Checking session" : submitting ? "Signing in" : "Sign in securely"}
          </button>
          <div className="login-security"><ShieldCheckIcon /><span><strong>Protected session</strong><small>Credentials are exchanged only with this local THOS gateway.</small></span></div>
        </form>
      </section>
    </main>
  );
}

function App() {
  const [authStatus, setAuthStatus] = useState("checking");
  const [analyst, setAnalyst] = useState("");
  const [session, setSession] = useState({ display_name: "", role: "Analyst", permissions: [] });
  const [page, setPage] = useState("hunts");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [hypotheses, setHypotheses] = useState([]);
  const [hypothesisError, setHypothesisError] = useState("");
  const [loadingHypotheses, setLoadingHypotheses] = useState(true);
  const [query, setQuery] = useState("");
  const [tactic, setTactic] = useState("All tactics");
  const [selectedId, setSelectedId] = useState("");
  const [readingHypothesis, setReadingHypothesis] = useState(null);
  const [activeSources, setActiveSources] = useState([{ id: "folder", label: "Local folder" }]);
  const [siemType, setSiemType] = useState("folder");
  const [folderPath, setFolderPath] = useState("/data/log_sources");
  const [coverStyle, setCoverStyle] = useState("1");
  const [running, setRunning] = useState(false);
  const [platformHuntActive, setPlatformHuntActive] = useState(false);
  const [huntId, setHuntId] = useState("");
  const [huntTitle, setHuntTitle] = useState("");
  const [progress, setProgress] = useState([]);
  const [activeNode, setActiveNode] = useState("");
  const [expandedNode, setExpandedNode] = useState("");
  const [huntError, setHuntError] = useState("");
  const [finalState, setFinalState] = useState(null);
  const [lastRun, setLastRun] = useState(null);
  const [reports, setReports] = useState([]);
  const [huntHistory, setHuntHistory] = useState([]);
  const [reportsLoading, setReportsLoading] = useState(false);
  const [reportQuery, setReportQuery] = useState("");
  const [selectedReport, setSelectedReport] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState("");

  const loadHypotheses = useCallback(async () => {
    setLoadingHypotheses(true);
    setHypothesisError("");
    try {
      const items = await api("/api/hypotheses");
      setHypotheses(Array.isArray(items) ? items : []);
      setSelectedId((current) => current || items?.[0]?.id || "");
    } catch (error) {
      setHypothesisError(error.message);
    } finally {
      setLoadingHypotheses(false);
    }
  }, []);

  const loadTelemetrySources = useCallback(async () => {
    try {
      const payload = await api("/api/telemetry-sources");
      const items = Array.isArray(payload.items) && payload.items.length ? payload.items : [{ id: "folder", label: "Local folder" }];
      setActiveSources(items);
      setSiemType(payload.default || items[0].id || "folder");
    } catch {
      setActiveSources([{ id: "folder", label: "Local folder" }]);
      setSiemType("folder");
    }
  }, []);

  const loadHuntStatus = useCallback(async () => {
    try {
      const status = await api("/api/hunts/status");
      const active = Boolean(status.active);
      setPlatformHuntActive(active);
      let hunt = status.hunt || null;
      const rememberedId = window.localStorage.getItem("thos:active-hunt") || "";
      if (!hunt && rememberedId) {
        try { hunt = await api(`/api/hunts/${rememberedId}/progress`); }
        catch { window.localStorage.removeItem("thos:active-hunt"); }
      }
      if (hunt) {
        const id = String(hunt.hunt_id || "");
        setHuntId(id);
        setHuntTitle(`${hunt.hypothesis_id || "Dynamic hunt"} · ${String(hunt.hypothesis_text || "Scheduled or analyst hunt").slice(0, 140)}`);
        setProgress((hunt.steps || []).map(progressItem));
        setActiveNode(active ? (hunt.current_stage || "") : "");
        setRunning(active);
        if (active) {
          window.localStorage.setItem("thos:active-hunt", id);
          setHuntError("");
          setFinalState(null);
        } else {
          window.localStorage.removeItem("thos:active-hunt");
          setFinalState({ ...(hunt.outcome || {}), status: hunt.status });
          setHuntError(hunt.status === "failed" ? (hunt.failure_reason || "Hunt failed") : "");
        }
      } else if (!active) {
        setRunning(false);
      }
    } catch {
      setPlatformHuntActive(false);
    }
  }, []);

  const loadReports = useCallback(async () => {
    setReportsLoading(true);
    setReportError("");
    try {
      const [reportItems, historyItems] = await Promise.all([
        api("/api/reports"),
        api("/api/hunts/history?limit=100"),
      ]);
      setReports(Array.isArray(reportItems) ? reportItems : []);
      setHuntHistory(Array.isArray(historyItems) ? historyItems : []);
    } catch (error) {
      setReportError(error.message);
    } finally {
      setReportsLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    fetch("/api/session")
      .then(async (response) => {
        if (!response.ok) throw new Error("not authenticated");
        return response.json();
      })
      .then((payload) => { if (active) { setAnalyst(payload.analyst || "analyst"); setSession(payload); setAuthStatus("authenticated"); } })
      .catch(() => { if (active) setAuthStatus("unauthenticated"); });
    const unauthorized = () => { setAnalyst(""); setAuthStatus("unauthenticated"); };
    window.addEventListener("thos:unauthorized", unauthorized);
    return () => { active = false; window.removeEventListener("thos:unauthorized", unauthorized); };
  }, []);
  useEffect(() => {
    if (authStatus === "authenticated" && (session.role === "SME" || session.permissions?.includes("hunts"))) {
      loadHypotheses();
      loadTelemetrySources();
      loadHuntStatus();
    }
  }, [authStatus, session, loadHypotheses, loadTelemetrySources, loadHuntStatus]);
  useEffect(() => {
    if (authStatus !== "authenticated" || !(session.role === "SME" || session.permissions?.includes("hunts"))) return undefined;
    const timer = window.setInterval(loadHuntStatus, 3000);
    return () => window.clearInterval(timer);
  }, [authStatus, session, loadHuntStatus]);
  useEffect(() => { if (authStatus === "authenticated" && page === "reports") loadReports(); }, [authStatus, page, loadReports]);
  useEffect(() => {
    if (authStatus !== "authenticated") return;
    const permissions = new Set(session.permissions || []);
    if (session.role === "SME") return;
    const allowed = { hunts: permissions.has("hunts"), reports: permissions.has("reports"), detections: permissions.has("reports"), settings: permissions.has("knowledge"), home: permissions.has("chat") };
    if (!allowed[page]) setPage(allowed.hunts ? "hunts" : allowed.reports ? "reports" : allowed.settings ? "settings" : "home");
  }, [authStatus, page, session]);

  const authenticated = (payload) => { setAnalyst(payload.analyst || payload.username || "analyst"); setSession(payload); setAuthStatus("authenticated"); };
  const logout = async () => {
    await fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
    setAnalyst("");
    setSession({ display_name: "", role: "Analyst", permissions: [] });
    setAuthStatus("unauthenticated");
  };

  const tactics = useMemo(
    () => ["All tactics", ...Array.from(new Set(hypotheses.map((item) => item.tactic).filter(Boolean))).sort()],
    [hypotheses],
  );

  const filteredHypotheses = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return hypotheses.filter((item) => {
      if (tactic !== "All tactics" && item.tactic !== tactic) return false;
      if (!needle) return true;
      return [item.id, item.title, item.tactic, item.technique, item.text]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle));
    });
  }, [hypotheses, query, tactic]);

  const filteredReports = useMemo(() => {
    const needle = reportQuery.trim().toLowerCase();
    return reports.filter((item) => !needle || `${item.title} ${item.filename} ${item.hunt_id || ""}`.toLowerCase().includes(needle));
  }, [reports, reportQuery]);

  const runHunt = useCallback(async ({ hypothesisId = null, hypothesisText = null, hypothesisTactic = "", hypothesisTechnique = "", title }) => {
    if (running || platformHuntActive) {
      setHuntError("A hunt is already running. Wait for it to complete before starting another hypothesis.");
      return;
    }
    setLastRun({ hypothesisId, hypothesisText, hypothesisTactic, hypothesisTechnique, title });
    setRunning(true);
    setPlatformHuntActive(true);
    setHuntId("");
    setHuntTitle(title);
    setProgress([]);
    setActiveNode("");
    setExpandedNode("");
    setHuntError("");
    setFinalState(null);

    try {
      const response = await fetch("/api/hunts/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          hypothesis_id: hypothesisId,
          hypothesis_text: hypothesisText,
          hypothesis_tactic: hypothesisTactic,
          hypothesis_technique: hypothesisTechnique,
          siem_type: siemType,
          log_source_path: siemType === "folder" ? folderPath : null,
          cover_style: coverStyle,
        }),
      });
      if (!response.ok || !response.body) throw new Error(`Unable to start hunt (${response.status})`);

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (!line.trim()) continue;
          const event = JSON.parse(line);
          if (event.event === "hunt_started") {
            setHuntId(event.hunt_id);
            window.localStorage.setItem("thos:active-hunt", event.hunt_id);
          }
          if (event.event === "node_started") setActiveNode(event.node || "");
          if (event.event === "node_complete") {
            setProgress((current) => [...current, {
              node: event.node,
              label: NODE_LABELS[event.node] || event.node,
              duration: formatDuration(event.duration_ms),
              reason: eventReason(event.node, event.data),
              details: moduleDetails(event.data),
            }]);
          }
          if (event.event === "error") setHuntError(event.error || "Hunt failed");
          if (event.event === "hunt_complete") {
            setFinalState(event.state || {});
            setHuntId(event.hunt_id || "");
            setActiveNode("");
            window.localStorage.removeItem("thos:active-hunt");
          }
        }
        if (done) break;
      }
    } catch (error) {
      setHuntError(error.message);
    } finally {
      setRunning(false);
      await Promise.all([loadHuntStatus(), loadHypotheses()]);
    }
  }, [coverStyle, folderPath, running, platformHuntActive, siemType, loadHuntStatus, loadHypotheses]);

  const runSelected = () => {
    const selected = hypotheses.find((item) => item.id === selectedId);
    if (selected) runHunt({
      hypothesisId: selected.id,
      hypothesisText: selected.custom ? selected.text : null,
      hypothesisTactic: selected.custom ? selected.tactic : "",
      hypothesisTechnique: selected.custom ? selected.technique : "",
      title: `${selected.id} · ${selected.title}`,
    });
  };

  const openReport = useCallback(async (filename) => {
    setPage("reports");
    setReportLoading(true);
    setReportError("");
    try {
      const item = await api(`/api/reports/${encodeURIComponent(filename)}`);
      setSelectedReport(item);
    } catch (error) {
      setReportError(error.message);
    } finally {
      setReportLoading(false);
    }
  }, []);

  const openLatestHuntReport = () => {
    const path = finalState?.report_path || "";
    const filename = path.split(/[\\/]/).pop();
    if (filename) openReport(filename);
  };

  if (authStatus !== "authenticated") return <LoginPage checking={authStatus === "checking"} onAuthenticated={authenticated} />;

  const initials = analyst.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join("").toUpperCase() || "AN";
  const can = (feature) => session.role === "SME" || session.permissions?.includes(feature);
  const pageLabel = page === "hunts" ? "Hunt Board" : page === "reports" ? "Reports" : page === "detections" ? "Detections" : page === "settings" ? "Settings" : page === "create-hypothesis" ? "Create Hunt" : "Workspace";
  const huntLocked = running || platformHuntActive;
  const completedModules = new Set(progress.map((item) => item.node)).size;
  const progressPercent = finalState && !huntError ? 100 : Math.min(96, Math.round((completedModules / Object.keys(NODE_LABELS).length) * 100));

  return (
    <div className="soc-shell">
      {sidebarOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
      <aside className={`soc-sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="brand-block">
          <span className="brand-mark"><img src={logo} alt="" /></span>
          <div><strong>THOS</strong><small>Threat Hunting OS</small></div>
          <button className="mobile-close" onClick={() => setSidebarOpen(false)}><XMarkIcon /></button>
        </div>
        <nav className="nav-stack" aria-label="Primary navigation">
          {can("reports") && <button className={page === "detections" ? "active" : ""} onClick={() => { setPage("detections"); setSidebarOpen(false); }}>
            <ShieldExclamationIcon /><span>Detections</span><ChevronRightIcon className="nav-chevron" />
          </button>}
          {can("hunts") && <button className={page === "hunts" ? "active" : ""} onClick={() => { setPage("hunts"); setSidebarOpen(false); }}>
            <Squares2X2Icon /><span>Hunt Board</span><ChevronRightIcon className="nav-chevron" />
          </button>}
          {session.role === "SME" && <button className={page === "create-hypothesis" ? "active" : ""} onClick={() => { setPage("create-hypothesis"); setSidebarOpen(false); }}>
            <LightBulbIcon /><span>Create Hunt</span><ChevronRightIcon className="nav-chevron" />
          </button>}
          {can("reports") && <button className={page === "reports" ? "active" : ""} onClick={() => { setPage("reports"); setSidebarOpen(false); }}>
            <DocumentTextIcon /><span>Reports</span><ChevronRightIcon className="nav-chevron" />
          </button>}
          {(can("settings") || can("knowledge")) && <button className={page === "settings" ? "active" : ""} onClick={() => { setPage("settings"); setSidebarOpen(false); }}>
            <Cog6ToothIcon /><span>Settings</span><ChevronRightIcon className="nav-chevron" />
          </button>}
        </nav>
        <div className="sidebar-note">
          <span><ShieldCheckIcon /></span>
          <div><strong>On-prem intelligence</strong><p>Evidence and model inference remain inside your environment.</p></div>
        </div>
        <div className="analyst-card">
          <span className="avatar">{initials}</span>
          <div><strong>{session.display_name || analyst}</strong><small>{session.role} · authenticated</small></div>
          <button className="logout-button" onClick={logout} title="Sign out" aria-label="Sign out"><ArrowLeftOnRectangleIcon /></button>
        </div>
      </aside>

      <main className="soc-main">
        <header className="topbar">
          <button className="menu-button" onClick={() => setSidebarOpen(true)}><Bars3Icon /></button>
          <div className="breadcrumb"><span>Operations</span><ChevronRightIcon />{pageLabel}</div>
          <div className="system-state"><RadioIcon /><span>Platform online</span></div>
        </header>

        {page === "hunts" ? (
          <div className="page-wrap">
            <section className="page-heading">
              <div>
                <StatusPill tone="indigo"><SparklesIcon /> HEARTH catalogue</StatusPill>
                <h1>Choose the next hunt</h1>
                <p>Search the complete hypothesis catalogue, select a tile, or run a hypothesis directly.</p>
              </div>
              <button className="secondary-button" onClick={loadHypotheses} disabled={loadingHypotheses}>
                <ArrowPathIcon className={loadingHypotheses ? "spinning" : ""} /> Refresh catalogue
              </button>
            </section>

            <section className="control-deck panel">
              <div className="field search-field">
                <label htmlFor="hypothesis-search">Search hypotheses</label>
                <span><MagnifyingGlassIcon /></span>
                <input id="hypothesis-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search by title, ID, tactic, technique, or text…" />
                {query && <button onClick={() => setQuery("")} aria-label="Clear search"><XMarkIcon /></button>}
              </div>
              <div className="field">
                <label htmlFor="tactic-filter">ATT&CK tactic</label>
                <select id="tactic-filter" value={tactic} onChange={(event) => setTactic(event.target.value)}>
                  {tactics.map((item) => <option key={item}>{item}</option>)}
                </select>
              </div>
              <div className="field compact-field">
                <label htmlFor="siem-type">Telemetry source</label>
                <select id="siem-type" value={siemType} onChange={(event) => setSiemType(event.target.value)}>
                  {activeSources.map((source) => <option key={source.id} value={source.id}>{source.label}</option>)}
                </select>
              </div>
              <div className="field compact-field">
                <label htmlFor="cover-style">Report audience</label>
                <select id="cover-style" value={coverStyle} onChange={(event) => setCoverStyle(event.target.value)}>
                  <option value="1">Executive</option><option value="2">SOC analyst</option>
                </select>
              </div>
              {siemType === "folder" && (
                <div className="field folder-field"><label htmlFor="folder-path">Server log folder</label><input id="folder-path" value={folderPath} onChange={(event) => setFolderPath(event.target.value)} /></div>
              )}
            </section>

            <section className="catalogue-bar">
              <div><h2>Hunting hypotheses</h2><p>{filteredHypotheses.length} of {hypotheses.length} shown</p></div>
              <button className="primary-button" disabled={!selectedId || huntLocked} onClick={runSelected}><PlayIcon /> Run selected hypothesis</button>
            </section>

            {hypothesisError && <div className="alert error-alert"><ExclamationTriangleIcon />{hypothesisError}</div>}
            {huntLocked && <div className="alert hunt-lock-alert"><ClockIcon /><span><strong>One hunt is already running.</strong> Another hypothesis can be started after it completes.</span></div>}
            {loadingHypotheses ? (
              <div className="tile-grid">{Array.from({ length: 6 }).map((_, index) => <div className="hypothesis-tile tile-skeleton" key={index} />)}</div>
            ) : filteredHypotheses.length ? (
              <div className="tile-grid">
                {filteredHypotheses.map((item) => {
                  const selected = selectedId === item.id;
                  return (
                    <article className={`hypothesis-tile ${selected ? "selected" : ""}`} key={item.id} onClick={() => setSelectedId(item.id)}>
                      <div className="tile-topline">
                        <button className="tile-radio" aria-label={`Select ${item.title}`} onClick={(event) => { event.stopPropagation(); setSelectedId(item.id); }}><span /></button>
                        <StatusPill tone="indigo">{item.id}</StatusPill>
                        <StatusPill tone="cyan">{item.technique || "Unmapped"}</StatusPill>
                      </div>
                      <h3>{item.title}</h3>
                      <p className="hypothesis-copy">{readableHypothesisText(item.text)}</p>
                      {item.last_ran_at && <p className="tile-last-run"><ClockIcon /> Last ran {new Date(item.last_ran_at).toLocaleString()}</p>}
                      <div className="tile-footer">
                        <span className="tactic-label"><ShieldCheckIcon />{item.tactic || "Unassigned tactic"}</span>
                        <span className="tile-actions"><button className="tile-read" onClick={(event) => { event.stopPropagation(); setReadingHypothesis(item); }}><EyeIcon /> Read</button><button className="tile-run" disabled={huntLocked} onClick={(event) => { event.stopPropagation(); setSelectedId(item.id); runHunt({ hypothesisId: item.id, hypothesisText: item.custom ? item.text : null, hypothesisTactic: item.custom ? item.tactic : "", hypothesisTechnique: item.custom ? item.technique : "", title: `${item.id} · ${item.title}` }); }}>
                          <PlayIcon /> Run
                        </button></span>
                      </div>
                    </article>
                  );
                })}
              </div>
            ) : <EmptyState icon={MagnifyingGlassIcon} title="No hypotheses match" body="Try another keyword or clear the tactic filter." />}

            {(running || huntId || huntError || finalState) && (
              <section className="hunt-console panel">
                <div className="console-header">
                  <div><StatusPill tone={running ? "amber" : huntError ? "red" : "green"}>{running ? <ClockIcon /> : huntError ? <ExclamationTriangleIcon /> : <CheckCircleIcon />}{running ? "Hunt running" : huntError ? "Needs attention" : "Hunt completed"}</StatusPill><h2>{huntTitle}</h2><p>{huntId ? `Hunt ${huntId}` : "Waiting for hunt identifier…"}</p></div>
                  <div className="console-actions">
                    {huntError && lastRun && !huntLocked && <button className="secondary-button" onClick={() => runHunt(lastRun)}><ArrowPathIcon /> Retry hunt</button>}
                    {finalState?.report_path && <button className="primary-button" onClick={openLatestHuntReport}><DocumentTextIcon /> View report</button>}
                  </div>
                </div>
                {huntError && <div className="alert error-alert"><ExclamationTriangleIcon />{huntError}</div>}
                <button className="pipeline-overview" onClick={() => activeNode && setExpandedNode(expandedNode === activeNode ? "" : activeNode)} disabled={!activeNode}>
                  <span className="pipeline-overview-copy"><strong>{activeNode ? `Running: ${NODE_LABELS[activeNode] || activeNode}` : finalState ? "Pipeline complete" : "Preparing pipeline"}</strong><small>{completedModules} module(s) completed · {progressPercent}%</small></span>
                  <span className="pipeline-track"><i style={{ width: `${progressPercent}%` }} /></span><b>{progressPercent}%</b>
                </button>
                {expandedNode && expandedNode === activeNode && <div className="module-detail active-detail"><strong>{NODE_LABELS[activeNode] || activeNode}</strong><p>{NODE_REASONS[activeNode] || "This module is currently processing the hunt state."}</p><code>Module key: {activeNode}</code></div>}
                <div className="progress-list">
                  {progress.map((item, index) => (
                    <div className="progress-entry" key={item.id || `${item.node}-${index}`}><button className="progress-row" onClick={() => setExpandedNode(expandedNode === `${item.node}-${index}` ? "" : `${item.node}-${index}`)}>
                      <span className="progress-check"><CheckCircleIcon /></span>
                      <div><strong>{item.label}</strong><p>{item.reason}</p></div>
                      <time>{item.duration}</time>
                    </button>{expandedNode === `${item.node}-${index}` && <div className="module-detail"><pre>{JSON.stringify(item.details, null, 2)}</pre></div>}</div>
                  ))}
                  {running && activeNode && <button className="progress-row current" onClick={() => setExpandedNode(expandedNode === activeNode ? "" : activeNode)}><span className="pulse-ring" /><div><strong>{NODE_LABELS[activeNode] || activeNode}</strong><p>{NODE_REASONS[activeNode] || "Module is working on the current hunt state."}</p></div><time>running</time></button>}
                </div>
                {finalState?.reasoning_summary && !finalState.reasoning_failed && <div className="result-summary"><h3>{finalState.reasoning_degraded ? "Deterministic fallback conclusion" : "Verified conclusion"}</h3><p>{finalState.reasoning_summary}</p></div>}
              </section>
            )}
          </div>
        ) : page === "reports" ? (
          <div className="page-wrap reports-page">
            <section className="page-heading">
              <div><StatusPill tone="cyan"><DocumentTextIcon /> Evidence library</StatusPill><h1>Hunt reports</h1><p>Read generated Markdown as a polished investigation record or export the same structure to PDF.</p></div>
              <button className="secondary-button" onClick={loadReports} disabled={reportsLoading}><ArrowPathIcon className={reportsLoading ? "spinning" : ""} /> Refresh reports</button>
            </section>
            {reportError && <div className="alert error-alert"><ExclamationTriangleIcon />{reportError}</div>}
            <section className="hunt-history panel">
              <div className="hunt-history-heading"><div><h2>Hunt run history</h2><p>Every started hunt is retained with its terminal outcome and failure reason.</p></div><span>{huntHistory.length} runs</span></div>
              <div className="hunt-history-list">
                {huntHistory.map((hunt) => {
                  const report = reports.find((item) => item.hunt_id === hunt.hunt_id);
                  const degraded = Boolean(hunt.outcome?.reasoning_degraded);
                  const failed = hunt.status === "failed";
                  const failureReason = hunt.failure_reason || (failed ? "Hunt failed before a detailed reason was recorded." : "");
                  return <article key={hunt.hunt_id} className={`hunt-history-row ${hunt.status}`}>
                    <span className={`run-status run-${hunt.status}`}>{hunt.status}</span>
                    <div><strong>{hunt.hypothesis_id || "Dynamic hypothesis"}</strong><code>{hunt.hunt_id}</code><small>{new Date(hunt.created_at).toLocaleString()} · Last stage: {hunt.last_stage || "started"}</small></div>
                    <div className="run-outcome">{failed ? <p><ExclamationTriangleIcon />{failureReason}</p> : degraded ? <p className="degraded"><ShieldCheckIcon />Completed with deterministic evidence fallback; human approval required.</p> : <p className="successful"><CheckCircleIcon />Completed successfully</p>}{hunt.outcome?.reasoning_error && <details><summary>Reasoning strikes</summary><pre>{hunt.outcome.reasoning_error}</pre></details>}</div>
                    {report ? <button className="secondary-button" onClick={() => openReport(report.filename)}>View report</button> : <span className="no-report">No report</span>}
                  </article>;
                })}
                {!reportsLoading && !huntHistory.length && <p className="muted-list">No hunt runs have been recorded.</p>}
              </div>
            </section>
            <div className="report-layout">
              <aside className="report-index panel">
                <div className="field search-field"><label htmlFor="report-search">Find a report</label><span><MagnifyingGlassIcon /></span><input id="report-search" value={reportQuery} onChange={(event) => setReportQuery(event.target.value)} placeholder="Title, hunt ID, filename…" /></div>
                <div className="report-count"><QueueListIcon />{filteredReports.length} reports</div>
                <div className="report-list">
                  {filteredReports.map((item) => (
                    <button key={item.filename} className={selectedReport?.filename === item.filename ? "active" : ""} onClick={() => openReport(item.filename)}>
                      <span className="report-doc-icon"><DocumentTextIcon /></span>
                      <span><strong>{item.title}</strong><small>{new Date(item.modified).toLocaleString()}</small><em>{item.hunt_id || item.filename}</em></span>
                      <ChevronRightIcon />
                    </button>
                  ))}
                  {!reportsLoading && !filteredReports.length && <p className="muted-list">No reports found.</p>}
                </div>
              </aside>
              <section className="report-reader panel">
                {reportLoading ? <div className="report-loading"><ArrowPathIcon className="spinning" /> Rendering report…</div> : selectedReport ? (
                  <>
                    <div className="report-toolbar">
                      <div><span>Investigation report</span><strong>{selectedReport.filename}</strong></div>
                      <div>
                        <a className="secondary-button" href={`/api/reports/${encodeURIComponent(selectedReport.filename)}/markdown`} download><ArrowDownTrayIcon /> Markdown</a>
                        <a className="primary-button" href={`/api/reports/${encodeURIComponent(selectedReport.filename)}/pdf`} download><ArrowDownTrayIcon /> Download PDF</a>
                      </div>
                    </div>
                    <article className="markdown-report">
                      <ReactMarkdown remarkPlugins={[remarkGfm]}>{selectedReport.content}</ReactMarkdown>
                    </article>
                  </>
                ) : <EmptyState icon={DocumentTextIcon} title="Select a hunt report" body="Choose a report from the library to view its fully rendered Markdown." />}
              </section>
            </div>
          </div>
        ) : page === "detections" ? <Detections /> : page === "create-hypothesis" && session.role === "SME" ? <HypothesisCreate onCreated={loadHypotheses} /> : page === "settings" ? <Settings hypotheses={hypotheses} session={session} activeSources={activeSources} onTelemetryChange={loadTelemetrySources} /> : <div className="page-wrap"><EmptyState icon={SparklesIcon} title="THOS assistant is ready" body="Use the Ask THOS button on the right to work with the local model and approved MCP tools." /></div>}
      </main>
      {readingHypothesis && <div className="hypothesis-reader-backdrop" role="presentation" onClick={() => setReadingHypothesis(null)}><section className="hypothesis-reader" role="dialog" aria-modal="true" aria-label={`Read hypothesis ${readingHypothesis.id}`} onClick={(event) => event.stopPropagation()}>
        <header><div><span className="status-pill status-indigo">{readingHypothesis.id}</span><span className="status-pill status-cyan">{readingHypothesis.technique || "Unmapped"}</span></div><button aria-label="Close hypothesis" onClick={() => setReadingHypothesis(null)}><XMarkIcon /></button></header>
        <h2>{readingHypothesis.title}</h2><div className="reader-meta"><span><ShieldCheckIcon />{readingHypothesis.tactic || "Unassigned tactic"}</span>{readingHypothesis.last_ran_at && <span><ClockIcon />Last ran {new Date(readingHypothesis.last_ran_at).toLocaleString()}</span>}</div>
        <article>{readableHypothesisText(readingHypothesis.text)}</article>
        <footer><button className="secondary-button" onClick={() => setReadingHypothesis(null)}>Close</button><button className="primary-button" disabled={huntLocked} onClick={() => { const item = readingHypothesis; setReadingHypothesis(null); runHunt({ hypothesisId: item.id, hypothesisText: item.custom ? item.text : null, hypothesisTactic: item.custom ? item.tactic : "", hypothesisTechnique: item.custom ? item.technique : "", title: `${item.id} · ${item.title}` }); }}><PlayIcon /> Run hypothesis</button></footer>
      </section></div>}
      {can("chat") && <ChatPage />}
    </div>
  );
}

export default App;
