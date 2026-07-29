import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowDownTrayIcon,
  ArrowLeftOnRectangleIcon,
  ArrowPathIcon,
  Bars3Icon,
  ChartBarSquareIcon,
  CheckCircleIcon,
  ChevronDoubleLeftIcon,
  ChevronDoubleRightIcon,
  ChevronRightIcon,
  CircleStackIcon,
  ClockIcon,
  Cog6ToothIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon,
  EyeIcon,
  FireIcon,
  FingerPrintIcon,
  GlobeAltIcon,
  LightBulbIcon,
  MagnifyingGlassIcon,
  QuestionMarkCircleIcon,
  PlayIcon,
  QueueListIcon,
  RadioIcon,
  ShieldExclamationIcon,
  ShieldCheckIcon,
  SparklesIcon,
  Squares2X2Icon,
  TrashIcon,
  XMarkIcon,
} from "@heroicons/react/24/outline";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import logo from "./assets/appLogo.svg";
import ChatPage from "./ChatPage";
import HypothesisCreate from "./HypothesisCreate";
import Settings from "./Settings";
import Detections from "./Detections";
import Forensics from "./Forensics";
import Integrations from "./Integrations";
import ThreatIntelligence from "./ThreatIntelligence";
import Help from "./Help";
import Overview from "./Overview";
import Risks from "./Risks";

const CONFIGURATION_TABS = new Set([
  "account", "general", "rules", "yara", "ioc", "schedules",
  "audit", "knowledge", "users",
]);
const SAFE_DYNAMIC_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SAFE_REPORT_NAME = /^[A-Za-z0-9._-]{1,255}$/;
const UUID_PATH_ID = /^[0-9a-fA-F-]{36}$/;

function parseBrowserRoute(pathname = window.location.pathname) {
  let segments;
  try {
    segments = pathname.split("/").filter(Boolean).map((part) => decodeURIComponent(part));
  } catch {
    return { page: "overview", canonicalPath: "/overview", invalid: true };
  }
  if (!segments.length || segments[0] === "overview") return { page: "overview", canonicalPath: "/overview" };
  if (segments.length === 1 && segments[0] === "risks") return { page: "risks", canonicalPath: "/risks" };
  if (segments[0] === "detections" && segments.length <= 2 && (!segments[1] || SAFE_DYNAMIC_ID.test(segments[1]))) {
    return { page: "detections", detectionId: segments[1] || "", canonicalPath: segments[1] ? `/detections/${encodeURIComponent(segments[1])}` : "/detections" };
  }
  if (segments[0] === "hunt-board" && segments.length <= 2 && (!segments[1] || UUID_PATH_ID.test(segments[1]))) {
    return { page: "hunts", huntId: segments[1] || "", canonicalPath: segments[1] ? `/hunt-board/${segments[1]}` : "/hunt-board" };
  }
  if (segments[0] === "forensic" && segments.length <= 3) {
    const forensicTab = ["evidence", "yara"].includes(segments[1]) ? segments[1] : "evidence";
    const forensicId = segments[2] || "";
    if ((!segments[2] || UUID_PATH_ID.test(forensicId)) && (!segments[1] || ["evidence", "yara"].includes(segments[1]))) {
      return {
        page: "forensics",
        forensicTab,
        forensicId,
        canonicalPath: `/forensic/${forensicTab}${forensicId ? `/${forensicId}` : ""}`,
      };
    }
  }
  if (segments.length === 1 && segments[0] === "threat-intelligence") return { page: "threat-intel", canonicalPath: "/threat-intelligence" };
  if (segments[0] === "reports" && segments.length <= 2 && (!segments[1] || SAFE_REPORT_NAME.test(segments[1]))) {
    return { page: "reports", reportFilename: segments[1] || "", canonicalPath: segments[1] ? `/reports/${encodeURIComponent(segments[1])}` : "/reports" };
  }
  if (segments.length === 1 && segments[0] === "integrations") return { page: "integrations", canonicalPath: "/integrations" };
  if (segments[0] === "configuration" && segments.length <= 2 && (!segments[1] || CONFIGURATION_TABS.has(segments[1]))) {
    const settingsTab = segments[1] || "account";
    return { page: "settings", settingsTab, canonicalPath: `/configuration/${settingsTab}` };
  }
  if (segments.length === 1 && segments[0] === "help") return { page: "help", canonicalPath: "/help" };
  if (segments.length === 2 && segments[0] === "hypotheses" && segments[1] === "new") return { page: "create-hypothesis", canonicalPath: "/hypotheses/new" };
  if (segments.length === 1 && segments[0] === "workspace") return { page: "home", canonicalPath: "/workspace" };
  return { page: "overview", canonicalPath: "/overview", invalid: true };
}

function pagePath(target, detail = {}) {
  const base = {
    overview: "/overview",
    risks: "/risks",
    detections: "/detections",
    hunts: "/hunt-board",
    forensics: "/forensic/evidence",
    "threat-intel": "/threat-intelligence",
    reports: "/reports",
    integrations: "/integrations",
    settings: "/configuration/account",
    help: "/help",
    "create-hypothesis": "/hypotheses/new",
    home: "/workspace",
  }[target] || "/overview";
  if (target === "settings" && CONFIGURATION_TABS.has(detail.tab)) return `/configuration/${detail.tab}`;
  if (target === "detections" && SAFE_DYNAMIC_ID.test(detail.id || "")) return `/detections/${encodeURIComponent(detail.id)}`;
  if (target === "hunts" && UUID_PATH_ID.test(detail.id || "")) return `/hunt-board/${detail.id}`;
  if (target === "forensics") {
    const tab = detail.tab === "yara" ? "yara" : "evidence";
    return `/forensic/${tab}${UUID_PATH_ID.test(detail.id || "") ? `/${detail.id}` : ""}`;
  }
  if (target === "reports" && SAFE_REPORT_NAME.test(detail.filename || "")) return `/reports/${encodeURIComponent(detail.filename)}`;
  return base;
}

function commitBrowserPath(path, replace = false) {
  if (window.location.pathname === path) return;
  window.history[replace ? "replaceState" : "pushState"]({}, "", path);
}

const NODE_LABELS = {
  refresh_hearth_kb: "Refreshing hypothesis knowledge",
  supervisor: "Planning adaptive hunt workflow",
  hypothesis: "Selecting hypothesis & MITRE context",
  hunt_memory: "Recalling relevant completed hunts",
  query_gen: "Generating SIEM query",
  siem_fetch: "Fetching logs from SIEM",
  log_processing: "Normalizing and deduplicating logs",
  guardrail: "Screening untrusted telemetry",
  soc_tools: "Running detection and enrichment tools",
  coverage_gap: "Checking telemetry coverage gaps",
  adaptive_replan: "Reviewing intermediate findings and next steps",
  threat_intel: "Enriching indicators with threat intelligence",
  negative_screening_gate: "Screening for actionable evidence",
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
  soc_tools: "runs community rules, local rules, and enrichment concurrently",
  coverage_gap: "checks whether available telemetry supports a conclusion",
  adaptive_replan: "decides whether one evidence-based query refinement is justified",
  threat_intel: "compares observed indicators with local intelligence",
  negative_screening_gate: "checks whether any rule, artifact, IOC, or behavioral evidence exists",
  reasoning: "turns evidence into cited findings",
  verifier: "validates citations before findings are trusted",
  report: "persists evidence and governance status",
};

function formatDuration(value) {
  const milliseconds = Number(value);
  if (!Number.isFinite(milliseconds)) return "—";
  return milliseconds < 1000 ? `${Math.max(0, Math.round(milliseconds))} ms` : `${(milliseconds / 1000).toFixed(2)} s`;
}

function formatLocalTimestamp(value) {
  const parsed = value ? new Date(value) : new Date();
  if (Number.isNaN(parsed.getTime())) return "—";
  const pad = (number) => String(number).padStart(2, "0");
  return `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())} ${pad(parsed.getHours())}:${pad(parsed.getMinutes())}:${pad(parsed.getSeconds())}`;
}

function displayReportContent(value) {
  return String(value || "")
    .replace(/SigmaHQ/gi, "Community")
    .replace(/pySigma/gi, "audited rule compiler")
    .replace(/Sigma/gi, "detection rule");
}

function eventReason(node, data = {}) {
  if (node === "siem_fetch") return `retrieved ${data.record_count || 0} matching records`;
  if (node === "log_processing") return `retained ${(data.processed_logs || []).length} normalized records`;
  if (node === "soc_tools") {
    const enrichment = data.enrichment || {};
    const evaluated = enrichment.sigma_rules_evaluated || 0;
    const unsupported = enrichment.sigma_query_coverage?.unsupported || 0;
    if (!evaluated && unsupported) {
      return `0 executable rules; ${unsupported} blocked by unavailable telemetry fields; flagged ${data.sigma_matched_count || 0} records`;
    }
    return `evaluated ${evaluated} rules; flagged ${data.sigma_matched_count || 0} records`;
  }
  if (node === "coverage_gap") return `identified ${(data.coverage_gaps || []).length} coverage gaps`;
  if (node === "threat_intel") return `found ${(data.enrichment_hits || []).length} local IOC matches`;
  if (node === "negative_screening_gate" && data.reasoning_skipped) return "found no actionable evidence; stopped before model reasoning and report generation";
  if (node === "negative_screening_gate") return "found evidence requiring analyst reasoning";
  if (node === "reasoning" && data.reasoning_failed) return `failed after ${data.reasoning_attempts || 3} attempts; report generation was stopped`;
  if (node === "reasoning" && data.reasoning_degraded) return `model attempts exhausted; completed with deterministic evidence fallback and analyst review`;
  if (node === "reasoning" && data.reasoning_cache_hit) return "reused a previously validated reasoning result";
  if (node === "reasoning" && data.reasoning_attempts) return `returned a complete validated result on attempt ${data.reasoning_attempts}`;
  return NODE_REASONS[node] || "completed this hunt stage";
}

function moduleDetails(data = {}) {
  const details = {};
  Object.entries(data).forEach(([key, value]) => {
    const displayKey = {
      sigma_rule: "detection_summary",
      sigma_matched_refs: "detection_matched_references",
      sigma_rule_matches: "detection_rule_matches",
      sigma_matched_count: "detection_matched_count",
    }[key] || key;
    if (["logs", "processed_logs", "findings"].includes(key) && Array.isArray(value)) details[displayKey] = `${value.length} item(s)`;
    else if (Array.isArray(value)) details[displayKey] = value.length <= 8 ? value : `${value.length} item(s)`;
    else if (value && typeof value === "object") details[displayKey] = Object.keys(value).length <= 12 ? value : `${Object.keys(value).length} field(s)`;
    else if (typeof value === "string") details[displayKey] = value.length > 500 ? `${value.slice(0, 500)}…` : value;
    else details[displayKey] = value;
  });
  return details;
}

function progressItem(step) {
  const data = step?.output && typeof step.output === "object" ? step.output : {};
  return {
    id: step?.step_id || `${step?.node_name}-${step?.created_at || ""}`,
    node: step?.node_name || "unknown",
    agentName: step?.agent_name || NODE_LABELS[step?.node_name] || step?.node_name || "Unknown agent",
    modelTier: step?.model_tier || "",
    modelName: step?.model_name || "",
    label: NODE_LABELS[step?.node_name] || step?.node_name || "Unknown module",
    completedAt: formatLocalTimestamp(step?.created_at),
    reason: eventReason(step?.node_name, data),
    details: { ...moduleDetails(data), execution_duration: formatDuration(step?.duration_ms) },
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
      const rawDetail = payload.detail || payload.error;
      detail = typeof rawDetail === "object"
        ? rawDetail.message || JSON.stringify(rawDetail)
        : rawDetail || detail;
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
          <h1>Turn hypotheses into<br />defensible evidence.</h1>
          <p>Run governed threat hunts, inspect each analysis stage, and publish verified investigation reports without moving telemetry outside your environment.</p>
          <div className="login-assurances">
            <span><CheckCircleIcon /> Local model inference</span>
            <span><CheckCircleIcon /> Evidence-verified detections</span>
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
  const initialRoute = useMemo(() => parseBrowserRoute(), []);
  const [authStatus, setAuthStatus] = useState("checking");
  const [analyst, setAnalyst] = useState("");
  const [session, setSession] = useState({ display_name: "", role: "Expert", permissions: [] });
  const [page, setPage] = useState(initialRoute.page);
  const [settingsTab, setSettingsTab] = useState(initialRoute.settingsTab || "account");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [hypotheses, setHypotheses] = useState([]);
  const [hypothesisError, setHypothesisError] = useState("");
  const [loadingHypotheses, setLoadingHypotheses] = useState(true);
  const [query, setQuery] = useState("");
  const [tactic, setTactic] = useState("All tactics");
  const [severity, setSeverity] = useState("all");
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
  const [activeAgent, setActiveAgent] = useState(null);
  const [expandedNode, setExpandedNode] = useState("");
  const [huntError, setHuntError] = useState("");
  const [finalState, setFinalState] = useState(null);
  const [lastRun, setLastRun] = useState(null);
  const [reports, setReports] = useState([]);
  const [huntHistory, setHuntHistory] = useState([]);
  const [reportsLoading, setReportsLoading] = useState(false);
  const [reportQuery, setReportQuery] = useState("");
  const [reportType, setReportType] = useState("all");
  const [reportAgeUnit, setReportAgeUnit] = useState("all");
  const [reportAgeValue, setReportAgeValue] = useState(7);
  const [detectionFocus, setDetectionFocus] = useState(initialRoute.detectionId || "");
  const [forensicFocus, setForensicFocus] = useState({
    tab: initialRoute.forensicTab || "evidence",
    id: initialRoute.forensicId || "",
  });
  const [routeReportFilename, setRouteReportFilename] = useState(initialRoute.reportFilename || "");
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
        setActiveAgent(active ? (hunt.current_agent || null) : null);
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
    const applyLocation = () => {
      const route = parseBrowserRoute();
      setPage(route.page);
      setSettingsTab(route.settingsTab || "account");
      setDetectionFocus(route.detectionId || "");
      setForensicFocus({
        tab: route.forensicTab || "evidence",
        id: route.forensicId || "",
      });
      setRouteReportFilename(route.reportFilename || "");
      if (!route.reportFilename) setSelectedReport(null);
      if (route.invalid) commitBrowserPath(route.canonicalPath, true);
    };
    window.addEventListener("popstate", applyLocation);
    if (initialRoute.invalid) commitBrowserPath(initialRoute.canonicalPath, true);
    return () => window.removeEventListener("popstate", applyLocation);
  }, [initialRoute]);
  useEffect(() => {
    if (authStatus === "authenticated" && window.location.pathname === "/") {
      commitBrowserPath("/overview", true);
    }
  }, [authStatus]);
  useEffect(() => {
    if (authStatus === "authenticated" && (["Admin", "SME"].includes(session.role) || session.permissions?.includes("hunts"))) {
      loadHypotheses();
      loadTelemetrySources();
      loadHuntStatus();
    }
  }, [authStatus, session, loadHypotheses, loadTelemetrySources, loadHuntStatus]);
  useEffect(() => {
    if (authStatus !== "authenticated" || !(["Admin", "SME"].includes(session.role) || session.permissions?.includes("hunts"))) return undefined;
    const timer = window.setInterval(loadHuntStatus, 3000);
    return () => window.clearInterval(timer);
  }, [authStatus, session, loadHuntStatus]);
  useEffect(() => { if (authStatus === "authenticated" && page === "reports") loadReports(); }, [authStatus, page, loadReports]);
  useEffect(() => {
    if (authStatus !== "authenticated") return;
    const permissions = new Set(session.permissions || []);
    const privileged = ["Admin", "SME"].includes(session.role);
    const roleAllows = (feature) => privileged || permissions.has(feature);
    const allowed = {
      overview: true,
      risks: roleAllows("reports"),
      hunts: roleAllows("hunts"),
      forensics: roleAllows("forensics"),
      reports: roleAllows("reports"),
      detections: roleAllows("reports"),
      "threat-intel": roleAllows("threat_intel"),
      integrations: privileged,
      "create-hypothesis": privileged,
      help: true,
      settings: true,
      home: roleAllows("chat"),
    };
    if (!allowed[page]) {
      setPage("overview");
      setDetectionFocus("");
      setForensicFocus({ tab: "evidence", id: "" });
      setRouteReportFilename("");
      commitBrowserPath("/overview", true);
    }
  }, [authStatus, page, session]);

  const authenticated = (payload) => { setAnalyst(payload.analyst || payload.username || "analyst"); setSession(payload); setAuthStatus("authenticated"); };
  const logout = async () => {
    await fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
    setAnalyst("");
    setSession({ display_name: "", role: "Expert", permissions: [] });
    setAuthStatus("unauthenticated");
    setPage("overview");
    setDetectionFocus("");
    setForensicFocus({ tab: "evidence", id: "" });
    setRouteReportFilename("");
    commitBrowserPath("/", true);
  };

  const tactics = useMemo(
    () => ["All tactics", ...Array.from(new Set(hypotheses.map((item) => item.tactic).filter(Boolean))).sort()],
    [hypotheses],
  );

  const filteredHypotheses = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return hypotheses.filter((item) => {
      if (severity !== "all" && (item.severity || "medium") !== severity) return false;
      if (tactic !== "All tactics" && item.tactic !== tactic) return false;
      if (!needle) return true;
      return [item.id, item.title, item.tactic, item.technique, item.text]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle));
    });
  }, [hypotheses, query, tactic, severity]);

  const groupedHypotheses = useMemo(
    () => ["critical", "high", "medium", "low"]
      .map((type) => ({
        severity: type,
        items: filteredHypotheses.filter((item) => (item.severity || "medium") === type),
      }))
      .filter((group) => group.items.length),
    [filteredHypotheses],
  );

  useEffect(() => {
    if (!filteredHypotheses.some((item) => item.id === selectedId)) {
      setSelectedId(filteredHypotheses[0]?.id || "");
    }
  }, [filteredHypotheses, selectedId]);

  const filteredReports = useMemo(() => {
    const needle = reportQuery.trim().toLowerCase();
    const unitDays = { days: 1, months: 30.44, years: 365.25 };
    const cutoff = reportAgeUnit === "all"
      ? 0
      : Date.now() - reportAgeValue * unitDays[reportAgeUnit] * 86_400_000;
    return reports.filter((item) => {
      if (reportType !== "all" && item.type !== reportType) return false;
      if (cutoff && new Date(item.modified).getTime() < cutoff) return false;
      return !needle || `${item.title} ${item.filename} ${item.hunt_id || ""} ${item.case_id || ""}`.toLowerCase().includes(needle);
    });
  }, [reports, reportQuery, reportType, reportAgeUnit, reportAgeValue]);

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
    setActiveAgent(null);
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
          if (event.event === "node_started") {
            setActiveNode(event.node || "");
            setActiveAgent(event);
          }
          if (event.event === "node_complete") {
            setProgress((current) => [...current, {
              node: event.node,
              agentName: event.agent_name || NODE_LABELS[event.node] || event.node,
              modelTier: event.model_tier || "",
              modelName: event.model_name || "",
              label: NODE_LABELS[event.node] || event.node,
              completedAt: formatLocalTimestamp(event.completed_at),
              reason: eventReason(event.node, event.data),
              details: { ...moduleDetails(event.data), execution_duration: formatDuration(event.duration_ms) },
            }]);
          }
          if (event.event === "error") setHuntError(event.error || "Hunt failed");
          if (event.event === "hunt_complete") {
            setFinalState(event.state || {});
            setHuntId(event.hunt_id || "");
            setActiveNode("");
            setActiveAgent(null);
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

  const openReport = useCallback(async (filename, updateUrl = true) => {
    if (!SAFE_REPORT_NAME.test(String(filename || ""))) {
      setReportError("Invalid report identifier.");
      return;
    }
    setPage("reports");
    setRouteReportFilename(filename);
    if (updateUrl) commitBrowserPath(pagePath("reports", { filename }));
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
  useEffect(() => {
    if (authStatus === "authenticated" && routeReportFilename) {
      openReport(routeReportFilename, false);
    }
  }, [authStatus, routeReportFilename, openReport]);

  const openLatestHuntReport = () => {
    const path = finalState?.report_path || "";
    const filename = path.split(/[\\/]/).pop();
    if (filename) openReport(filename);
  };

  const deleteSelectedReport = async () => {
    if (!selectedReport || session.role !== "Admin") return;
    if (!window.confirm(`Remove ${selectedReport.filename} from the active report library? It will remain in the server-side recovery archive.`)) return;
    try {
      await api(`/api/reports/${encodeURIComponent(selectedReport.filename)}`, { method: "DELETE" });
      setSelectedReport(null);
      await loadReports();
    } catch (error) {
      setReportError(error.message);
    }
  };

  const clearHuntHistory = async () => {
    if (session.role !== "Admin") return;
    if (!window.confirm("Clear all hunt run history? Generated reports remain in the report library.")) return;
    try {
      await api("/api/hunts/history", { method: "DELETE" });
      setHuntHistory([]);
    } catch (error) {
      setReportError(error.message);
    }
  };

  if (authStatus !== "authenticated") return <LoginPage checking={authStatus === "checking"} onAuthenticated={authenticated} />;

  const initials = analyst.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join("").toUpperCase() || "AN";
  const can = (feature) => ["Admin", "SME"].includes(session.role) || session.permissions?.includes(feature);
  const pageLabel = page === "overview" ? "Overview" : page === "risks" ? "Risks" : page === "hunts" ? "Hunt Operations" : page === "forensics" ? "Forensic" : page === "reports" ? "Investigation Reports" : page === "detections" ? "Detection Operations" : page === "threat-intel" ? "Threat Intelligence" : page === "integrations" ? "Security Integrations" : page === "help" ? "Help & Documentation" : page === "settings" ? "Configuration" : page === "create-hypothesis" ? "Hypothesis Authoring" : "Workspace";
  const huntLocked = running || platformHuntActive;
  const completedModules = new Set(progress.map((item) => item.node)).size;
  const workflowTimestamp = progress.at(-1)?.completedAt || formatLocalTimestamp(finalState?.hunt_started_at);
  const navigate = (target, tab = "", detail = {}) => {
    const routeDetail = { ...detail, tab: tab || detail.tab };
    if (target === "settings") setSettingsTab(routeDetail.tab || "account");
    if (target === "detections") setDetectionFocus(routeDetail.id || "");
    if (target === "forensics") setForensicFocus({
      tab: routeDetail.tab === "yara" ? "yara" : "evidence",
      id: routeDetail.id || "",
    });
    if (target !== "reports" || !routeDetail.filename) {
      setRouteReportFilename("");
      setSelectedReport(null);
    }
    commitBrowserPath(pagePath(target, routeDetail));
    setPage(target);
    setSidebarOpen(false);
  };
  const openHuntProgress = () => {
    navigate("hunts", "", { id: huntId });
    window.requestAnimationFrame(() => {
      document.getElementById("hunt-progress-details")?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    });
  };
  const openRiskSource = (risk) => {
    if (risk.report_filename) {
      openReport(risk.report_filename);
      return;
    }
    if (risk.detection_run_id) {
      setDetectionFocus(risk.detection_run_id);
      navigate("detections", "", { id: String(risk.detection_run_id) });
    }
  };

  return (
    <div className="soc-shell">
      {sidebarOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
      <aside className={`soc-sidebar ${sidebarOpen ? "sidebar-open" : ""} ${sidebarCollapsed ? "collapsed" : ""}`}>
        <div className="brand-block">
          <span className="brand-mark"><img src={logo} alt="" /></span>
          <div><strong>THOS</strong><small>Threat Hunting OS</small></div>
          <button className="mobile-close" onClick={() => setSidebarOpen(false)}><XMarkIcon /></button>
          <button className="desktop-sidebar-toggle" onClick={() => setSidebarCollapsed(true)} title="Hide navigation" aria-label="Hide navigation"><ChevronDoubleLeftIcon /></button>
        </div>
        <nav className="nav-stack" aria-label="Primary navigation">
          <button className={page === "overview" ? "active" : ""} onClick={() => navigate("overview")}>
            <ChartBarSquareIcon /><span>Overview</span><ChevronRightIcon className="nav-chevron" />
          </button>
          {can("reports") && <button className={page === "risks" ? "active" : ""} onClick={() => navigate("risks")}>
            <FireIcon /><span>Risks</span><ChevronRightIcon className="nav-chevron" />
          </button>}
          {can("reports") && <button className={page === "detections" ? "active" : ""} onClick={() => navigate("detections")}>
            <ShieldExclamationIcon /><span>Detections</span><ChevronRightIcon className="nav-chevron" />
          </button>}
          {can("hunts") && <button className={page === "hunts" ? "active" : ""} onClick={() => navigate("hunts")}>
            <Squares2X2Icon /><span>Hunt Board</span><ChevronRightIcon className="nav-chevron" />
          </button>}
          {can("forensics") && <button className={page === "forensics" ? "active" : ""} onClick={() => navigate("forensics")}>
            <FingerPrintIcon /><span>Forensic</span><ChevronRightIcon className="nav-chevron" />
          </button>}
          {can("threat_intel") && <button className={page === "threat-intel" ? "active" : ""} onClick={() => navigate("threat-intel")}>
            <GlobeAltIcon /><span>Threat Intelligence</span><ChevronRightIcon className="nav-chevron" />
          </button>}
          {can("reports") && <button className={page === "reports" ? "active" : ""} onClick={() => navigate("reports")}>
            <DocumentTextIcon /><span>Reports</span><ChevronRightIcon className="nav-chevron" />
          </button>}
          {["Admin", "SME"].includes(session.role) && <button className={page === "integrations" ? "active" : ""} onClick={() => navigate("integrations")}>
            <CircleStackIcon /><span>Integrations</span><ChevronRightIcon className="nav-chevron" />
          </button>}
          <button className={page === "settings" ? "active" : ""} onClick={() => navigate("settings")}>
            <Cog6ToothIcon /><span>Configuration</span><ChevronRightIcon className="nav-chevron" />
          </button>
        </nav>
      </aside>

      {sidebarCollapsed && <button className="sidebar-reveal" onClick={() => setSidebarCollapsed(false)} title="Show navigation" aria-label="Show navigation"><ChevronDoubleRightIcon /></button>}
      <main className={`soc-main ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
        <header className="topbar">
          <button className="menu-button" onClick={() => setSidebarOpen(true)}><Bars3Icon /></button>
          <div className="breadcrumb"><span>Operations</span><ChevronRightIcon />{pageLabel}</div>
          <div className="topbar-actions">
            <div className="system-state platform-identity" title="Platform identity"><img className="platform-status-logo" src={session.branding?.logo_url || logo} alt="Platform logo" /></div>
            <button className={`topbar-help ${page === "help" ? "active" : ""}`} onClick={() => navigate("help")}><QuestionMarkCircleIcon /><span>Help</span></button>
            <button className="topbar-account" onClick={() => navigate("settings", "account")} title="Open account settings">
              {session.avatar_url ? <img className="avatar small" src={session.avatar_url} alt="" /> : <span className="avatar small">{initials}</span>}
              <span><strong>{session.display_name || analyst}</strong><small>{session.role}</small></span>
            </button>
            <button className="topbar-logout" onClick={logout} title="Sign out" aria-label="Sign out"><ArrowLeftOnRectangleIcon /></button>
          </div>
        </header>

        {page === "overview" ? <Overview onNavigate={navigate} /> : page === "risks" ? <Risks onOpenRisk={openRiskSource} /> : page === "hunts" ? (
          <div className="page-wrap">
            <section className="page-heading">
              <div>
                <StatusPill tone="indigo"><SparklesIcon /> Curated hypothesis catalog</StatusPill>
                <h1>Threat Hunting Operations</h1>
                <p>Prioritize hypotheses by severity, review the investigative scope, and launch a governed hunt workflow.</p>
              </div>
              <div className="page-heading-actions">
                {["Admin", "SME"].includes(session.role) && <button className="primary-button" onClick={() => navigate("create-hypothesis")}><LightBulbIcon /> Create hunt hypothesis</button>}
                <button className="secondary-button" onClick={loadHypotheses} disabled={loadingHypotheses}>
                  <ArrowPathIcon className={loadingHypotheses ? "spinning" : ""} /> Refresh catalog
                </button>
              </div>
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
                <label htmlFor="hypothesis-severity">Severity</label>
                <select id="hypothesis-severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>
                  <option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
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
              <div><h2>{severity === "all" ? "All severity groups" : `${severity[0].toUpperCase() + severity.slice(1)} severity hypotheses`}</h2><p>{filteredHypotheses.length} hypotheses in the selected severity view</p></div>
            </section>

            {hypothesisError && <div className="alert error-alert"><ExclamationTriangleIcon />{hypothesisError}</div>}
            {huntLocked && <button type="button" className="alert hunt-lock-alert" onClick={openHuntProgress}><ClockIcon /><span><strong>One hunt is already running.</strong><small>View the timestamped progress details and execution flow.</small></span></button>}
            {loadingHypotheses ? (
              <div className="tile-grid">{Array.from({ length: 6 }).map((_, index) => <div className="hypothesis-tile tile-skeleton" key={index} />)}</div>
            ) : filteredHypotheses.length ? (
              <div className="severity-catalog">
                {groupedHypotheses.map((group) => <section className={`severity-group severity-group-${group.severity}`} key={group.severity}>
                  <header><div><span className={`detection-level level-${group.severity}`}>{group.severity}</span><h3>{group.severity[0].toUpperCase() + group.severity.slice(1)} severity</h3></div><small>{group.items.length} hypotheses</small></header>
                  <div className="tile-grid">
                  {group.items.map((item) => {
                  const selected = selectedId === item.id;
                  return (
                    <article className={`hypothesis-tile ${selected ? "selected" : ""}`} key={item.id} onClick={() => setSelectedId(item.id)}>
                      <div className="tile-topline">
                        <button className="tile-radio" aria-label={`Select ${item.title}`} onClick={(event) => { event.stopPropagation(); setSelectedId(item.id); }}><span /></button>
                        <StatusPill tone="indigo">{item.id}</StatusPill>
                        <StatusPill tone="cyan">{item.technique || "Unmapped"}</StatusPill>
                        <span className={`detection-level level-${item.severity || "medium"}`}>{item.severity || "medium"}</span>
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
                </section>)}
              </div>
            ) : <EmptyState icon={MagnifyingGlassIcon} title={severity === "all" ? "No hypotheses match" : `No ${severity} severity hypotheses match`} body="Try another keyword, tactic, or severity type." />}

            {(running || huntId || huntError || finalState) && (
              <section className="hunt-console panel" id="hunt-progress-details">
                <div className="console-header">
                  <div><StatusPill tone={running ? "amber" : huntError ? "red" : "green"}>{running ? <ClockIcon /> : huntError ? <ExclamationTriangleIcon /> : <CheckCircleIcon />}{running ? "Hunt running" : huntError ? "Needs attention" : "Hunt completed"}</StatusPill><h2>{huntTitle}</h2><p>{huntId ? `Hunt ${huntId}` : "Waiting for hunt identifier…"}</p></div>
                  <div className="console-actions">
                    {huntError && lastRun && !huntLocked && <button className="secondary-button" onClick={() => runHunt(lastRun)}><ArrowPathIcon /> Retry hunt</button>}
                    {finalState?.report_path && <button className="primary-button" onClick={openLatestHuntReport}><DocumentTextIcon /> View report</button>}
                  </div>
                </div>
                {huntError && <div className="alert error-alert"><ExclamationTriangleIcon />{huntError}</div>}
                <button className="pipeline-overview" onClick={() => activeNode && setExpandedNode(expandedNode === activeNode ? "" : activeNode)} disabled={!activeNode}>
                  <span className="pipeline-overview-copy"><strong>{activeNode ? `Running: ${activeAgent?.agent_name || NODE_LABELS[activeNode] || activeNode}` : finalState ? "Agent workflow complete" : "Preparing agent workflow"}</strong><small>{completedModules} agent stage(s) completed</small></span>
                  <span className="pipeline-timestamp"><ClockIcon /> Latest local update</span><time>{workflowTimestamp}</time>
                </button>
                {expandedNode && expandedNode === activeNode && <div className="module-detail active-detail"><strong>{activeAgent?.agent_name || NODE_LABELS[activeNode] || activeNode}</strong><p>{activeAgent?.activity || NODE_REASONS[activeNode] || "This agent is processing the current hunt state."}</p><code>{activeAgent?.model_name ? `Model: ${activeAgent.model_name} (${activeAgent.model_tier} tier)` : "Model: none (deterministic/tool stage)"}</code></div>}
                <div className="progress-list">
                  {progress.map((item, index) => (
                    <div className="progress-entry" key={item.id || `${item.node}-${index}`}><button className="progress-row" onClick={() => setExpandedNode(expandedNode === `${item.node}-${index}` ? "" : `${item.node}-${index}`)}>
                      <span className="progress-check"><CheckCircleIcon /></span>
                      <div><strong>{item.agentName}</strong><p>{item.reason}</p><small>{item.label} · {item.modelName ? `${item.modelName} (${item.modelTier} tier)` : "deterministic/tool stage"}</small></div>
                      <time title="Local completion timestamp">{item.completedAt}</time>
                    </button>{expandedNode === `${item.node}-${index}` && <div className="module-detail"><pre>{JSON.stringify(item.details, null, 2)}</pre></div>}</div>
                  ))}
                  {running && activeNode && <button className="progress-row current" onClick={() => setExpandedNode(expandedNode === activeNode ? "" : activeNode)}><span className="pulse-ring" /><div><strong>{activeAgent?.agent_name || NODE_LABELS[activeNode] || activeNode}</strong><p>{NODE_REASONS[activeNode] || "Agent is working on the current hunt state."}</p><small>{activeAgent?.model_name ? `${activeAgent.model_name} (${activeAgent.model_tier} tier)` : "deterministic/tool stage"}</small></div><time>running</time></button>}
                </div>
                {finalState?.reasoning_summary && !finalState.reasoning_failed && <div className="result-summary"><h3>{finalState.reasoning_degraded ? "Deterministic fallback conclusion" : "Verified conclusion"}</h3><p>{finalState.reasoning_summary}</p></div>}
              </section>
            )}
          </div>
        ) : page === "threat-intel" ? <ThreatIntelligence /> : page === "forensics" ? <Forensics
          onOpenReport={openReport}
          initialTab={forensicFocus.tab}
          focusId={forensicFocus.id}
          onRouteChange={(tab, id = "") => {
            setForensicFocus({ tab, id });
            commitBrowserPath(pagePath("forensics", { tab, id }));
          }}
        /> : page === "reports" ? (
          <div className="page-wrap reports-page">
            <section className="page-heading">
              <div><StatusPill tone="cyan"><DocumentTextIcon /> Evidence library</StatusPill><h1>Hunt and forensic reports</h1><p>Keep threat-hunting and technical digital-forensic reports clearly classified, searchable, and exportable.</p></div>
              <button className="secondary-button" onClick={loadReports} disabled={reportsLoading}><ArrowPathIcon className={reportsLoading ? "spinning" : ""} /> Refresh reports</button>
            </section>
            {reportError && <div className="alert error-alert"><ExclamationTriangleIcon />{reportError}</div>}
            <section className="hunt-history panel">
              <div className="hunt-history-heading"><div><h2>Hunt Run Audit History</h2><p>Every started hunt is retained with its terminal outcome and failure reason.</p></div><div className="history-heading-actions"><span>{huntHistory.length} runs</span>{session.role === "Admin" && <button className="danger-button" disabled={!huntHistory.length || platformHuntActive} onClick={clearHuntHistory}><TrashIcon /> Clear history</button>}</div></div>
              <div className="hunt-history-list">
                {huntHistory.map((hunt) => {
                  const report = reports.find((item) => item.hunt_id === hunt.hunt_id);
                  const degraded = Boolean(hunt.outcome?.reasoning_degraded);
                  const failed = hunt.status === "failed";
                  const failureReason = hunt.failure_reason || (failed ? "Hunt failed before a detailed reason was recorded." : "");
                  return <article key={hunt.hunt_id} className={`hunt-history-row ${hunt.status}`}>
                    <span className={`run-status run-${hunt.status}`}>{hunt.status}</span>
                    <div><strong>{hunt.hypothesis_id || "Dynamic hypothesis"}</strong><code>{hunt.hunt_id}</code><small>{new Date(hunt.created_at).toLocaleString()} · Last stage: {hunt.last_stage || "started"}</small></div>
                    <div className="run-outcome">{failed ? <p><ExclamationTriangleIcon />{failureReason}</p> : degraded ? <p className="degraded"><ShieldCheckIcon />Completed with deterministic evidence fallback; analyst review recommended.</p> : <p className="successful"><CheckCircleIcon />Completed successfully</p>}{hunt.outcome?.reasoning_error && <details><summary>Reasoning strikes</summary><pre>{hunt.outcome.reasoning_error}</pre></details>}</div>
                    {report ? <button className="secondary-button" onClick={() => openReport(report.filename)}>View report</button> : <span className="no-report">No report</span>}
                  </article>;
                })}
                {!reportsLoading && !huntHistory.length && <p className="muted-list">No hunt runs have been recorded.</p>}
              </div>
            </section>
            <div className="report-layout">
              <aside className="report-index panel">
                <div className="field search-field"><label htmlFor="report-search">Find a report</label><span><MagnifyingGlassIcon /></span><input id="report-search" value={reportQuery} onChange={(event) => setReportQuery(event.target.value)} placeholder="Title, hunt ID, filename…" /></div>
                <div className="report-age-filter">
                  <label>Time period<select value={reportAgeUnit} onChange={(event) => {
                    const unit = event.target.value;
                    setReportAgeUnit(unit);
                    setReportAgeValue(unit === "days" ? 7 : unit === "months" ? 3 : 1);
                  }}><option value="all">All time</option><option value="days">Last N days</option><option value="months">Last N months</option><option value="years">Last N years</option></select></label>
                  {reportAgeUnit !== "all" && <label>{reportAgeUnit}<select value={reportAgeValue} onChange={(event) => setReportAgeValue(Number(event.target.value))}>
                    {Array.from({ length: reportAgeUnit === "days" ? 31 : reportAgeUnit === "months" ? 12 : 10 }, (_, index) => index + 1).map((value) => <option key={value} value={value}>{value} {reportAgeUnit}</option>)}
                  </select></label>}
                </div>
                <div className="report-type-filter">
                  {["all", "hunt", "forensic"].map((type) => <button key={type} className={reportType === type ? "active" : ""} onClick={() => setReportType(type)}>{type}</button>)}
                </div>
                <div className="report-count"><QueueListIcon />{filteredReports.length} reports</div>
                <div className="report-list">
                  {filteredReports.map((item) => (
                    <button key={item.filename} className={selectedReport?.filename === item.filename ? "active" : ""} onClick={() => openReport(item.filename)}>
                      <span className="report-doc-icon"><DocumentTextIcon /></span>
                      <span><strong>{item.title}</strong><small>{item.type} · {new Date(item.modified).toLocaleString()}</small><em>{item.hunt_id || item.case_id || item.filename}</em></span>
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
                        {session.role === "Admin" && <button className="danger-button" onClick={deleteSelectedReport}><TrashIcon /> Delete</button>}
                        <a className="secondary-button" href={`/api/reports/${encodeURIComponent(selectedReport.filename)}/markdown`} download><ArrowDownTrayIcon /> Markdown</a><a className="primary-button" href={`/api/reports/${encodeURIComponent(selectedReport.filename)}/pdf`} download><ArrowDownTrayIcon /> Download PDF</a>
                      </div>
                    </div>
                    <article className="markdown-report">
                      <ReactMarkdown remarkPlugins={[remarkGfm]}>{displayReportContent(selectedReport.content)}</ReactMarkdown>
                    </article>
                  </>
                ) : <EmptyState icon={DocumentTextIcon} title="Select a report" body="Choose a hunt or forensic report from the classified library." />}
              </section>
            </div>
          </div>
        ) : page === "detections" ? <Detections focusId={detectionFocus} /> : page === "integrations" && ["Admin", "SME"].includes(session.role) ? <Integrations session={session} activeSources={activeSources} onTelemetryChange={loadTelemetrySources} /> : page === "help" ? <Help /> : page === "create-hypothesis" && ["Admin", "SME"].includes(session.role) ? <HypothesisCreate onCreated={loadHypotheses} /> : page === "settings" ? <Settings initialTab={settingsTab} onTabChange={(tab) => { setSettingsTab(tab); commitBrowserPath(pagePath("settings", { tab })); }} hypotheses={hypotheses} session={session} activeSources={activeSources} onTelemetryChange={loadTelemetrySources} onSessionChange={(profile) => { setSession((current) => ({ ...current, ...profile })); setAnalyst(profile.display_name || analyst); }} /> : <div className="page-wrap"><EmptyState icon={SparklesIcon} title="THOS assistant is ready" body="Use the Ask THOS button on the right to work with the local model and governed SOC tools." /></div>}
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
