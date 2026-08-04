import { useMemo, useState } from "react";
import {
  BookOpenIcon, BoltIcon, CircleStackIcon, CloudIcon, Cog6ToothIcon,
  DocumentMagnifyingGlassIcon, MagnifyingGlassIcon, ShieldCheckIcon,
} from "@heroicons/react/24/outline";

const SECTIONS = [
  {
    id: "start", icon: BoltIcon, title: "Getting started", tags: "login hunt hypothesis source report",
    content: [
      "Connect and test a telemetry source in Settings. Only successfully tested live SIEMs are offered to hunts; the managed evidence folder remains available.",
      "Choose a hypothesis, confirm its ATT&CK technique and severity, then run it. The live timeline shows each agent, its purpose, and duration.",
      "Start with Summary and Key Evidence in the report. Key Evidence reports the complete grounded/corroborated inventory, groups repetition without dropping record references, and lists literal-only or detection-only candidates separately. The local model reviews a bounded representative sample, not the total evidence set.",
    ],
  },
  {
    id: "hunts", icon: DocumentMagnifyingGlassIcon, title: "Hypotheses and threat hunts", tags: "HEARTH gaps MITRE query Nmap evidence",
    content: [
      "Every catalog entry uses the same eleven-section schema: metadata, falsifiable statement and null, ATT&CK mapping, justification, scope, required data, hunting logic, outcomes, visibility gaps, knowledge capture, and references.",
      "ATT&CK enrichment is mechanically extracted from the pinned official Enterprise v19.1 STIX release. HEARTH and analyst claims retain their attribution; missing telemetry, scope, thresholds, or references are shown as missing rather than invented.",
      "HEARTH refreshes normalize new entries, update officially revoked mappings, preserve source Markdown, and apply a conservative same-technique duplicate gate. Equal technique IDs are not merged when their observable, telemetry path, platform, entity, or sequence differs.",
      "Admin and SME authoring requires an exact active ATT&CK technique, null hypothesis, rationale, data sources, analytic approach, true-positive criteria, and false-positive knowledge. Duplicate submissions are rejected with the matching catalog IDs.",
      "The human reader receives the full structured hypothesis. MCP and query agents receive a shorter deterministic profile containing verified analytics, log channels, tunable elements, and exact literals for faster, more reliable execution.",
      "A hunt creates a structured investigation contract and a validated query for each selected telemetry source. Empty searches are retried with a governed broader technique/context query and a larger bounded time window; capped or noisy searches are tightened using the target dialect and discovered field map. Related Wazuh hunts reuse an ATT&CK-technique/time-window telemetry cache.",
      "Every proposed, normalized, rejected, skipped, and executed retrieval attempt records its source, objective, lookback, cap, counts, and error. Only after selected-source and bounded adaptive branches are exhausted does THOS apply the evidence gate, skip expensive reasoning, and avoid creating an empty report.",
      "Wazuh high-signal fields—including rule MITRE metadata, URL, user-agent, command line, process paths, and full_log—are preserved in an evidence summary. This allows artifacts such as Nmap NSE to remain visible even when the raw event is long.",
      "A clean result is meaningful only when the coverage section says the required ATT&CK data sources were available.",
    ],
  },
  {
    id: "detections", icon: ShieldCheckIcon, title: "Detection rules and YARA", tags: "rule detection scan batch compatible compile",
    content: [
      "Detection rules are compiled for the selected SIEM and validated against its discovered field schema. Incompatible rules remain visible but are never scheduled or executed.",
      "During hypothesis hunts, compatible Wazuh detection-rule queries use one OpenSearch multi-search request. If the deployment blocks multi-search, THOS automatically falls back to bounded individual read-only searches.",
      "The recommended scheduled Wazuh detection-rule rotation also executes each bounded rule batch as one multi-search request and resumes from a saved cursor. Splunk retains bounded individual searches until its connector exposes an equivalent safe batch API.",
      "YARA files are compiler-validated and enabled rules are assembled into one reusable bundle. Schedule the enabled bundle once—not one scan per rule. After the first scan, only evidence modified since the previous completed run is scanned.",
      "Detection proposals in hunt reports are experimental drafts. THOS does not automatically deploy or contain; use your normal detection change-control process.",
    ],
  },
  {
    id: "forensics", icon: DocumentMagnifyingGlassIcon, title: "Forensic analysis tools", tags: "forensic capa floss exiftool clamav strings pe registry disk memory volatility",
    content: [
      "Every upload is hashed, preserved read-only, classified from file content, and routed only to applicable static analyzers. THOS never executes a submitted sample and never invokes a tool through a command shell.",
      "The installed tool set is YARA, libmagic file, GNU strings, ExifTool, ClamAV, pefile, capa with pinned rules, FLOSS, pypdf, oletools, Volatility 3, libewf tools, The Sleuth Kit, and RegRipper.",
      "The File and Memory Analysis tab accepts executables, documents, registry hives, disk images, full-memory images, and process dumps. Expand each result to review tool status, duration, structured output, errors, truncation, and safety limits.",
      "The Forensic Planning Agent selects applicable installed tools for each artifact and may select a bounded second pass after reviewing first-pass facts.",
    ],
  },
  {
    id: "scheduling", icon: Cog6ToothIcon, title: "Scheduling and capacity", tags: "schedule daily rotation cursor time load",
    content: [
      "Configurations → General shows the CPU and memory visible inside the orchestrator cgroup and the resulting compact, balanced, capable, or enterprise profile. Internal forensic, risk, database, and scheduled worker lanes use that profile automatically.",
      "SIEM capacity is deliberately separate: set maximum returned rows, concurrent requests, and queue timeout globally or per connected SIEM. Every Log Search, hunt, anomaly, and detection fetch is clamped at the common connector boundary.",
      "At 2,000–8,000 EPS, keep the full stream in the SIEM and retrieve targeted evidence. If a broad anomaly window exceeds its row budget, THOS pauses baseline scoring instead of treating a partial newest-event sample as complete.",
      "Settings → Hypothesis scheduler supports individual or severity-group schedules. Recommended maintenance windows begin with 3 critical, 8 high, 4 medium, and 1 low hunt per day.",
      "The scheduler prioritizes never-run and most-overdue critical/high hypotheses. It records rolling p50/p95 duration per hypothesis and fits each batch to its maintenance window instead of relying on fixed catalog order.",
      "Ollama memory, SIEM p95 latency, and hunt queue depth are checked before and during a batch and can stop remaining work. Point THOS_SCHEDULED_OLLAMA_HOST at a separate Ollama or GPU worker so scheduled reasoning does not contend with interactive hunts; THOS_OLLAMA_METRICS_URL can supply exact memory_used_bytes and memory_limit_bytes.",
      "Progress and per-target timing are persisted after each target. At the initial measured 20-minute true-positive rate, the recommended windows reserve about 5 hours 20 minutes; faster negative-screened hunts let later batches safely expand within those windows.",
      "Use Settings → Hypothesis scheduler → Apply recommended schedule to replace only the THOS-managed recommendation; manually created schedules are preserved.",
    ],
  },
  {
    id: "connections", icon: CloudIcon, title: "External connections and firewall allowlist", tags: "network proxy firewall outbound port github feeds ollama internet",
    content: [
      "Core hunt execution can remain internal. Allow outbound HTTPS only for features you enable, and use a TLS-inspecting proxy only when its CA is trusted inside the containers.",
      "Rule and knowledge refresh: github.com and codeload.github.com for THORCollective/HEARTH, the community detection-rule corpus, and Yara-Rules/rules. Git operations may also use objects.githubusercontent.com and raw.githubusercontent.com.",
      "Built-in IOC feeds: openphish.com, feodotracker.abuse.ch, check.torproject.org, feeds.dshield.org, and raw.githubusercontent.com. Custom feeds require the hostname configured in Settings.",
      "Forensic updates: database.clamav.net over HTTPS for ClamAV signatures. Building the image also retrieves pinned capa rules from github.com/codeload.github.com.",
      "Model downloads, when performed, require Ollama's configured model registry (normally registry.ollama.ai). Inference itself uses the internal Ollama service and needs no Internet access.",
      "Telemetry connections are deployment-specific and normally stay private: Wazuh Indexer or Elasticsearch HTTPS 9200, Splunk management HTTPS 8089, QRadar HTTPS 443, and LogRhythm Web Console/Search API HTTPS 8505. Allow the exact configured hosts, not whole networks.",
      "Also permit internal DNS and NTP. Optional API integrations require outbound HTTPS to only the endpoint entered for that connector. No unsolicited inbound Internet access is required; publish the UI through your authenticated reverse proxy if remote analysts need access.",
      "For an air-gapped deployment, pre-stage model blobs, HEARTH, detection rules, YARA, IOC feeds, and CA certificates; disable refresh schedules that cannot reach an approved mirror.",
    ],
  },
  {
    id: "operations", icon: CircleStackIcon, title: "Data, cases, reports, and troubleshooting", tags: "case report audit storage error timeout",
    content: [
      "Verification failures or degraded reasoning can create an analyst-review case. There is no separate gated action workflow.",
      "The Risks page is generated by the Risk Analysis Agent. It includes only verifier-supported hunt findings and detections with matched events and links every item back to the originating report or detection.",
      "Risk scores range from 0-100 and are assigned by the evidence-bounded Risk Analysis Agent. Scores prioritize review; they do not authorize containment or prove malicious intent.",
      "Hunt reports contain only investigation content: hypothesis and scope, retrieval results and queries, evidence and correlation, coverage gaps, findings, recommendations, and draft detection logic. Platform audit, model, cache, case, and workflow details stay in operational views rather than the report.",
      "Use the Reports time-period controls to select all time or the last 1-31 days, 1-12 months, or 1-10 years.",
      "If evidence exists in the SIEM but not in a report, compare the executed query, total live matches, deduplicated count, coverage matrix, and Key Evidence Highlights. Confirm the source clock, lookback window, decoder fields, and discovered schema.",
      "For repeated timeouts, lower the per-run hypothesis or detection-rule batch size before increasing concurrency. More simultaneous model jobs usually increase latency and memory pressure on a single inference host.",
    ],
  },
  {
    id: "security", icon: BookOpenIcon, title: "Security model and operating boundaries", tags: "roles permissions secrets guardrails containment",
    content: [
      "Admin and SME roles manage connections, catalogs, schedules, and users. Expert access follows assigned feature permissions.",
      "Every primary page has a stable browser URL. Direct and back/forward navigation remain behind the session gate: the page shell contains no case or telemetry data, `/api/session` must validate the signed HttpOnly session, and every protected API rechecks role and feature permissions.",
      "Store SIEM and connector secrets through Settings, rotate default service credentials, restrict Docker host access, and terminate TLS at a trusted internal proxy.",
      "Untrusted telemetry is screened and sanitized before model use while original evidence remains available to deterministic tools and audit. A verifier checks every reported record reference.",
      "THOS performs investigation and drafts recommendations; it does not autonomously isolate hosts, delete data, block traffic, or deploy a detection.",
    ],
  },
];

const FAQS = [
  {
    q: "Can THOS work with a SIEM receiving 2,000–8,000 EPS?",
    a: "Yes as a bounded query and investigation layer, not as the ingestion pipeline. Keep all events indexed in the SIEM, use targeted source-side filtering or aggregation, and configure per-SIEM row and concurrency ceilings in Configurations → General. THOS enforces those ceilings for every retrieval path. Broad anomaly scoring pauses when a window exceeds the row budget so a partial sample is never presented as a complete baseline.",
    tags: "eps enterprise scale siem limits rows concurrency anomaly",
  },
  {
    q: "What is the minimum hardware required to run THOS?",
    a: "Use 8 x86-64 CPU cores, 16 GB RAM, and at least 50 GB of free SSD storage as the minimum supported starting point for a small deployment. A GPU is optional; CPU-only inference works but is slower. Retained telemetry, reports, model files, and forensic evidence require additional storage.",
    tags: "minimum hardware cpu ram disk gpu requirements",
  },
  {
    q: "What hardware is recommended for daily production use?",
    a: "For concurrent daily operations, start with 12-16 CPU cores, 32 GB RAM, 100 GB or more of SSD storage, and a supported GPU with 8-12 GB VRAM for the reasoning worker. Separate the scheduled Ollama worker from the orchestrator when running many hunts. Adjust capacity to telemetry volume, evidence retention, model size, and maintenance-window targets.",
    tags: "recommended production gpu vram capacity ollama",
  },
  {
    q: "What are the main THOS capabilities?",
    a: "THOS provides hypothesis-driven hunts, schema-aware SIEM retrieval, normalized evidence processing, deterministic detection-rule and YARA evaluation, IOC correlation, ATT&CK coverage analysis, routed static forensics, chain-of-custody timelines, evidence-cited reports, actionable risk correlation, scheduled operations, audit logs, and read-only AI-assisted investigation.",
    tags: "features capabilities hunt forensic risk reports yara ioc attack",
  },
  {
    q: "Which agents are included?",
    a: "The core workflow includes Knowledge Refresh, Hypothesis, Hunt Memory, Supervisor, Query Generation, SIEM Fetch, Log Processing, Guardrail, SOC Tools, Coverage Gap, Adaptive Replanning, Threat Intelligence, Evidence Screening, Reasoning, Verifier, Detection Engineering, Communication, and Reporting agents. Separate agents cover detection analysis, risk analysis, schema discovery, scheduled detection, IOC management, forensic intake and examination, product knowledge, and Ask THOS specialist investigations.",
    tags: "agents agent list workflow specialist",
  },
  {
    q: "Which Internet domains should be allowed?",
    a: "Allow only enabled features: github.com, codeload.github.com, objects.githubusercontent.com, and raw.githubusercontent.com for reviewed knowledge, forensic rules, and rule refreshes; openphish.com, feodotracker.abuse.ch, check.torproject.org, feeds.dshield.org, and raw.githubusercontent.com for built-in IOC feeds; database.clamav.net for malware-signature updates; and registry.ollama.ai only for model downloads. Custom feeds and API integrations additionally require their explicitly configured hostnames.",
    tags: "domains allowlist firewall internet github feeds registry",
  },
  {
    q: "Which ports must THOS reach?",
    a: "Outbound HTTPS normally uses TCP 443. Private telemetry defaults are Wazuh Indexer or Elasticsearch TCP 9200, Splunk management TCP 8089, QRadar TCP 443, and LogRhythm TCP 8505. Internal DNS and NTP are also required according to local infrastructure. Permit exact configured hosts only; THOS requires no unsolicited inbound Internet access.",
    tags: "ports 443 9200 8089 8505 dns ntp firewall",
  },
  {
    q: "Can THOS run without Internet access?",
    a: "Yes. Pre-stage model blobs, the hypothesis and detection corpora, YARA files, IOC snapshots, and trusted CA certificates. Disable refresh schedules that cannot reach an approved internal mirror. Live SIEM and internal Ollama connections can remain entirely private.",
    tags: "offline air gap internet mirror",
  },
  {
    q: "Which forensic tools are installed?",
    a: "The forensic worker includes YARA, libmagic file, GNU strings, ExifTool, ClamAV, pefile, capa, FLOSS, pypdf, oletools, Volatility 3, libewf tools, The Sleuth Kit, and RegRipper. Forensics shows only tools that are installed and ready; ClamAV appears after its signature database is initialized.",
    tags: "forensic tools installed yara capa floss volatility regripper sleuthkit",
  },
  {
    q: "Does forensic analysis execute or upload a suspicious file?",
    a: "No. THOS passes a preserved read-only path only to installed static parsers using fixed argument arrays, no shell, per-tool timeouts, and output limits. There is no sample-upload operation.",
    tags: "forensic execute upload sample safety static hash",
  },
  {
    q: "What actions will THOS not perform automatically?",
    a: "THOS does not isolate hosts, block network traffic, delete evidence, deploy a live detection, or assert compromise or attribution without evidence. It produces evidence-bounded analysis and recommendations for analyst-controlled response and normal change control.",
    tags: "limitations containment blocking deploy safety",
  },
  {
    q: "What happens when a hunt finds no evidence?",
    a: "THOS first queries every selected source, broadens a zero-result primary search with governed ATT&CK/literal context, and expands the bounded time window. After those retrieval branches are exhausted, the deterministic evidence-screening gate stops model reasoning, verification, communication, and report generation. Hunt history retains the complete attempt ledger and coverage limitations; absence of evidence is never proof of a clean environment.",
    tags: "no evidence negative screening report reasoning",
  },
  {
    q: "Does THOS create more than one query during a hunt?",
    a: "Yes when evidence conditions require it. THOS starts with one high-precision query per selected source, then can broaden an empty result, tighten a capped or noisy result, or request one dialect-validated adjacent-activity pivot from reasoning. Time windows and result caps are controlled separately from query text, duplicate source/query/window attempts are rejected, and every attempt is auditable.",
    tags: "multiple queries iterative adaptive broaden tighten lookback noise source",
  },
  {
    q: "Can I bookmark or share a THOS page URL?",
    a: "Yes. Overview, Risks, Detections, Hunt Board, Forensic, Threat Intelligence, Reports, Integrations, Configuration, and Help use stable URLs. Validated detail URLs are available for reports, detections, forensic cases, YARA file or memory scans, configuration tabs, and active hunts. The recipient must sign in and have the required role or feature permission; the URL itself never bypasses authorization.",
    tags: "url bookmark deep link session authentication authorization browser address",
  },
];

export default function Help() {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return SECTIONS;
    return SECTIONS.filter((section) =>
      `${section.title} ${section.tags} ${section.content.join(" ")}`.toLowerCase().includes(needle),
    );
  }, [query]);
  const filteredFaqs = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return FAQS;
    return FAQS.filter((item) =>
      `${item.q} ${item.a} ${item.tags}`.toLowerCase().includes(needle),
    );
  }, [query]);

  return <div className="page-wrap help-page">
    <div className="page-heading help-heading">
      <div><span className="eyebrow">Product guide</span><h1>Help and documentation</h1><p>Search product features, operating guidance, network requirements, and troubleshooting.</p></div>
    </div>
    <div className="help-search"><MagnifyingGlassIcon /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search schedules, Nmap, firewall, detection rules, reports…" /></div>
    <div className="help-layout">
      <aside>{SECTIONS.map((section) => <a key={section.id} href={`#help-${section.id}`}>{section.title}</a>)}<a href="#help-faq">Questions and answers</a></aside>
      <main>
        {filtered.map(({ id, icon: Icon, title, content }) => <section id={`help-${id}`} className="help-card" key={id}>
          <div className="help-card-title"><span><Icon /></span><h2>{title}</h2></div>
          <ul>{content.map((item) => <li key={item}>{item}</li>)}</ul>
        </section>)}
        {!!filteredFaqs.length && <section id="help-faq" className="help-card">
          <div className="help-card-title"><span><BookOpenIcon /></span><h2>Product questions and answers</h2></div>
          <dl className="help-qa">{filteredFaqs.map((item) => <div key={item.q}><dt>{item.q}</dt><dd>{item.a}</dd></div>)}</dl>
        </section>}
        {!filtered.length && !filteredFaqs.length && <div className="help-empty"><BookOpenIcon /><h2>No matching guide entry</h2><p>Try a broader term such as “schedule”, “connection”, “report”, or “rule”.</p></div>}
      </main>
    </div>
  </div>;
}
