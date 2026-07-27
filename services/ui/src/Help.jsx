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
      "Start with the Hunt Summary and Key Evidence Highlights in the report. Treat findings as investigative leads and verify cited records before response actions.",
    ],
  },
  {
    id: "hunts", icon: DocumentMagnifyingGlassIcon, title: "Hypotheses and threat hunts", tags: "HEARTH gaps MITRE query Nmap evidence",
    content: [
      "The hypothesis catalog combines pinned HEARTH content with THOS gap hypotheses for ATT&CK techniques not adequately represented upstream.",
      "A hunt generates a validated source-specific query, normalizes and deduplicates telemetry, runs Sigma and literal artifact correlation, enriches public IOCs, checks coverage, reasons over bounded evidence, verifies citations, and writes a report. Related Wazuh hunts reuse an ATT&CK-technique/time-window telemetry cache.",
      "When Sigma, literal artifacts, local IOC matches, and deterministic behavioral signals are all zero, THOS skips expensive model reasoning. Missing or partial telemetry is still reported as inconclusive, never as a clean result.",
      "Wazuh high-signal fields—including rule MITRE metadata, URL, user-agent, command line, process paths, and full_log—are preserved in an evidence summary. This allows artifacts such as Nmap NSE to remain visible even when the raw event is long.",
      "A clean result is meaningful only when the coverage section says the required ATT&CK data sources were available.",
    ],
  },
  {
    id: "detections", icon: ShieldCheckIcon, title: "Sigma and YARA", tags: "rule detection scan batch compatible compile",
    content: [
      "Sigma rules are compiled for the selected SIEM and validated against its discovered field schema. Incompatible rules remain visible but are never scheduled or executed.",
      "During hypothesis hunts, compatible Wazuh Sigma queries use one OpenSearch multi-search request. If the deployment blocks multi-search, THOS automatically falls back to bounded individual read-only searches.",
      "The recommended scheduled Wazuh Sigma rotation also executes each bounded rule batch as one multi-search request and resumes from a saved cursor. Splunk retains bounded individual searches until its connector exposes an equivalent safe batch API.",
      "YARA files are compiler-validated and enabled rules are assembled into one reusable bundle. Schedule the enabled bundle once—not one scan per rule. After the first scan, only evidence modified since the previous completed run is scanned.",
      "Detection proposals in hunt reports are experimental drafts. THOS does not automatically deploy or contain; use your normal detection change-control process.",
    ],
  },
  {
    id: "scheduling", icon: Cog6ToothIcon, title: "Scheduling and capacity", tags: "schedule daily rotation cursor time load",
    content: [
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
      "Rule and knowledge refresh: github.com and codeload.github.com for THORCollective/HEARTH, SigmaHQ/sigma, and Yara-Rules/rules. Git operations may also use objects.githubusercontent.com and raw.githubusercontent.com.",
      "Built-in IOC feeds: openphish.com, feodotracker.abuse.ch, check.torproject.org, feeds.dshield.org, and raw.githubusercontent.com. Custom feeds require the hostname configured in Settings.",
      "Model downloads, when performed, require Ollama's configured model registry (normally registry.ollama.ai). Inference itself uses the internal Ollama service and needs no Internet access.",
      "Telemetry connections are deployment-specific and normally stay private: Wazuh Indexer HTTPS 9200, Splunk management HTTPS 8089, QRadar HTTPS 443, and LogRhythm Web Console/Search API HTTPS 8505. Allow the exact configured hosts, not whole networks.",
      "Also permit internal DNS and NTP. Optional API integrations require outbound HTTPS to only the endpoint entered for that connector. No unsolicited inbound Internet access is required; publish the UI through your authenticated reverse proxy if remote analysts need access.",
      "For an air-gapped deployment, pre-stage model blobs, HEARTH, Sigma, YARA, IOC feeds, and CA certificates; disable refresh schedules that cannot reach an approved mirror.",
    ],
  },
  {
    id: "operations", icon: CircleStackIcon, title: "Data, cases, reports, and troubleshooting", tags: "case report audit storage error timeout",
    content: [
      "Verification failures or degraded reasoning can create an analyst-review case. There is no separate approval workflow.",
      "Reports retain executed queries, ingestion diagnostics, citations, representative evidence, agent timing, coverage gaps, recommendations, and draft rules.",
      "If evidence exists in the SIEM but not in a report, compare the executed query, total live matches, deduplicated count, coverage matrix, and Key Evidence Highlights. Confirm the source clock, lookback window, decoder fields, and discovered schema.",
      "For repeated timeouts, lower the per-run hypothesis or Sigma batch size before increasing concurrency. More simultaneous model jobs usually increase latency and memory pressure on a single inference host.",
    ],
  },
  {
    id: "security", icon: BookOpenIcon, title: "Security model and operating boundaries", tags: "roles permissions secrets guardrails containment",
    content: [
      "Admin and SME roles manage connections, catalogs, schedules, and users. Expert access follows assigned feature permissions.",
      "Store SIEM and connector secrets through Settings, rotate default service credentials, restrict Docker host access, and terminate TLS at a trusted internal proxy.",
      "Untrusted telemetry is screened and sanitized before model use while original evidence remains available to deterministic tools and audit. A verifier checks every reported record reference.",
      "THOS performs investigation and drafts recommendations; it does not autonomously isolate hosts, delete data, block traffic, or deploy a detection.",
    ],
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

  return <div className="page-wrap help-page">
    <div className="page-heading help-heading">
      <div><span className="eyebrow">Product guide</span><h1>Help and documentation</h1><p>Search product features, operating guidance, network requirements, and troubleshooting.</p></div>
    </div>
    <div className="help-search"><MagnifyingGlassIcon /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search schedules, Nmap, firewall, Sigma, reports…" /></div>
    <div className="help-layout">
      <aside>{SECTIONS.map((section) => <a key={section.id} href={`#help-${section.id}`}>{section.title}</a>)}</aside>
      <main>
        {filtered.map(({ id, icon: Icon, title, content }) => <section id={`help-${id}`} className="help-card" key={id}>
          <div className="help-card-title"><span><Icon /></span><h2>{title}</h2></div>
          <ul>{content.map((item) => <li key={item}>{item}</li>)}</ul>
        </section>)}
        {!filtered.length && <div className="help-empty"><BookOpenIcon /><h2>No matching guide entry</h2><p>Try a broader term such as “schedule”, “connection”, “report”, or “rule”.</p></div>}
      </main>
    </div>
  </div>;
}
