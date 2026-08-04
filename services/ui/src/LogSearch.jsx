import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowDownTrayIcon,
  ArrowPathIcon,
  CircleStackIcon,
  CodeBracketIcon,
  ExclamationTriangleIcon,
  MagnifyingGlassIcon,
  SparklesIcon,
} from "@heroicons/react/24/outline";


async function api(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || payload.error || `Request failed (${response.status})`);
  return payload;
}

function jsonOptions(body) {
  return { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

function flatten(record, prefix = "", output = {}) {
  Object.entries(record || {}).forEach(([key, value]) => {
    const name = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === "object" && !Array.isArray(value)) flatten(value, name, output);
    else output[name] = value;
  });
  return output;
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") return "—";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

const DIALECTS = {
  wazuh: "OpenSearch query DSL",
  elasticsearch: "Elasticsearch query DSL",
  splunk: "SPL",
  qradar: "AQL",
  logrhythm: "LogRhythm filter syntax",
  folder: "bounded keyword list",
};

export default function LogSearch({ activeSources, defaultSource = "folder" }) {
  const initialSource = activeSources.some((item) => item.id === defaultSource)
    ? defaultSource
    : (activeSources[0]?.id || "folder");
  const [source, setSource] = useState(initialSource);
  const [portableQuery, setPortableQuery] = useState("");
  const [targetQuery, setTargetQuery] = useState("");
  const [lookbackMinutes, setLookbackMinutes] = useState(1440);
  const [limit, setLimit] = useState(250);
  const [folderPath, setFolderPath] = useState("/data/log_sources");
  const [context, setContext] = useState({ field_mapping: {}, schema: {} });
  const [result, setResult] = useState(null);
  const [working, setWorking] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!activeSources.some((item) => item.id === source)) {
      setSource(activeSources.some((item) => item.id === defaultSource) ? defaultSource : (activeSources[0]?.id || "folder"));
    }
  }, [activeSources, defaultSource, source]);

  useEffect(() => {
    if (activeSources.some((item) => item.id === defaultSource)) setSource(defaultSource);
  }, [activeSources, defaultSource]);

  const loadContext = useCallback(async () => {
    setError("");
    try {
      setContext(await api(`/api/log-search/context/${encodeURIComponent(source)}`));
    } catch (reason) {
      setContext({ field_mapping: {}, schema: {} });
      setError(reason.message);
    }
  }, [source]);

  useEffect(() => {
    setTargetQuery("");
    setResult(null);
    loadContext();
  }, [loadContext]);

  const serverMaxRows = Math.max(1, Number(context.retrieval_policy?.max_rows || 2000));
  useEffect(() => {
    setLimit((current) => Math.min(current, serverMaxRows));
  }, [serverMaxRows]);

  const run = async () => {
    if (!portableQuery.trim()) {
      setError("Describe the correlation you want to search for first.");
      return;
    }
    setWorking("run");
    setError("");
    setResult(null);
    try {
      const translation = await api("/api/log-search/translate", jsonOptions({
        portable_query: portableQuery.trim(),
        siem_type: source,
        lookback_minutes: lookbackMinutes,
      }));
      const translatedQuery = String(translation.query || "").trim();
      if (!translatedQuery) throw new Error("The selected SIEM returned no executable query.");
      setTargetQuery(translatedQuery);
      setResult(await api("/api/log-search/run", jsonOptions({
        portable_query: portableQuery.trim(),
        query: translatedQuery,
        siem_type: source,
        lookback_minutes: lookbackMinutes,
        limit,
        log_source_path: source === "folder" ? folderPath : null,
      })));
    } catch (reason) {
      setResult(null);
      setError(reason.message);
    } finally {
      setWorking("");
    }
  };

  const exportExcel = async () => {
    if (!result?.logs?.length) return;
    setWorking("export");
    setError("");
    try {
      const response = await fetch("/api/log-search/export", jsonOptions({
        portable_query: portableQuery.trim(),
        query: result.query || targetQuery.trim(),
        siem_type: source,
        lookback_minutes: lookbackMinutes,
        executed_at: result.executed_at || "",
        field_mapping: context.field_mapping || {},
        logs: result.logs,
      }));
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail || `Export failed (${response.status})`);
      }
      const disposition = response.headers.get("Content-Disposition") || "";
      const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] || "thos-log-search.xlsx";
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      link.click();
      URL.revokeObjectURL(url);
    } catch (reason) {
      setError(reason.message);
    } finally {
      setWorking("");
    }
  };

  const flattenedLogs = useMemo(() => (result?.logs || []).map((item) => flatten(item)), [result]);
  const columns = useMemo(() => {
    const keys = [...new Set(flattenedLogs.flatMap((item) => Object.keys(item)))];
    return keys.slice(0, 30);
  }, [flattenedLogs]);
  const mappings = Object.entries(context.field_mapping || {});
  const schemaFields = (context.schema?.fields || []).map((item) => typeof item === "string" ? item : item.name).filter(Boolean);
  const sourceLabel = activeSources.find((item) => item.id === source)?.label || source;
  const rowOptions = [...new Set([100, 250, 500, 1000, 2000, 5000, 10000, serverMaxRows])]
    .filter((value) => value <= serverMaxRows)
    .sort((left, right) => left - right);
  const fieldSpecificEmptyHint = result && Number(result.record_count || 0) === 0
    && source === "wazuh" && /\brule_description\b/i.test(portableQuery)
    ? <>No Wazuh rule descriptions matched. That field searches only <code>rule.description</code>; use <code>message contains "keyword"</code> to search the raw Wazuh <code>full_log</code> text.</>
    : null;

  return <div className="page-wrap log-search-page">
    <section className="page-heading">
      <div>
        <span className="status-pill status-indigo"><MagnifyingGlassIcon /> Manual correlation workspace</span>
        <h1>Log search</h1>
        <p>Write one portable correlation intent, search the selected SIEM, and export the returned records to Excel.</p>
      </div>
    </section>

    <section className="log-search-guidance panel">
      <SparklesIcon />
      <div><strong>Use normalized KQL-like intent—not vendor KQL.</strong><p>THOS maps normalized fields to the selected SIEM schema and translates the query automatically in the background when you select Search.</p></div>
    </section>

    {error && <div className="alert error-alert"><ExclamationTriangleIcon />{error}</div>}

    <section className="log-search-layout">
      <div className="log-query-panel panel">
        <header><span><CodeBracketIcon /></span><div><h2>1. Author and search</h2><p>The current default telemetry selection and its field mapping are used automatically.</p></div></header>
        <div className="log-query-controls">
          <label>Telemetry source<select value={source} onChange={(event) => setSource(event.target.value)}>{activeSources.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label>
          <label>Lookback<select value={lookbackMinutes} onChange={(event) => setLookbackMinutes(Number(event.target.value))}><option value={15}>15 minutes</option><option value={60}>1 hour</option><option value={360}>6 hours</option><option value={1440}>24 hours</option><option value={10080}>7 days</option><option value={43200}>30 days</option></select></label>
          <label>Maximum rows · server cap {serverMaxRows.toLocaleString()}<select value={limit} onChange={(event) => setLimit(Number(event.target.value))}>{rowOptions.map((value) => <option key={value} value={value}>{value.toLocaleString()}</option>)}</select></label>
          {source === "folder" && <label className="log-folder-path">Server log folder<input value={folderPath} onChange={(event) => setFolderPath(event.target.value)} /></label>}
        </div>
        <label className="log-query-editor"><span>Portable correlation intent</span><textarea value={portableQuery} onChange={(event) => { setPortableQuery(event.target.value); setTargetQuery(""); setResult(null); }} placeholder={'Example: process_name == "powershell.exe" and command_line contains "-enc"\n\nPlain language also works: Find the same user authenticating from multiple source IPs followed by privileged process execution.'} /></label>
        <div className="log-query-actions"><button className="primary-button" onClick={run} disabled={Boolean(working) || !portableQuery.trim()}>{working === "run" ? <ArrowPathIcon className="spinning" /> : <MagnifyingGlassIcon />} Search</button></div>
      </div>

      <aside className="log-field-panel panel">
        <header><span><CircleStackIcon /></span><div><h2>Field standardization</h2><p>{mappings.length} normalized mappings · {Number(context.schema?.field_count || schemaFields.length)} discovered fields</p></div></header>
        <div className="mapping-list">{mappings.length ? mappings.map(([normalized, vendor]) => <div key={normalized}><strong>{normalized}</strong><span>{vendor}</span></div>) : <p>No normalized field mapping is available for this source yet.</p>}</div>
        <div className="schema-field-list"><strong>Available field sample</strong><div>{schemaFields.slice(0, 24).map((field) => <span key={field}>{field}</span>)}</div>{context.schema?.stale && <small>The cached schema is stale; refresh schema discovery in Configuration for the most accurate translation.</small>}</div>
      </aside>
    </section>

    <section className="log-results panel">
      <header><div><span><CircleStackIcon /></span><div><h2>2. Search results</h2><p>{result ? `${Number(result.record_count || 0).toLocaleString()} returned in ${Number(result.duration_ms || 0).toLocaleString()} ms · ${sourceLabel}${result.retrieval_policy?.capped ? ` · request capped at ${Number(result.retrieval_policy.applied_rows || 0).toLocaleString()} rows` : ""}` : "Run a translated query to preview matching records."}</p></div></div><button className="secondary-button" onClick={exportExcel} disabled={!result?.logs?.length || Boolean(working)}>{working === "export" ? <ArrowPathIcon className="spinning" /> : <ArrowDownTrayIcon />} Download Excel</button></header>
      {flattenedLogs.length ? <><div className="log-results-table"><table><thead><tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr></thead><tbody>{flattenedLogs.slice(0, 100).map((record, index) => <tr key={index}>{columns.map((column) => <td key={column} title={displayValue(record[column])}>{displayValue(record[column])}</td>)}</tr>)}</tbody></table></div><footer>Previewing {Math.min(flattenedLogs.length, 100).toLocaleString()} of {flattenedLogs.length.toLocaleString()} rows and {columns.length} columns. Excel includes every returned row and up to 200 discovered columns.</footer></> : <div className="log-results-empty"><MagnifyingGlassIcon /><strong>{result ? "No matching logs" : "No result set yet"}</strong><span>{fieldSpecificEmptyHint || "Select Search to translate safely in the background and fetch matching records."}</span></div>}
    </section>
  </div>;
}
