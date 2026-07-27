import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowPathIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  GlobeAltIcon,
  MagnifyingGlassIcon,
  ShieldExclamationIcon,
} from "@heroicons/react/24/outline";

async function api(path) {
  const response = await fetch(path);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`);
  return payload;
}

function localTime(value) {
  if (!value) return "Not observed";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

export default function ThreatIntelligence() {
  const [query, setQuery] = useState("");
  const [type, setType] = useState("all");
  const [category, setCategory] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [page, setPage] = useState(1);
  const [data, setData] = useState({
    items: [], total: 0, indexed_total: 0, type_counts: {}, category_counts: {},
  });
  const [knownTypes, setKnownTypes] = useState([]);
  const [knownCategories, setKnownCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const params = new URLSearchParams({
        query, indicator_type: type, category, severity, page: String(page), page_size: "100",
      });
      const payload = await api(`/api/threat-intelligence/iocs?${params}`);
      setData(payload);
      setKnownTypes((current) => Array.from(new Set([...current, ...Object.keys(payload.type_counts || {})])).sort());
      setKnownCategories((current) => Array.from(new Set([...current, ...Object.keys(payload.category_counts || {})])).sort());
    } catch (caught) {
      setError(caught.message);
    } finally {
      setLoading(false);
    }
  }, [query, type, category, severity, page]);

  useEffect(() => {
    const timer = window.setTimeout(load, 250);
    return () => window.clearTimeout(timer);
  }, [load]);
  useEffect(() => { setPage(1); }, [query, type, category, severity]);

  const totalPages = Math.max(1, Math.ceil(Number(data.total || 0) / 100));
  const summary = useMemo(() => [
    ["Indexed indicators", Number(data.indexed_total || 0).toLocaleString()],
    ["Matching this view", Number(data.total || 0).toLocaleString()],
    ["Last index update", localTime(data.updated_at)],
  ], [data]);

  return <div className="page-wrap threat-intel-page">
    <section className="page-heading"><div><span className="status-pill status-indigo"><GlobeAltIcon /> Local intelligence index</span><h1>Threat Intelligence Operations</h1><p>Search normalized indicators collected by the IOC Management Agent. Results are ordered by freshness, severity, category, type, and indicator value.</p></div><button className="secondary-button" onClick={load} disabled={loading}><ArrowPathIcon className={loading ? "spinning" : ""} /> Refresh view</button></section>

    <section className="intel-summary">{summary.map(([label, value]) => <div className="panel" key={label}><small>{label}</small><strong>{value}</strong></div>)}</section>

    <section className="control-deck panel intel-controls">
      <div className="field search-field"><label htmlFor="ioc-search">IOC or source search</label><span><MagnifyingGlassIcon /></span><input id="ioc-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="IP, network, domain, URL, hash, CVE, source…" /></div>
      <div className="field"><label htmlFor="ioc-severity">Severity</label><select id="ioc-severity" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></div>
      <div className="field"><label htmlFor="ioc-category">Category</label><select id="ioc-category" value={category} onChange={(event) => setCategory(event.target.value)}><option value="all">All categories</option>{knownCategories.map((item) => <option key={item}>{item}</option>)}</select></div>
      <div className="field"><label htmlFor="ioc-type">Type</label><select id="ioc-type" value={type} onChange={(event) => setType(event.target.value)}><option value="all">All types</option>{knownTypes.map((item) => <option key={item}>{item}</option>)}</select></div>
    </section>

    {error && <div className="settings-notice error"><ShieldExclamationIcon />{error}</div>}
    <section className="panel intel-catalog">
      <header><div><h2>Collected indicators</h2><p>{data.total || 0} results · page {page} of {totalPages}</p></div></header>
      <div className="intel-table-wrap"><table className="intel-table"><thead><tr><th>Indicator</th><th>Type</th><th>Category</th><th>Severity</th><th>Freshness</th><th>Last observed</th><th>Confidence</th><th>Sources</th></tr></thead><tbody>
        {data.items.map((item) => <tr key={`${item.type}:${item.indicator}`}><td><code title={item.indicator}>{item.indicator}</code><small>First indexed {localTime(item.first_seen)}</small></td><td>{item.type}</td><td>{item.category}</td><td><span className={`detection-level level-${item.severity}`}>{item.severity}</span></td><td><span className={`freshness freshness-${item.freshness}`}>{item.freshness}</span></td><td>{localTime(item.last_seen)}</td><td>{item.confidence}</td><td title={(item.sources || []).join(", ")}>{(item.sources || []).slice(0, 2).join(", ")}{item.source_count > 2 ? ` +${item.source_count - 2}` : ""}</td></tr>)}
        {!loading && !data.items.length && <tr><td colSpan="8" className="intel-empty">No collected IOC matches these filters.</td></tr>}
      </tbody></table></div>
      <footer className="intel-pagination"><button className="secondary-button compact" disabled={page <= 1 || loading} onClick={() => setPage((value) => value - 1)}><ChevronLeftIcon /> Previous</button><span>Page {page} of {totalPages}</span><button className="secondary-button compact" disabled={page >= totalPages || loading} onClick={() => setPage((value) => value + 1)}>Next <ChevronRightIcon /></button></footer>
    </section>
  </div>;
}
