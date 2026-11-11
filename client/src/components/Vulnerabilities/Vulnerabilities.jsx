import { useCallback, useEffect, useMemo, useState } from "react";
import {
  FaArrowLeft,
  FaBug,
  FaDownload,
  FaExclamationCircle,
  FaSpinner,
} from "react-icons/fa";
import { loadWazuhVulnerabilities, login as authenticate } from "../../api/intellisecops";
import "./Vulnerabilities.css";

const SEVERITIES = ["Critical", "High", "Medium", "Low"];
const EXPLANATIONS = {
  Critical: "Urgent risk; address as soon as possible.",
  High: "Significant risk; plan a prompt update.",
  Medium: "Moderate risk; include it in your next maintenance cycle.",
  Low: "Lower risk; keep the package maintained.",
};
const SEVERITY_COLORS = {
  Critical: "#fb565d",
  High: "#ff963f",
  Medium: "#f5ca54",
  Low: "#69a9ff",
};
const PAGE_SIZE = 10;

function displayDate(value) {
  if (!value) return "Not available";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function csvCell(value) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

function Vulnerabilities({ agent }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [requiresLogin, setRequiresLogin] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [signingIn, setSigningIn] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("All");
  const [search, setSearch] = useState("");
  const [packageSearch, setPackageSearch] = useState("");
  const [sort, setSort] = useState({ key: "cvss_score", direction: "desc" });
  const [page, setPage] = useState(1);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const result = await loadWazuhVulnerabilities(agent);
      setData(result);
      setRequiresLogin(false);
    } catch (requestError) {
      setError(requestError.message || "Could not load Wazuh vulnerabilities.");
      setRequiresLogin(requestError.status === 401);
    } finally {
      setLoading(false);
    }
  }, [agent]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const filteredItems = useMemo(() => {
    const query = search.trim().toLowerCase();
    const packageQuery = packageSearch.trim().toLowerCase();
    return (data?.items || [])
      .filter((item) => severityFilter === "All" || item.severity === severityFilter)
      .filter((item) => !packageQuery || item.package_name.toLowerCase().includes(packageQuery))
      .filter((item) => !query || [
        item.cve_id,
        item.description,
        item.package_name,
        item.package_version,
      ].some((value) => String(value || "").toLowerCase().includes(query)));
  }, [data, packageSearch, search, severityFilter]);

  const sortedItems = useMemo(() => {
    return [...filteredItems].sort((first, second) => {
      const left = first[sort.key] ?? "";
      const right = second[sort.key] ?? "";
      const comparison = sort.key === "cvss_score"
        ? Number(left) - Number(right)
        : String(left).localeCompare(String(right), undefined, { numeric: true });
      return sort.direction === "asc" ? comparison : -comparison;
    });
  }, [filteredItems, sort]);

  const pageCount = Math.max(1, Math.ceil(sortedItems.length / PAGE_SIZE));
  const visibleItems = sortedItems.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const summary = data?.summary || {};
  const chartTotal = SEVERITIES.reduce(
    (total, severity) => total + (summary[severity.toLowerCase()] || 0),
    0,
  );
  let chartPosition = 0;
  const chartStops = SEVERITIES.map((severity) => {
    const start = chartPosition;
    chartPosition += chartTotal
      ? ((summary[severity.toLowerCase()] || 0) / chartTotal) * 100
      : 0;
    return `${SEVERITY_COLORS[severity]} ${start}% ${chartPosition}%`;
  });

  function changeSort(key) {
    setSort((current) => ({
      key,
      direction: current.key === key && current.direction === "asc" ? "desc" : "asc",
    }));
    setPage(1);
  }

  async function handleLogin(event) {
    event.preventDefault();
    setSigningIn(true);
    setError("");
    try {
      await authenticate(username, password);
      setPassword("");
      await fetchData();
    } catch (loginError) {
      setError(loginError.message || "Sign-in failed.");
    } finally {
      setSigningIn(false);
    }
  }

  function exportCsv() {
    const columns = [
      ["CVE ID", "cve_id"],
      ["Severity", "severity"],
      ["CVSS Score", "cvss_score"],
      ["Package", "package_name"],
      ["Version", "package_version"],
      ["Description", "description"],
      ["Reference", "reference_url"],
      ["Detected", "detected_at"],
      ["Status", "status"],
    ];
    const rows = [
      columns.map(([label]) => csvCell(label)).join(","),
      ...sortedItems.map((item) => columns.map(([, key]) => csvCell(item[key])).join(",")),
    ];
    const blob = new Blob([`\uFEFF${rows.join("\r\n")}`], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `wazuh-vulnerabilities-${data?.agent?.id || "agent"}.csv`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return (
    <main className="wazuh-page">
      <header className="wazuh-page-header">
        <a className="wazuh-back-link" href="/#scanner"><FaArrowLeft /> Back to scans</a>
        <div className="wazuh-page-title">
          <span className="wazuh-eyebrow"><FaBug /> WAZUH VULNERABILITY DETECTION</span>
          <h1>Vulnerability overview</h1>
          <p>
            {data?.agent
              ? `Agent ${data.agent.name} · ID ${data.agent.id}`
              : "Review package vulnerabilities reported by your Wazuh agent."}
          </p>
        </div>
      </header>

      {requiresLogin ? (
        <section className="wazuh-state-card">
          <h2>Sign in to continue</h2>
          <p>A valid account is required to view protected vulnerability data.</p>
          {error ? <p className="wazuh-error-message" role="alert">{error}</p> : null}
          <form className="wazuh-login-form" onSubmit={handleLogin}>
            <label>
              Username
              <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required />
            </label>
            <label>
              Password
              <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required />
            </label>
            <button type="submit" disabled={signingIn}>
              {signingIn ? <FaSpinner className="wazuh-spin" /> : null}
              {signingIn ? "Signing in..." : "Sign in"}
            </button>
          </form>
          <button className="wazuh-secondary-button" type="button" onClick={fetchData} disabled={loading}>
            Retry
          </button>
        </section>
      ) : loading ? (
        <div className="wazuh-state-card" role="status">
          <FaSpinner className="wazuh-spinner" />
          <p>Loading vulnerabilities...</p>
        </div>
      ) : error ? (
        <section className="wazuh-state-card" role="alert">
          <FaExclamationCircle className="wazuh-error-icon" />
          <h2>Could not load vulnerabilities</h2>
          <p>{error}</p>
          <button type="button" onClick={fetchData}>Retry</button>
        </section>
      ) : (
        <>
          <section className="wazuh-summary-grid" aria-label="Vulnerability summary">
            {[
              ...SEVERITIES.map((severity) => ({
                label: severity,
                value: summary[severity.toLowerCase()] || 0,
                color: SEVERITY_COLORS[severity],
              })),
              { label: "Total", value: summary.total || 0, color: "#a9b5c8" },
            ].map((card) => (
              <article className="wazuh-summary-card" key={card.label} style={{ "--severity-color": card.color }}>
                <span>{card.label}</span>
                <strong>{card.value}</strong>
                <small>{card.label === "Total" ? "detected records" : EXPLANATIONS[card.label]}</small>
              </article>
            ))}
          </section>

          <section className="wazuh-overview-panel">
            <div className="wazuh-chart" style={{ background: `conic-gradient(${chartStops.join(", ")})` }} aria-label="Severity distribution">
              <div><strong>{summary.total || 0}</strong><span>findings</span></div>
            </div>
            <div className="wazuh-chart-legend">
              <h2>Severity distribution</h2>
              {SEVERITIES.map((severity) => (
                <div className="wazuh-legend-row" key={severity}>
                  <span style={{ "--severity-color": SEVERITY_COLORS[severity] }} />
                  <strong>{severity}</strong>
                  <span>{summary[severity.toLowerCase()] || 0}</span>
                  <small>{EXPLANATIONS[severity]}</small>
                </div>
              ))}
            </div>
            <p className="wazuh-last-scan">
              Last detected: <strong>{displayDate(summary.last_scan_time)}</strong>
              <span>{summary.affected_packages || 0} affected packages</span>
            </p>
          </section>

          <section className="wazuh-findings-panel">
            <div className="wazuh-findings-heading">
              <div>
                <h2>Detected vulnerabilities</h2>
                <p>{filteredItems.length} matching records</p>
              </div>
              <button type="button" onClick={exportCsv} disabled={!filteredItems.length}>
                <FaDownload /> Export CSV
              </button>
            </div>
            {data.truncated ? (
              <p className="wazuh-cap-note">
                Showing the highest-scored {data.items.length} records of {summary.total} total.
                Refine filters or review the agent directly for the complete inventory.
              </p>
            ) : null}
            <div className="wazuh-filters">
              <label>
                Search CVE or description
                <input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); }} placeholder="e.g. CVE-2026-1234" />
              </label>
              <label>
                Package
                <input value={packageSearch} onChange={(event) => { setPackageSearch(event.target.value); setPage(1); }} placeholder="Filter by package name" />
              </label>
              <label>
                Severity
                <select value={severityFilter} onChange={(event) => { setSeverityFilter(event.target.value); setPage(1); }}>
                  <option>All</option>
                  {SEVERITIES.map((severity) => <option key={severity}>{severity}</option>)}
                </select>
              </label>
            </div>

            {loading ? (
              <p className="wazuh-inline-loading"><FaSpinner className="wazuh-spin" /> Refreshing vulnerability data...</p>
            ) : filteredItems.length ? (
              <>
                <div className="wazuh-table-wrap">
                  <table className="wazuh-table">
                    <thead>
                      <tr>
                        {[
                          ["cve_id", "CVE ID"],
                          ["severity", "Severity"],
                          ["cvss_score", "CVSS"],
                          ["package_name", "Package"],
                          ["package_version", "Version"],
                          ["description", "Description"],
                          ["detected_at", "Detected"],
                        ].map(([key, label]) => (
                          <th key={key} aria-sort={sort.key === key ? `${sort.direction === "asc" ? "ascending" : "descending"}` : "none"}>
                            <button type="button" onClick={() => changeSort(key)}>
                              {label}{sort.key === key ? (sort.direction === "asc" ? " ↑" : " ↓") : ""}
                            </button>
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {visibleItems.map((item, index) => (
                        <tr key={`${item.cve_id}-${item.package_name}-${item.package_version}-${index}`}>
                          <td>
                            {item.cve_id ? (
                              <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.cve_id)}`} target="_blank" rel="noreferrer">
                                {item.cve_id}
                              </a>
                            ) : "Unknown"}
                          </td>
                          <td><span className={`wazuh-severity-badge ${item.severity.toLowerCase()}`}>{item.severity}</span></td>
                          <td>{item.cvss_score ?? "—"}</td>
                          <td>{item.package_name || "Unknown"}</td>
                          <td>{item.package_version || "—"}</td>
                          <td>
                            <p>{item.description || "No description provided."}</p>
                            <small className="wazuh-remediation-hint">
                              What should I do? Update {item.package_name || "the affected package"} to a vendor-fixed version, then rescan.
                            </small>
                          </td>
                          <td>{displayDate(item.detected_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="wazuh-pagination">
                  <span>Page {page} of {pageCount}</span>
                  <div>
                    <button type="button" onClick={() => setPage((current) => Math.max(1, current - 1))} disabled={page <= 1}>Previous</button>
                    <button type="button" onClick={() => setPage((current) => Math.min(pageCount, current + 1))} disabled={page >= pageCount}>Next</button>
                  </div>
                </div>
              </>
            ) : (
              <div className="wazuh-empty-state">
                <FaBug />
                <h3>No vulnerabilities found</h3>
                <p>Try changing the filters or check again after the next Wazuh inventory scan.</p>
              </div>
            )}
          </section>
        </>
      )}
    </main>
  );
}

export default Vulnerabilities;
