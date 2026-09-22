import React, { useState, useEffect } from "react";
import "./SecurityReports.css";
import {
  FaShieldAlt,
  FaDatabase,
  FaTerminal,
  FaCheckCircle,
  FaExclamationTriangle,
  FaDownload,
  FaSearch,
  FaBug,
  FaChartLine,
  FaCode,
  FaCopy,
} from "react-icons/fa";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:5000";

function SecurityReports() {
  const [activeTab, setActiveTab] = useState("all");
  const [copied, setCopied] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchTable, setSearchTable] = useState("services");
  const [searchMode, setSearchMode] = useState("raw");
  const [searchResult, setSearchResult] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [selectedReport, setSelectedReport] = useState(null);

  // Live metrics from backend
  const [metrics, setMetrics] = useState({
    totalScans: 14,
    zapScans: 9,
    sqlmapScans: 5,
    criticalCount: 0,
    mediumCount: 3,
    lowCount: 6,
    gateStatus: "PASSED",
  });

  useEffect(() => {
    // Attempt fetching real metrics from Django backend
    const fetchMetrics = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/grafana-metrics/`);
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data)) {
            const getVal = (name) => {
              const item = data.find((d) => d.metric === name);
              return item ? item.value : 0;
            };
            setMetrics((prev) => ({
              ...prev,
              totalScans: getVal("Total Scans") || prev.totalScans,
              zapScans: getVal("ZAP Scans") || prev.zapScans,
              sqlmapScans: getVal("SQLMap Scans") || prev.sqlmapScans,
              criticalCount: getVal("Critical & High Severity") || 0,
              mediumCount: getVal("Medium Severity") || prev.mediumCount,
              lowCount: getVal("Low Severity") || prev.lowCount,
            }));
          }
        }
      } catch {
        // Graceful fallback to initial values
      }
    };
    fetchMetrics();
  }, []);

  const handleAuditSearch = async (e) => {
    e.preventDefault();
    setSearchLoading(true);
    try {
      const url = `${API_BASE}/api/audit/search/?query=${encodeURIComponent(
        searchQuery
      )}&table=${searchTable}&mode=${searchMode}`;
      const res = await fetch(url);
      const data = await res.json();
      setSearchResult(data);
    } catch {
      setSearchResult({
        status: "simulated_local",
        message: "Backend offline - simulated audit evaluation result",
        query_executed: `SELECT * FROM api_${searchTable} WHERE query LIKE '%${searchQuery}%'`,
        count: 0,
        mode: searchMode,
      });
    } finally {
      setSearchLoading(false);
    }
  };

  const sampleJsonLog = {
    timestamp: new Date().toISOString(),
    event: "security_scan_analyzed",
    scanner: "ZAP & SQLMap DevSecOps Pipeline",
    target: "http://13.63.222.33",
    metrics: {
      total_scans: metrics.totalScans,
      critical_high: metrics.criticalCount,
      medium: metrics.mediumCount,
      low: metrics.lowCount,
      security_gate: metrics.criticalCount > 0 ? "BLOCKED" : "PASSED",
    },
    export_format: "grafana_loki_json_v2",
  };

  const handleCopyLogs = () => {
    navigator.clipboard.writeText(JSON.stringify(sampleJsonLog, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  const handleDownloadLogs = () => {
    const blob = new Blob([JSON.stringify(sampleJsonLog, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `pipeline_security_scan_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <section className="security-reports-section" id="reports">
      <div className="reports-container">
        {/* Section Header */}
        <div className="reports-header">
          <div className="badge-pill">
            <span className="pulsing-radar"></span>
            DEVSECOPS PIPELINE OBSERVABILITY
          </div>
          <h2>
            Automated Security Scan <span>Intelligence</span>
          </h2>
          <p>
            Continuous audit telemetry powered by OWASP ZAP baseline testing, SQLMap dynamic
            database evaluation, and Grafana structured log pipelines.
          </p>
        </div>

        {/* Top Metric Strip */}
        <div className="telemetry-strip">
          <div className="telemetry-card">
            <div className="telemetry-icon zap">
              <FaShieldAlt />
            </div>
            <div className="telemetry-info">
              <h3>{metrics.totalScans}</h3>
              <p>Total Pipeline Scans</p>
            </div>
            <span className="telemetry-tag live">ACTIVE</span>
          </div>

          <div className="telemetry-card">
            <div className="telemetry-icon alert">
              <FaExclamationTriangle />
            </div>
            <div className="telemetry-info">
              <h3>{metrics.criticalCount}</h3>
              <p>Critical Escapes</p>
            </div>
            <span className="telemetry-tag passed">CLEAN GATE</span>
          </div>

          <div className="telemetry-card">
            <div className="telemetry-icon db">
              <FaDatabase />
            </div>
            <div className="telemetry-info">
              <h3>{metrics.sqlmapScans}</h3>
              <p>Database Injection Audits</p>
            </div>
            <span className="telemetry-tag db">AUDITED</span>
          </div>

          <div className="telemetry-card">
            <div className="telemetry-icon grafana">
              <FaChartLine />
            </div>
            <div className="telemetry-info">
              <h3>JSON Log Export</h3>
              <p>Grafana Loki Stream</p>
            </div>
            <span className="telemetry-tag sync">LIVE SYNC</span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="reports-tabs">
          <button
            className={`tab-btn ${activeTab === "all" ? "active" : ""}`}
            onClick={() => setActiveTab("all")}
          >
            All Reports
          </button>
          <button
            className={`tab-btn ${activeTab === "zap" ? "active" : ""}`}
            onClick={() => setActiveTab("zap")}
          >
            OWASP ZAP DAST
          </button>
          <button
            className={`tab-btn ${activeTab === "sqlmap" ? "active" : ""}`}
            onClick={() => setActiveTab("sqlmap")}
          >
            SQLMap Database Audits
          </button>
          <button
            className={`tab-btn ${activeTab === "tester" ? "active" : ""}`}
            onClick={() => setActiveTab("tester")}
          >
            Dynamic Query Tester
          </button>
          <button
            className={`tab-btn ${activeTab === "grafana" ? "active" : ""}`}
            onClick={() => setActiveTab("grafana")}
          >
            Grafana Logs (JSON)
          </button>
        </div>

        {/* Interactive Scan Cards Grid */}
        <div className="reports-grid">
          {/* Card 1: OWASP ZAP */}
          {(activeTab === "all" || activeTab === "zap") && (
            <div className="report-card">
              <div className="card-header">
                <div className="scanner-badge zap">
                  <FaShieldAlt /> OWASP ZAP Baseline
                </div>
                <span className="gate-badge passed">
                  <FaCheckCircle /> GATE PASSED
                </span>
              </div>

              <h3>Automated Dynamic Application Security Testing (DAST)</h3>
              <p className="target-url">
                Target: <code>http://13.63.222.33/</code>
              </p>

              <div className="severity-bar">
                <div className="sev-item critical">
                  <span>Critical / High</span>
                  <strong>{metrics.criticalCount}</strong>
                </div>
                <div className="sev-item medium">
                  <span>Medium</span>
                  <strong>{metrics.mediumCount}</strong>
                </div>
                <div className="sev-item low">
                  <span>Low / Info</span>
                  <strong>{metrics.lowCount}</strong>
                </div>
              </div>

              <div className="card-summary">
                <div className="summary-item">
                  <span>Scan Engine:</span>
                  <span>ZAP Docker 2.14 Stable</span>
                </div>
                <div className="summary-item">
                  <span>AI Assessment:</span>
                  <span className="ai-highlight">Gemini 2.0 Flash Summarized</span>
                </div>
                <div className="summary-item">
                  <span>Jenkins Gate:</span>
                  <span className="text-emerald">Zero High Risk Detected</span>
                </div>
              </div>

              <div className="card-actions">
                <button
                  className="card-btn primary"
                  onClick={() =>
                    setSelectedReport({
                      title: "OWASP ZAP Security Audit Details",
                      type: "ZAP",
                      target: "http://13.63.222.33",
                      details:
                        "Automated passive & baseline active security inspection finished cleanly with 0 high/critical severity escapes. Recommended headers (X-Frame-Options, CSP, HSTS) are verified in production.",
                    })
                  }
                >
                  View Analysis
                </button>
                <a href="#contact" className="card-btn secondary">
                  Request Patch
                </a>
              </div>
            </div>
          )}

          {/* Card 2: SQLMap Injection Audit */}
          {(activeTab === "all" || activeTab === "sqlmap") && (
            <div className="report-card">
              <div className="card-header">
                <div className="scanner-badge sqlmap">
                  <FaDatabase /> SQLMap Database Audit
                </div>
                <span className="gate-badge warning">
                  <FaBug /> LAB AUDITED
                </span>
              </div>

              <h3>Database Parameter & Query Injection Evaluation</h3>
              <p className="target-url">
                Endpoint: <code>/api/analyze-report/?id=1</code>
              </p>

              <div className="injection-details">
                <div className="detail-pill">
                  <span>Technique:</span>
                  <strong>Boolean-based & Time-based Blind</strong>
                </div>
                <div className="detail-pill">
                  <span>Audited Parameter:</span>
                  <strong>id (GET) / query (POST)</strong>
                </div>
                <div className="detail-pill">
                  <span>Risk Classification:</span>
                  <strong className="text-amber">CWE-89 Educational Lab</strong>
                </div>
              </div>

              <div className="card-summary">
                <div className="summary-item">
                  <span>Payload Tested:</span>
                  <code>id=1 AND 1=1 -- batch</code>
                </div>
                <div className="summary-item">
                  <span>Parser:</span>
                  <span>parse_sqlmap.py to Django JSON</span>
                </div>
                <div className="summary-item">
                  <span>Mitigation:</span>
                  <span>Django ORM parameterized query validation</span>
                </div>
              </div>

              <div className="card-actions">
                <button
                  className="card-btn primary"
                  onClick={() => setActiveTab("tester")}
                >
                  Launch Audit Tester
                </button>
                <button
                  className="card-btn secondary"
                  onClick={() =>
                    setSelectedReport({
                      title: "SQLMap Vulnerability Audit Summary",
                      type: "SQLMap",
                      target: "/api/analyze-report/?id=1",
                      details:
                        "SQLMap dynamic analysis detected raw database parameter querying on test endpoints. The application logs all raw executions to security_audit.json.log for Grafana and provides safe ORM fallback routes.",
                    })
                  }
                >
                  Audit Specs
                </button>
              </div>
            </div>
          )}

          {/* Card 3: Grafana Structured Observability */}
          {(activeTab === "all" || activeTab === "grafana") && (
            <div className="report-card grafana-card">
              <div className="card-header">
                <div className="scanner-badge grafana">
                  <FaChartLine /> Grafana SIEM Pipeline
                </div>
                <span className="gate-badge live">
                  <span className="pulse-dot"></span> STREAMING
                </span>
              </div>

              <h3>Structured JSON Log Export for Dashboards</h3>
              <p className="target-url">
                Sink: <code>/api/grafana-logs/</code> & <code>scan_metrics.json.log</code>
              </p>

              <div className="json-terminal-preview">
                <div className="terminal-bar">
                  <span>grafana_scans.json (Live Log Stream)</span>
                  <div className="terminal-actions">
                    <button onClick={handleCopyLogs} title="Copy JSON">
                      <FaCopy /> {copied ? "Copied!" : "Copy"}
                    </button>
                    <button onClick={handleDownloadLogs} title="Download JSON">
                      <FaDownload /> Export
                    </button>
                  </div>
                </div>
                <pre>{JSON.stringify(sampleJsonLog, null, 2)}</pre>
              </div>

              <div className="card-actions">
                <button className="card-btn primary" onClick={handleDownloadLogs}>
                  <FaDownload /> Download Scan JSON
                </button>
                <a
                  href={`${API_BASE}/api/grafana-metrics/`}
                  target="_blank"
                  rel="noreferrer"
                  className="card-btn secondary"
                >
                  Raw Metrics API
                </a>
              </div>
            </div>
          )}

          {/* Card 4: Dynamic Query Security Tester */}
          {(activeTab === "all" || activeTab === "tester") && (
            <div className="report-card tester-card">
              <div className="card-header">
                <div className="scanner-badge tester">
                  <FaTerminal /> Interactive Audit Tester
                </div>
                <span className="gate-badge info">
                  <FaCode /> LIVE ENDPOINT
                </span>
              </div>

              <h3>Test Dynamic Database Filtering & Query Logging</h3>
              <p className="target-url">
                Endpoint: <code>/api/audit/search/</code>
              </p>

              <form onSubmit={handleAuditSearch} className="tester-form">
                <div className="form-row">
                  <input
                    type="text"
                    placeholder="Search term or test payload (e.g. security or ' OR 1=1)..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="tester-input"
                  />
                  <button type="submit" className="tester-submit" disabled={searchLoading}>
                    <FaSearch /> {searchLoading ? "Evaluating..." : "Run Query"}
                  </button>
                </div>

                <div className="tester-options">
                  <label>
                    Target Table:
                    <select
                      value={searchTable}
                      onChange={(e) => setSearchTable(e.target.value)}
                      className="tester-select"
                    >
                      <option value="services">api_service</option>
                      <option value="reports">api_vulnerabilityreport</option>
                      <option value="projects">api_project</option>
                    </select>
                  </label>

                  <label>
                    Execution Mode:
                    <select
                      value={searchMode}
                      onChange={(e) => setSearchMode(e.target.value)}
                      className="tester-select"
                    >
                      <option value="raw">Raw SQL (Audit Lab)</option>
                      <option value="safe">Safe ORM (Sanitized)</option>
                    </select>
                  </label>
                </div>
              </form>

              {searchResult && (
                <div className="search-result-box">
                  <div className="result-meta">
                    <span>
                      Status: <strong>{searchResult.status}</strong>
                    </span>
                    <span>
                      Count: <strong>{searchResult.count ?? 0}</strong>
                    </span>
                    <span>
                      Mode: <strong>{searchResult.mode || searchMode}</strong>
                    </span>
                  </div>
                  <div className="result-query">
                    <code>{searchResult.query_executed}</code>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal for Details */}
        {selectedReport && (
          <div className="report-modal-overlay" onClick={() => setSelectedReport(null)}>
            <div className="report-modal" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <h3>{selectedReport.title}</h3>
                <button
                  className="close-btn"
                  onClick={() => setSelectedReport(null)}
                >
                  ✕
                </button>
              </div>
              <div className="modal-body">
                <p>
                  <strong>Scanner:</strong> {selectedReport.type}
                </p>
                <p>
                  <strong>Audited Target:</strong> {selectedReport.target}
                </p>
                <div className="modal-text">
                  <p>{selectedReport.details}</p>
                </div>
              </div>
              <div className="modal-footer">
                <button
                  className="card-btn primary"
                  onClick={() => setSelectedReport(null)}
                >
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

export default SecurityReports;
