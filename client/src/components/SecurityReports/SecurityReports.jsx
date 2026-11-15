import "./SecurityReports.css";
import {
  FaBrain,
  FaChartLine,
  FaCode,
  FaDatabase,
  FaExclamationTriangle,
  FaShieldAlt,
} from "react-icons/fa";

const capabilities = [
  {
    name: "OWASP ZAP Baseline",
    category: "Website scans",
    icon: <FaShieldAlt />,
    className: "zap",
    status: "Implemented",
    summary: "A limited crawl with passive security rules against an authorized website.",
    facts: [
      "Does not run ZAP active attack rules or a full penetration test.",
      "Findings cover only pages and responses reached by the baseline crawl.",
      "A completed scan with no findings is not proof that a site is secure.",
    ],
  },
  {
    name: "SonarQube",
    category: "Repository analysis",
    icon: <FaCode />,
    className: "tester",
    status: "Implemented",
    summary: "Static analysis of public GitHub repositories submitted through the scan form.",
    facts: [
      "The repository is shallow-cloned on the isolated Jenkins worker.",
      "Submitted source is not built or executed by this pipeline.",
      "This is not a dependency, secret, or complete application security audit.",
    ],
  },
  {
    name: "SQLMap",
    category: "SQL injection testing",
    icon: <FaDatabase />,
    className: "sqlmap",
    status: "Not in scan pipeline",
    summary: "SQLMap is not launched by this website and is not part of automated scan jobs.",
    facts: [
      "The repository contains a parser for previously captured SQLMap text output.",
      "A separate authenticated legacy endpoint can ingest an existing report.",
      "No target is automatically tested for SQL injection by the current pipeline.",
    ],
  },
  {
    name: "Gemini AI",
    category: "Optional finding explanations",
    icon: <FaBrain />,
    className: "grafana",
    status: "Optional",
    summary: "When enabled for a scan and configured by the operator, Gemini can explain returned findings.",
    facts: [
      "Requires a server-side GEMINI_API_KEY and network access.",
      "AI text is labeled unverified and is not a scanner result.",
      "AI suggestions should be reviewed before applying any changes.",
    ],
  },
];

function SecurityReports() {
  return (
    <section className="security-reports-section" id="reports" aria-labelledby="reports-title">
      <div className="reports-container">
        <div className="reports-header">
          <div className="badge-pill">
            <FaChartLine />
            SCANNING SCOPE & INTEGRATIONS
          </div>
          <h2 id="reports-title">
            Know what was <span>actually tested</span>
          </h2>
          <p>
            This page describes the integrations in the current codebase. It does not show
            live scan telemetry or sample findings; real results appear on the scan result
            page after a configured pipeline completes.
          </p>
        </div>

        <div className="reports-disclaimer" role="note">
          <FaExclamationTriangle />
          <p>
            Only scan systems you own or have explicit permission to test. The authorization
            checkbox is an attestation; it is not independent proof of ownership. Website
            scan jobs require an approved isolated worker.
          </p>
        </div>

        <div className="reports-grid">
          {capabilities.map((capability) => (
            <article className="report-card" key={capability.name}>
              <div className="card-header">
                <div className={`scanner-badge ${capability.className}`}>
                  {capability.icon}
                  {capability.name}
                </div>
                <span className="gate-badge info">{capability.status}</span>
              </div>
              <p className="capability-category">{capability.category}</p>
              <h3>{capability.summary}</h3>
              <ul className="report-fact-list">
                {capability.facts.map((fact) => <li key={fact}>{fact}</li>)}
              </ul>
            </article>
          ))}
        </div>

        <p className="reports-footer-note">
          Grafana dashboards are not included in this deployment. The backend exposes
          authenticated metrics and log APIs; Wazuh data requires an operator-configured
          Wazuh service. These integrations are not shown here as live or verified.
        </p>
      </div>
    </section>
  );
}

export default SecurityReports;
