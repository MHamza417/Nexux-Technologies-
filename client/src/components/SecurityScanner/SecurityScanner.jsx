import { useEffect, useState } from "react";
import { FaArrowRight, FaBug, FaCheckCircle, FaClock, FaGithub, FaGlobe, FaLock, FaShieldAlt, FaSpinner, FaTimes } from "react-icons/fa";
import {
  downloadPublicReport,
  loadPublicScan,
  rememberPublicScan,
  submitPublicScan,
} from "../../api/intellisecops";
import "./SecurityScanner.css";

function targetError(targetType, value) {
  let url;
  try {
    url = new URL(value.trim());
  } catch {
    return "Enter a complete URL, including https://.";
  }
  if (url.username || url.password || url.hash) {
    return "URLs must not contain credentials or fragments.";
  }
  if (targetType === "repository") {
    return url.protocol !== "https:"
      || url.hostname.toLowerCase() !== "github.com"
      || !/^\/[A-Za-z0-9-]+\/[A-Za-z0-9_.-]+(?:\.git)?\/?$/.test(url.pathname)
      || url.search
      ? "Use a public GitHub URL: https://github.com/owner/repository."
      : "";
  }
  return ["http:", "https:"].includes(url.protocol)
    ? ""
    : "Website targets must use HTTP or HTTPS.";
}

function statusLabel(status) {
  return {
    pending: "Queued",
    running: "Scanning",
    completed: "Complete",
    blocked: "Blocked",
    failed: "Failed",
  }[status] || status || "Unknown";
}

function SecurityScanner() {
  const [targetType, setTargetType] = useState("website");
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [includeAi, setIncludeAi] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");
  const [scanError, setScanError] = useState("");
  const [downloading, setDownloading] = useState(false);
  const [scanAccess, setScanAccess] = useState(null);
  const [scan, setScan] = useState(null);

  useEffect(() => {
    if (!scanAccess || !["pending", "running"].includes(scan?.status)) return undefined;
    let active = true;
    const refresh = async () => {
      try {
        const latest = await loadPublicScan(scanAccess.scan_id, scanAccess.access_token);
        if (active) {
          setScan(latest);
          setScanError("");
        }
      } catch (error) {
        if (active) setScanError(error.message || "Could not refresh the scan status.");
      }
    };
    const timer = window.setInterval(refresh, 4000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [scanAccess, scan?.status]);

  async function handleSubmit(event) {
    event.preventDefault();
    setFormError("");
    setScanError("");
    const validationError = targetError(targetType, target);
    if (validationError) {
      setFormError(validationError);
      return;
    }
    if (!authorized) {
      setFormError("Confirm that you own or have explicit permission to test this target.");
      return;
    }

    setSubmitting(true);
    try {
      const result = await submitPublicScan({
        target_type: targetType,
        target: target.trim(),
        authorized: true,
        include_ai: includeAi,
      });
      openScan(result.scan, result.access_token);
      setTarget("");
      setAuthorized(false);
    } catch (error) {
      const blocked = error.data?.scan;
      if (blocked?.scan_id && error.data?.access_token) {
        openScan(blocked, error.data.access_token);
      } else {
        setFormError(error.message || "The scan request could not be submitted.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  function openScan(scanData, accessToken) {
    if (!scanData?.scan_id || !accessToken) {
      setFormError("The scan service returned an incomplete response. Please try again.");
      return;
    }
    const access = { scan_id: scanData.scan_id, access_token: accessToken };
    rememberPublicScan({
      ...access,
      target: scanData.target,
      target_type: scanData.target_type,
      created_at: scanData.created_at,
      status: scanData.status,
      overall_status: scanData.overall_status,
    });
    setScanAccess(access);
    setScan(scanData);
  }

  async function handleDownloadReport() {
    if (!scan || !scanAccess) return;
    setDownloading(true);
    setScanError("");
    try {
      const report = await downloadPublicReport(scan.scan_id, scanAccess.access_token);
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `intellisecops-${scan.scan_id}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      setScanError(error.message || "Could not download the scan report.");
    } finally {
      setDownloading(false);
    }
  }

  const scanner = scan?.target_type === "repository" ? "SonarQube" : "OWASP ZAP";
  const findings = scan?.findings || [];

  return (
    <section className="security-scanner-section" id="scanner" aria-labelledby="scanner-title">
      <div className="security-scanner-container">
        <div className="security-scanner-intro">
          <span className="scanner-eyebrow"><FaShieldAlt /> AQEVORA SECURITY LAB</span>
          <h2 id="scanner-title">Scan with confidence.<br /><span>Ship with clarity.</span></h2>
          <p>
            Run an authorized security scan against your website or public GitHub repository.
            Review pipeline status and findings in one place.
          </p>
          <ul className="scanner-capabilities">
            <li><FaCheckCircle /> OWASP ZAP website scanning</li>
            <li><FaCheckCircle /> SonarQube repository analysis</li>
            <li><FaLock /> Targets are checked before scanning</li>
          </ul>
        </div>

        <div className="scanner-console">
          <div className="scanner-console-heading">
            <span className="scanner-console-icon"><FaShieldAlt /></span>
            <div>
              <span>NEW SECURITY SCAN</span>
              <h3>Choose a target</h3>
            </div>
            <span className="scanner-secure"><FaLock /> AUTHORIZED USE</span>
          </div>

          <form className="scanner-submit-form" onSubmit={handleSubmit}>
            <div className="scanner-target-tabs" aria-label="Target type">
              <button
                type="button"
                aria-pressed={targetType === "website"}
                onClick={() => { setTargetType("website"); setFormError(""); }}
              >
                <FaGlobe /> Website
              </button>
              <button
                type="button"
                aria-pressed={targetType === "repository"}
                onClick={() => { setTargetType("repository"); setFormError(""); }}
              >
                <FaGithub /> GitHub repository
              </button>
            </div>

            <label htmlFor="security-target">
              {targetType === "website" ? "Website URL" : "Public GitHub repository"}
            </label>
            <input
              id="security-target"
              type="url"
              value={target}
              onChange={(event) => {
                setTarget(event.target.value);
                setFormError("");
              }}
              placeholder={targetType === "website" ? "https://yourwebsite.com" : "https://github.com/owner/repository"}
              maxLength={2048}
              required
              aria-invalid={Boolean(formError)}
              aria-describedby={formError ? "scan-form-error" : "scan-target-help"}
            />
            <p className="scanner-field-help" id="scan-target-help">
              {targetType === "website"
                ? "Use the full URL of a site you are authorized to test."
                : "Only public GitHub repositories can be scanned."}
            </p>

            <label className="scanner-check-row">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(event) => setAuthorized(event.target.checked)}
              />
              <span>I own this target or have explicit permission to test it.</span>
            </label>
            <label className="scanner-check-row optional">
              <input
                type="checkbox"
                checked={includeAi}
                onChange={(event) => setIncludeAi(event.target.checked)}
              />
              <span>Add optional Gemini analysis <small>(AI guidance is unverified)</small></span>
            </label>

            {formError ? <p className="scanner-form-error" id="scan-form-error" role="alert">{formError}</p> : null}
            <button className="scanner-submit-button" type="submit" disabled={submitting}>
              {submitting ? <><FaSpinner className="scanner-spin" /> Submitting scan</> : <>Start security scan <FaArrowRight /></>}
            </button>
          </form>

          {scan ? (
            <div className={`scanner-result ${scan.status}`} aria-live="polite">
              <div className="scanner-result-heading">
                <span className="scanner-result-icon">
                  {scan.status === "completed" ? <FaCheckCircle /> : ["failed", "blocked"].includes(scan.status) ? <FaTimes /> : <FaClock />}
                </span>
                <div>
                  <span>{scanner} PIPELINE</span>
                  <h4>{statusLabel(scan.status)}</h4>
                </div>
                <span className="scanner-status-tag">{statusLabel(scan.status)}</span>
              </div>
              <p className="scanner-result-target" title={scan.target}>{scan.target}</p>
              {["pending", "running"].includes(scan.status) ? (
                <div className="scanner-progress" role="progressbar" aria-label="Scan progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={scan.status === "running" ? 65 : 25}>
                  <span style={{ width: scan.status === "running" ? "65%" : "25%" }} />
                </div>
              ) : null}
              {scanError ? <p className="scanner-form-error" role="alert">{scanError}</p> : null}
              {scan.failure_reason ? <p className="scanner-result-note">{scan.failure_reason}</p> : null}
              {scan.status === "completed" ? (
                <>
                  <p className="scanner-result-note">{findings.length} finding{findings.length === 1 ? "" : "s"} reported.</p>
                  {findings.length ? (
                    <ul className="scanner-findings">
                      {findings.slice(0, 5).map((finding, index) => (
                        <li key={`${finding.title}-${index}`}>
                          <span className={`scanner-severity ${String(finding.severity || "informational").toLowerCase()}`}>{finding.severity || "Informational"}</span>
                          <span>{finding.title}</span>
                        </li>
                      ))}
                    </ul>
                  ) : null}
                  {scan.ai_analysis ? (
                    <div className="scanner-ai-note">
                      <strong>Gemini analysis · unverified</strong>
                      <p>{scan.ai_analysis.replace(/^AI-generated suggestion \(unverified\):\s*/i, "")}</p>
                    </div>
                  ) : null}
                  <button
                    className="scanner-report-link"
                    type="button"
                    onClick={handleDownloadReport}
                    disabled={downloading}
                  >
                    {downloading ? <FaSpinner className="scanner-spin" /> : <FaArrowRight />}
                    {downloading ? "Preparing report" : "Download scan report"}
                  </button>
                  <a
                    className="scanner-report-link"
                    href="/vulnerabilities/default"
                  >
                    <FaBug /> View Vulnerabilities
                  </a>
                </>
              ) : null}
            </div>
          ) : null}
          <p className="scanner-legal-note">Private networks and unsupported targets are rejected. Scan only systems you own or have explicit permission to test.</p>
        </div>
      </div>
    </section>
  );
}

export default SecurityScanner;
