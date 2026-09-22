import { useState, useEffect } from "react";
import "./Hero.css";
import {
  FaShieldAlt,
  FaTerminal,
  FaArrowRight,
  FaLock,
  FaCheckCircle,
  FaBug,
  FaChartLine,
} from "react-icons/fa";

function Hero() {
  const [activeStep, setActiveStep] = useState(0);

  const logs = [
    { type: "init", text: "[DEVSECOPS] Initializing automated security baseline..." },
    { type: "zap", text: "[ZAP SCAN] Inspecting target: http://13.63.222.33/ [RUNNING]" },
    { type: "sqlmap", text: "[SQLMAP] Auditing dynamic endpoint: /api/analyze-report/?id=1" },
    { type: "gate", text: "[SECURITY GATE] Analyzing alerts: 0 Critical / 0 High detected" },
    { type: "grafana", text: "[GRAFANA LOKI] Exporting structured JSON logs -> OK" },
    { type: "ready", text: "[STATUS] System Defense Online. Deployment PASSED." },
  ];

  useEffect(() => {
    const timer = setInterval(() => {
      setActiveStep((prev) => (prev + 1) % logs.length);
    }, 2400);
    return () => clearInterval(timer);
  }, [logs.length]);

  return (
    <section className="cyber-hero" id="home">
      {/* Background Cyber Grid */}
      <div className="cyber-grid-bg"></div>
      <div className="ambient-glow cyan"></div>
      <div className="ambient-glow purple"></div>

      <div className="hero-content">
        <div className="hero-left">
          <div className="hero-badge">
            <span className="badge-radar"></span>
            <span>ENTERPRISE DEVSECOPS & CYBER AUDITING</span>
          </div>

          <h1 className="hero-title">
            Autonomous Cyber Defense & <span>Security Intelligence</span>
          </h1>

          <p className="hero-description">
            Nexus Technologies delivers automated DAST & SAST vulnerability auditing,
            continuous OWASP ZAP baseline verification, SQLMap database injection testing,
            and real-time Grafana JSON observability for resilient digital infrastructure.
          </p>

          <div className="hero-actions">
            <a href="#reports" className="hero-btn-primary">
              <span>View Pipeline Scans</span>
              <FaArrowRight />
            </a>
            <a href="#services" className="hero-btn-secondary">
              <FaShieldAlt />
              <span>Cyber Services</span>
            </a>
          </div>

          {/* Quick HUD Metrics */}
          <div className="hero-hud-stats">
            <div className="hud-stat">
              <span className="hud-val">100%</span>
              <span className="hud-lbl">Automated Security Gates</span>
            </div>
            <div className="hud-stat">
              <span className="hud-val">0</span>
              <span className="hud-lbl">Critical Escapes Allowed</span>
            </div>
            <div className="hud-stat">
              <span className="hud-val">JSON</span>
              <span className="hud-lbl">Grafana Telemetry Stream</span>
            </div>
          </div>
        </div>

        {/* Right Interactive Cyber Terminal HUD */}
        <div className="hero-right">
          <div className="terminal-window">
            <div className="terminal-header">
              <div className="window-dots">
                <span className="dot red"></span>
                <span className="dot yellow"></span>
                <span className="dot green"></span>
              </div>
              <div className="terminal-title">
                <FaTerminal /> SOC_MONITOR :: /dev/secops/pipeline.sh
              </div>
              <span className="live-tag">LIVE</span>
            </div>

            <div className="terminal-screen">
              <div className="target-banner">
                <span className="target-label">ACTIVE TARGET</span>
                <span className="target-host">http://13.63.222.33 (Staging Production)</span>
              </div>

              <div className="terminal-log-flow">
                {logs.map((log, index) => (
                  <div
                    key={index}
                    className={`log-entry ${index <= activeStep ? "visible" : "pending"} ${
                      index === activeStep ? "current" : ""
                    }`}
                  >
                    <span className="log-index">[{String(index + 1).padStart(2, "0")}]</span>
                    <span className={`log-text ${log.type}`}>{log.text}</span>
                  </div>
                ))}
              </div>

              <div className="terminal-hud-footer">
                <div className="hud-meter">
                  <div className="meter-label">
                    <span>SECURITY GATE STATUS</span>
                    <strong className="gate-clean">PASSED</strong>
                  </div>
                  <div className="meter-bar">
                    <div className="meter-fill" style={{ width: "96%" }}></div>
                  </div>
                </div>

                <div className="hud-badges">
                  <span className="badge-chip">
                    <FaCheckCircle className="text-emerald" /> OWASP ZAP OK
                  </span>
                  <span className="badge-chip">
                    <FaBug className="text-amber" /> SQLMap Audited
                  </span>
                  <span className="badge-chip">
                    <FaChartLine className="text-cyan" /> Grafana Ingested
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default Hero;