import React, { useEffect, useState } from "react";
import { getServices } from "../../api/serviceApi";
import "./Services.css";
import {
  FaShieldAlt,
  FaDatabase,
  FaCode,
  FaBrain,
  FaChartLine,
  FaLock,
  FaArrowRight,
} from "react-icons/fa";

const DEFAULT_CYBER_SERVICES = [
  {
    id: "s-1",
    title: "Automated DAST & OWASP ZAP Scanning",
    description:
      "Continuous dynamic security verification integrated into Jenkins pipelines to identify misconfigurations and web vulnerabilities before production deployment.",
    icon: "shield",
    tag: "AUTOMATED DAST",
    metric: "0s Escapes",
  },
  {
    id: "s-2",
    title: "Dynamic SQL Injection & DB Auditing",
    description:
      "Automated SQLMap parameter evaluation detecting blind and union-based injection vectors, paired with ORM mitigation enforcement.",
    icon: "database",
    tag: "DATABASE SECURITY",
    metric: "CWE-89 Shield",
  },
  {
    id: "s-3",
    title: "Smart DevSecOps Security Gates",
    description:
      "Autonomous policy gates that halt deployments when critical CVEs are detected, notifying engineering teams instantly via Slack and automated alerts.",
    icon: "code",
    tag: "CI/CD SECURITY",
    metric: "Zero-Trust Gate",
  },
  {
    id: "s-4",
    title: "AI-Powered Threat Analysis",
    description:
      "Google Gemini 2.0 Flash automated security assessment transforming raw scanner logs into prioritized remediation steps and executive summaries.",
    icon: "brain",
    tag: "GENAI DEFENSE",
    metric: "Gemini 2.0 Flash",
  },
  {
    id: "s-5",
    title: "Grafana & SIEM Observability",
    description:
      "Structured JSON log shipping to Grafana Loki and dashboard visualization tracking vulnerability frequencies and scan distributions in real time.",
    icon: "chart",
    tag: "TELEMETRY & LOGS",
    metric: "JSON Streaming",
  },
  {
    id: "s-6",
    title: "Cloud & Container Hardening",
    description:
      "Container vulnerability scanning, Docker base image hardening, strict CORS isolation, and cryptographic secrets management.",
    icon: "lock",
    tag: "CLOUD SECURITY",
    metric: "ISO 27001 Ready",
  },
];

function Services() {
  const [services, setServices] = useState(DEFAULT_CYBER_SERVICES);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchServicesData = async () => {
      try {
        const data = await getServices();
        if (Array.isArray(data) && data.length > 0) {
          // Merge API services with cybersecurity metadata
          const merged = data.map((item, idx) => ({
            id: item.id || `api-${idx}`,
            title: item.title,
            description: item.description,
            icon: item.icon || "shield",
            tag: "CYBER DEFENSE",
            metric: "Enterprise Tier",
          }));
          setServices(merged);
        }
      } catch (err) {
        console.error("Using default cybersecurity services:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchServicesData();
  }, []);

  const renderIcon = (iconName) => {
    switch (iconName) {
      case "database":
        return <FaDatabase />;
      case "code":
        return <FaCode />;
      case "brain":
        return <FaBrain />;
      case "chart":
        return <FaChartLine />;
      case "lock":
        return <FaLock />;
      case "shield":
      default:
        return <FaShieldAlt />;
    }
  };

  return (
    <section className="cyber-services" id="services">
      <div className="services-container">
        <div className="services-header">
          <div className="badge-pill">
            <span className="pulsing-radar"></span>
            DEFENSIVE ARCHITECTURE & AUDITING
          </div>
          <h2>
            Modern Cybersecurity <span>Solutions</span>
          </h2>
          <p>
            End-to-end vulnerability scanning, automated CI/CD testing gates, and
            structured telemetry to safeguard your web applications and database tiers.
          </p>
        </div>

        <div className="services-grid">
          {services.map((service) => (
            <div className="cyber-service-card" key={service.id}>
              <div className="card-top">
                <div className="service-icon-box">{renderIcon(service.icon)}</div>
                <span className="service-metric-tag">{service.metric}</span>
              </div>

              <div className="service-tag">{service.tag}</div>
              <h3>{service.title}</h3>
              <p>{service.description}</p>

              <div className="card-footer">
                <a href="#contact" className="service-learn-more">
                  <span>Explore Architecture</span>
                  <FaArrowRight className="arrow-icon" />
                </a>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

export default Services;