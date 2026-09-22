import { useState } from "react";
import "./Contact.css";
import { sendContactMessage } from "../../api/contactApi";
import {
  FaPhoneAlt,
  FaEnvelope,
  FaMapMarkerAlt,
  FaLinkedinIn,
  FaGithub,
  FaLock,
  FaShieldAlt,
  FaKey,
  FaPaperPlane,
} from "react-icons/fa";

function Contact() {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    subject: "",
    message: "",
  });
  const [statusMsg, setStatusMsg] = useState("");
  const [isSuccess, setIsSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleEmailClick = () => {
    const email = "hamzadevelopers35@gmail.com";
    const subject = encodeURIComponent("Security Audit Inquiry - Nexus Technologies");
    const body = encodeURIComponent(
      "Hi Security Team,\n\nWe would like to request an automated security baseline & pipeline audit for our infrastructure.\n\n"
    );
    const gmailUrl = `https://mail.google.com/mail/?view=cm&fs=1&to=${email}&su=${subject}&body=${body}`;
    window.open(gmailUrl, "_blank");
  };

  const handlePhoneClick = () => {
    window.location.href = "tel:+923191073635";
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setStatusMsg("Transmitting encrypted request...");
    setIsSuccess(false);

    const backendData = {
      name: formData.name,
      email: formData.email,
      message: `[SECURITY AUDIT REQUEST]\nSubject: ${formData.subject}\n\nDetails:\n${formData.message}`,
    };

    try {
      const result = await sendContactMessage(backendData);
      if (
        result &&
        (result.status === "success" || result.message === "Message saved successfully!")
      ) {
        setIsSuccess(true);
        setStatusMsg("Inquiry Received! Our SOC team will respond within 2 hours. 🛡️");
        setFormData({ name: "", email: "", subject: "", message: "" });
      } else {
        setIsSuccess(false);
        setStatusMsg(result?.message || "Transmission failed. Please check network.");
      }
    } catch {
      setIsSuccess(false);
      setStatusMsg("Connection error. Ensure backend service is reachable.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section className="cyber-contact" id="contact">
      <div className="contact-wrapper">
        <div className="contact-header">
          <div className="badge-pill">
            <span className="pulsing-radar"></span>
            INCIDENT RESPONSE & AUDIT REQUESTS
          </div>
          <h2>
            Initiate Security <span>Audit Engagement</span>
          </h2>
          <p>
            Connect directly with our DevSecOps engineers for automated pipeline integration,
            DAST/SAST audits, or urgent vulnerability assessment.
          </p>
        </div>

        <div className="contact-grid">
          {/* Left Info Column */}
          <div className="contact-info-panel">
            <div className="security-notice-card">
              <div className="notice-icon">
                <FaLock />
              </div>
              <div className="notice-text">
                <h4>Encrypted Communications</h4>
                <p>
                  All audit data and inquiries are handled under strict confidentiality protocols.
                </p>
              </div>
            </div>

            <div className="info-cards-stack">
              {/* Phone */}
              <div className="contact-info-card" onClick={handlePhoneClick}>
                <div className="info-icon phone">
                  <FaPhoneAlt />
                </div>
                <div className="info-body">
                  <span className="info-label">SOC Hotline (24/7)</span>
                  <strong className="info-val">+92 3191073635</strong>
                </div>
              </div>

              {/* Email */}
              <div className="contact-info-card" onClick={handleEmailClick}>
                <div className="info-icon email">
                  <FaEnvelope />
                </div>
                <div className="info-body">
                  <span className="info-label">Security Operations Email</span>
                  <strong className="info-val">hamzadevelopers35@gmail.com</strong>
                </div>
              </div>

              {/* Location */}
              <div className="contact-info-card">
                <div className="info-icon location">
                  <FaMapMarkerAlt />
                </div>
                <div className="info-body">
                  <span className="info-label">SOC Command Headquarters</span>
                  <strong className="info-val">Lahore, Pakistan</strong>
                </div>
              </div>

              {/* PGP Fingerprint */}
              <div className="contact-info-card pgp-card">
                <div className="info-icon key">
                  <FaKey />
                </div>
                <div className="info-body">
                  <span className="info-label">PGP Fingerprint</span>
                  <code className="pgp-code">4A8F-912C-DEVSECOPS-NEXUS-2026</code>
                </div>
              </div>
            </div>

            {/* Socials */}
            <div className="contact-socials">
              <span>Verified Channels:</span>
              <div className="social-links">
                <a
                  href="https://github.com/MHamza417"
                  target="_blank"
                  rel="noreferrer"
                  className="social-btn"
                  aria-label="GitHub"
                >
                  <FaGithub />
                </a>
                <a
                  href="https://www.linkedin.com"
                  target="_blank"
                  rel="noreferrer"
                  className="social-btn"
                  aria-label="LinkedIn"
                >
                  <FaLinkedinIn />
                </a>
              </div>
            </div>
          </div>

          {/* Right Form Column */}
          <div className="contact-form-panel">
            <div className="form-header-bar">
              <span className="form-title">
                <FaShieldAlt className="text-cyan" /> Secure Dispatch Form
              </span>
              <span className="form-enc-tag">AES-256 TLS 1.3</span>
            </div>

            <form onSubmit={handleSubmit} className="cyber-form">
              <div className="form-group">
                <label>Target Organization / Contact Name</label>
                <input
                  type="text"
                  name="name"
                  placeholder="e.g. Alex Miller"
                  value={formData.name}
                  onChange={handleChange}
                  required
                />
              </div>

              <div className="form-group">
                <label>Verified Work Email</label>
                <input
                  type="email"
                  name="email"
                  placeholder="e.g. alex@enterprise.com"
                  value={formData.email}
                  onChange={handleChange}
                  required
                />
              </div>

              <div className="form-group">
                <label>Audit Scope / Subject</label>
                <input
                  type="text"
                  name="subject"
                  placeholder="e.g. Jenkins ZAP & SQLMap Pipeline Audit"
                  value={formData.subject}
                  onChange={handleChange}
                  required
                />
              </div>

              <div className="form-group">
                <label>Scope Specifications & Environment Details</label>
                <textarea
                  name="message"
                  rows="5"
                  placeholder="Describe your architecture, endpoints, or penetration testing timelines..."
                  value={formData.message}
                  onChange={handleChange}
                  required
                ></textarea>
              </div>

              <button
                type="submit"
                className="submit-cyber-btn"
                disabled={submitting}
              >
                <FaPaperPlane />
                <span>{submitting ? "Transmitting..." : "Submit Audit Request"}</span>
              </button>

              {statusMsg && (
                <div
                  className={`form-status-alert ${
                    isSuccess ? "alert-success" : "alert-error"
                  }`}
                >
                  {statusMsg}
                </div>
              )}
            </form>
          </div>
        </div>
      </div>
    </section>
  );
}

export default Contact;