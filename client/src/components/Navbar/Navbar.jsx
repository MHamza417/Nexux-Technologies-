import { useState, useEffect } from "react";
import "./Navbar.css";
import { FaShieldAlt, FaTerminal, FaBars, FaTimes } from "react-icons/fa";

function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 40);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <header className={`cyber-navbar ${scrolled ? "scrolled" : ""}`}>
      <div className="nav-brand">
        <div className="brand-logo">
          <FaShieldAlt className="shield-icon" />
          <div className="brand-text">
            <span>NEXUS</span>
            <small>TECHNOLOGIES</small>
          </div>
        </div>
        <div className="status-pill">
          <span className="live-radar"></span>
          <span className="status-label">SOC MONITORED</span>
        </div>
      </div>

      <nav className={`nav-menu ${mobileMenuOpen ? "open" : ""}`}>
        <ul className="cyber-links">
          <li>
            <a href="#home" onClick={() => setMobileMenuOpen(false)}>
              Home
            </a>
          </li>
          <li>
            <a href="#about" onClick={() => setMobileMenuOpen(false)}>
              About
            </a>
          </li>
          <li>
            <a href="#services" onClick={() => setMobileMenuOpen(false)}>
              Services
            </a>
          </li>
          <li>
            <a href="#reports" onClick={() => setMobileMenuOpen(false)} className="nav-highlight">
              <span className="nav-dot"></span> Pipeline Scans
            </a>
          </li>
          <li>
            <a href="#projects" onClick={() => setMobileMenuOpen(false)}>
              Projects
            </a>
          </li>
          <li>
            <a href="#contact" onClick={() => setMobileMenuOpen(false)}>
              Contact
            </a>
          </li>
        </ul>
      </nav>

      <div className="nav-right">
        <a href="#reports" className="cyber-btn-nav">
          <FaTerminal className="btn-icon" />
          <span>Audit Console</span>
        </a>
        <button
          className="mobile-toggle"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          aria-label="Toggle Navigation"
        >
          {mobileMenuOpen ? <FaTimes /> : <FaBars />}
        </button>
      </div>
    </header>
  );
}

export default Navbar;