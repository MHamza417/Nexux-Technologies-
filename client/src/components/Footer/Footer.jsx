import "./Footer.css";

import {
  FaFacebookF,
  FaLinkedinIn,
  FaGithub,
  FaInstagram,
  FaArrowUp,
} from "react-icons/fa";

function Footer() {

  const scrollTop = () => {
    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  return (
    <footer className="footer">

      <div className="footer-container">

        {/* Company */}

        <div className="footer-box">

          <h2>Aqevora Technologies</h2>

          <p>
            We provide Web Development, Mobile Apps,
            DevOps, Cloud Computing, Networking and
            Cyber Security Solutions worldwide.
          </p>

        </div>

        {/* Quick Links */}

        <div className="footer-box">

          <h3>Quick Links</h3>

          <a href="#home">Home</a>

          <a href="#about">About</a>

          <a href="#services">Services</a>

          <a href="#projects">Projects</a>

          <a href="#contact">Contact</a>

        </div>

        {/* Services */}

        <div className="footer-box">

          <h3>Services</h3>

          <a href="#">Web Development</a>

          <a href="#">Cloud & DevOps</a>

          <a href="#">Mobile Apps</a>

          <a href="#">Networking</a>

          <a href="#">Cyber Security</a>

        </div>

        {/* Contact */}

        <div className="footer-box">

          <h3>Contact</h3>

          <p>📍 Lahore, Pakistan</p>

          <p>📞 +92 300 1234567</p>

          <p>📧 info@aqevoratechnologies.com</p>

          <div className="footer-social">

            <FaFacebookF />

            <FaLinkedinIn />

            <FaGithub />

            <FaInstagram />

          </div>

        </div>

      </div>

      <div className="footer-bottom">

        <p>
          © 2026 Aqevora Technologies | All Rights Reserved.
        </p>

        <button onClick={scrollTop}>
          <FaArrowUp />
        </button>

      </div>

    </footer>
  );
}

export default Footer;