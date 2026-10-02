import "./About.css";
import aboutImg from "../../assets/images/about.png";
import { FaLaptopCode, FaCloud, FaShieldAlt, FaUsers } from "react-icons/fa";

function About() {
  return (
    <section className="about" id="about">

      <div className="about-image">
        <img src={aboutImg} alt="About Aqevora Technologies" />
      </div>

      <div className="about-content">

        <span className="section-tag">ABOUT US</span>

        <h2>
          Building Digital Solutions for
          <span> Modern Businesses</span>
        </h2>

        <p>
          Aqevora Technologies is a professional software company providing
          Web Development, Mobile Applications, Cloud Computing,
          DevOps, Networking and Cyber Security solutions.
          Our goal is to help businesses grow using modern technology.
        </p>

        <div className="feature-grid">

          <div className="feature-card">
            <FaLaptopCode className="icon" />
            <h3>Web Solutions</h3>
            <p>Modern & Responsive Websites</p>
          </div>

          <div className="feature-card">
            <FaCloud className="icon" />
            <h3>Cloud</h3>
            <p>AWS • Azure • DevOps</p>
          </div>

          <div className="feature-card">
            <FaShieldAlt className="icon" />
            <h3>Security</h3>
            <p>Cyber Security Solutions</p>
          </div>

          <div className="feature-card">
            <FaUsers className="icon" />
            <h3>Support</h3>
            <p>24/7 Technical Support</p>
          </div>

        </div>

      </div>

    </section>
  );
}

export default About;