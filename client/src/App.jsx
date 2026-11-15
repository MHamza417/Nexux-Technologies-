import { lazy, Suspense } from "react";
import "./App.css";

import Navbar from "./components/Navbar/Navbar";
import Hero from "./components/Hero/Hero";
import SecurityScanner from "./components/SecurityScanner/SecurityScanner";
import SecurityReports from "./components/SecurityReports/SecurityReports";
import About from "./components/About/About";
import Services from "./components/Services/Services";
import Projects from "./components/Projects/Projects";
import Team from "./components/Team/Team";
import Testimonials from "./components/Testimonials/Testimonials";
import Contact from "./components/Contact/Contact";
import Footer from "./components/Footer/Footer";
import Vulnerabilities from "./components/Vulnerabilities/Vulnerabilities";
const ReportDashboard = lazy(() => import("./components/ReportDashboard/ReportDashboard"));

function App() {
  if (/^\/reports\/?$/.test(window.location.pathname)) {
    return (
      <Suspense fallback={<main style={{ minHeight: "100vh", padding: "3rem", background: "#f3f6fb", color: "#17365e" }}>Loading security report…</main>}>
        <ReportDashboard />
      </Suspense>
    );
  }

  const vulnerabilityRoute = window.location.pathname.match(/^\/vulnerabilities\/([^/]+)\/?$/);
  if (vulnerabilityRoute) {
    let agent = vulnerabilityRoute[1];
    try {
      agent = decodeURIComponent(agent);
    } catch {
      agent = "default";
    }
    return <Vulnerabilities agent={agent} />;
  }

  return (
    <div className="cyber-app-container">
      <Navbar />
      <main>
        <Hero />
        <SecurityScanner />
        <SecurityReports />
        <About />
        <Services />
        <Projects />
        <Team />
        <Testimonials />
        <Contact />
      </main>
      <Footer />
    </div>
  );
}

export default App;