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

function App() {
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