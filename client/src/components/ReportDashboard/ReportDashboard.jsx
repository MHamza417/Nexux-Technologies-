import { useEffect, useMemo, useRef, useState } from "react";
import {
  FaArrowLeft,
  FaDownload,
  FaExclamationTriangle,
  FaFilePdf,
  FaMicrophone,
  FaPause,
  FaPlay,
  FaRobot,
  FaSearch,
  FaShieldAlt,
  FaStop,
  FaVolumeUp,
} from "react-icons/fa";
import {
  askScanAssistant,
  downloadPublicReport,
  hasSession,
  loadHistory,
  loadReport,
  readPublicScans,
  tokenForScan,
} from "../../api/intellisecops";
import "./ReportDashboard.css";

const SEVERITIES = [
  { name: "Critical", color: "#b42318" },
  { name: "High", color: "#d94841" },
  { name: "Medium", color: "#d97706" },
  { name: "Low", color: "#2563eb" },
  { name: "Informational", color: "#64748b" },
];
const CHART_RADIUS = 42;
const CHART_CIRCUMFERENCE = 2 * Math.PI * CHART_RADIUS;
const EMPTY_FINDINGS = [];

function splitSpeechText(text, maxLength = 180) {
  if (!text) return [];
  const words = String(text)
    .replace(/```[\s\S]*?```/g, " code example omitted ")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/<[^>]*>/g, " ")
    .replace(/[*_#~>|]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .split(" ");
  const chunks = [];
  let chunk = "";

  words.forEach((word) => {
    if (!word) return;
    if (word.length > maxLength) {
      if (chunk) chunks.push(chunk);
      chunk = "";
      for (let index = 0; index < word.length; index += maxLength) {
        chunks.push(word.slice(index, index + maxLength));
      }
      return;
    }
    if (chunk && chunk.length + word.length + 1 > maxLength) {
      chunks.push(chunk);
      chunk = word;
    } else {
      chunk = chunk ? `${chunk} ${word}` : word;
    }
  });
  if (chunk) chunks.push(chunk);
  return chunks;
}

function speechErrorMessage(error) {
  switch (error) {
    case "not-allowed":
      return "Browser blocked audio output. Please allow audio/autoplay for this site and click Play again.";
    case "voice-unavailable":
    case "language-unavailable":
      return "No suitable speech voice is installed. Add a voice in your system or browser settings and reload.";
    case "audio-hardware":
    case "audio-busy":
      return "Voice playback could not access audio output. Check your speakers or headphones.";
    case "network":
      return "Network error during voice playback. Check your connection.";
    case "canceled":
    case "interrupted":
      return "";
    default:
      return "Voice playback could not be started. Check browser audio settings and try again.";
  }
}

function pickBestVoice(voices) {
  if (!voices || !voices.length) return null;
  const browserLang = (typeof navigator !== "undefined" && navigator.language ? navigator.language : "en-US").toLowerCase();
  const langPrefix = browserLang.split("-")[0];

  return (
    voices.find((v) => v.lang && v.lang.toLowerCase() === browserLang) ||
    voices.find((v) => v.lang && v.lang.toLowerCase().startsWith(browserLang)) ||
    voices.find((v) => v.lang && v.lang.toLowerCase().startsWith(langPrefix)) ||
    voices.find((v) => v.lang && v.lang.toLowerCase().startsWith("en")) ||
    voices.find((v) => v.default) ||
    voices[0] ||
    null
  );
}

function normalizedSeverity(value) {
  const normalized = String(value || "").toLowerCase();
  return SEVERITIES.find((item) => item.name.toLowerCase() === normalized)?.name
    || "Informational";
}

function dateLabel(value) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Not recorded" : date.toLocaleString();
}

function scopeLabel(report) {
  if (report.scan_type === "ZAP") {
    return "OWASP ZAP Baseline · limited crawl and passive rules only";
  }
  if (report.scan_type === "SonarQube") {
    return "SonarQube · static analysis of the submitted public repository";
  }
  return `${report.scan_type || "Scanner"} · scope not specified`;
}

function saveJson(report, messages) {
  const exportReport = {
    ...report,
    ai_assistant_responses: messages
      .filter((message) => message.role === "assistant")
      .map((message) => ({ answer: message.text, ai_generated: message.aiGenerated })),
  };
  const blob = new Blob([JSON.stringify(exportReport, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `intellisecops-${report.scan_id}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function savePdf(report, counts, findings) {
  const { jsPDF } = await import("jspdf");
  const pdf = new jsPDF({ unit: "pt", format: "a4" });
  const pageWidth = pdf.internal.pageSize.getWidth();
  const pageHeight = pdf.internal.pageSize.getHeight();
  const margin = 44;
  const contentWidth = pageWidth - margin * 2;
  let y = 44;

  pdf.setFillColor(12, 35, 67);
  pdf.rect(0, 0, pageWidth, 112, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(19);
  pdf.text("IntelliSecOps", margin, y + 8);
  pdf.setFontSize(12);
  pdf.text("Security assessment report", margin, y + 31);
  pdf.setFont("helvetica", "normal");
  pdf.setFontSize(9);
  pdf.text("AI recommendations are advisory and separate from scanner findings.", margin, y + 52);
  y = 136;

  function writeText(text, { size = 10, color = [35, 48, 65], bold = false, gap = 6 } = {}) {
    pdf.setFont("helvetica", bold ? "bold" : "normal");
    pdf.setFontSize(size);
    pdf.setTextColor(...color);
    const lines = pdf.splitTextToSize(String(text || "Not recorded"), contentWidth);
    const lineHeight = size * 1.45;
    for (const line of lines) {
      if (y + lineHeight > pageHeight - margin) {
        pdf.addPage();
        y = margin;
      }
      pdf.text(line, margin, y);
      y += lineHeight;
    }
    y += gap;
  }

  writeText("Scan overview", { size: 13, bold: true, color: [12, 35, 67] });
  writeText(`Target: ${report.target}`);
  writeText(`Target type: ${report.target_type || "Not recorded"} · Scanner: ${report.scan_type || "Not recorded"}`);
  writeText(`Scan ID: ${report.scan_id}`);
  writeText(`Created: ${dateLabel(report.created_at)} · Completed: ${dateLabel(report.completed_at)}`);
  writeText(`Coverage: ${scopeLabel(report)}`);
  writeText(`Total stored findings: ${findings.length}`, { bold: true });
  writeText(SEVERITIES.map(({ name }) => `${name}: ${counts[name]}`).join("   "));

  const aiText = String(report.ai_analysis || "").replace(
    /^AI-generated suggestion \(unverified\):\s*/i,
    "",
  );
  if (aiText && !aiText.toLowerCase().startsWith("ai analysis unavailable")) {
    writeText("AI-generated analysis · unverified", {
      size: 13,
      bold: true,
      color: [29, 78, 137],
      gap: 8,
    });
    writeText(aiText, { size: 9 });
  }

  writeText("Scanner findings", { size: 13, bold: true, color: [12, 35, 67], gap: 8 });
  if (!findings.length) {
    writeText("No findings were stored for this scan. This does not prove that the target is secure.");
  }
  findings.forEach((finding, index) => {
    writeText(`${index + 1}. [${normalizedSeverity(finding.severity)}] ${finding.title}`, {
      size: 11,
      bold: true,
      color: [12, 35, 67],
      gap: 4,
    });
    writeText(`Scanner: ${finding.scanner || report.scan_type || "Not recorded"}`);
    writeText(`Affected component: ${finding.affected_component || "Not recorded"}`);
    writeText(`Evidence: ${finding.evidence || "No evidence was supplied by the scanner."}`);
    writeText(`Remediation: ${finding.remediation || "No remediation guidance was supplied by the scanner."}`, {
      gap: 10,
    });
  });

  const pageCount = pdf.internal.getNumberOfPages();
  for (let page = 1; page <= pageCount; page += 1) {
    pdf.setPage(page);
    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(8);
    pdf.setTextColor(100, 116, 139);
    pdf.text("Generated from the stored scan report · verify recommendations before implementation.", margin, pageHeight - 22);
    pdf.text(`${page} / ${pageCount}`, pageWidth - margin, pageHeight - 22, { align: "right" });
  }
  pdf.save(`intellisecops-${report.scan_id}.pdf`);
}

function ReportDashboard() {
  const scanId = new URLSearchParams(window.location.search).get("scan_id") || "";
  const [report, setReport] = useState(null);
  const [availableReports, setAvailableReports] = useState([]);
  const [loading, setLoading] = useState(Boolean(scanId));
  const [pageError, setPageError] = useState("");
  const [pdfError, setPdfError] = useState("");
  const [pdfGenerating, setPdfGenerating] = useState(false);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [findingSelection, setFindingSelection] = useState("all");
  const [question, setQuestion] = useState("");
  const [assistantError, setAssistantError] = useState("");
  const [asking, setAsking] = useState(false);
  const [messages, setMessages] = useState([]);
  const [latestAssistantText, setLatestAssistantText] = useState("");
  const [speechState, setSpeechState] = useState("stopped");
  const [voiceError, setVoiceError] = useState("");
  const recognitionRef = useRef(null);
  const speechQueueRef = useRef([]);
  const speechIndexRef = useRef(0);
  const speechSessionRef = useRef(0);
  const activeUtteranceRef = useRef(null);
  const speechTimerRef = useRef(null);
  const voicesRef = useRef([]);
  const accessToken = scanId ? tokenForScan(scanId) : "";

  useEffect(() => {
    if (typeof window === "undefined" || !window.speechSynthesis) return undefined;
    const synth = window.speechSynthesis;
    const loadVoices = () => {
      try {
        const loaded = synth.getVoices() || [];
        if (loaded.length > 0) {
          voicesRef.current = loaded;
        }
      } catch (err) {
        console.warn("Could not retrieve speechSynthesis voices:", err);
      }
    };
    loadVoices();
    if (typeof synth.addEventListener === "function") {
      synth.addEventListener("voiceschanged", loadVoices);
      return () => synth.removeEventListener("voiceschanged", loadVoices);
    }
    synth.onvoiceschanged = loadVoices;
    return () => {
      if (synth.onvoiceschanged === loadVoices) synth.onvoiceschanged = null;
    };
  }, []);

  useEffect(() => {
    let active = true;
    async function loadPage() {
      setLoading(Boolean(scanId));
      setPageError("");
      try {
        if (!scanId) {
          if (hasSession()) {
            const history = await loadHistory();
            if (active) setAvailableReports(history.scans || []);
          } else if (active) {
            setAvailableReports(readPublicScans());
          }
          return;
        }
        const result = accessToken
          ? await downloadPublicReport(scanId, accessToken)
          : await loadReport(scanId);
        if (active) setReport(result);
      } catch (error) {
        if (active) setPageError(error.message || "Could not load the stored scan report.");
      } finally {
        if (active) setLoading(false);
      }
    }
    loadPage();
    return () => { active = false; };
  }, [accessToken, scanId]);

  useEffect(() => () => {
    speechSessionRef.current += 1;
    if (speechTimerRef.current) clearTimeout(speechTimerRef.current);
    activeUtteranceRef.current = null;
    if (window.speechSynthesis) {
      try {
        window.speechSynthesis.cancel();
        if (window.speechSynthesis.paused) {
          window.speechSynthesis.resume();
        }
      } catch {
        // ignore
      }
    }
    recognitionRef.current?.stop();
  }, []);

  const findings = report?.findings || EMPTY_FINDINGS;
  const counts = useMemo(() => {
    const result = Object.fromEntries(SEVERITIES.map(({ name }) => [name, 0]));
    findings.forEach((finding) => {
      result[normalizedSeverity(finding.severity)] += 1;
    });
    return result;
  }, [findings]);
  const totalFindings = findings.length;
  const filteredFindings = useMemo(() => {
    const query = search.trim().toLowerCase();
    return findings
      .map((finding, index) => ({ finding, index }))
      .filter(({ finding }) => (
        (severityFilter === "All" || normalizedSeverity(finding.severity) === severityFilter)
        && (!query || [
          finding.title,
          finding.scanner,
          finding.affected_component,
          finding.evidence,
          finding.remediation,
        ].some((value) => String(value || "").toLowerCase().includes(query)))
      ));
  }, [findings, search, severityFilter]);
  const donutSegments = useMemo(() => {
    let offset = 0;
    return SEVERITIES.map((severity) => {
      const length = totalFindings ? counts[severity.name] / totalFindings * CHART_CIRCUMFERENCE : 0;
      const segment = { ...severity, length, offset };
      offset += length;
      return segment;
    });
  }, [counts, totalFindings]);

  function speak(text) {
    const synth = typeof window !== "undefined" ? window.speechSynthesis : null;
    if (!synth || typeof window.SpeechSynthesisUtterance !== "function") {
      const errorMsg = "Text-to-speech is not supported in this browser.";
      console.error(errorMsg);
      setVoiceError(errorMsg);
      return;
    }
    const chunks = splitSpeechText(text);
    if (!chunks.length) {
      setVoiceError("No speech text available to read.");
      return;
    }

    const session = speechSessionRef.current + 1;
    speechSessionRef.current = session;
    if (speechTimerRef.current) {
      clearTimeout(speechTimerRef.current);
      speechTimerRef.current = null;
    }
    activeUtteranceRef.current = null;

    try {
      if (synth.speaking || synth.pending) {
        synth.cancel();
      }
      if (synth.paused) {
        synth.resume();
      }
    } catch (err) {
      console.warn("speechSynthesis cancel/resume error:", err);
    }

    speechQueueRef.current = chunks;
    speechIndexRef.current = 0;
    setVoiceError("");
    setSpeechState("playing");

    const speakNextChunk = () => {
      if (speechSessionRef.current !== session) return;
      const chunk = speechQueueRef.current[speechIndexRef.current];
      if (!chunk) {
        activeUtteranceRef.current = null;
        setSpeechState("stopped");
        return;
      }

      try {
        const utterance = new window.SpeechSynthesisUtterance(chunk);
        activeUtteranceRef.current = utterance;

        // Check if voices are loaded before calling speak()
        let availableVoices = voicesRef.current;
        if (!availableVoices || availableVoices.length === 0) {
          try {
            const freshVoices = synth.getVoices ? synth.getVoices() : [];
            if (freshVoices && freshVoices.length > 0) {
              availableVoices = freshVoices;
              voicesRef.current = freshVoices;
            }
          } catch (voiceErr) {
            console.warn("Could not retrieve voices from speechSynthesis:", voiceErr);
          }
        }

        let chosenVoice = null;
        if (availableVoices && availableVoices.length > 0) {
          chosenVoice = pickBestVoice(availableVoices);
        } else {
          console.warn("SpeechSynthesis voices are not yet loaded. Falling back to default browser voice.");
        }

        if (chosenVoice) {
          utterance.voice = chosenVoice;
          utterance.lang = chosenVoice.lang || (typeof navigator !== "undefined" && navigator.language) || "en-US";
        } else {
          // Fallback to browser/system default voice and language
          utterance.lang = (typeof navigator !== "undefined" && navigator.language) || "en-US";
        }

        utterance.rate = 1.0;
        utterance.pitch = 1.0;

        utterance.onend = () => {
          if (speechSessionRef.current !== session) return;
          speechIndexRef.current += 1;
          speakNextChunk();
        };

        utterance.onerror = (event) => {
          if (speechSessionRef.current !== session) return;
          if (event.error === "canceled" || event.error === "interrupted") {
            return;
          }
          console.error("SpeechSynthesis utterance error:", event.error, event);
          speechSessionRef.current += 1;
          activeUtteranceRef.current = null;
          setSpeechState("stopped");
          setVoiceError(speechErrorMessage(event.error));
        };

        if (synth.paused) {
          synth.resume();
        }
        synth.speak(utterance);
        if (synth.paused) {
          synth.resume();
        }
      } catch (error) {
        console.error("Voice playback could not be started:", error);
        speechSessionRef.current += 1;
        activeUtteranceRef.current = null;
        setSpeechState("stopped");
        const isBlock = error?.name === "NotAllowedError" || String(error?.message).toLowerCase().includes("not allowed");
        setVoiceError(
          isBlock
            ? "Browser blocked audio output. Please allow audio/autoplay for this site and click Play again."
            : "Voice playback could not be started. Check browser audio and speech voice settings."
        );
      }
    };

    // Strictly trigger playback directly inside the user click handler to comply with autoplay policy
    speakNextChunk();
  }

  function handlePlay() {
    if (!playableText) return;
    if (speechState === "paused") {
      pauseSpeech();
      return;
    }
    speak(playableText);
  }

  function pauseSpeech() {
    const synth = typeof window !== "undefined" ? window.speechSynthesis : null;
    if (!synth) return;
    try {
      if (synth.paused) {
        synth.resume();
        setSpeechState("playing");
      } else if (synth.speaking) {
        synth.pause();
        setSpeechState("paused");
      }
    } catch (err) {
      console.error("Error pausing/resuming voice playback:", err);
    }
  }

  function stopSpeech() {
    speechSessionRef.current += 1;
    if (speechTimerRef.current) {
      clearTimeout(speechTimerRef.current);
      speechTimerRef.current = null;
    }
    activeUtteranceRef.current = null;
    const synth = typeof window !== "undefined" ? window.speechSynthesis : null;
    if (synth) {
      try {
        synth.cancel();
        if (synth.paused) {
          synth.resume();
        }
      } catch (err) {
        console.warn("speechSynthesis stop error:", err);
      }
    }
    setSpeechState("stopped");
  }

  function startListening() {
    if (typeof window === "undefined" || !window.isSecureContext) {
      setVoiceError(
        "Voice dictation requires HTTPS or localhost. You can still type your question and use voice playback.",
      );
      return;
    }
    const SpeechRecognition = typeof window !== "undefined" ? (window.SpeechRecognition || window.webkitSpeechRecognition) : null;
    if (!SpeechRecognition) {
      setVoiceError("Microphone dictation is not supported. Type your question instead.");
      return;
    }
    setVoiceError("");
    const recognition = new SpeechRecognition();
    recognition.lang = (typeof navigator !== "undefined" && navigator.language) || "en-US";
    recognition.interimResults = false;
    recognition.onresult = (event) => {
      const transcript = event.results?.[0]?.[0]?.transcript;
      if (transcript) setQuestion((previous) => `${previous}${previous ? " " : ""}${transcript}`);
    };
    recognition.onerror = (err) => {
      console.error("SpeechRecognition error:", err);
      setVoiceError("Microphone input was unavailable. Type your question instead.");
    };
    recognitionRef.current = recognition;
    try {
      recognition.start();
    } catch (err) {
      console.error("SpeechRecognition start error:", err);
      setVoiceError("Microphone input could not start. Type your question instead.");
    }
  }

  async function submitQuestion(event) {
    event.preventDefault();
    const trimmedQuestion = question.trim();
    if (!trimmedQuestion || !report || asking) return;
    const userMessage = { role: "user", text: trimmedQuestion };
    setMessages((previous) => [...previous, userMessage]);
    setQuestion("");
    setAssistantError("");
    setAsking(true);
    try {
      const result = await askScanAssistant(
        report.scan_id,
        trimmedQuestion,
        findingSelection === "all" ? undefined : Number(findingSelection),
        accessToken,
      );
      const answer = typeof result?.answer === "string" ? result.answer.trim() : "";
      if (!answer) throw new Error("The AI assistant returned no readable answer.");
      setLatestAssistantText(answer);
      setMessages((previous) => [...previous, {
        role: "assistant",
        text: answer,
        aiGenerated: result.ai_generated,
      }]);
    } catch (error) {
      setAssistantError(error.message || "AI assistance is unavailable. The stored report is unchanged.");
    } finally {
      setAsking(false);
    }
  }

  async function generateFixSuggestions() {
    if (!report || asking) return;
    setAssistantError("");
    setAsking(true);
    try {
      const result = await askScanAssistant(
        report.scan_id,
        "For each stored finding, explain the risk briefly and give prioritized, actionable remediation steps plus safe verification steps. Use only the supplied report, do not invent evidence or code context, and state when more code context is needed.",
        undefined,
        accessToken,
      );
      const answer = typeof result?.answer === "string" ? result.answer.trim() : "";
      if (!answer) throw new Error("Gemini returned no readable suggestions.");
      setLatestAssistantText(answer);
      setMessages((previous) => [...previous, {
        role: "assistant",
        text: answer,
        aiGenerated: result.ai_generated,
      }]);
      document.getElementById("report-ai-chat")?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
    } catch (error) {
      setAssistantError(error.message || "Gemini could not generate suggestions. Check the server-side API key, quota, and connectivity.");
    } finally {
      setAsking(false);
    }
  }

  async function handlePdfDownload() {
    setPdfError("");
    setPdfGenerating(true);
    try {
      await savePdf(report, counts, findings);
    } catch {
      setPdfError("PDF could not be generated. Try downloading the original JSON report instead.");
    } finally {
      setPdfGenerating(false);
    }
  }

  const savedAnalysis = String(report?.ai_analysis || "").replace(
    /^AI-generated suggestion \(unverified\):\s*/i,
    "",
  );
  const hasSavedAnalysis = Boolean(
    savedAnalysis && !savedAnalysis.toLowerCase().startsWith("ai analysis unavailable"),
  );
  const hasGeneratedAnswer = messages.some((message) => message.role === "assistant");
  const playableText = latestAssistantText || (hasSavedAnalysis ? savedAnalysis : "");

  return (
    <main className="report-page">
      <header className="report-topbar">
        <a className="report-brand" href="/" aria-label="IntelliSecOps home">
          <FaShieldAlt />
          <span>IntelliSecOps<small>SECURITY REPORTS</small></span>
        </a>
        <a className="report-back-link" href="/#scanner"><FaArrowLeft /> Back to scanner</a>
      </header>

      <div className="report-content">
        {loading ? <div className="report-state">Loading the stored scan report…</div> : null}
        {!loading && pageError ? (
          <div className="report-state report-state-error" role="alert">
            <FaExclamationTriangle />
            <div><strong>Report unavailable</strong><p>{pageError}</p></div>
          </div>
        ) : null}
        {!loading && !scanId && !pageError ? (
          <section className="report-library">
            <p className="report-eyebrow">YOUR REPORT LIBRARY</p>
            <h1>Security reports</h1>
            <p className="report-intro">Open a completed scan to review its stored findings and report details.</p>
            {availableReports.length ? (
              <div className="report-library-list">
                {availableReports.map((item) => (
                  <a
                    className="report-library-item"
                    href={`/reports/?scan_id=${encodeURIComponent(item.scan_id)}`}
                    key={item.scan_id}
                  >
                    <span><strong>{item.target}</strong><small>{item.target_type} · {dateLabel(item.created_at)}</small></span>
                    <span className={`report-status ${item.status}`}>{item.status}</span>
                  </a>
                ))}
              </div>
            ) : (
              <div className="report-empty">
                <FaShieldAlt />
                <h2>No saved reports in this browser</h2>
                <p>Submit an authorized scan first. A report appears here only after the backend stores a completed result.</p>
                <a className="report-primary-button" href="/#scanner">Go to scanner</a>
              </div>
            )}
          </section>
        ) : null}
        {!loading && report ? (
          <>
            <section className="report-heading-card">
              <div>
                <p className="report-eyebrow">STORED SCAN REPORT · {report.scan_type || "SCANNER"}</p>
                <h1>Security assessment</h1>
                <p className="report-target">{report.target}</p>
                <p className="report-scope">{scopeLabel(report)}</p>
              </div>
              <div className="report-actions">
                <button className="report-secondary-button" type="button" onClick={() => saveJson(report, messages)}>
                  <FaDownload /> Download JSON
                </button>
                <button className="report-primary-button" type="button" onClick={handlePdfDownload} disabled={pdfGenerating}>
                  <FaFilePdf /> {pdfGenerating ? "Preparing PDF…" : "Download PDF"}
                </button>
              </div>
              {pdfError ? <p className="report-inline-error" role="alert">{pdfError}</p> : null}
              <div className="report-metadata">
                <span><small>Scan ID</small><strong>{report.scan_id}</strong></span>
                <span><small>Target type</small><strong>{report.target_type || "Not recorded"}</strong></span>
                <span><small>Started</small><strong>{dateLabel(report.started_at)}</strong></span>
                <span><small>Completed</small><strong>{dateLabel(report.completed_at || report.created_at)}</strong></span>
              </div>
            </section>

            <section className="report-summary-grid" aria-label="Finding severity totals">
              <article className="report-total-card">
                <span>Total findings</span><strong>{totalFindings}</strong>
                <small>Stored by the scanner callback</small>
              </article>
              {SEVERITIES.map(({ name, color }) => (
                <button
                  className={`report-severity-card ${severityFilter === name ? "selected" : ""}`}
                  key={name}
                  type="button"
                  onClick={() => setSeverityFilter((current) => current === name ? "All" : name)}
                  aria-pressed={severityFilter === name}
                >
                  <span><i style={{ backgroundColor: color }} />{name}</span>
                  <strong>{counts[name]}</strong>
                  <small>Filter findings</small>
                </button>
              ))}
            </section>

            <section className="report-charts-grid">
              <article className="report-panel">
                <div className="report-panel-heading"><div><p className="report-eyebrow">RISK DISTRIBUTION</p><h2>Findings by severity</h2></div></div>
                <div className="report-donut-layout">
                  <div className="report-donut" role="img" aria-label={`Severity distribution across ${totalFindings} stored findings`}>
                    <svg viewBox="0 0 120 120" aria-hidden="true">
                      <circle cx="60" cy="60" r={CHART_RADIUS} fill="none" stroke="#e9eef5" strokeWidth="16" />
                      {donutSegments.map((segment) => segment.length > 0 ? (
                        <circle
                          key={segment.name}
                          cx="60"
                          cy="60"
                          r={CHART_RADIUS}
                          fill="none"
                          stroke={segment.color}
                          strokeWidth="16"
                          strokeDasharray={`${segment.length} ${CHART_CIRCUMFERENCE - segment.length}`}
                          strokeDashoffset={-segment.offset}
                          transform="rotate(-90 60 60)"
                        />
                      ) : null)}
                    </svg>
                    <span><strong>{totalFindings}</strong><small>findings</small></span>
                  </div>
                  <div className="report-chart-legend">
                    {SEVERITIES.map(({ name, color }) => (
                      <button
                        key={name}
                        type="button"
                        onClick={() => setSeverityFilter((current) => current === name ? "All" : name)}
                        aria-pressed={severityFilter === name}
                      >
                        <i style={{ backgroundColor: color }} /><span>{name}</span><strong>{counts[name]}</strong>
                      </button>
                    ))}
                  </div>
                </div>
              </article>
              <article className="report-panel">
                <div className="report-panel-heading"><div><p className="report-eyebrow">SEVERITY BREAKDOWN</p><h2>Compare counts</h2></div></div>
                <div className="report-bar-chart">
                  {SEVERITIES.map(({ name, color }) => {
                    const percentage = totalFindings ? counts[name] / totalFindings * 100 : 0;
                    return (
                      <button
                        className={`report-bar-row ${severityFilter === name ? "selected" : ""}`}
                        key={name}
                        type="button"
                        onClick={() => setSeverityFilter((current) => current === name ? "All" : name)}
                        aria-pressed={severityFilter === name}
                      >
                        <span className="report-bar-label">{name}</span>
                        <span className="report-bar-track"><i style={{ width: `${percentage}%`, backgroundColor: color }} /></span>
                        <strong>{counts[name]}</strong>
                      </button>
                    );
                  })}
                </div>
                <p className="report-chart-note">Select a severity to filter the stored findings below.</p>
              </article>
            </section>

            <section className="report-panel report-findings-panel">
              <div className="report-panel-heading report-findings-heading">
                <div><p className="report-eyebrow">SCANNER DATA</p><h2>Vulnerability findings</h2><p>Only findings returned and stored by this scan are listed.</p></div>
                <label className="report-search">
                  <FaSearch />
                  <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search findings" aria-label="Search findings" />
                </label>
              </div>
              <div className="report-filter-row" aria-label="Filter findings by severity">
                {["All", ...SEVERITIES.map(({ name }) => name)].map((severity) => (
                  <button
                    className={severityFilter === severity ? "active" : ""}
                    key={severity}
                    type="button"
                    onClick={() => setSeverityFilter(severity)}
                  >
                    {severity}{severity === "All" ? ` (${totalFindings})` : ` (${counts[severity]})`}
                  </button>
                ))}
              </div>
              {filteredFindings.length ? (
                <div className="report-findings-list">
                  {filteredFindings.map(({ finding, index }) => (
                    <article className="report-finding" key={`${finding.title}-${index}`}>
                      <div className="report-finding-title">
                        <span className={`report-severity-pill ${normalizedSeverity(finding.severity).toLowerCase()}`}>{normalizedSeverity(finding.severity)}</span>
                        <h3>{finding.title || "Untitled scanner finding"}</h3>
                        <span className="report-finding-scanner">{finding.scanner || report.scan_type}</span>
                      </div>
                      <dl>
                        <div><dt>Affected component</dt><dd>{finding.affected_component || "Not supplied by scanner"}</dd></div>
                        <div><dt>Evidence</dt><dd>{finding.evidence || "No evidence supplied by scanner."}</dd></div>
                        <div><dt>Scanner remediation</dt><dd>{finding.remediation || "No remediation guidance supplied by scanner."}</dd></div>
                      </dl>
                      <button
                        className="report-ask-finding"
                        type="button"
                        onClick={() => {
                          setFindingSelection(String(index));
                          document.getElementById("report-ai-question")?.scrollIntoView({ behavior: "smooth", block: "center" });
                        }}
                      >
                        Ask AI about this finding
                      </button>
                    </article>
                  ))}
                </div>
              ) : (
                <div className="report-no-findings">
                  {totalFindings === 0
                    ? "No findings were stored for this scan. This does not prove that the target is secure."
                    : "No findings match the selected search and severity filters."}
                </div>
              )}
            </section>

            <section className="report-panel report-ai-panel">
              <div className="report-panel-heading">
                <div><p className="report-eyebrow">AI SECURITY AGENT</p><h2><FaRobot /> Explanations & follow-up questions</h2></div>
                <div className="report-ai-actions">
                  <span className="report-ai-label">
                    {hasSavedAnalysis || hasGeneratedAnswer
                      ? "AI-generated · unverified"
                      : "Gemini suggestions on request"}
                  </span>
                  <button
                    className="report-secondary-button"
                    type="button"
                    onClick={generateFixSuggestions}
                    disabled={asking}
                  >
                    <FaRobot /> {asking ? "Generating suggestions…" : "Generate Gemini fix suggestions"}
                  </button>
                </div>
              </div>
              <p className="report-ai-disclaimer">AI guidance is separate from scanner findings. Each request uses up to 30 stored findings. Verify recommendations against your code and environment; the agent must not invent evidence.</p>

              {hasSavedAnalysis ? (
                <article className="report-ai-summary">
                  <div className="report-ai-summary-head"><strong>Saved scan-time Gemini analysis</strong><button type="button" onClick={() => speak(savedAnalysis)}><FaVolumeUp /> Read aloud</button></div>
                  <p>{savedAnalysis}</p>
                </article>
              ) : (
                <div className="report-ai-unavailable">
                  {report.ai_analysis
                    ? "Scan-time AI analysis is unavailable. You can still ask a follow-up if Gemini is configured on the backend."
                    : "No scan-time AI analysis was saved. Ask a follow-up below if the server-side Gemini integration is available."}
                </div>
              )}

              <div className="report-voice-controls" aria-label="Voice playback controls">
                <button
                  type="button"
                  onClick={handlePlay}
                  disabled={!playableText}
                  title={playableText ? "Play AI explanation aloud" : "No AI text available to play"}
                >
                  <FaPlay /> Play
                </button>
                <button type="button" onClick={pauseSpeech} disabled={speechState === "stopped"}>
                  <FaPause /> {speechState === "paused" ? "Resume" : "Pause"}
                </button>
                <button type="button" onClick={stopSpeech} disabled={speechState === "stopped"}>
                  <FaStop /> Stop
                </button>
                <span>
                  {speechState === "playing"
                    ? "Playing"
                    : speechState === "paused"
                    ? "Paused"
                    : playableText
                    ? "Voice ready"
                    : "No voice text"}
                </span>
              </div>

              <div className="report-chat" id="report-ai-chat" aria-live="polite">
                {messages.map((message, index) => (
                  <article className={`report-chat-message ${message.role}`} key={`${message.role}-${index}`}>
                    <strong>{message.role === "assistant" ? "Gemini · AI-generated" : "You"}</strong>
                    <p>{message.text}</p>
                    {message.role === "assistant" ? <button type="button" onClick={() => speak(message.text)}><FaVolumeUp /> Read aloud</button> : null}
                  </article>
                ))}
              </div>
              {assistantError ? <p className="report-inline-error" role="alert">{assistantError}</p> : null}
              {voiceError ? <p className="report-inline-error" role="status">{voiceError}</p> : null}

              <form className="report-question-form" onSubmit={submitQuestion}>
                <label htmlFor="report-ai-question">Ask about this report</label>
                <div className="report-question-context">
                  <select value={findingSelection} onChange={(event) => setFindingSelection(event.target.value)} aria-label="AI question context">
                    <option value="all">Whole report</option>
                    {findings.map((finding, index) => (
                      <option key={`${finding.title}-${index}`} value={index}>Finding {index + 1}: {finding.title}</option>
                    ))}
                  </select>
                  <button
                    type="button"
                    onClick={startListening}
                    aria-label="Dictate question with microphone"
                    title={typeof window !== "undefined" && !window.isSecureContext
                      ? "Voice dictation requires HTTPS or localhost."
                      : "Dictate your question"}
                  >
                    <FaMicrophone /> Dictate
                  </button>
                </div>
                <div className="report-question-input">
                  <textarea
                    id="report-ai-question"
                    value={question}
                    onChange={(event) => setQuestion(event.target.value)}
                    placeholder="Ask how a stored finding affects your application or how to verify a fix…"
                    maxLength={2000}
                    rows={3}
                  />
                  <button type="submit" disabled={asking || !question.trim()}>
                    {asking ? "Thinking…" : "Ask Gemini"}
                  </button>
                </div>
                <small>Questions are sent to the configured backend Gemini integration. Microphone support depends on your browser; typing always works.</small>
              </form>
            </section>
          </>
        ) : null}
      </div>
    </main>
  );
}

export default ReportDashboard;
