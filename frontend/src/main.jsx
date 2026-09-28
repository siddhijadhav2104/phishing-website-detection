import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "bootstrap/dist/css/bootstrap.min.css";
import "./styles.css";

const API = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL.replace(/\/+$/, "")}/api`
  : "/api";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadData = async () => {
    try {
      const [h, hist] = await Promise.all([
        fetch(`${API}/health`),
        fetch(`${API}/history`)
      ]);
      if (h.ok) setHealth(await h.json());
      if (hist.ok) setHistory((await hist.json()).history || []);
    } catch {
      setHealth(null);
    }
  };

  useEffect(() => { loadData(); }, []);

  const analyze = async (e) => {
    e.preventDefault();
    setError("");
    setResult(null);
    if (!url.trim()) {
      setError("Please enter a URL.");
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${API}/predict`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({url})
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Prediction failed.");
      setResult(data);
      await loadData();
    } catch (err) {
      setError(err.message + " Make sure START_PROJECT.bat is running.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <nav className="navbar navbar-dark">
        <div className="container">
          <span className="navbar-brand fw-bold">🛡️ PhishGuard ML</span>
          <span className="badge rounded-pill bg-light text-dark">Machine Learning</span>
        </div>
      </nav>

      <main className="container py-5">
        <section className="hero text-center mb-4">
          <span className="eyebrow">CYBERSECURITY • URL ANALYSIS</span>
          <h1>Phishing Website Detection</h1>
          <p>Analyze a website URL using a trained machine learning model before you visit it.</p>
        </section>

        <div className="card shadow-lg border-0 scanner-card">
          <div className="card-body p-4 p-md-5">
            <form onSubmit={analyze}>
              <label className="form-label fw-semibold">Website URL</label>
              <div className="input-group input-group-lg">
                <input
                  className="form-control"
                  value={url}
                  onChange={e => setUrl(e.target.value)}
                  placeholder="https://example.com/login"
                  autoComplete="off"
                />
                <button className="btn btn-primary px-4" disabled={loading}>
                  {loading ? "Analyzing..." : "Analyze URL"}
                </button>
              </div>
              {error && <div className="alert alert-danger mt-3 mb-0">{error}</div>}
            </form>

            {result && (
              <div className={`result mt-4 ${result.result === "Phishing" ? "danger" : "safe"}`}>
                <div>
                  <div className="small text-uppercase fw-bold opacity-75">Prediction</div>
                  <div className="display-6 fw-bold">{result.result === "Phishing" ? "⚠️ Phishing" : "✅ Legitimate"}</div>
                  <div className="mt-2">Confidence: <b>{result.confidence}%</b></div>
                  <div>Phishing probability: <b>{result.phishingProbability}%</b></div>
                </div>
                <div className="result-icon">{result.result === "Phishing" ? "!" : "✓"}</div>
              </div>
            )}

            {result && (
              <div className="row g-3 mt-1">
                <Indicator title="HTTPS" value={result.indicators.https ? "Enabled" : "Missing"} ok={result.indicators.https} />
                <Indicator title="IP Address" value={result.indicators.hasIp ? "Detected" : "Not detected"} ok={!result.indicators.hasIp} />
                <Indicator title="URL Shortener" value={result.indicators.shortener ? "Detected" : "Not detected"} ok={!result.indicators.shortener} />
                <Indicator title="Suspicious Keywords" value={result.indicators.suspiciousKeywords} ok={result.indicators.suspiciousKeywords === 0} />
              </div>
            )}
          </div>
        </div>

        <section className="row g-4 mt-1">
          <div className="col-lg-4">
            <div className="card border-0 shadow-sm h-100 info-card">
              <div className="card-body">
                <h5>How it works</h5>
                <ol>
                  <li>Enter a URL.</li>
                  <li>Features are extracted from the URL.</li>
                  <li>Random Forest ML model classifies it.</li>
                  <li>Result and confidence are displayed.</li>
                </ol>
              </div>
            </div>
          </div>
          <div className="col-lg-8">
            <div className="card border-0 shadow-sm h-100">
              <div className="card-body">
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <h5 className="mb-0">Recent Scans</h5>
                  <span className="badge text-bg-secondary">{history.length}</span>
                </div>
                {history.length === 0 ? (
                  <p className="text-muted mb-0">No scans yet.</p>
                ) : (
                  <div className="table-responsive">
                    <table className="table align-middle">
                      <thead><tr><th>URL</th><th>Result</th><th>Confidence</th></tr></thead>
                      <tbody>
                        {history.map((x, i) => (
                          <tr key={i}>
                            <td className="url-cell">{x.url}</td>
                            <td><span className={`badge ${x.result === "Phishing" ? "text-bg-danger" : "text-bg-success"}`}>{x.result}</span></td>
                            <td>{x.confidence}%</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        <footer className="text-center text-muted small mt-5">
          Backend: {health ? "Connected" : "Checking..."} • Storage: {health?.database || "—"} • For academic/project demonstration
        </footer>
      </main>
    </div>
  );
}

function Indicator({title, value, ok}) {
  return (
    <div className="col-md-3">
      <div className="indicator">
        <span className={ok ? "dot ok" : "dot bad"}></span>
        <div><small>{title}</small><strong>{value}</strong></div>
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
