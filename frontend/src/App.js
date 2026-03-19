import React, { useState } from "react";

// ─── Design tokens ────────────────────────────────────────────────
const C = {
  bg: "#0a0e1a",
  surface: "#111827",
  surfaceHover: "#1a2235",
  border: "#1e2d45",
  accent: "#00d4ff",
  accentDim: "#00d4ff22",
  green: "#00e5a0",
  greenDim: "#00e5a015",
  yellow: "#ffb800",
  yellowDim: "#ffb80015",
  red: "#ff4560",
  redDim: "#ff456015",
  text: "#e2e8f0",
  textMuted: "#64748b",
  textDim: "#94a3b8",
};

const font = `'IBM Plex Mono', 'Courier New', monospace`;

// ─── Helpers ──────────────────────────────────────────────────────
const severityColor = (s) =>
  s === "HIGH" ? C.red : s === "MEDIUM" ? C.yellow : C.green;
const severityBg = (s) =>
  s === "HIGH" ? C.redDim : s === "MEDIUM" ? C.yellowDim : C.greenDim;

const passColor = (p) => (p ? C.green : C.red);
const passLabel = (p) => (p ? "PASS" : "FAIL");

// ─── Sub-components ───────────────────────────────────────────────

function Panel({ title, badge, badgeColor, children, style = {} }) {
  return (
    <div style={{
      background: C.surface,
      border: `1px solid ${C.border}`,
      borderRadius: 8,
      marginBottom: 20,
      overflow: "hidden",
      ...style,
    }}>
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "14px 20px",
        borderBottom: `1px solid ${C.border}`,
        background: "#0d1525",
      }}>
        <span style={{ fontFamily: font, fontSize: 13, color: C.accent, letterSpacing: "0.08em", textTransform: "uppercase" }}>
          {title}
        </span>
        {badge !== undefined && (
          <span style={{
            fontFamily: font, fontSize: 12,
            background: badgeColor ? `${badgeColor}22` : C.accentDim,
            color: badgeColor || C.accent,
            padding: "2px 10px", borderRadius: 4,
            border: `1px solid ${badgeColor || C.accent}44`,
          }}>
            {badge}
          </span>
        )}
      </div>
      <div style={{ padding: 20 }}>{children}</div>
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div style={{
      flex: 1,
      background: "#0d1525",
      border: `1px solid ${C.border}`,
      borderLeft: `3px solid ${color}`,
      borderRadius: 6,
      padding: "14px 18px",
      minWidth: 120,
    }}>
      <div style={{ fontFamily: font, fontSize: 22, color, fontWeight: 700, marginBottom: 4 }}>
        {value}
      </div>
      <div style={{ fontFamily: font, fontSize: 11, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>
        {label}
      </div>
    </div>
  );
}

function Btn({ onClick, children, variant = "primary", disabled = false }) {
  const styles = {
    primary: { background: C.accent, color: "#000", border: "none" },
    ghost: { background: "transparent", color: C.accent, border: `1px solid ${C.accent}44` },
    danger: { background: C.red, color: "#fff", border: "none" },
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        fontFamily: font, fontSize: 12, fontWeight: 600,
        letterSpacing: "0.08em", textTransform: "uppercase",
        padding: "10px 20px", borderRadius: 5, cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1,
        transition: "opacity 0.2s",
        ...styles[variant],
      }}
    >
      {children}
    </button>
  );
}

function Input({ value, onChange, placeholder, style = {} }) {
  return (
    <input
      value={value}
      onChange={onChange}
      placeholder={placeholder}
      style={{
        fontFamily: font, fontSize: 13,
        background: "#0d1525", color: C.text,
        border: `1px solid ${C.border}`, borderRadius: 5,
        padding: "10px 14px", outline: "none", width: "100%",
        boxSizing: "border-box",
        ...style,
      }}
    />
  );
}

function StatusDot({ status }) {
  const color =
    status === "healthy" ? C.green :
    status === "unreachable" ? C.red : C.yellow;
  return (
    <span style={{
      display: "inline-block", width: 8, height: 8,
      borderRadius: "50%", background: color,
      marginRight: 8, boxShadow: `0 0 6px ${color}`,
    }} />
  );
}

// ─── Security Findings Table ──────────────────────────────────────

function SecurityTable({ findings }) {
  const [expanded, setExpanded] = useState(null);

  if (!findings || findings.length === 0) {
    return <p style={{ fontFamily: font, color: C.green, fontSize: 13 }}>✓ No findings detected.</p>;
  }

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: font, fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: `1px solid ${C.border}` }}>
            {["Endpoint", "Risk Type", "Severity", "Confidence", "Details"].map(h => (
              <th key={h} style={{ color: C.textMuted, fontWeight: 600, padding: "8px 12px", textAlign: "left", letterSpacing: "0.06em" }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <React.Fragment key={i}>
              <tr
                style={{ borderBottom: `1px solid ${C.border}22`, cursor: "pointer", transition: "background 0.15s" }}
                onClick={() => setExpanded(expanded === i ? null : i)}
                onMouseEnter={e => e.currentTarget.style.background = C.surfaceHover}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                <td style={{ padding: "10px 12px", color: C.accent }}>{f.endpoint}</td>
                <td style={{ padding: "10px 12px", color: C.text }}>{f.risk_type}</td>
                <td style={{ padding: "10px 12px" }}>
                  <span style={{
                    background: severityBg(f.severity),
                    color: severityColor(f.severity),
                    padding: "2px 8px", borderRadius: 3,
                    border: `1px solid ${severityColor(f.severity)}44`,
                    fontWeight: 700,
                  }}>
                    {f.severity}
                  </span>
                </td>
                <td style={{ padding: "10px 12px", color: C.textDim }}>{f.confidence}</td>
                <td style={{ padding: "10px 12px", color: C.textMuted }}>
                  {expanded === i ? "▲ hide" : "▼ show"}
                </td>
              </tr>
              {expanded === i && (
                <tr>
                  <td colSpan={5} style={{ padding: "0 12px 12px 12px" }}>
                    <div style={{
                      background: "#0d1525", border: `1px solid ${C.border}`,
                      borderRadius: 5, padding: "12px 16px",
                      color: C.textDim, fontSize: 12, lineHeight: 1.6,
                    }}>
                      {f.description}
                    </div>
                  </td>
                </tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── API Test Results ─────────────────────────────────────────────

function TestResults({ results }) {
  const [openEp, setOpenEp] = useState(null);

  if (!results || results.length === 0) {
    return <p style={{ fontFamily: font, color: C.textMuted, fontSize: 13 }}>No test results.</p>;
  }

  return (
    <div>
      {results.map((ep, i) => {
        const tests = ep.tests || [];
        const passed = tests.filter(t => t.passed === true).length;
        const failed = tests.filter(t => t.passed === false).length;
        const isOpen = openEp === i;

        return (
          <div key={i} style={{ marginBottom: 8 }}>
            <div
              onClick={() => setOpenEp(isOpen ? null : i)}
              style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                background: "#0d1525", border: `1px solid ${C.border}`,
                borderRadius: 5, padding: "10px 14px",
                cursor: "pointer", fontFamily: font, fontSize: 12,
              }}
            >
              <span style={{ color: C.accent }}>{ep.method} {ep.endpoint}</span>
              <span style={{ display: "flex", gap: 8 }}>
                <span style={{ color: C.green }}>{passed} pass</span>
                <span style={{ color: C.textMuted }}>/</span>
                <span style={{ color: failed > 0 ? C.red : C.textMuted }}>{failed} fail</span>
                <span style={{ color: C.textMuted, marginLeft: 8 }}>{isOpen ? "▲" : "▼"}</span>
              </span>
            </div>

            {isOpen && (
              <div style={{
                border: `1px solid ${C.border}`, borderTop: "none",
                borderRadius: "0 0 5px 5px", overflow: "hidden",
              }}>
                {tests.map((t, j) => {
                  if (t.test === "dynamic_fuzz_testing") {
                    return (
                      <div key={j} style={{ padding: "10px 14px", borderBottom: `1px solid ${C.border}22`, fontFamily: font, fontSize: 12 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                          <span style={{ color: C.textDim }}>dynamic_fuzz_testing</span>
                          <span style={{ color: t.passed ? C.green : C.red }}>
                            {t.vulnerable_count} vulnerable / {t.total_payloads} payloads
                          </span>
                        </div>
                        {t.results && t.results.filter(r => r.possible_vulnerability).map((r, k) => (
                          <div key={k} style={{
                            background: C.redDim, border: `1px solid ${C.red}33`,
                            borderRadius: 4, padding: "6px 10px", marginBottom: 4,
                            color: C.red, fontSize: 11,
                          }}>
                            ⚠ {r.payload} → {r.status_code || r.error}
                          </div>
                        ))}
                      </div>
                    );
                  }

                  return (
                    <div key={j} style={{
                      display: "flex", justifyContent: "space-between", alignItems: "center",
                      padding: "8px 14px", borderBottom: `1px solid ${C.border}22`,
                      fontFamily: font, fontSize: 12,
                    }}>
                      <span style={{ color: C.textDim }}>{t.test}</span>
                      <span style={{ display: "flex", gap: 12, alignItems: "center" }}>
                        {t.status_code && <span style={{ color: C.textMuted }}>HTTP {t.status_code}</span>}
                        {t.error && <span style={{ color: C.red, fontSize: 11 }}>{t.error.slice(0, 60)}</span>}
                        <span style={{
                          color: passColor(t.passed),
                          background: t.passed ? C.greenDim : C.redDim,
                          padding: "1px 8px", borderRadius: 3,
                          border: `1px solid ${passColor(t.passed)}44`,
                          fontWeight: 700, fontSize: 11,
                        }}>
                          {passLabel(t.passed)}
                        </span>
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────

export default function App() {
  const [specText, setSpecText] = useState("");
  const [specId, setSpecId] = useState(null);
  const [report, setReport] = useState(null);
  const [file, setFile] = useState(null);
  const [apiUrl, setApiUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("security");

  const BASE = "http://localhost:8000";

  const wrap = async (fn) => {
    setLoading(true); setError("");
    try { await fn(); }
    catch (e) { setError(e.message || "Request failed"); }
    finally { setLoading(false); }
  };

  const uploadSpec = () => wrap(async () => {
    let parsed;
    try { parsed = JSON.parse(specText); }
    catch { throw new Error("Invalid JSON in spec textarea"); }

    const res = await fetch(`${BASE}/api/specs/upload`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "uploaded_spec", spec: parsed }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Upload failed");
    setSpecId(data.id);
  });

  const uploadFile = () => wrap(async () => {
    if (!file) throw new Error("No file selected");
    const form = new FormData();
    form.append("file", file);
    const res = await fetch(`${BASE}/api/specs/upload-file`, { method: "POST", body: form });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "File upload failed");
    setSpecId(data.id);
  });

  const runScan = () => wrap(async () => {
    const res = await fetch(`${BASE}/api/run/${specId}`, { method: "POST" });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Scan failed");
    setReport(data.result);
    setActiveTab("security");
  });

  const scanUrl = () => wrap(async () => {
    if (!apiUrl) throw new Error("Enter an API URL first");
    const res = await fetch(`${BASE}/api/scan-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ base_url: apiUrl }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "URL scan failed");
    setReport(data.result);
    setActiveTab("security");
  });

  const tabs = [
    { key: "security", label: "Security Findings" },
    { key: "tests", label: "API Tests" },
    { key: "recommendations", label: "Recommendations" },
    { key: "llm", label: "AI Analysis" },
  ];

  return (
    <div style={{ fontFamily: font, background: C.bg, minHeight: "100vh", color: C.text }}>

      {/* Header */}
      <div style={{
        background: C.surface, borderBottom: `1px solid ${C.border}`,
        padding: "0 40px", display: "flex", alignItems: "center", height: 56,
      }}>
        <span style={{ color: C.accent, fontSize: 14, fontWeight: 700, letterSpacing: "0.12em", textTransform: "uppercase" }}>
          ◈ API_SENTINEL
        </span>
        <span style={{ marginLeft: 20, color: C.textMuted, fontSize: 11 }}>
          automated security testing platform
        </span>
        {loading && (
          <span style={{ marginLeft: "auto", color: C.yellow, fontSize: 11, animation: "pulse 1s infinite" }}>
            ⟳ scanning...
          </span>
        )}
      </div>

      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "32px 40px" }}>

        {/* Error banner */}
        {error && (
          <div style={{
            background: C.redDim, border: `1px solid ${C.red}44`,
            borderRadius: 6, padding: "12px 16px",
            color: C.red, fontFamily: font, fontSize: 12, marginBottom: 20,
          }}>
            ✕ {error}
          </div>
        )}

        {/* Input panels — 3 columns */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16, marginBottom: 24 }}>

          {/* Paste JSON */}
          <Panel title="Paste Spec">
            <textarea
              rows={6}
              value={specText}
              onChange={e => setSpecText(e.target.value)}
              placeholder={"{\n  \"openapi\": \"3.0.0\",\n  ...\n}"}
              style={{
                fontFamily: font, fontSize: 11, background: "#0d1525",
                color: C.text, border: `1px solid ${C.border}`, borderRadius: 4,
                padding: "10px", width: "100%", resize: "vertical",
                outline: "none", boxSizing: "border-box", marginBottom: 12,
              }}
            />
            <Btn onClick={uploadSpec} disabled={loading || !specText}>Upload JSON</Btn>
          </Panel>

          {/* Upload file */}
          <Panel title="Upload File">
            <div style={{
              border: `1px dashed ${C.border}`, borderRadius: 5,
              padding: "24px", textAlign: "center", marginBottom: 12,
              color: C.textMuted, fontSize: 12,
            }}>
              <input
                type="file" accept=".json,.yaml,.yml"
                onChange={e => setFile(e.target.files[0])}
                style={{ display: "none" }} id="file-input"
              />
              <label htmlFor="file-input" style={{ cursor: "pointer", color: C.accent }}>
                {file ? file.name : "Click to select .json / .yaml"}
              </label>
            </div>
            <Btn onClick={uploadFile} disabled={loading || !file}>Upload File</Btn>
          </Panel>

          {/* Scan URL */}
          <Panel title="Scan URL">
            <Input
              value={apiUrl}
              onChange={e => setApiUrl(e.target.value)}
              placeholder="https://api.example.com"
              style={{ marginBottom: 12 }}
            />
            <Btn onClick={scanUrl} disabled={loading || !apiUrl}>Scan API</Btn>
          </Panel>
        </div>

        {/* Spec uploaded — run scan */}
        {specId && (
          <div style={{
            background: C.accentDim, border: `1px solid ${C.accent}33`,
            borderRadius: 6, padding: "14px 20px",
            display: "flex", alignItems: "center", justifyContent: "space-between",
            marginBottom: 24,
          }}>
            <span style={{ fontSize: 12, color: C.accent }}>
              Spec uploaded — ID: <code>{specId}</code>
            </span>
            <Btn onClick={runScan} disabled={loading}>▶ Run Scan</Btn>
          </div>
        )}

        {/* Report */}
        {report && (
          <>
            {/* Summary cards */}
            <div style={{ display: "flex", gap: 12, marginBottom: 24, flexWrap: "wrap" }}>
              <StatCard label="High Risks" value={report.summary.high_risks} color={C.red} />
              <StatCard label="Total Findings" value={report.summary.total_security_findings} color={C.yellow} />
              <StatCard label="Tests Run" value={report.summary.total_tests_run ?? "—"} color={C.accent} />
              <StatCard label="Failed Tests" value={report.summary.failed_tests} color={report.summary.failed_tests > 0 ? C.red : C.green} />
              <StatCard label="Passed Tests" value={report.summary.passed_tests ?? "—"} color={C.green} />
              <div style={{
                flex: 1, background: "#0d1525", border: `1px solid ${C.border}`,
                borderLeft: `3px solid ${report.summary.deployment_status === "healthy" ? C.green : C.red}`,
                borderRadius: 6, padding: "14px 18px", minWidth: 120,
              }}>
                <div style={{ fontSize: 13, marginBottom: 4 }}>
                  <StatusDot status={report.summary.deployment_status} />
                  <span style={{ color: report.summary.deployment_status === "healthy" ? C.green : C.red }}>
                    {report.summary.deployment_status?.toUpperCase()}
                  </span>
                </div>
                <div style={{ fontSize: 11, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                  Deployment
                </div>
              </div>
            </div>

            {/* Tab bar */}
            <div style={{ display: "flex", gap: 4, marginBottom: 16 }}>
              {tabs.map(t => (
                <button key={t.key} onClick={() => setActiveTab(t.key)} style={{
                  fontFamily: font, fontSize: 11, letterSpacing: "0.08em",
                  textTransform: "uppercase", padding: "8px 16px",
                  borderRadius: "5px 5px 0 0", cursor: "pointer",
                  border: `1px solid ${activeTab === t.key ? C.accent : C.border}`,
                  borderBottom: activeTab === t.key ? `1px solid ${C.surface}` : `1px solid ${C.border}`,
                  background: activeTab === t.key ? C.surface : C.bg,
                  color: activeTab === t.key ? C.accent : C.textMuted,
                }}>
                  {t.label}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div style={{
              background: C.surface, border: `1px solid ${C.accent}`,
              borderRadius: "0 5px 5px 5px", padding: 24,
            }}>

              {activeTab === "security" && (
                <SecurityTable findings={report.security_findings} />
              )}

              {activeTab === "tests" && (
                <TestResults results={report.api_test_results} />
              )}

              {activeTab === "recommendations" && (
                <div>
                  {(report.recommendations || []).length === 0 ? (
                    <p style={{ color: C.green, fontSize: 13 }}>✓ No recommendations — all clear.</p>
                  ) : (
                    (report.recommendations || []).map((r, i) => (
                      <div key={i} style={{
                        display: "flex", gap: 12, alignItems: "flex-start",
                        padding: "12px 16px", marginBottom: 8,
                        background: "#0d1525", border: `1px solid ${C.border}`,
                        borderLeft: `3px solid ${C.yellow}`, borderRadius: 5,
                      }}>
                        <span style={{ color: C.yellow, fontSize: 14, marginTop: 1 }}>▲</span>
                        <span style={{ color: C.textDim, fontSize: 13, lineHeight: 1.6 }}>{r}</span>
                      </div>
                    ))
                  )}
                </div>
              )}

              {activeTab === "llm" && (
                <div>
                  {report.llm_analysis ? (
                    <pre style={{
                      fontFamily: font, fontSize: 13, color: C.textDim,
                      lineHeight: 1.7, whiteSpace: "pre-wrap", margin: 0,
                    }}>
                      {report.llm_analysis}
                    </pre>
                  ) : (
                    <p style={{ color: C.textMuted, fontSize: 13 }}>
                      Set <code style={{ color: C.accent }}>ANTHROPIC_API_KEY</code> in your environment to enable AI analysis.
                    </p>
                  )}
                </div>
              )}
            </div>
          </>
        )}
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        code { background: ${C.accentDim}; color: ${C.accent}; padding: 1px 5px; border-radius: 3px; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
      `}</style>
    </div>
  );
}