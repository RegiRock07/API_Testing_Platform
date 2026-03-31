import React, { useState, useEffect, useCallback } from "react";

// ─── Config ───────────────────────────────────────────────────────
const BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";
const API_URL = BASE;
const APP_NAME = process.env.REACT_APP_APP_NAME || "API TESTING";

// FIX #1: mono/sans MUST be declared before C, because C.input and C.heading
// reference them. The original code had these declared AFTER C, causing a
// ReferenceError at runtime (temporal dead zone for const).
const mono = `'IBM Plex Mono', 'Courier New', monospace`;
const sans = `'DM Sans', system-ui, sans-serif`;

// ─── Design tokens ────────────────────────────────────────────────
const C = {
  bg: "#080c14",
  surface: "#0e1420",
  surfaceHigh: "#141c2e",
  border: "#1a2540",
  borderHigh: "#243050",
  accent: "#00c8ff",
  accentDim: "#00c8ff18",
  accentBorder: "#00c8ff33",
  primary: "#00c8ff",
  success: "#00e5a0",
  critical: "#ff4560",
  green: "#00e5a0",
  greenDim: "#00e5a012",
  yellow: "#ffb800",
  yellowDim: "#ffb80012",
  red: "#ff4560",
  redDim: "#ff456012",
  text: "#dde4f0",
  textMuted: "#4a5a7a",
  textDim: "#8899bb",
  sidebar: "#090d18",
  card: "#0e1420",
  btn: {
    background: "#00c8ff",
    color: "#000",
    border: "none",
    borderRadius: 4,
    padding: "9px 18px",
    fontSize: 12,
    fontWeight: 600,
    cursor: "pointer",
    textTransform: "uppercase",
    letterSpacing: "0.08em",
  },
  input: {
    fontFamily: mono,   // safe now — mono is declared above
    fontSize: 12,
    background: "#080c14",
    color: "#dde4f0",
    border: "1px solid #1a2540",
    borderRadius: 4,
    padding: "9px 12px",
    outline: "none",
    width: "100%",
    boxSizing: "border-box",
  },
  heading: { fontFamily: sans, fontSize: 16, fontWeight: 600, color: "#dde4f0", marginBottom: 12 },
  statCard: { background: "#141c2e", border: "1px solid #1a2540", borderRadius: 6, padding: "12px 16px", flex: 1, minWidth: 100 },
};

// ─── Helpers ──────────────────────────────────────────────────────
const sev = (s) => s === "CRITICAL" || s === "HIGH" ? C.red : s === "MEDIUM" ? C.yellow : C.green;
const sevBg = (s) => s === "CRITICAL" || s === "HIGH" ? C.redDim : s === "MEDIUM" ? C.yellowDim : C.greenDim;
const fmt = (iso) => new Date(iso).toLocaleString();

// ─── API hook ─────────────────────────────────────────────────────
// FIX #2 & #3: Accept `token` as a parameter so JWT auth flows through
// the single shared apiFetch. The duplicate apiFetch inside App() is removed.
function useApi(token) {
  const [apiKey, setApiKey] = useState(() => sessionStorage.getItem("sentinel_key") || "");

  const apiFetch = useCallback(async (path, opts = {}) => {
    const headers = { "Content-Type": "application/json", ...opts.headers };
    if (apiKey) headers["X-API-Key"] = apiKey;
    if (token) headers["Authorization"] = `Bearer ${token}`; // JWT support
    const res = await fetch(BASE + path, { ...opts, headers });
    if (res.status === 401) throw new Error("AUTH_FAILED");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  }, [apiKey, token]); // token included in deps

  const apiUpload = useCallback(async (path, formData) => {
    const headers = {};
    if (apiKey) headers["X-API-Key"] = apiKey;
    if (token) headers["Authorization"] = `Bearer ${token}`; // JWT support for uploads too
    const res = await fetch(BASE + path, { method: "POST", body: formData, headers });
    if (res.status === 401) throw new Error("AUTH_FAILED");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  }, [apiKey, token]);

  return { apiKey, setApiKey, apiFetch, apiUpload };
}

// ─── Sub-components ───────────────────────────────────────────────

function Pill({ label, color }) {
  return (
    <span style={{
      fontFamily: mono, fontSize: 10, fontWeight: 700,
      letterSpacing: "0.08em", padding: "2px 8px", borderRadius: 3,
      background: `${color}18`, color, border: `1px solid ${color}44`,
    }}>{label}</span>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div style={{
      background: C.surfaceHigh, border: `1px solid ${C.border}`,
      borderLeft: `3px solid ${color}`, borderRadius: 6,
      padding: "12px 16px", flex: 1, minWidth: 100,
    }}>
      <div style={{ fontFamily: mono, fontSize: 24, color, fontWeight: 700 }}>{value ?? "—"}</div>
      <div style={{ fontFamily: mono, fontSize: 10, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", marginTop: 2 }}>{label}</div>
    </div>
  );
}

function Btn({ onClick, children, variant = "primary", disabled, small }) {
  const map = {
    primary: { bg: C.accent, color: "#000", border: "none" },
    ghost: { bg: "transparent", color: C.accent, border: `1px solid ${C.accentBorder}` },
    danger: { bg: C.red, color: "#fff", border: "none" },
    subtle: { bg: C.surfaceHigh, color: C.textDim, border: `1px solid ${C.border}` },
  };
  const s = map[variant] || map.primary;
  return (
    <button onClick={onClick} disabled={disabled} style={{
      fontFamily: mono, fontSize: small ? 10 : 12, fontWeight: 600,
      letterSpacing: "0.08em", textTransform: "uppercase",
      padding: small ? "5px 10px" : "9px 18px", borderRadius: 4,
      cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? 0.4 : 1,
      background: s.bg, color: s.color, border: s.border,
      transition: "opacity 0.15s, filter 0.15s",
    }}>{children}</button>
  );
}

function Input({ value, onChange, placeholder, type = "text", style = {} }) {
  return (
    <input type={type} value={value} onChange={onChange} placeholder={placeholder}
      style={{
        fontFamily: mono, fontSize: 12, background: C.bg, color: C.text,
        border: `1px solid ${C.border}`, borderRadius: 4,
        padding: "9px 12px", outline: "none", width: "100%",
        boxSizing: "border-box", ...style,
      }} />
  );
}

// ─── Agent Progress (streaming) ───────────────────────────────────

const AGENTS = [
  { key: "planner", label: "Planner" },
  { key: "security", label: "Security" },
  { key: "api_testing", label: "API Testing" },
  { key: "deployment", label: "Deployment" },
  { key: "deep_scan", label: "Deep Scan" },
  { key: "synthesis", label: "Synthesis" },
];

function AgentProgress({ events }) {
  const stateMap = {};
  const metricMap = {};
  for (const e of events) {
    stateMap[e.agent] = e.status;
    if (e.data) {
      if (e.agent === "security" && e.data.total_findings !== undefined) {
        metricMap[e.agent] = `${e.data.total_findings} findings`;
      } else if (e.agent === "security" && e.data.critical_count !== undefined) {
        metricMap[e.agent] = `${e.data.critical_count} critical, ${e.data.high_count} high`;
      } else if (e.agent === "api_testing") {
        metricMap[e.agent] = e.data.api_was_reachable ? "reachable" : "unreachable";
      } else if (e.agent === "deployment") {
        metricMap[e.agent] = e.data.security_score || "";
      } else if (e.agent === "deep_scan") {
        metricMap[e.agent] = e.data.deep_scan_performed ? "performed" : "skipped";
      }
    }
  }

  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 7, padding: "16px 20px", marginBottom: 20,
    }}>
      <div style={{ fontFamily: mono, fontSize: 10, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 12 }}>
        Agent Progress
      </div>
      {AGENTS.map(a => {
        const status = stateMap[a.key] || "waiting";
        const icon = status === "running" ? "⟳" : status === "completed" ? "✓" : status === "skipped" ? "—" : "○";
        const color = status === "running" ? C.accent : status === "completed" ? C.green : status === "skipped" ? C.textMuted : C.textMuted;
        return (
          <div key={a.key} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
            <span style={{ fontFamily: mono, fontSize: 14, color, width: 20 }}>{icon}</span>
            <span style={{ fontFamily: mono, fontSize: 12, color: status === "waiting" ? C.textMuted : C.text, width: 100 }}>{a.label}</span>
            {metricMap[a.key] && (
              <span style={{ fontFamily: mono, fontSize: 10, color: C.textDim }}>{metricMap[a.key]}</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Login screen ───────────────────────────────────────────────

function LoginScreen({ onLogin }) {
  const [tab, setTab] = useState("login"); // "login" | "register"
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    const endpoint = tab === "login" ? "/api/auth/login" : "/api/auth/register";
    try {
      const res = await fetch(`${BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Failed");
      }
      const data = await res.json();
      if (tab === "login") {
        onLogin(data.token, { id: data.user_id, email: data.email });
      } else {
        setTab("login");
        setError("Registered! Please login.");
      }
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: C.bg }}>
      <div style={{ background: C.card, borderRadius: 12, padding: 40, width: 380, boxShadow: "0 4px 24px rgba(0,0,0,0.3)" }}>
        <div style={{ display: "flex", gap: 8, marginBottom: 24 }}>
          <button onClick={() => setTab("login")} style={{ ...C.btn, flex: 1, background: tab === "login" ? C.primary : C.surface }}>Login</button>
          <button onClick={() => setTab("register")} style={{ ...C.btn, flex: 1, background: tab === "register" ? C.primary : C.surface }}>Register</button>
        </div>
        <form onSubmit={handleSubmit}>
          <input style={{ ...C.input, marginBottom: 12 }} placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} type="email" required />
          <input style={{ ...C.input, marginBottom: 12 }} placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} type="password" required />
          {error && <div style={{ color: C.critical, marginBottom: 12, fontSize: 13 }}>{error}</div>}
          <button type="submit" style={{ ...C.btn, width: "100%", background: C.primary }}>
            {tab === "login" ? "Sign In" : "Create Account"}
          </button>
        </form>
      </div>
    </div>
  );
}

// ─── Scan Comparison ─────────────────────────────────────────────

function ScanComparison({ scanA, scanB, comparison }) {
  if (!comparison) return null;
  const { summary, resolved_findings, persistent_findings, worsened_findings, new_findings } = comparison;
  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 20 }}>
        <div style={{ ...C.statCard, background: "#1a3a1a" }}>
          <div style={{ fontSize: 11, color: "#4ade80", textTransform: "uppercase" }}>Resolved</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: "#4ade80" }}>{summary.findings_resolved}</div>
        </div>
        <div style={{ ...C.statCard, background: "#3a1a1a" }}>
          <div style={{ fontSize: 11, color: "#f87171", textTransform: "uppercase" }}>New</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: "#f87171" }}>{summary.findings_new}</div>
        </div>
        <div style={{ ...C.statCard, background: "#1a1a3a" }}>
          <div style={{ fontSize: 11, color: "#fbbf24", textTransform: "uppercase" }}>Worsened</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: "#fbbf24" }}>{summary.findings_worsened}</div>
        </div>
      </div>
      <div style={{ fontSize: 14, color: C.textMuted, marginBottom: 16 }}>
        Score improvement: <span style={{ color: summary.score_improvement > 0 ? "#4ade80" : summary.score_improvement < 0 ? "#f87171" : C.text }}>{summary.score_improvement > 0 ? "+" : ""}{summary.score_improvement}</span>
      </div>
      {resolved_findings && resolved_findings.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, color: "#4ade80", fontWeight: 600, marginBottom: 8, textTransform: "uppercase" }}>✓ Resolved</div>
          {resolved_findings.map((f, i) => (
            <div key={i} style={{ background: "#0d1f0d", borderLeft: "3px solid #4ade80", padding: "8px 12px", marginBottom: 6, borderRadius: 4 }}>
              <span style={{ color: C.textMuted, fontSize: 12 }}>{f.endpoint} [{f.method}]</span>
              <div style={{ color: "#4ade80", fontSize: 13 }}>{f.vulnerability || f.risk_type}</div>
            </div>
          ))}
        </div>
      )}
      {persistent_findings && persistent_findings.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, color: "#fbbf24", fontWeight: 600, marginBottom: 8, textTransform: "uppercase" }}>— Persistent</div>
          {persistent_findings.map((f, i) => (
            <div key={i} style={{ background: "#1f1a0d", borderLeft: "3px solid #fbbf24", padding: "8px 12px", marginBottom: 6, borderRadius: 4 }}>
              <span style={{ color: C.textMuted, fontSize: 12 }}>{f.endpoint} [{f.method}]</span>
              <div style={{ color: "#fbbf24", fontSize: 13 }}>{f.vulnerability || f.risk_type}</div>
            </div>
          ))}
        </div>
      )}
      {/* worsened_findings kept for completeness — displayed same style as new */}
      {worsened_findings && worsened_findings.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, color: "#fbbf24", fontWeight: 600, marginBottom: 8, textTransform: "uppercase" }}>↑ Worsened</div>
          {worsened_findings.map((f, i) => (
            <div key={i} style={{ background: "#1f1a0d", borderLeft: "3px solid #fbbf24", padding: "8px 12px", marginBottom: 6, borderRadius: 4 }}>
              <span style={{ color: C.textMuted, fontSize: 12 }}>{f.endpoint} [{f.method}]</span>
              <div style={{ color: "#fbbf24", fontSize: 13 }}>{f.vulnerability || f.risk_type}</div>
            </div>
          ))}
        </div>
      )}
      {new_findings && new_findings.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, color: "#f87171", fontWeight: 600, marginBottom: 8, textTransform: "uppercase" }}>✗ New</div>
          {new_findings.map((f, i) => (
            <div key={i} style={{ background: "#1f0d0d", borderLeft: "3px solid #f87171", padding: "8px 12px", marginBottom: 6, borderRadius: 4 }}>
              <span style={{ color: C.textMuted, fontSize: 12 }}>{f.endpoint} [{f.method}]</span>
              <div style={{ color: "#f87171", fontSize: 13 }}>{f.vulnerability || f.risk_type}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── History Sidebar ─────────────────────────────────────────────

function HistorySidebar({ apiFetch, onSelect, onCompare, activeId }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try { setScans(await apiFetch("/api/scans")); }
    catch { /* silently skip */ }
    finally { setLoading(false); }
  }, [apiFetch]);

  useEffect(() => { refresh(); }, [refresh]);

  const handleDelete = async (e, id) => {
    e.stopPropagation();
    try {
      await apiFetch(`/api/scans/${id}`, { method: "DELETE" });
      setScans(s => s.filter(x => x.id !== id));
    } catch { }
  };

  return (
    <div style={{
      width: 260, minWidth: 260, background: C.sidebar,
      borderRight: `1px solid ${C.border}`, display: "flex",
      flexDirection: "column", height: "100vh", overflow: "hidden",
    }}>
      <div style={{
        padding: "16px 16px 12px",
        borderBottom: `1px solid ${C.border}`,
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <span style={{ fontFamily: mono, fontSize: 11, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.08em" }}>
          Scan History
        </span>
        <button onClick={refresh} style={{
          fontFamily: mono, fontSize: 11, color: C.textMuted,
          background: "none", border: "none", cursor: "pointer",
        }}>
          {loading ? "…" : "↻"}
        </button>
      </div>

      <div style={{ flex: 1, overflowY: "auto" }}>
        {scans.length === 0 && !loading && (
          <div style={{ padding: "24px 16px", fontFamily: mono, fontSize: 11, color: C.textMuted, textAlign: "center" }}>
            No scans yet
          </div>
        )}
        {scans.map(s => {
          const isActive = s.id === activeId;
          return (
            <div key={s.id}
              onClick={() => onSelect(s)}
              style={{
                padding: "10px 14px", cursor: "pointer",
                background: isActive ? C.accentDim : "transparent",
                borderLeft: `2px solid ${isActive ? C.accent : "transparent"}`,
                borderBottom: `1px solid ${C.border}22`,
                transition: "background 0.15s",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div style={{ fontFamily: mono, fontSize: 11, color: isActive ? C.accent : C.text, marginBottom: 3, wordBreak: "break-all" }}>
                  {s.api_title || s.name}
                </div>
                <button onClick={e => handleDelete(e, s.id)} style={{
                  background: "none", border: "none", color: C.textMuted,
                  cursor: "pointer", fontSize: 13, lineHeight: 1, marginLeft: 6,
                  flexShrink: 0,
                }}>×</button>
              </div>
              <div style={{ fontFamily: mono, fontSize: 10, color: C.textMuted }}>
                {s.endpoint_count} endpoints · {fmt(s.created_at)}
              </div>
              <div style={{ marginTop: 4 }}>
                <Pill label={s.status} color={s.status === "completed" ? C.green : C.yellow} />
              </div>
              {isActive && s.status === "completed" && (
                <button
                  onClick={(e) => { e.stopPropagation(); onCompare(s); }}
                  style={{
                    marginTop: 6, width: "100%", padding: "5px 8px",
                    fontFamily: mono, fontSize: 10, fontWeight: 600,
                    letterSpacing: "0.06em", textTransform: "uppercase",
                    background: C.accentDim, color: C.accent,
                    border: `1px solid ${C.accentBorder}`, borderRadius: 3,
                    cursor: "pointer",
                  }}
                >
                  Compare
                </button>
              )}
            </div>
          );
        })}
      </div>

      <div style={{ padding: "12px 16px", borderTop: `1px solid ${C.border}` }}>
        <div style={{ fontFamily: mono, fontSize: 10, color: C.textMuted }}>
          ◈ {APP_NAME} · {BASE.replace("http://", "").replace("https://", "")}
        </div>
      </div>
    </div>
  );
}

// ─── Security Findings ────────────────────────────────────────────

function SecurityTable({ findings = [] }) {
  const [exp, setExp] = useState(null);
  if (!findings.length) return <p style={{ fontFamily: mono, color: C.green, fontSize: 12 }}>✓ No findings.</p>;

  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: mono, fontSize: 12 }}>
      <thead>
        <tr style={{ borderBottom: `1px solid ${C.border}` }}>
          {["Endpoint", "Vulnerability", "Severity", "Details"].map(h => (
            <th key={h} style={{ color: C.textMuted, fontWeight: 600, padding: "8px 10px", textAlign: "left", fontSize: 10, letterSpacing: "0.06em" }}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {findings.map((f, i) => {
          const vulnName = f.vulnerability || f.risk_type || "Unknown";
          return (
            <React.Fragment key={i}>
              <tr onClick={() => setExp(exp === i ? null : i)}
                style={{ borderBottom: `1px solid ${C.border}22`, cursor: "pointer" }}>
                <td style={{ padding: "9px 10px", color: C.accent }}>{f.endpoint}</td>
                <td style={{ padding: "9px 10px", color: C.text }}>{vulnName}</td>
                <td style={{ padding: "9px 10px" }}>
                  <span style={{ display: "flex", gap: 5, alignItems: "center" }}>
                    <span style={{ background: sevBg(f.severity), color: sev(f.severity), padding: "2px 8px", borderRadius: 3, border: `1px solid ${sev(f.severity)}44`, fontWeight: 700 }}>
                      {f.severity}
                    </span>
                    {f.exploit_poc && (
                      <Pill label="DEEP SCAN" color={C.accent} />
                    )}
                  </span>
                </td>
                <td style={{ padding: "9px 10px", color: C.textMuted, fontSize: 11 }}>{exp === i ? "▲ hide" : "▼ show"}</td>
              </tr>
              {exp === i && (
                <tr><td colSpan={4} style={{ padding: "0 10px 10px" }}>
                  <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 4, padding: "10px 14px", color: C.textDim, lineHeight: 1.6 }}>
                    {f.owasp_category && <div style={{ marginBottom: 6 }}><strong style={{ color: C.textMuted }}>OWASP Category:</strong> <span style={{ color: C.accent }}>{f.owasp_category}</span></div>}
                    {f.description && <div style={{ marginBottom: 6 }}><strong style={{ color: C.textMuted }}>Description:</strong> {f.description}</div>}
                    {f.evidence && <div style={{ marginBottom: 6 }}><strong style={{ color: C.textMuted }}>Evidence:</strong> {f.evidence}</div>}
                    {f.exploit_scenario && <div style={{ marginBottom: 6 }}><strong style={{ color: C.textMuted }}>Exploit:</strong> {f.exploit_scenario}</div>}
                    {f.remediation && <div style={{ marginBottom: 6 }}><strong style={{ color: C.textMuted }}>Remediation:</strong> {f.remediation}</div>}
                    {f.exploit_poc && (
                      <div>
                        <strong style={{ color: C.textMuted }}>Proof of Concept:</strong>
                        <div style={{ marginTop: 6, background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, padding: "8px 12px", fontSize: 11 }}>
                          <div style={{ marginBottom: 4 }}>{f.exploit_poc.summary}</div>
                          {f.exploit_poc.steps && f.exploit_poc.steps.map((s, si) => (
                            <div key={si} style={{ color: C.textDim }}>{si + 1}. {s}</div>
                          ))}
                          {f.exploit_poc.sample_curl && (
                            <div style={{ marginTop: 6, background: C.bg, padding: "4px 8px", borderRadius: 3, color: C.accent, fontSize: 10, wordBreak: "break-all" }}>
                              {f.exploit_poc.sample_curl}
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </td></tr>
              )}
            </React.Fragment>
          );
        })}
      </tbody>
    </table>
  );
}

// ─── API Test Results ─────────────────────────────────────────────

function TestResults({ results = [], apiWasReachable }) {
  const [open, setOpen] = useState(null);

  if (!results.length) {
    return <p style={{ fontFamily: mono, color: C.textMuted, fontSize: 12 }}>No test results.</p>;
  }

  if (!apiWasReachable) {
    return (
      <div style={{
        background: C.surfaceHigh, border: `1px solid ${C.border}`,
        borderRadius: 6, padding: "16px 20px", textAlign: "center",
      }}>
        <div style={{ fontFamily: mono, fontSize: 12, color: C.textMuted, marginBottom: 8 }}>
          ⚠ API was not reachable — tests skipped
        </div>
        <div style={{ fontFamily: mono, fontSize: 11, color: C.textMuted }}>
          Connection errors are not counted as security failures.
        </div>
      </div>
    );
  }

  return results.map((ep, i) => {
    const tests = ep.tests || [];
    const passed = tests.filter(t => t.passed === true).length;
    const failed = tests.filter(t => t.passed === false && !t.connection_error).length;
    const errors = tests.filter(t => t.connection_error).length;
    return (
      <div key={i} style={{ marginBottom: 6 }}>
        <div onClick={() => setOpen(open === i ? null : i)} style={{
          display: "flex", justifyContent: "space-between", alignItems: "center",
          background: C.surfaceHigh, border: `1px solid ${C.border}`,
          borderRadius: open === i ? "4px 4px 0 0" : 4,
          padding: "9px 14px", cursor: "pointer", fontFamily: mono, fontSize: 12,
        }}>
          <span style={{ color: C.accent }}>{ep.method} {ep.endpoint}</span>
          <span>
            <span style={{ color: C.green }}>{passed}✓</span>
            <span style={{ color: C.textMuted, margin: "0 6px" }}>/</span>
            {failed > 0 && <span style={{ color: C.red }}>{failed}✗</span>}
            {errors > 0 && <span style={{ color: C.textMuted }}>{errors}⚠</span>}
            <span style={{ color: C.textMuted, marginLeft: 12 }}>{open === i ? "▲" : "▼"}</span>
          </span>
        </div>
        {open === i && (
          <div style={{ border: `1px solid ${C.border}`, borderTop: "none", borderRadius: "0 0 4px 4px" }}>
            {tests.map((t, j) => {
              if (t.test === "dynamic_fuzz_testing") {
                return (
                  <div key={j} style={{ padding: "10px 14px", borderBottom: `1px solid ${C.border}22`, fontFamily: mono, fontSize: 11 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                      <span style={{ color: C.textDim }}>fuzz_testing</span>
                      <span style={{ color: t.vulnerable_count > 0 ? C.red : C.green }}>
                        {t.vulnerable_count} / {t.total_payloads} flagged
                      </span>
                    </div>
                    {(t.results || []).filter(r => r.possible_vulnerability).map((r, k) => (
                      <div key={k} style={{
                        background: C.redDim, border: `1px solid ${C.red}33`,
                        borderRadius: 3, padding: "5px 9px", marginBottom: 3, color: C.red, fontSize: 10,
                      }}>
                        ⚠ {r.payload} → {r.status_code || r.error}
                      </div>
                    ))}
                  </div>
                );
              }
              const isConnError = t.connection_error;
              const pillColor = isConnError ? C.textMuted : t.passed ? C.green : C.red;
              return (
                <div key={j} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  padding: "7px 14px", borderBottom: `1px solid ${C.border}22`,
                  fontFamily: mono, fontSize: 11,
                }}>
                  <span style={{ color: C.textDim }}>{t.test}</span>
                  <span style={{ display: "flex", gap: 10, alignItems: "center" }}>
                    {t.status_code && <span style={{ color: C.textMuted }}>HTTP {t.status_code}</span>}
                    {t.error && <span style={{ color: isConnError ? C.textMuted : C.red, fontSize: 10 }}>{t.error.slice(0, 50)}</span>}
                    <Pill label={isConnError ? "UNREACHABLE" : t.passed ? "PASS" : "FAIL"} color={pillColor} />
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  });
}

// ─── Report viewer ───────────────────────────────────────────────
// FIX #4: Accept `initialTab` prop so that handleCompare() in App can
// programmatically switch to the "compare" tab after fetching comparison data.

function ReportView({ report, comparisonResult, initialTab }) {
  // FIX #4: Use initialTab when provided, default to "security"
  const [tab, setTab] = useState(initialTab || "security");

  // FIX #4: Sync if parent changes initialTab (e.g. after handleCompare)
  useEffect(() => {
    if (initialTab) setTab(initialTab);
  }, [initialTab]);

  const s = report.summary || {};

  const tabs = [
    { key: "security", label: "Security" },
    { key: "tests", label: "API Tests" },
    { key: "planner", label: "Planner" },
    { key: "recs", label: "Recommendations" },
    { key: "roadmap", label: "Roadmap" },
    { key: "llm", label: "AI Analysis" },
    { key: "compare", label: "Compare" },
    { key: "export", label: "Export" },
  ];

  return (
    <div>
      {/* Summary cards */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
        <StatCard label="Critical Risks" value={s.critical_risks} color={s.critical_risks > 0 ? C.red : C.green} />
        <StatCard label="High Risks" value={s.high_risks} color={s.high_risks > 0 ? C.red : C.green} />
        <StatCard label="Total Findings" value={s.total_security_findings} color={C.yellow} />
        <StatCard label="Tests Run" value={s.total_tests_run} color={C.accent} />
        <StatCard label="Failed" value={s.failed_tests} color={s.failed_tests > 0 ? C.red : C.green} />
        <StatCard label="Passed" value={s.passed_tests} color={C.green} />
        <StatCard label="Security Score" value={s.security_score || s.deployment_security_score || "—"} color={C.accent} />
        <div style={{
          background: C.surfaceHigh, border: `1px solid ${C.border}`,
          borderLeft: `3px solid ${s.deployment_status === "healthy" ? C.green : C.red}`,
          borderRadius: 6, padding: "12px 16px", flex: 1, minWidth: 100,
        }}>
          <div style={{ fontFamily: mono, fontSize: 13, marginBottom: 2 }}>
            <span style={{
              display: "inline-block", width: 7, height: 7, borderRadius: "50%",
              background: s.deployment_status === "healthy" ? C.green : C.red,
              marginRight: 6, boxShadow: `0 0 5px ${s.deployment_status === "healthy" ? C.green : C.red}`,
            }} />
            <span style={{ color: s.deployment_status === "healthy" ? C.green : C.red }}>
              {(s.deployment_status || "—").toUpperCase()}
            </span>
          </div>
          <div style={{ fontFamily: mono, fontSize: 10, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.08em" }}>Deployment</div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 3, marginBottom: -1 }}>
        {tabs.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)} style={{
            fontFamily: mono, fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase",
            padding: "7px 14px", borderRadius: "4px 4px 0 0", cursor: "pointer",
            border: `1px solid ${C.border}`,
            borderBottom: tab === t.key ? `1px solid ${C.surface}` : `1px solid ${C.border}`,
            background: tab === t.key ? C.surface : C.bg,
            color: tab === t.key ? C.accent : C.textMuted,
          }}>{t.label}</button>
        ))}
      </div>

      <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: "0 4px 4px 4px", padding: 20 }}>

        {tab === "security" && <SecurityTable findings={report.security_findings} />}

        {tab === "tests" && (
          <TestResults
            results={report.api_test_results}
            apiWasReachable={s.api_was_reachable}
          />
        )}

        {tab === "planner" && (
          <div>
            {report.planner_assessment && Object.keys(report.planner_assessment).length > 0 ? (
              <>
                {report.planner_assessment.risk_summary && (
                  <div style={{ marginBottom: 20, fontFamily: sans, fontSize: 13, color: C.textDim, lineHeight: 1.7 }}>
                    {report.planner_assessment.risk_summary}
                  </div>
                )}
                {report.planner_assessment.auth_pattern_detected && (
                  <div style={{ marginBottom: 16 }}>
                    <span style={{ fontFamily: mono, fontSize: 10, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>Auth Pattern: </span>
                    <Pill label={report.planner_assessment.auth_pattern_detected.toUpperCase()} color={C.accent} />
                  </div>
                )}
                {report.planner_assessment.high_risk_endpoints && report.planner_assessment.high_risk_endpoints.length > 0 && (
                  <div style={{ fontFamily: mono, fontSize: 12, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 10 }}>High Risk Endpoints</div>
                )}
                {(report.planner_assessment.high_risk_endpoints || []).map((h, i) => (
                  <div key={i} style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 4, padding: "10px 14px", marginBottom: 8 }}>
                    <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 4 }}>
                      <Pill label={h.method} color={C.accent} />
                      <span style={{ fontFamily: mono, fontSize: 12, color: C.text }}>{h.path}</span>
                      <Pill label={h.risk_level} color={h.risk_level === "CRITICAL" ? C.red : h.risk_level === "HIGH" ? C.red : C.yellow} />
                    </div>
                    {h.risk_reasons && h.risk_reasons.length > 0 && (
                      <div style={{ marginBottom: 4 }}>
                        {h.risk_reasons.map((r, ri) => (
                          <div key={ri} style={{ fontFamily: mono, fontSize: 11, color: C.textDim }}>• {r}</div>
                        ))}
                      </div>
                    )}
                    {h.attack_vectors && h.attack_vectors.length > 0 && (
                      <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 4 }}>
                        {h.attack_vectors.map((a, ai) => (
                          <Pill key={ai} label={a} color={C.yellow} />
                        ))}
                      </div>
                    )}
                  </div>
                ))}
                {report.planner_assessment.business_logic_risks && report.planner_assessment.business_logic_risks.length > 0 && (
                  <>
                    <div style={{ fontFamily: mono, fontSize: 12, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 10, marginTop: 16 }}>Business Logic Risks</div>
                    {report.planner_assessment.business_logic_risks.map((r, i) => (
                      <div key={i} style={{ fontFamily: mono, fontSize: 11, color: C.textDim, marginBottom: 4 }}>• {r}</div>
                    ))}
                  </>
                )}
              </>
            ) : (
              <p style={{ fontFamily: mono, color: C.textMuted, fontSize: 12 }}>No planner assessment available. Run scan with Ollama for LLM-powered planning.</p>
            )}
          </div>
        )}

        {tab === "recs" && (
          <div>
            {!(report.recommendations || []).length
              ? <p style={{ fontFamily: mono, color: C.green, fontSize: 12 }}>✓ No recommendations.</p>
              : (report.recommendations || []).map((r, i) => (
                <div key={i} style={{
                  display: "flex", gap: 10, padding: "10px 14px", marginBottom: 6,
                  background: C.bg, border: `1px solid ${C.border}`,
                  borderLeft: `3px solid ${C.yellow}`, borderRadius: 4,
                }}>
                  <span style={{ color: C.yellow }}>▲</span>
                  <span style={{ fontFamily: sans, fontSize: 13, color: C.textDim, lineHeight: 1.6 }}>{r}</span>
                </div>
              ))
            }
          </div>
        )}

        {tab === "roadmap" && (
          <div>
            {report.remediation_roadmap && Object.keys(report.remediation_roadmap).length > 0 ? (
              <>
                {(["immediate", "short_term", "long_term"]).map(phase => (
                  report.remediation_roadmap[phase] && report.remediation_roadmap[phase].length > 0 && (
                    <div key={phase} style={{ marginBottom: 20 }}>
                      <div style={{ fontFamily: mono, fontSize: 11, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8, display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ width: 8, height: 8, borderRadius: "50%", background: phase === "immediate" ? C.red : phase === "short_term" ? C.yellow : C.green, display: "inline-block" }} />
                        {phase.replace("_", " ")}
                      </div>
                      {(report.remediation_roadmap[phase] || []).map((item, i) => (
                        <div key={i} style={{ display: "flex", gap: 10, padding: "8px 12px", marginBottom: 4, background: C.bg, border: `1px solid ${C.border}`, borderRadius: 4 }}>
                          <span style={{ color: C.textDim, fontFamily: mono, fontSize: 12 }}>{i + 1}.</span>
                          <span style={{ fontFamily: sans, fontSize: 13, color: C.textDim, lineHeight: 1.5 }}>{item}</span>
                        </div>
                      ))}
                    </div>
                  )
                ))}
              </>
            ) : (
              <p style={{ fontFamily: mono, color: C.textMuted, fontSize: 12 }}>No roadmap available. Run scan with Ollama for LLM-powered synthesis.</p>
            )}
          </div>
        )}

        {tab === "llm" && (
          report.executive_summary
            ? (
              <div>
                <div style={{
                  background: C.accentDim, border: `1px solid ${C.accentBorder}`,
                  borderRadius: 6, padding: "14px 18px",
                  fontFamily: sans, fontSize: 14, color: C.text, lineHeight: 1.7,
                  marginBottom: 16
                }}>
                  {report.executive_summary}
                </div>
                {report.synthesis && report.synthesis.cross_cutting_concerns && report.synthesis.cross_cutting_concerns.length > 0 && (
                  <div>
                    <div style={{ fontFamily: mono, fontSize: 10, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 10 }}>Cross-Cutting Concerns</div>
                    {report.synthesis.cross_cutting_concerns.map((c, i) => (
                      <div key={i} style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 4, padding: "10px 14px", marginBottom: 8 }}>
                        <div style={{ fontFamily: mono, fontSize: 11, color: C.yellow, marginBottom: 4 }}>{c.pattern}</div>
                        <div style={{ fontFamily: sans, fontSize: 13, color: C.textDim }}>{c.description}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
            : (
              <div>
                <p style={{ fontFamily: mono, color: C.textMuted, fontSize: 12, marginBottom: 12 }}>
                  Start Ollama and pull a model to enable AI-powered analysis:
                </p>
                <pre style={{ fontFamily: mono, fontSize: 11, color: C.accent, background: C.bg, padding: "12px 16px", borderRadius: 4, border: `1px solid ${C.border}` }}>
                  ollama serve
                  ollama pull llama3.1:8b
                </pre>
              </div>
            )
        )}

        {tab === "compare" && (
          <div>
            <h3 style={{ ...C.heading, marginBottom: 16 }}>Scan Comparison</h3>
            {comparisonResult ? (
              <ScanComparison scanA={report.scan_id} scanB={report.scan_id} comparison={comparisonResult} />
            ) : (
              <div style={{ color: C.textMuted, textAlign: "center", padding: 40 }}>
                Run a comparison from the History sidebar to see diff.
              </div>
            )}
          </div>
        )}

        {tab === "export" && (
          <div>
            <h3 style={{ ...C.heading, marginBottom: 16 }}>Export Report</h3>
            <div style={{ display: "flex", gap: 12 }}>
              <button
                onClick={() => window.open(`${API_URL}/api/scans/${report.scan_id}/report/export/json`, "_blank")}
                style={{ ...C.btn, background: C.success }}
              >
                Export JSON
              </button>
              <button
                onClick={() => window.open(`${API_URL}/api/scans/${report.scan_id}/report/export/pdf`, "_blank")}
                style={{ ...C.btn, background: C.primary }}
              >
                Export PDF
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────

export default function App() {
  // FIX #3: token state MUST be declared before useApi() so it can be passed in.
  // Persist the current auth token and user to sessionStorage so reloads keep
  // the session alive and unauthorized requests are not fired automatically.
  const [token, setToken] = useState(() => sessionStorage.getItem("token") || null);
  const [user, setUser] = useState(() => {
    const stored = sessionStorage.getItem("user");
    return stored ? JSON.parse(stored) : null;
  });

  // FIX #2: Pass token into useApi so apiFetch includes the Authorization header.
  // The duplicate apiFetch declared inside App() below has been removed entirely.
  const { apiKey, apiFetch, apiUpload } = useApi(token);

  const [authChecked, setAuthChecked] = useState(false);
  const [needsAuth, setNeedsAuth] = useState(false);

  useEffect(() => {
    fetch(BASE + "/health").then(r => {
      if (r.status === 401 && !apiKey) setNeedsAuth(true);
      setAuthChecked(true);
    }).catch(() => setAuthChecked(true));
  }, [apiKey]);

  const [specText, setSpecText] = useState("");
  const [specId, setSpecId] = useState(null);
  const [file, setFile] = useState(null);
  const [apiUrl, setApiUrl] = useState("");
  const [report, setReport] = useState(null);
  const [activeScanId, setActiveScanId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [sidebarKey, setSidebarKey] = useState(0);
  const [streamEvents, setStreamEvents] = useState([]);
  // FIX #5: Removed unused `schedules` and `webhooks` state.
  const [comparisonResult, setComparisonResult] = useState(null);
  const [showLogin, setShowLogin] = useState(false);
  // FIX #4: activeTab2 now wires to ReportView's initialTab prop so
  // handleCompare() can actually switch the visible tab after fetching data.
  const [activeTab2, setActiveTab2] = useState("security");

  // ── NO duplicate apiFetch here (FIX #2) ──────────────────────────

  const wrap = async (fn) => {
    setLoading(true); setError("");
    try { await fn(); }
    catch (e) {
      if (e.message === "AUTH_FAILED") { setNeedsAuth(true); return; }
      setError(e.message || "Request failed");
    }
    finally { setLoading(false); }
  };

  const uploadSpec = () => wrap(async () => {
    let parsed;
    try { parsed = JSON.parse(specText); } catch { throw new Error("Invalid JSON"); }
    const data = await apiFetch("/api/specs/upload", {
      method: "POST",
      body: JSON.stringify({ name: "uploaded_spec", spec: parsed }),
    });
    setSpecId(data.id); setActiveScanId(data.id);
  });

  const uploadFile = () => wrap(async () => {
    if (!file) throw new Error("No file selected");
    const form = new FormData(); form.append("file", file);
    const data = await apiUpload("/api/specs/upload-file", form);
    setSpecId(data.id); setActiveScanId(data.id);
  });

  // FIX #6: runScanStream now includes the JWT Authorization header in addition
  // to the API key header. Previously, JWT-authenticated users would get 401.
  const runScanStream = async () => {
    if (!specId) return;
    setLoading(true);
    setError("");
    setReport(null);
    setStreamEvents([]);

    try {
      const headers = {};
      if (apiKey) headers["X-API-Key"] = apiKey;
      if (token) headers["Authorization"] = `Bearer ${token}`; // FIX #6

      const response = await fetch(`${BASE}/api/run/${specId}/stream`, {
        method: "POST",
        headers
      });

      if (response.status === 401) { setNeedsAuth(true); return; }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      const events = [];

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const text = decoder.decode(value, { stream: true });
        const lines = text.split("\n").filter(l => l.startsWith("data: "));

        for (const line of lines) {
          const raw = line.slice(6).trim();
          if (raw === "[DONE]") break;
          try {
            const event = JSON.parse(raw);
            events.push(event);
            setStreamEvents([...events]);

            if (event.agent === "report" && event.status === "completed" && event.data && event.data.report) {
              setReport(event.data.report);
              setActiveScanId(specId);
              setSidebarKey(k => k + 1);
            }
          } catch { /* ignore malformed */ }
        }
      }
    } catch (e) {
      setError(e.message || "Scan failed");
    } finally {
      setLoading(false);
      setStreamEvents([]);
    }
  };

  const verifyFix = async () => {
    if (!specId) return;
    setLoading(true);
    setError("");
    try {
      const data = await apiFetch(`/api/run/${specId}/verify-fix`, { method: "POST" });
      setReport(data.result || data);
    } catch (e) {
      setError(e.message || "Verify fix failed");
    } finally {
      setLoading(false);
    }
  };

  const scanUrl = () => wrap(async () => {
    if (!apiUrl) throw new Error("Enter a URL");
    const data = await apiFetch("/api/scan-url", {
      method: "POST",
      body: JSON.stringify({ base_url: apiUrl }),
    });
    setReport(data.result);
    setActiveScanId(data.spec_id);
    setSidebarKey(k => k + 1);
  });

  const loadHistoryScan = async (scan) => {
    setError("");
    setActiveScanId(scan.id);
    if (scan.status !== "completed") {
      setReport(null);
      setSpecId(scan.id);
      return;
    }
    try {
      const rep = await apiFetch(`/api/scans/${scan.id}/report`);
      setReport(rep);
      setSpecId(scan.id);
    } catch (e) {
      setError(e.message);
    }
  };

  // FIX #7: Removed redundant `headers: { "Content-Type": "application/json" }`
  // from this call — apiFetch already sets Content-Type by default.
  // FIX #4: setActiveTab2("compare") now actually works because ReportView
  // receives activeTab2 as the `initialTab` prop and syncs to it via useEffect.
  const handleCompare = async (scanA) => {
    setError("");
    try {
      const scans = await apiFetch("/api/scans");
      const sortedScans = scans.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      const idxA = sortedScans.findIndex(s => s.id === scanA.id);
      const scanB = sortedScans[idxA + 1];
      if (!scanB) {
        setError("No previous scan found to compare with");
        return;
      }
      const comp = await apiFetch("/api/scans/compare", {
        method: "POST",
        // FIX #7: removed redundant Content-Type header
        body: JSON.stringify({ scan_a_id: scanB.id, scan_b_id: scanA.id }),
      });
      setComparisonResult(comp);
      setActiveTab2("compare"); // now actually switches the tab (FIX #4)
    } catch (e) {
      setError(e.message || "Comparison failed");
    }
  };

  if (!authChecked) return null;

  if ((!user && !apiKey) || needsAuth || showLogin) {
    return <LoginScreen onLogin={(t, u) => {
      setToken(t);
      setUser(u);
      sessionStorage.setItem("token", t);
      sessionStorage.setItem("user", JSON.stringify(u));
      setShowLogin(false);
    }} />;
  }

  return (
    <div style={{ display: "flex", height: "100vh", background: C.bg, fontFamily: sans, color: C.text, overflow: "hidden" }}>

      <HistorySidebar
        key={sidebarKey}
        apiFetch={apiFetch}
        onSelect={loadHistoryScan}
        onCompare={handleCompare}
        activeId={activeScanId}
      />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>

        {/* Topbar */}
        <div style={{
          height: 52, background: C.surface, borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", padding: "0 24px", flexShrink: 0,
          justifyContent: "space-between",
        }}>
          <span style={{ fontFamily: mono, fontSize: 13, color: C.accent, letterSpacing: "0.1em" }}>
            ◈ {APP_NAME}
          </span>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            {loading && <span style={{ fontFamily: mono, fontSize: 11, color: C.yellow }}>⟳ scanning…</span>}
            {user ? (
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span style={{ fontFamily: mono, fontSize: 13, color: C.textMuted }}>{user.email}</span>
                <button onClick={() => {
                  setUser(null);
                  setToken(null);
                  sessionStorage.removeItem("token");
                  sessionStorage.removeItem("user");
                }} style={{ fontFamily: mono, fontSize: 10, color: C.textMuted, background: "none", border: "none", cursor: "pointer" }}>
                  Logout
                </button>
              </div>
            ) : (
              <button onClick={() => setShowLogin(true)} style={{ fontFamily: mono, fontSize: 11, color: C.accent, background: "none", border: "pointer" }}>
                Login
              </button>
            )}
          </div>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "24px 28px" }}>

          {/* Error */}
          {error && (
            <div style={{
              background: C.redDim, border: `1px solid ${C.red}44`,
              borderRadius: 5, padding: "10px 14px",
              fontFamily: mono, fontSize: 12, color: C.red, marginBottom: 18,
            }}>✕ {error}</div>
          )}

          {/* Agent progress */}
          {loading && streamEvents.length > 0 && <AgentProgress events={streamEvents} />}

          {/* Input panels */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 20 }}>

            {/* Paste JSON */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 7, overflow: "hidden" }}>
              <div style={{ padding: "10px 14px", borderBottom: `1px solid ${C.border}`, fontFamily: mono, fontSize: 10, color: C.accent, textTransform: "uppercase", letterSpacing: "0.08em" }}>
                Paste OpenAPI JSON
              </div>
              <div style={{ padding: 14 }}>
                <textarea rows={6} value={specText} onChange={e => setSpecText(e.target.value)}
                  placeholder={"{\n  \"openapi\": \"3.0.0\",\n  ...\n}"}
                  style={{
                    fontFamily: mono, fontSize: 11, background: C.bg, color: C.text,
                    border: `1px solid ${C.border}`, borderRadius: 4, padding: 10,
                    width: "100%", resize: "vertical", outline: "none",
                    boxSizing: "border-box", marginBottom: 10,
                  }} />
                <Btn onClick={uploadSpec} disabled={loading || !specText}>Upload JSON</Btn>
              </div>
            </div>

            {/* Upload file */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 7, overflow: "hidden" }}>
              <div style={{ padding: "10px 14px", borderBottom: `1px solid ${C.border}`, fontFamily: mono, fontSize: 10, color: C.accent, textTransform: "uppercase", letterSpacing: "0.08em" }}>
                Upload File
              </div>
              <div style={{ padding: 14 }}>
                <div style={{
                  border: `1px dashed ${C.border}`, borderRadius: 5,
                  padding: "28px 14px", textAlign: "center", marginBottom: 10,
                }}>
                  <input type="file" accept=".json,.yaml,.yml"
                    onChange={e => setFile(e.target.files[0])}
                    style={{ display: "none" }} id="fup" />
                  <label htmlFor="fup" style={{ fontFamily: mono, fontSize: 11, color: C.accent, cursor: "pointer" }}>
                    {file ? file.name : "Click to select .json / .yaml"}
                  </label>
                </div>
                <Btn onClick={uploadFile} disabled={loading || !file}>Upload File</Btn>
              </div>
            </div>

            {/* Scan URL */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 7, overflow: "hidden" }}>
              <div style={{ padding: "10px 14px", borderBottom: `1px solid ${C.border}`, fontFamily: mono, fontSize: 10, color: C.accent, textTransform: "uppercase", letterSpacing: "0.08em" }}>
                Scan API URL
              </div>
              <div style={{ padding: 14 }}>
                <Input value={apiUrl} onChange={e => setApiUrl(e.target.value)}
                  placeholder="https://api.yourcompany.com" style={{ marginBottom: 10 }} />
                <Btn onClick={scanUrl} disabled={loading || !apiUrl}>Scan URL</Btn>
              </div>
            </div>

          </div>

          {/* Run scan banner */}
          {specId && !report && (
            <div style={{
              background: C.accentDim, border: `1px solid ${C.accentBorder}`,
              borderRadius: 6, padding: "12px 18px",
              display: "flex", alignItems: "center", justifyContent: "space-between",
              marginBottom: 20, fontFamily: mono, fontSize: 12,
            }}>
              <span style={{ color: C.accent }}>
                Spec uploaded — ID: <code>{specId}</code>
              </span>
              <div style={{ display: "flex", gap: 10 }}>
                <Btn onClick={runScanStream} disabled={loading}>▶ Run Security Scan</Btn>
                <Btn onClick={verifyFix} disabled={loading}>Verify Fix</Btn>
              </div>
            </div>
          )}

          {/* FIX #4: Pass activeTab2 as initialTab so handleCompare can switch tabs */}
          {report && (
            <ReportView
              report={report}
              comparisonResult={comparisonResult}
              initialTab={activeTab2}
            />
          )}

          {/* Empty state */}
          {!report && !specId && (
            <div style={{ textAlign: "center", marginTop: 60 }}>
              <div style={{ fontFamily: mono, fontSize: 36, color: C.border, marginBottom: 12 }}>◈</div>
              <div style={{ fontFamily: mono, fontSize: 13, color: C.textMuted }}>
                Upload a spec or enter an API URL to begin scanning
              </div>
            </div>
          )}

        </div>
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=DM+Sans:wght@400;500&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        code { background: ${C.accentDim}; color: ${C.accent}; padding: 1px 5px; border-radius: 3px; font-family: ${mono}; font-size: 0.9em; }
      `}</style>
    </div>
  );
}