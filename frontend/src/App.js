import React, { useState, useEffect, useCallback } from "react";

// ─── Step 1: configurable via .env ───────────────────────────────
const BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";
const APP_NAME = process.env.REACT_APP_APP_NAME || "API TESTING";

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
};

const mono = `'IBM Plex Mono', 'Courier New', monospace`;
const sans = `'DM Sans', system-ui, sans-serif`;

// ─── Helpers ──────────────────────────────────────────────────────
const sev = (s) => s === "HIGH" ? C.red : s === "MEDIUM" ? C.yellow : C.green;
const sevBg = (s) => s === "HIGH" ? C.redDim : s === "MEDIUM" ? C.yellowDim : C.greenDim;
const fmt = (iso) => new Date(iso).toLocaleString();

// ─── Step 5: API fetch wrapper that attaches X-API-Key ────────────
function useApi() {
  const [apiKey, setApiKey] = useState(() => sessionStorage.getItem("sentinel_key") || "");

  const apiFetch = useCallback(async (path, opts = {}) => {
    const headers = { "Content-Type": "application/json", ...opts.headers };
    if (apiKey) headers["X-API-Key"] = apiKey;
    const res = await fetch(BASE + path, { ...opts, headers });
    if (res.status === 401) throw new Error("AUTH_FAILED");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  }, [apiKey]);

  const apiUpload = useCallback(async (path, formData) => {
    const headers = {};
    if (apiKey) headers["X-API-Key"] = apiKey;
    const res = await fetch(BASE + path, { method: "POST", body: formData, headers });
    if (res.status === 401) throw new Error("AUTH_FAILED");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  }, [apiKey]);

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

// ─── Step 5: Login screen ─────────────────────────────────────────

function LoginScreen({ onAuth }) {
  const [key, setKey] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  const tryLogin = async () => {
    setLoading(true); setErr("");
    try {
      const headers = { "X-API-Key": key };
      const res = await fetch(BASE + "/health", { headers });
      if (res.status === 401) { setErr("Wrong API key"); return; }
      sessionStorage.setItem("sentinel_key", key);
      onAuth(key);
    } catch {
      setErr("Cannot reach backend at " + BASE);
    } finally { setLoading(false); }
  };

  return (
    <div style={{
      minHeight: "100vh", background: C.bg,
      display: "flex", alignItems: "center", justifyContent: "center",
    }}>
      <div style={{
        background: C.surface, border: `1px solid ${C.border}`,
        borderRadius: 10, padding: "40px 48px", width: 380, textAlign: "center",
      }}>
        <div style={{ fontFamily: mono, fontSize: 22, color: C.accent, marginBottom: 6, letterSpacing: "0.1em" }}>
          ◈ {APP_NAME}
        </div>
        <div style={{ fontFamily: sans, fontSize: 13, color: C.textMuted, marginBottom: 32 }}>
          Enter your API key to continue
        </div>
        <Input value={key} onChange={e => setKey(e.target.value)} placeholder="sk-••••••••••••••••" type="password"
          style={{ marginBottom: 12, textAlign: "center" }} />
        {err && <div style={{ color: C.red, fontFamily: mono, fontSize: 11, marginBottom: 12 }}>{err}</div>}
        <Btn onClick={tryLogin} disabled={loading || !key} style={{ width: "100%" }}>
          {loading ? "Connecting…" : "Enter →"}
        </Btn>
        <div style={{ fontFamily: mono, fontSize: 10, color: C.textMuted, marginTop: 20 }}>
          Set <code style={{ color: C.accent }}>SENTINEL_API_KEY</code> env var on the backend.<br />
          Leave blank to run without auth in dev mode.
        </div>
      </div>
    </div>
  );
}

// ─── Step 3: Scan History Sidebar ────────────────────────────────

function HistorySidebar({ apiFetch, onSelect, activeId }) {
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
          {["Endpoint", "Risk Type", "Severity", "Details"].map(h => (
            <th key={h} style={{ color: C.textMuted, fontWeight: 600, padding: "8px 10px", textAlign: "left", fontSize: 10, letterSpacing: "0.06em" }}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {findings.map((f, i) => (
          <React.Fragment key={i}>
            <tr onClick={() => setExp(exp === i ? null : i)}
              style={{ borderBottom: `1px solid ${C.border}22`, cursor: "pointer" }}>
              <td style={{ padding: "9px 10px", color: C.accent }}>{f.endpoint}</td>
              <td style={{ padding: "9px 10px", color: C.text }}>{f.risk_type}</td>
              <td style={{ padding: "9px 10px" }}>
                <span style={{ background: sevBg(f.severity), color: sev(f.severity), padding: "2px 8px", borderRadius: 3, border: `1px solid ${sev(f.severity)}44`, fontWeight: 700 }}>
                  {f.severity}
                </span>
              </td>
              <td style={{ padding: "9px 10px", color: C.textMuted, fontSize: 11 }}>{exp === i ? "▲ hide" : "▼ show"}</td>
            </tr>
            {exp === i && (
              <tr><td colSpan={4} style={{ padding: "0 10px 10px" }}>
                <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 4, padding: "10px 14px", color: C.textDim, lineHeight: 1.6 }}>
                  {f.description}
                </div>
              </td></tr>
            )}
          </React.Fragment>
        ))}
      </tbody>
    </table>
  );
}

// ─── API Test Results ─────────────────────────────────────────────

function TestResults({ results = [] }) {
  const [open, setOpen] = useState(null);
  if (!results.length) return <p style={{ fontFamily: mono, color: C.textMuted, fontSize: 12 }}>No test results.</p>;

  return results.map((ep, i) => {
    const tests = ep.tests || [];
    const passed = tests.filter(t => t.passed === true).length;
    const failed = tests.filter(t => t.passed === false).length;
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
            <span style={{ color: failed > 0 ? C.red : C.textMuted }}>{failed}✗</span>
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
              return (
                <div key={j} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  padding: "7px 14px", borderBottom: `1px solid ${C.border}22`,
                  fontFamily: mono, fontSize: 11,
                }}>
                  <span style={{ color: C.textDim }}>{t.test}</span>
                  <span style={{ display: "flex", gap: 10, alignItems: "center" }}>
                    {t.status_code && <span style={{ color: C.textMuted }}>HTTP {t.status_code}</span>}
                    {t.error && <span style={{ color: C.red, fontSize: 10 }}>{t.error.slice(0, 50)}</span>}
                    <Pill label={t.passed ? "PASS" : "FAIL"} color={t.passed ? C.green : C.red} />
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

// ─── Report viewer ────────────────────────────────────────────────

function ReportView({ report }) {
  const [tab, setTab] = useState("security");
  const tabs = [
    { key: "security", label: "Security" },
    { key: "tests", label: "API Tests" },
    { key: "recs", label: "Recommendations" },
    { key: "llm", label: "AI Analysis" },
  ];

  const s = report.summary || {};

  return (
    <div>
      {/* Summary cards */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
        <StatCard label="High Risks" value={s.high_risks} color={s.high_risks > 0 ? C.red : C.green} />
        <StatCard label="Total Findings" value={s.total_security_findings} color={C.yellow} />
        <StatCard label="Tests Run" value={s.total_tests_run} color={C.accent} />
        <StatCard label="Failed" value={s.failed_tests} color={s.failed_tests > 0 ? C.red : C.green} />
        <StatCard label="Passed" value={s.passed_tests} color={C.green} />
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
            border: `1px solid ${tab === t.key ? C.border : C.border}`,
            borderBottom: tab === t.key ? `1px solid ${C.surface}` : `1px solid ${C.border}`,
            background: tab === t.key ? C.surface : C.bg,
            color: tab === t.key ? C.accent : C.textMuted,
          }}>{t.label}</button>
        ))}
      </div>

      <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: "0 4px 4px 4px", padding: 20 }}>
        {tab === "security" && <SecurityTable findings={report.security_findings} />}
        {tab === "tests" && <TestResults results={report.api_test_results} />}
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
        {tab === "llm" && (
          report.llm_analysis
            ? <pre style={{ fontFamily: mono, fontSize: 12, color: C.textDim, lineHeight: 1.7, whiteSpace: "pre-wrap", margin: 0 }}>{report.llm_analysis}</pre>
            : <p style={{ fontFamily: mono, color: C.textMuted, fontSize: 12 }}>
                Set <code style={{ color: C.accent }}>ANTHROPIC_API_KEY</code> on the backend to enable AI analysis.
              </p>
        )}
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────

export default function App() {
  const { apiKey, setApiKey, apiFetch, apiUpload } = useApi();

  // Step 5: if SENTINEL_API_KEY is set on backend, check auth first
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

  const runScan = () => wrap(async () => {
    const data = await apiFetch(`/api/run/${specId}`, { method: "POST" });
    setReport(data.result);
    setActiveScanId(specId);
    setSidebarKey(k => k + 1);
  });

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

  // Load a past scan from history
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

  if (!authChecked) return null;

  if (needsAuth && !apiKey) {
    return <LoginScreen onAuth={(k) => { setApiKey(k); setNeedsAuth(false); }} />;
  }

  return (
    <div style={{ display: "flex", height: "100vh", background: C.bg, fontFamily: sans, color: C.text, overflow: "hidden" }}>

      {/* Step 3: Sidebar */}
      <HistorySidebar
        key={sidebarKey}
        apiFetch={apiFetch}
        onSelect={loadHistoryScan}
        activeId={activeScanId}
      />

      {/* Main area */}
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
            {apiKey && (
              <button onClick={() => { sessionStorage.clear(); setApiKey(""); setNeedsAuth(true); }}
                style={{ fontFamily: mono, fontSize: 10, color: C.textMuted, background: "none", border: "none", cursor: "pointer" }}>
                sign out
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
              <Btn onClick={runScan} disabled={loading}>▶ Run Security Scan</Btn>
            </div>
          )}

          {/* Report */}
          {report && <ReportView report={report} />}

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