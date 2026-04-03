import React, { useState, useEffect, useCallback } from "react";

// ─── Config ───────────────────────────────────────────────────────
const BASE     = process.env.REACT_APP_API_URL || "http://localhost:8000";
const APP_NAME = process.env.REACT_APP_APP_NAME || "API SENTINEL";

// ─── Design tokens ────────────────────────────────────────────────
const C = {
  bg:           "#080c14",
  surface:      "#0e1420",
  surfaceHigh:  "#141c2e",
  border:       "#1a2540",
  borderHigh:   "#243050",
  accent:       "#00c8ff",
  accentDim:    "#00c8ff18",
  accentBorder: "#00c8ff33",
  green:        "#00e5a0",
  greenDim:     "#00e5a012",
  yellow:       "#ffb800",
  yellowDim:    "#ffb80012",
  red:          "#ff4560",
  redDim:       "#ff456012",
  purple:       "#b06fff",
  purpleDim:    "#b06fff12",
  text:         "#dde4f0",
  textMuted:    "#4a5a7a",
  textDim:      "#8899bb",
  sidebar:      "#090d18",
};

const mono = `'IBM Plex Mono', 'Courier New', monospace`;
const sans = `'DM Sans', system-ui, sans-serif`;

// ─── Agent metadata for progress panel ───────────────────────────
const AGENTS = [
  { key: "planner",        label: "Planner",         icon: "◎" },
  { key: "test_generation",label: "Test Generator",  icon: "⊡" },
  { key: "security",       label: "Security Agent",  icon: "⊘" },
  { key: "api_testing",    label: "API Testing",     icon: "⊛" },
  { key: "deployment",     label: "Deployment",      icon: "⊕" },
  { key: "deep_scan",      label: "Deep Scan",       icon: "◆" },
  { key: "llm_analysis",   label: "AI Analysis",     icon: "◈" },
  { key: "report",         label: "Report",          icon: "◉" },
];

// ─── Helpers ──────────────────────────────────────────────────────
const sevColor = (s) =>
  s === "CRITICAL" || s === "HIGH" ? C.red
    : s === "MEDIUM" ? C.yellow : C.green;
const sevBg = (s) =>
  s === "CRITICAL" || s === "HIGH" ? C.redDim
    : s === "MEDIUM" ? C.yellowDim : C.greenDim;

const timeAgo = (iso) => {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

// Render LLM markdown to HTML safely (no extra packages)
const renderMarkdown = (text) => {
  if (!text) return "";
  return text
    .replace(/\*\*(.+?)\*\*/g, `<strong style="color:${C.text}">$1</strong>`)
    .replace(/\*(.+?)\*/g, `<em>$1</em>`)
    .replace(/^### (.+)$/gm, `<div style="font-family:${mono};font-size:11px;color:${C.accent};letter-spacing:0.08em;margin:16px 0 8px;text-transform:uppercase">$1</div>`)
    .replace(/^## (.+)$/gm, `<div style="font-family:${mono};font-size:12px;color:${C.accent};letter-spacing:0.08em;margin:16px 0 8px;text-transform:uppercase">$1</div>`)
    .replace(/^\d+\. (.+)$/gm, `<div style="padding:4px 0 4px 16px;border-left:2px solid ${C.accentBorder};margin-bottom:4px">$1</div>`)
    .replace(/\n\n/g, `<div style="margin:8px 0"></div>`)
    .replace(/\n/g, `<br/>`);
};

// ─── API hook ─────────────────────────────────────────────────────
function useApi() {
  const [apiKey, setApiKey] = useState(
    () => sessionStorage.getItem("sentinel_key") || ""
  );

  const apiFetch = useCallback(async (path, opts = {}) => {
    const headers = { "Content-Type": "application/json", ...opts.headers };
    if (apiKey) headers["X-API-Key"] = apiKey;
    const res  = await fetch(BASE + path, { ...opts, headers });
    if (res.status === 401) throw new Error("AUTH_FAILED");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  }, [apiKey]);

  const apiUpload = useCallback(async (path, formData) => {
    const headers = {};
    if (apiKey) headers["X-API-Key"] = apiKey;
    const res  = await fetch(BASE + path, { method: "POST", body: formData, headers });
    if (res.status === 401) throw new Error("AUTH_FAILED");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  }, [apiKey]);

  return { apiKey, setApiKey, apiFetch, apiUpload };
}

// ─── Primitive components ─────────────────────────────────────────
function Pill({ label, color, small }) {
  return (
    <span style={{
      fontFamily: mono, fontSize: small ? 9 : 10, fontWeight: 700,
      letterSpacing: "0.08em", padding: small ? "1px 6px" : "2px 8px",
      borderRadius: 3, background: `${color}18`, color,
      border: `1px solid ${color}44`,
    }}>{label}</span>
  );
}

function StatCard({ label, value, color, sub }) {
  return (
    <div style={{
      background: C.surfaceHigh, border: `1px solid ${C.border}`,
      borderLeft: `3px solid ${color}`, borderRadius: 6,
      padding: "12px 16px", flex: 1, minWidth: 90,
    }}>
      <div style={{ fontFamily: mono, fontSize: 24, color, fontWeight: 700 }}>
        {value ?? "—"}
      </div>
      <div style={{
        fontFamily: mono, fontSize: 10, color: C.textMuted,
        textTransform: "uppercase", letterSpacing: "0.08em", marginTop: 2,
      }}>{label}</div>
      {sub && (
        <div style={{
          fontFamily: mono, fontSize: 9, color: C.textMuted, marginTop: 3,
        }}>{sub}</div>
      )}
    </div>
  );
}

function Btn({ onClick, children, variant = "primary", disabled, small }) {
  const map = {
    primary: { bg: C.accent,      color: "#000", border: "none" },
    ghost:   { bg: "transparent", color: C.accent, border: `1px solid ${C.accentBorder}` },
    danger:  { bg: C.red,         color: "#fff", border: "none" },
    subtle:  { bg: C.surfaceHigh, color: C.textDim, border: `1px solid ${C.border}` },
  };
  const s = map[variant] || map.primary;
  return (
    <button onClick={onClick} disabled={disabled} style={{
      fontFamily: mono, fontSize: small ? 10 : 12, fontWeight: 600,
      letterSpacing: "0.08em", textTransform: "uppercase",
      padding: small ? "5px 10px" : "9px 18px", borderRadius: 4,
      cursor: disabled ? "not-allowed" : "pointer",
      opacity: disabled ? 0.4 : 1,
      background: s.bg, color: s.color, border: s.border,
      transition: "opacity 0.15s",
    }}>{children}</button>
  );
}

function Input({ value, onChange, placeholder, type = "text", style = {} }) {
  return (
    <input type={type} value={value} onChange={onChange}
      placeholder={placeholder}
      style={{
        fontFamily: mono, fontSize: 12, background: C.bg, color: C.text,
        border: `1px solid ${C.border}`, borderRadius: 4,
        padding: "9px 12px", outline: "none", width: "100%",
        boxSizing: "border-box", ...style,
      }} />
  );
}

// ─── Streaming Progress Panel ─────────────────────────────────────
function ScanProgress({ events }) {
  // Build agent status map from events
  const statusMap = {};
  for (const ev of events) {
    statusMap[ev.agent] = ev.status;
  }

  const statusColor = (s) =>
    s === "completed" ? C.green
      : s === "running"   ? C.yellow
      : s === "skipped"   ? C.textMuted
      : s === "error"     ? C.red
      : C.border;

  const statusIcon = (s) =>
    s === "completed" ? "✓"
      : s === "running"   ? "⟳"
      : s === "skipped"   ? "—"
      : s === "error"     ? "✕"
      : "·";

  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 8, padding: "20px 24px", marginBottom: 20,
    }}>
      <div style={{
        fontFamily: mono, fontSize: 11, color: C.accent,
        letterSpacing: "0.1em", marginBottom: 16,
      }}>◈ SCAN IN PROGRESS</div>

      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {AGENTS.map((agent) => {
          const status = statusMap[agent.key] || "pending";
          const color  = statusColor(status);
          const isRunning = status === "running";

          return (
            <div key={agent.key} style={{
              display: "flex", alignItems: "center", gap: 12,
            }}>
              {/* Status dot */}
              <div style={{
                width: 8, height: 8, borderRadius: "50%",
                background: color,
                boxShadow: isRunning ? `0 0 8px ${color}` : "none",
                flexShrink: 0,
                animation: isRunning ? "pulse 1s infinite" : "none",
              }} />

              {/* Agent name */}
              <span style={{
                fontFamily: mono, fontSize: 11,
                color: status === "pending" ? C.textMuted : C.text,
                flex: 1,
              }}>
                {agent.icon} {agent.label}
              </span>

              {/* Status label */}
              <span style={{
                fontFamily: mono, fontSize: 10, color,
                letterSpacing: "0.06em",
              }}>
                {statusIcon(status)} {status.toUpperCase()}
              </span>
            </div>
          );
        })}
      </div>

      {/* Progress bar */}
      {(() => {
        const completed = AGENTS.filter(
          a => ["completed", "skipped", "error"].includes(statusMap[a.key])
        ).length;
        const pct = Math.round((completed / AGENTS.length) * 100);
        return (
          <div style={{ marginTop: 16 }}>
            <div style={{
              height: 2, background: C.border, borderRadius: 2, overflow: "hidden",
            }}>
              <div style={{
                height: "100%", width: `${pct}%`,
                background: C.accent,
                transition: "width 0.4s ease",
                boxShadow: `0 0 8px ${C.accent}`,
              }} />
            </div>
            <div style={{
              fontFamily: mono, fontSize: 10, color: C.textMuted,
              marginTop: 6, textAlign: "right",
            }}>{pct}% complete</div>
          </div>
        );
      })()}
    </div>
  );
}

// ─── Login screen ─────────────────────────────────────────────────
function LoginScreen({ onAuth }) {
  const [key, setKey]         = useState("");
  const [err, setErr]         = useState("");
  const [loading, setLoading] = useState(false);

  const tryLogin = async () => {
    setLoading(true); setErr("");
    try {
      const res = await fetch(BASE + "/health", {
        headers: { "X-API-Key": key },
      });
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
        <div style={{
          fontFamily: mono, fontSize: 22, color: C.accent,
          marginBottom: 6, letterSpacing: "0.1em",
        }}>◈ {APP_NAME}</div>
        <div style={{
          fontFamily: sans, fontSize: 13, color: C.textMuted, marginBottom: 32,
        }}>Enter your API key to continue</div>
        <Input value={key} onChange={e => setKey(e.target.value)}
          placeholder="sk-••••••••••••••••" type="password"
          style={{ marginBottom: 12, textAlign: "center" }} />
        {err && (
          <div style={{
            color: C.red, fontFamily: mono, fontSize: 11, marginBottom: 12,
          }}>{err}</div>
        )}
        <Btn onClick={tryLogin} disabled={loading || !key}>
          {loading ? "Connecting…" : "Enter →"}
        </Btn>
        <div style={{
          fontFamily: mono, fontSize: 10, color: C.textMuted, marginTop: 20,
        }}>
          Leave blank to run without auth in dev mode.
        </div>
      </div>
    </div>
  );
}

// ─── Scan History Sidebar ─────────────────────────────────────────
function HistorySidebar({ apiFetch, onSelect, activeId }) {
  const [scans,   setScans]   = useState([]);
  const [loading, setLoading] = useState(false);
  const [search,  setSearch]  = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    try { setScans(await apiFetch("/api/scans")); }
    catch { }
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

  const filtered = scans.filter(s =>
    !search ||
    (s.api_title || s.name || "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={{
      width: 260, minWidth: 260, background: C.sidebar,
      borderRight: `1px solid ${C.border}`, display: "flex",
      flexDirection: "column", height: "100vh", overflow: "hidden",
    }}>
      <div style={{
        padding: "16px 16px 10px", borderBottom: `1px solid ${C.border}`,
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <span style={{
          fontFamily: mono, fontSize: 11, color: C.textMuted,
          textTransform: "uppercase", letterSpacing: "0.08em",
        }}>Scan History</span>
        <button onClick={refresh} style={{
          fontFamily: mono, fontSize: 11, color: C.textMuted,
          background: "none", border: "none", cursor: "pointer",
        }}>{loading ? "…" : "↻"}</button>
      </div>

      <div style={{ padding: "8px 12px", borderBottom: `1px solid ${C.border}22` }}>
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Filter scans…"
          style={{
            fontFamily: mono, fontSize: 11, background: C.bg, color: C.text,
            border: `1px solid ${C.border}`, borderRadius: 3,
            padding: "5px 8px", width: "100%", outline: "none",
            boxSizing: "border-box",
          }} />
      </div>

      <div style={{ flex: 1, overflowY: "auto" }}>
        {filtered.length === 0 && !loading && (
          <div style={{
            padding: "24px 16px", fontFamily: mono, fontSize: 11,
            color: C.textMuted, textAlign: "center",
          }}>
            {search ? "No matches" : "No scans yet"}
          </div>
        )}
        {filtered.map(s => {
          const isActive = s.id === activeId;
          return (
            <div key={s.id} onClick={() => onSelect(s)} style={{
              padding: "10px 14px", cursor: "pointer",
              background: isActive ? C.accentDim : "transparent",
              borderLeft: `2px solid ${isActive ? C.accent : "transparent"}`,
              borderBottom: `1px solid ${C.border}22`,
              transition: "background 0.15s",
            }}>
              <div style={{
                display: "flex", justifyContent: "space-between",
                alignItems: "flex-start",
              }}>
                <div style={{
                  fontFamily: mono, fontSize: 11,
                  color: isActive ? C.accent : C.text,
                  marginBottom: 3, wordBreak: "break-all",
                }}>
                  {s.api_title || s.name}
                </div>
                <button onClick={e => handleDelete(e, s.id)} style={{
                  background: "none", border: "none", color: C.textMuted,
                  cursor: "pointer", fontSize: 13, lineHeight: 1, marginLeft: 6,
                  flexShrink: 0,
                }}>×</button>
              </div>
              <div style={{
                fontFamily: mono, fontSize: 10, color: C.textMuted, marginBottom: 4,
              }}>
                {s.endpoint_count} endpoints · {timeAgo(s.created_at)}
              </div>
              <Pill
                label={s.status}
                color={s.status === "completed" ? C.green : C.yellow}
                small
              />
            </div>
          );
        })}
      </div>

      <div style={{ padding: "12px 16px", borderTop: `1px solid ${C.border}` }}>
        <div style={{ fontFamily: mono, fontSize: 10, color: C.textMuted }}>
          ◈ {APP_NAME} · {BASE.replace(/https?:\/\//, "")}
        </div>
      </div>
    </div>
  );
}

// ─── Security Findings Table ──────────────────────────────────────
function SecurityTable({ findings = [] }) {
  const [exp,            setExp]            = useState(null);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [typeFilter,     setTypeFilter]     = useState("ALL");
  const [sortBy,         setSortBy]         = useState("severity");

  if (!findings.length) return (
    <p style={{ fontFamily: mono, color: C.green, fontSize: 12 }}>
      ✓ No findings.
    </p>
  );

  const sevOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

  const filtered = findings
    .filter(f => severityFilter === "ALL" || f.severity === severityFilter)
    .filter(f => typeFilter    === "ALL" || f.detection_type === typeFilter)
    .sort((a, b) =>
      sortBy === "severity"
        ? (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0)
        : a.endpoint.localeCompare(b.endpoint)
    );

  const filterPill = (label, active, onClick, color = C.accent) => (
    <button key={label} onClick={onClick} style={{
      fontFamily: mono, fontSize: 10, padding: "3px 10px", borderRadius: 20,
      border: `1px solid ${active ? color : C.border}`,
      background: active ? `${color}18` : "transparent",
      color: active ? color : C.textMuted, cursor: "pointer",
      letterSpacing: "0.06em",
    }}>{label}</button>
  );

  return (
    <div>
      <div style={{
        display: "flex", gap: 6, marginBottom: 14, flexWrap: "wrap",
        alignItems: "center",
      }}>
        <span style={{
          fontFamily: mono, fontSize: 10, color: C.textMuted, marginRight: 4,
        }}>SEVERITY</span>
        {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(s => filterPill(
          s, severityFilter === s, () => setSeverityFilter(s),
          s === "CRITICAL" || s === "HIGH" ? C.red
            : s === "MEDIUM" ? C.yellow : s === "LOW" ? C.green : C.accent
        ))}
        <span style={{
          fontFamily: mono, fontSize: 10, color: C.textMuted,
          marginLeft: 8, marginRight: 4,
        }}>TYPE</span>
        {["ALL","STATIC","DYNAMIC"].map(t => filterPill(
          t, typeFilter === t, () => setTypeFilter(t),
          t === "DYNAMIC" ? C.green : C.textDim
        ))}
        <span style={{
          fontFamily: mono, fontSize: 10, color: C.textMuted,
          marginLeft: 8, marginRight: 4,
        }}>SORT</span>
        {filterPill("SEVERITY", sortBy === "severity", () => setSortBy("severity"))}
        {filterPill("ENDPOINT", sortBy === "endpoint", () => setSortBy("endpoint"))}
      </div>

      {filtered.length === 0 && (
        <p style={{ fontFamily: mono, color: C.textMuted, fontSize: 12 }}>
          No findings match current filters.
        </p>
      )}

      <table style={{
        width: "100%", borderCollapse: "collapse", fontFamily: mono, fontSize: 12,
      }}>
        <thead>
          <tr style={{ borderBottom: `1px solid ${C.border}` }}>
            {["Endpoint","Vulnerability","Severity","Type",""].map(h => (
              <th key={h} style={{
                color: C.textMuted, fontWeight: 600, padding: "8px 10px",
                textAlign: "left", fontSize: 10, letterSpacing: "0.06em",
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filtered.map((f, i) => {
            const vulnName = f.vulnerability || f.risk_type || "Unknown";
            const hasPoC   = !!f.exploit_poc;
            const isOpen   = exp === i;
            return (
              <React.Fragment key={i}>
                <tr onClick={() => setExp(isOpen ? null : i)} style={{
                  borderBottom: `1px solid ${C.border}22`, cursor: "pointer",
                  background: isOpen ? `${C.accent}08` : "transparent",
                }}>
                  <td style={{ padding: "9px 10px", color: C.accent }}>
                    {f.endpoint}
                    {f.affected_methods?.length > 1 && (
                      <span style={{
                        fontFamily: mono, fontSize: 9,
                        color: C.textMuted, marginLeft: 6,
                      }}>
                        [{f.affected_methods.join(", ")}]
                      </span>
                    )}
                  </td>
                  <td style={{ padding: "9px 10px", color: C.text }}>
                    {vulnName}
                    {hasPoC && (
                      <span style={{
                        fontFamily: mono, fontSize: 9, color: C.purple,
                        marginLeft: 8, border: `1px solid ${C.purple}44`,
                        padding: "1px 5px", borderRadius: 3,
                        background: C.purpleDim,
                      }}>PoC</span>
                    )}
                  </td>
                  <td style={{ padding: "9px 10px" }}>
                    <span style={{
                      background: sevBg(f.severity), color: sevColor(f.severity),
                      padding: "2px 8px", borderRadius: 3,
                      border: `1px solid ${sevColor(f.severity)}44`,
                      fontWeight: 700, fontSize: 10,
                    }}>{f.severity}</span>
                  </td>
                  <td style={{ padding: "9px 10px" }}>
                    {f.detection_type === "DYNAMIC"
                      ? <span style={{ fontFamily: mono, fontSize: 10, color: C.green }}>● CONFIRMED</span>
                      : <span style={{ fontFamily: mono, fontSize: 10, color: C.textMuted }}>○ STATIC</span>
                    }
                  </td>
                  <td style={{
                    padding: "9px 10px", color: C.textMuted, fontSize: 11,
                  }}>{isOpen ? "▲" : "▼"}</td>
                </tr>

                {isOpen && (
                  <tr><td colSpan={5} style={{ padding: "0 10px 12px" }}>
                    <div style={{
                      background: C.bg, border: `1px solid ${C.border}`,
                      borderRadius: 4, padding: "12px 16px",
                    }}>
                      <div style={{
                        color: C.textDim, lineHeight: 1.6,
                        fontFamily: sans, fontSize: 13,
                        marginBottom: hasPoC ? 14 : 0,
                      }}>{f.description}</div>

                      <div style={{
                        display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap",
                      }}>
                        {f.confidence && (
                          <Pill
                            label={`Confidence: ${f.confidence}`}
                            color={f.confidence === "HIGH" ? C.red : f.confidence === "MEDIUM" ? C.yellow : C.textMuted}
                            small
                          />
                        )}
                        {f.method && <Pill label={f.method} color={C.accent} small />}
                      </div>

                      {hasPoC && (
                        <div style={{
                          marginTop: 14, border: `1px solid ${C.purple}33`,
                          borderRadius: 4, background: C.purpleDim,
                          padding: "12px 14px",
                        }}>
                          <div style={{
                            fontFamily: mono, fontSize: 10, color: C.purple,
                            marginBottom: 10, letterSpacing: "0.08em",
                          }}>◆ PROOF OF CONCEPT EXPLOIT</div>
                          <div style={{
                            fontFamily: sans, fontSize: 13,
                            color: C.text, marginBottom: 10,
                          }}>{f.exploit_poc.summary}</div>
                          {f.exploit_poc.steps?.length > 0 && (
                            <div style={{ marginBottom: 10 }}>
                              <div style={{
                                fontFamily: mono, fontSize: 10,
                                color: C.textMuted, marginBottom: 6,
                              }}>STEPS</div>
                              {f.exploit_poc.steps.map((step, si) => (
                                <div key={si} style={{
                                  fontFamily: sans, fontSize: 12, color: C.textDim,
                                  lineHeight: 1.6, paddingLeft: 12, marginBottom: 3,
                                  borderLeft: `2px solid ${C.purple}44`,
                                }}>{step}</div>
                              ))}
                            </div>
                          )}
                          {f.exploit_poc.sample_curl && (
                            <div style={{ marginBottom: 10 }}>
                              <div style={{
                                fontFamily: mono, fontSize: 10,
                                color: C.textMuted, marginBottom: 6,
                              }}>SAMPLE CURL</div>
                              <div style={{
                                fontFamily: mono, fontSize: 11, color: C.green,
                                background: C.bg, border: `1px solid ${C.border}`,
                                borderRadius: 3, padding: "8px 12px",
                                wordBreak: "break-all", lineHeight: 1.5,
                              }}>{f.exploit_poc.sample_curl}</div>
                            </div>
                          )}
                          {f.exploit_poc.verification_test && (
                            <div>
                              <div style={{
                                fontFamily: mono, fontSize: 10,
                                color: C.textMuted, marginBottom: 6,
                              }}>VERIFICATION</div>
                              <div style={{
                                fontFamily: sans, fontSize: 12,
                                color: C.textDim, lineHeight: 1.6,
                              }}>{f.exploit_poc.verification_test}</div>
                            </div>
                          )}
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
    </div>
  );
}

// ─── API Test Results ─────────────────────────────────────────────
function TestResults({ results = [] }) {
  const [open, setOpen] = useState(null);
  if (!results.length) return (
    <p style={{ fontFamily: mono, color: C.textMuted, fontSize: 12 }}>
      No test results.
    </p>
  );
  return results.map((ep, i) => {
    const tests  = ep.tests || [];
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
            <span style={{ color: C.textMuted, marginLeft: 12 }}>
              {open === i ? "▲" : "▼"}
            </span>
          </span>
        </div>
        {open === i && (
          <div style={{
            border: `1px solid ${C.border}`, borderTop: "none",
            borderRadius: "0 0 4px 4px",
          }}>
            {tests.map((t, j) => {
              if (t.test === "dynamic_fuzz_testing") return (
                <div key={j} style={{
                  padding: "10px 14px", borderBottom: `1px solid ${C.border}22`,
                  fontFamily: mono, fontSize: 11,
                }}>
                  <div style={{
                    display: "flex", justifyContent: "space-between", marginBottom: 6,
                  }}>
                    <span style={{ color: C.textDim }}>fuzz_testing</span>
                    <span style={{ color: t.vulnerable_count > 0 ? C.red : C.green }}>
                      {t.vulnerable_count} / {t.total_payloads} flagged
                    </span>
                  </div>
                  {(t.results || []).filter(r => r.possible_vulnerability).map((r, k) => (
                    <div key={k} style={{
                      background: C.redDim, border: `1px solid ${C.red}33`,
                      borderRadius: 3, padding: "5px 9px", marginBottom: 3,
                      color: C.red, fontSize: 10,
                    }}>⚠ {r.payload} → {r.status_code || r.error}</div>
                  ))}
                </div>
              );
              return (
                <div key={j} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  padding: "7px 14px", borderBottom: `1px solid ${C.border}22`,
                  fontFamily: mono, fontSize: 11,
                }}>
                  <span style={{ color: C.textDim }}>{t.test}</span>
                  <span style={{ display: "flex", gap: 10, alignItems: "center" }}>
                    {t.status_code && (
                      <span style={{ color: C.textMuted }}>HTTP {t.status_code}</span>
                    )}
                    {t.error && (
                      <span style={{ color: C.red, fontSize: 10 }}>
                        {t.error.slice(0, 50)}
                      </span>
                    )}
                    <Pill
                      label={t.passed ? "PASS" : "FAIL"}
                      color={t.passed ? C.green : C.red} small
                    />
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

// ─── Planner Tab ──────────────────────────────────────────────────
function PlannerView({ plan }) {
  if (!plan || !Object.keys(plan).length) return (
    <p style={{ fontFamily: mono, color: C.textMuted, fontSize: 12 }}>
      No planner assessment available.
    </p>
  );
  const riskColor = (l) =>
    l === "CRITICAL" || l === "HIGH" ? C.red : l === "MEDIUM" ? C.yellow : C.green;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div style={{
        background: C.bg, border: `1px solid ${C.accentBorder}`,
        borderLeft: `3px solid ${C.accent}`, borderRadius: 4, padding: "12px 16px",
      }}>
        <div style={{
          fontFamily: mono, fontSize: 10, color: C.accent,
          marginBottom: 8, letterSpacing: "0.08em",
        }}>RISK SUMMARY</div>
        <div style={{
          fontFamily: sans, fontSize: 13, color: C.textDim, lineHeight: 1.7,
        }}>{plan.risk_summary}</div>
        {plan.auth_pattern_detected && (
          <div style={{ marginTop: 10 }}>
            <Pill
              label={`Auth: ${plan.auth_pattern_detected}`}
              color={plan.auth_pattern_detected === "none" ? C.red : C.green}
            />
          </div>
        )}
      </div>
      {plan.high_risk_endpoints?.length > 0 && (
        <div>
          <div style={{
            fontFamily: mono, fontSize: 10, color: C.textMuted,
            marginBottom: 10, letterSpacing: "0.08em",
          }}>HIGH RISK ENDPOINTS</div>
          {plan.high_risk_endpoints.map((ep, i) => (
            <div key={i} style={{
              background: C.surfaceHigh, border: `1px solid ${C.border}`,
              borderLeft: `3px solid ${riskColor(ep.risk_level)}`,
              borderRadius: 4, padding: "10px 14px", marginBottom: 8,
            }}>
              <div style={{
                display: "flex", justifyContent: "space-between",
                alignItems: "center", marginBottom: 6,
              }}>
                <span style={{ fontFamily: mono, fontSize: 12, color: C.accent }}>
                  {ep.method} {ep.path}
                </span>
                <Pill label={ep.risk_level} color={riskColor(ep.risk_level)} small />
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {ep.risk_reasons?.map((r, ri) => (
                  <span key={ri} style={{
                    fontFamily: mono, fontSize: 9, color: C.textDim,
                    background: C.bg, border: `1px solid ${C.border}`,
                    borderRadius: 3, padding: "2px 6px",
                  }}>{r}</span>
                ))}
              </div>
              {ep.attack_vectors?.length > 0 && (
                <div style={{
                  fontFamily: mono, fontSize: 10, color: C.textMuted, marginTop: 6,
                }}>Vectors: {ep.attack_vectors.join(", ")}</div>
              )}
            </div>
          ))}
        </div>
      )}
      {plan.business_logic_risks?.length > 0 && (
        <div>
          <div style={{
            fontFamily: mono, fontSize: 10, color: C.textMuted,
            marginBottom: 8, letterSpacing: "0.08em",
          }}>BUSINESS LOGIC RISKS</div>
          {plan.business_logic_risks.map((r, i) => (
            <div key={i} style={{
              fontFamily: sans, fontSize: 13, color: C.textDim,
              padding: "6px 12px", borderLeft: `2px solid ${C.yellow}44`,
              marginBottom: 4, lineHeight: 1.5,
            }}>{r}</div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Deployment Tab ───────────────────────────────────────────────
function DeploymentView({ deployment }) {
  if (!deployment || deployment.status === "unknown") return (
    <p style={{ fontFamily: mono, color: C.textMuted, fontSize: 12 }}>
      No deployment data available.
    </p>
  );
  const scoreColor = (score) => {
    if (!score || score === "N/A") return C.textMuted;
    const n = parseInt(score);
    return n >= 5 ? C.green : n >= 3 ? C.yellow : C.red;
  };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        <div style={{
          background: C.surfaceHigh, border: `1px solid ${C.border}`,
          borderLeft: `3px solid ${scoreColor(deployment.security_score)}`,
          borderRadius: 6, padding: "12px 16px", flex: 1, minWidth: 120,
        }}>
          <div style={{
            fontFamily: mono, fontSize: 28,
            color: scoreColor(deployment.security_score), fontWeight: 700,
          }}>{deployment.security_score || "N/A"}</div>
          <div style={{
            fontFamily: mono, fontSize: 10, color: C.textMuted,
            textTransform: "uppercase", letterSpacing: "0.08em",
          }}>Security Score</div>
        </div>
        <div style={{
          background: C.surfaceHigh, border: `1px solid ${C.border}`,
          borderLeft: `3px solid ${deployment.status === "healthy" ? C.green : C.red}`,
          borderRadius: 6, padding: "12px 16px", flex: 1, minWidth: 120,
        }}>
          <div style={{
            fontFamily: mono, fontSize: 13,
            color: deployment.status === "healthy" ? C.green : C.red, marginBottom: 2,
          }}>
            <span style={{
              display: "inline-block", width: 7, height: 7, borderRadius: "50%",
              background: deployment.status === "healthy" ? C.green : C.red,
              marginRight: 8,
              boxShadow: `0 0 5px ${deployment.status === "healthy" ? C.green : C.red}`,
            }} />
            {(deployment.status || "unknown").toUpperCase()}
          </div>
          <div style={{
            fontFamily: mono, fontSize: 10, color: C.textMuted,
            textTransform: "uppercase", letterSpacing: "0.08em",
          }}>Status</div>
          {deployment.latency_ms && (
            <div style={{
              fontFamily: mono, fontSize: 10, color: C.textMuted, marginTop: 4,
            }}>{deployment.latency_ms}ms latency</div>
          )}
        </div>
      </div>
      {deployment.deployment_findings?.length > 0 && (
        <div>
          <div style={{
            fontFamily: mono, fontSize: 10, color: C.textMuted,
            marginBottom: 8, letterSpacing: "0.08em",
          }}>DEPLOYMENT FINDINGS</div>
          {deployment.deployment_findings.map((df, i) => {
            const isHeader = df.check?.startsWith("security_header");
            const color = isHeader ? C.yellow : df.check === "cors" ? C.red : C.yellow;
            return (
              <div key={i} style={{
                display: "flex", gap: 10, padding: "8px 12px", marginBottom: 4,
                background: C.bg, border: `1px solid ${C.border}`,
                borderLeft: `3px solid ${color}`, borderRadius: 4,
              }}>
                <span style={{ color, fontFamily: mono, fontSize: 11 }}>▲</span>
                <span style={{
                  fontFamily: sans, fontSize: 13, color: C.textDim, lineHeight: 1.5,
                }}>{df.issue}</span>
              </div>
            );
          })}
        </div>
      )}
      {deployment.security_headers && (
        <div>
          <div style={{
            fontFamily: mono, fontSize: 10, color: C.textMuted,
            marginBottom: 8, letterSpacing: "0.08em",
          }}>SECURITY HEADERS</div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {deployment.security_headers.present?.map(h => (
              <Pill key={h} label={`✓ ${h}`} color={C.green} small />
            ))}
            {deployment.security_headers.missing?.map(h => (
              <Pill key={h} label={`✗ ${h}`} color={C.red} small />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Report viewer ────────────────────────────────────────────────
function ReportView({ report, onRescan, specId }) {
  const [tab, setTab] = useState("security");
  const s = report.summary || {};

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a   = document.createElement("a");
    a.href     = url;
    a.download = `sentinel-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const tabs = [
    { key: "security",   label: "Security"   },
    { key: "tests",      label: "API Tests"  },
    { key: "planner",    label: "Planner"    },
    { key: "deployment", label: "Deployment" },
    { key: "recs",       label: "Recommendations" },
    { key: "llm",        label: "AI Analysis" },
  ];

  return (
    <div>
      {/* Stat cards */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
        <StatCard label="Critical" value={s.critical_risks ?? 0}
          color={s.critical_risks > 0 ? C.red : C.textMuted} />
        <StatCard label="High" value={s.high_risks ?? 0}
          color={s.high_risks > 0 ? C.red : C.textMuted} />
        <StatCard label="Medium" value={s.medium_risks ?? 0}
          color={s.medium_risks > 0 ? C.yellow : C.textMuted} />
        <StatCard label="Low" value={s.low_risks ?? 0} color={C.green} />
        <StatCard label="Tests Run" value={s.total_tests_run} color={C.accent} />
        <StatCard label="Failed" value={s.failed_tests}
          color={s.failed_tests > 0 ? C.red : C.green} />
        <StatCard label="Passed" value={s.passed_tests} color={C.green} />

        {/* Security score */}
        <div style={{
          background: C.surfaceHigh, border: `1px solid ${C.border}`,
          borderLeft: `3px solid ${
            !s.deployment_checks_ran ? C.textMuted
              : parseInt(s.deployment_security_score) >= 4 ? C.green : C.yellow
          }`,
          borderRadius: 6, padding: "12px 16px", flex: 1, minWidth: 100,
        }}>
          <div style={{
            fontFamily: mono, fontSize: 24, fontWeight: 700,
            color: !s.deployment_checks_ran ? C.textMuted
              : parseInt(s.deployment_security_score) >= 4 ? C.green : C.yellow,
          }}>
            {s.deployment_checks_ran
              ? (s.deployment_security_score || "N/A") : "N/A"}
          </div>
          <div style={{
            fontFamily: mono, fontSize: 10, color: C.textMuted,
            textTransform: "uppercase", letterSpacing: "0.08em", marginTop: 2,
          }}>Security Score</div>
          {!s.deployment_checks_ran && (
            <div style={{
              fontFamily: mono, fontSize: 9, color: C.textMuted, marginTop: 3,
            }}>unreachable</div>
          )}
        </div>

        {/* Deep scan badge */}
        {report.deep_scan_performed && (
          <div style={{
            background: C.purpleDim, border: `1px solid ${C.purple}44`,
            borderRadius: 6, padding: "12px 16px", flex: 1, minWidth: 100,
          }}>
            <div style={{
              fontFamily: mono, fontSize: 24, fontWeight: 700, color: C.purple,
            }}>
              {report.deep_scan_summary?.findings_enriched ?? 0}
            </div>
            <div style={{
              fontFamily: mono, fontSize: 10, color: C.purple,
              textTransform: "uppercase", letterSpacing: "0.08em", marginTop: 2,
            }}>PoC Generated</div>
          </div>
        )}
      </div>

      {/* Info bar + action buttons */}
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        background: C.accentDim, border: `1px solid ${C.accentBorder}`,
        borderRadius: 4, padding: "7px 14px", marginBottom: 14,
        fontFamily: mono, fontSize: 11,
      }}>
        <span style={{ color: C.accent }}>
          {report.test_generation?.test_cases_generated > 0
            ? `◈ ${report.test_generation.test_cases_generated} test cases · `
            : ""}
          {report.deep_scan_performed ? "◆ Deep scan · " : ""}
          {s.total_security_findings} findings
        </span>
        <div style={{ display: "flex", gap: 8 }}>
          {specId && onRescan && (
            <Btn onClick={onRescan} variant="ghost" small>↺ Re-scan</Btn>
          )}
          <Btn onClick={exportJSON} variant="subtle" small>↓ Export JSON</Btn>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 3, marginBottom: -1, flexWrap: "wrap" }}>
        {tabs.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)} style={{
            fontFamily: mono, fontSize: 10, letterSpacing: "0.08em",
            textTransform: "uppercase", padding: "7px 14px",
            borderRadius: "4px 4px 0 0", cursor: "pointer",
            border: `1px solid ${C.border}`,
            borderBottom: tab === t.key
              ? `1px solid ${C.surface}` : `1px solid ${C.border}`,
            background: tab === t.key ? C.surface : C.bg,
            color: tab === t.key ? C.accent : C.textMuted,
          }}>{t.label}</button>
        ))}
      </div>

      <div style={{
        background: C.surface, border: `1px solid ${C.border}`,
        borderRadius: "0 4px 4px 4px", padding: 20,
      }}>
        {tab === "security"   && <SecurityTable findings={report.security_findings} />}
        {tab === "tests"      && <TestResults results={report.api_test_results} />}
        {tab === "planner"    && <PlannerView plan={report.planner_assessment} />}
        {tab === "deployment" && <DeploymentView deployment={report.deployment} />}
        {tab === "recs" && (
          <div>
            {!(report.recommendations || []).length
              ? <p style={{ fontFamily: mono, color: C.green, fontSize: 12 }}>
                  ✓ No recommendations.
                </p>
              : (report.recommendations || []).map((r, i) => (
                <div key={i} style={{
                  display: "flex", gap: 10, padding: "10px 14px",
                  marginBottom: 6, background: C.bg,
                  border: `1px solid ${C.border}`,
                  borderLeft: `3px solid ${C.yellow}`, borderRadius: 4,
                }}>
                  <span style={{ color: C.yellow }}>▲</span>
                  <span style={{
                    fontFamily: sans, fontSize: 13,
                    color: C.textDim, lineHeight: 1.6,
                  }}>{r}</span>
                </div>
              ))
            }
          </div>
        )}
        {tab === "llm" && (
          report.llm_analysis
            ? <div
                style={{
                  fontFamily: sans, fontSize: 13,
                  color: C.textDim, lineHeight: 1.8,
                }}
                dangerouslySetInnerHTML={{
                  __html: renderMarkdown(report.llm_analysis)
                }}
              />
            : <p style={{ fontFamily: mono, color: C.textMuted, fontSize: 12 }}>
                Set <code style={{ color: C.accent }}>GROQ_API_KEY</code> to enable
                AI analysis.
              </p>
        )}
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────
export default function App() {
  const { apiKey, setApiKey, apiFetch, apiUpload } = useApi();

  const [authChecked, setAuthChecked] = useState(false);
  const [needsAuth,   setNeedsAuth]   = useState(false);

  useEffect(() => {
    fetch(BASE + "/health").then(r => {
      if (r.status === 401 && !apiKey) setNeedsAuth(true);
      setAuthChecked(true);
    }).catch(() => setAuthChecked(true));
  }, [apiKey]);

  const [specText,      setSpecText]      = useState("");
  const [specId,        setSpecId]        = useState(null);
  const [file,          setFile]          = useState(null);
  const [apiUrl,        setApiUrl]        = useState("");
  const [report,        setReport]        = useState(null);
  const [activeScanId,  setActiveScanId]  = useState(null);
  const [loading,       setLoading]       = useState(false);
  const [streaming,     setStreaming]      = useState(false);
  const [streamEvents,  setStreamEvents]  = useState([]);
  const [error,         setError]         = useState("");
  const [sidebarKey,    setSidebarKey]    = useState(0);

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
    try { parsed = JSON.parse(specText); }
    catch { throw new Error("Invalid JSON"); }
    const data = await apiFetch("/api/specs/upload", {
      method: "POST",
      body: JSON.stringify({ name: "uploaded_spec", spec: parsed }),
    });
    setSpecId(data.id); setActiveScanId(data.id);
  });

  const uploadFile = () => wrap(async () => {
    if (!file) throw new Error("No file selected");
    const form = new FormData();
    form.append("file", file);
    const data = await apiUpload("/api/specs/upload-file", form);
    setSpecId(data.id); setActiveScanId(data.id);
  });

  // ── Streaming scan ────────────────────────────────────────────
  const runScanStream = async (sid) => {
    const id = sid || specId;
    if (!id) return;

    setStreaming(true);
    setStreamEvents([]);
    setReport(null);
    setError("");

    try {
      const headers = {};
      if (apiKey) headers["X-API-Key"] = apiKey;

      const response = await fetch(`${BASE}/api/run/${id}/stream`, {
        method: "POST", headers,
      });

      if (response.status === 401) { setNeedsAuth(true); return; }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const reader  = response.body.getReader();
      const decoder = new TextDecoder();
      const events  = [];

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const text  = decoder.decode(value, { stream: true });
        const lines = text.split("\n").filter(l => l.startsWith("data: "));

        for (const line of lines) {
          const raw = line.slice(6).trim();
          if (raw === "[DONE]") break;
          try {
            const ev = JSON.parse(raw);
            events.push(ev);
            setStreamEvents([...events]);

            if (ev.agent === "report" && ev.status === "completed") {
              setReport(ev.data.report);
              setActiveScanId(id);
              setSidebarKey(k => k + 1);
            }
            if (ev.agent === "error") {
              setError(ev.data?.message || "Scan failed");
            }
          } catch { /* ignore malformed SSE lines */ }
        }
      }
    } catch (e) {
      if (e.message !== "AUTH_FAILED") setError(e.message || "Scan failed");
    } finally {
      setStreaming(false);
      setStreamEvents([]);
    }
  };

  const scanUrl = () => wrap(async () => {
    if (!apiUrl) throw new Error("Enter a URL");
    const data = await apiFetch("/api/scan-url", {
      method: "POST",
      body: JSON.stringify({ base_url: apiUrl }),
    });
    setReport(data.result || data);
    setActiveScanId(data.spec_id || null);
    setSidebarKey(k => k + 1);
  });

  const loadHistoryScan = async (scan) => {
    setError(""); setActiveScanId(scan.id);
    if (scan.status !== "completed") {
      setReport(null); setSpecId(scan.id); return;
    }
    try {
      const rep = await apiFetch(`/api/scans/${scan.id}/report`);
      setReport(rep); setSpecId(scan.id);
    } catch (e) { setError(e.message); }
  };

  if (!authChecked) return null;
  if (needsAuth && !apiKey) {
    return <LoginScreen onAuth={(k) => { setApiKey(k); setNeedsAuth(false); }} />;
  }

  return (
    <div style={{
      display: "flex", height: "100vh", background: C.bg,
      fontFamily: sans, color: C.text, overflow: "hidden",
    }}>
      <HistorySidebar
        key={sidebarKey}
        apiFetch={apiFetch}
        onSelect={loadHistoryScan}
        activeId={activeScanId}
      />

      <div style={{
        flex: 1, display: "flex", flexDirection: "column", overflow: "hidden",
      }}>
        {/* Topbar */}
        <div style={{
          height: 52, background: C.surface,
          borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", padding: "0 24px",
          flexShrink: 0, justifyContent: "space-between",
        }}>
          <span style={{
            fontFamily: mono, fontSize: 13, color: C.accent,
            letterSpacing: "0.1em",
          }}>◈ {APP_NAME}</span>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            {(loading || streaming) && (
              <span style={{ fontFamily: mono, fontSize: 11, color: C.yellow }}>
                ⟳ {streaming ? "streaming…" : "scanning…"}
              </span>
            )}
            {apiKey && (
              <button onClick={() => {
                sessionStorage.clear(); setApiKey(""); setNeedsAuth(true);
              }} style={{
                fontFamily: mono, fontSize: 10, color: C.textMuted,
                background: "none", border: "none", cursor: "pointer",
              }}>sign out</button>
            )}
          </div>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "24px 28px" }}>

          {error && (
            <div style={{
              background: C.redDim, border: `1px solid ${C.red}44`,
              borderRadius: 5, padding: "10px 14px",
              fontFamily: mono, fontSize: 12, color: C.red, marginBottom: 18,
            }}>✕ {error}</div>
          )}

          {/* Input panels */}
          <div style={{
            display: "grid", gridTemplateColumns: "1fr 1fr 1fr",
            gap: 14, marginBottom: 20,
          }}>
            {/* Paste JSON */}
            <div style={{
              background: C.surface, border: `1px solid ${C.border}`,
              borderRadius: 7, overflow: "hidden",
            }}>
              <div style={{
                padding: "10px 14px", borderBottom: `1px solid ${C.border}`,
                fontFamily: mono, fontSize: 10, color: C.accent,
                textTransform: "uppercase", letterSpacing: "0.08em",
              }}>Paste OpenAPI JSON</div>
              <div style={{ padding: 14 }}>
                <textarea rows={6} value={specText}
                  onChange={e => setSpecText(e.target.value)}
                  placeholder={"{\n  \"openapi\": \"3.0.0\",\n  ...\n}"}
                  style={{
                    fontFamily: mono, fontSize: 11, background: C.bg,
                    color: C.text, border: `1px solid ${C.border}`,
                    borderRadius: 4, padding: 10, width: "100%",
                    resize: "vertical", outline: "none",
                    boxSizing: "border-box", marginBottom: 10,
                  }} />
                <Btn onClick={uploadSpec} disabled={loading || streaming || !specText}>
                  Upload JSON
                </Btn>
              </div>
            </div>

            {/* Upload file */}
            <div style={{
              background: C.surface, border: `1px solid ${C.border}`,
              borderRadius: 7, overflow: "hidden",
            }}>
              <div style={{
                padding: "10px 14px", borderBottom: `1px solid ${C.border}`,
                fontFamily: mono, fontSize: 10, color: C.accent,
                textTransform: "uppercase", letterSpacing: "0.08em",
              }}>Upload File</div>
              <div style={{ padding: 14 }}>
                <div style={{
                  border: `1px dashed ${C.border}`, borderRadius: 5,
                  padding: "28px 14px", textAlign: "center", marginBottom: 10,
                }}>
                  <input type="file" accept=".json,.yaml,.yml"
                    onChange={e => setFile(e.target.files[0])}
                    style={{ display: "none" }} id="fup" />
                  <label htmlFor="fup" style={{
                    fontFamily: mono, fontSize: 11, color: C.accent, cursor: "pointer",
                  }}>
                    {file ? file.name : "Click to select .json / .yaml"}
                  </label>
                </div>
                <Btn onClick={uploadFile} disabled={loading || streaming || !file}>
                  Upload File
                </Btn>
              </div>
            </div>

            {/* Scan URL */}
            <div style={{
              background: C.surface, border: `1px solid ${C.border}`,
              borderRadius: 7, overflow: "hidden",
            }}>
              <div style={{
                padding: "10px 14px", borderBottom: `1px solid ${C.border}`,
                fontFamily: mono, fontSize: 10, color: C.accent,
                textTransform: "uppercase", letterSpacing: "0.08em",
              }}>Scan API URL</div>
              <div style={{ padding: 14 }}>
                <Input value={apiUrl} onChange={e => setApiUrl(e.target.value)}
                  placeholder="https://api.yourcompany.com"
                  style={{ marginBottom: 10 }} />
                <Btn onClick={scanUrl} disabled={loading || streaming || !apiUrl}>
                  Scan URL
                </Btn>
              </div>
            </div>
          </div>

          {/* Run scan banner */}
          {specId && !report && !streaming && (
            <div style={{
              background: C.accentDim, border: `1px solid ${C.accentBorder}`,
              borderRadius: 6, padding: "12px 18px",
              display: "flex", alignItems: "center",
              justifyContent: "space-between",
              marginBottom: 20, fontFamily: mono, fontSize: 12,
            }}>
              <span style={{ color: C.accent }}>
                Spec uploaded — ID: <code>{specId}</code>
              </span>
              <Btn onClick={() => runScanStream(specId)} disabled={streaming}>
                ▶ Run Security Scan
              </Btn>
            </div>
          )}

          {/* Streaming progress */}
          {streaming && streamEvents.length > 0 && (
            <ScanProgress events={streamEvents} />
          )}

          {/* Report */}
          {report && !streaming && (
            <ReportView
              report={report}
              specId={specId}
              onRescan={() => runScanStream(specId)}
            />
          )}

          {/* Empty state */}
          {!report && !specId && !streaming && (
            <div style={{ textAlign: "center", marginTop: 60 }}>
              <div style={{
                fontFamily: mono, fontSize: 36, color: C.border, marginBottom: 12,
              }}>◈</div>
              <div style={{
                fontFamily: mono, fontSize: 13, color: C.textMuted,
              }}>
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
        code {
          background: ${C.accentDim}; color: ${C.accent};
          padding: 1px 5px; border-radius: 3px;
          font-family: ${mono}; font-size: 0.9em;
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </div>
  );
}