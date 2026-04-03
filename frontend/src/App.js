import React, { useState, useEffect, useCallback } from "react";

// ─── Config ───────────────────────────────────────────────────────
const BASE     = process.env.REACT_APP_API_URL || "http://localhost:8000";
const APP_NAME = process.env.REACT_APP_APP_NAME || "API Sentinel";

// ─── Design tokens — Light theme ─────────────────────────────────
const C = {
  bg:           "#f5f6fa",
  bgWhite:      "#ffffff",
  surface:      "#ffffff",
  surfaceHigh:  "#f8f9fc",
  border:       "#e4e7ef",
  borderHigh:   "#d0d5e8",
  accent:       "#4f6ef7",
  accentLight:  "#eef0fe",
  accentBorder: "#c7cefc",
  green:        "#12b76a",
  greenLight:   "#ecfdf3",
  greenBorder:  "#a9efcc",
  yellow:       "#f79009",
  yellowLight:  "#fffaeb",
  yellowBorder: "#fec84b",
  red:          "#f04438",
  redLight:     "#fef3f2",
  redBorder:    "#fecdca",
  purple:       "#7c3aed",
  purpleLight:  "#f5f3ff",
  purpleBorder: "#c4b5fd",
  text:         "#101828",
  textSub:      "#344054",
  textMuted:    "#667085",
  textFaint:    "#98a2b3",
  sidebar:      "#ffffff",
  sidebarBg:    "#f9fafb",
  shadow:       "0 1px 3px rgba(16,24,40,0.08), 0 1px 2px rgba(16,24,40,0.04)",
  shadowMd:     "0 4px 8px rgba(16,24,40,0.08), 0 2px 4px rgba(16,24,40,0.04)",
};

const mono = `'JetBrains Mono', 'Fira Code', 'Courier New', monospace`;
const sans = `'Plus Jakarta Sans', 'DM Sans', system-ui, sans-serif`;

// ─── Agent metadata ───────────────────────────────────────────────
const AGENTS = [
  { key: "planner",        label: "Planner",        icon: "◎" },
  { key: "test_generation",label: "Test Generator", icon: "⊡" },
  { key: "security",       label: "Security Agent", icon: "⊘" },
  { key: "api_testing",    label: "API Testing",    icon: "⊛" },
  { key: "deployment",     label: "Deployment",     icon: "⊕" },
  { key: "deep_scan",      label: "Deep Scan",      icon: "◆" },
  { key: "llm_analysis",   label: "AI Analysis",    icon: "◈" },
  { key: "report",         label: "Report",         icon: "◉" },
];

// ─── Helpers ──────────────────────────────────────────────────────
const sevColor = (s) =>
  s === "CRITICAL" ? C.red :
  s === "HIGH"     ? C.red :
  s === "MEDIUM"   ? C.yellow : C.green;

const sevBg = (s) =>
  s === "CRITICAL" ? C.redLight :
  s === "HIGH"     ? C.redLight :
  s === "MEDIUM"   ? C.yellowLight : C.greenLight;

const sevBorder = (s) =>
  s === "CRITICAL" ? C.redBorder :
  s === "HIGH"     ? C.redBorder :
  s === "MEDIUM"   ? C.yellowBorder : C.greenBorder;

const timeAgo = (iso) => {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

const renderMarkdown = (text) => {
  if (!text) return "";
  return text
    .replace(/\*\*(.+?)\*\*/g, `<strong style="color:${C.text}">$1</strong>`)
    .replace(/\*(.+?)\*/g, `<em>$1</em>`)
    .replace(/^### (.+)$/gm, `<div style="font-weight:600;font-size:13px;color:${C.text};margin:18px 0 8px">${"$1"}</div>`)
    .replace(/^## (.+)$/gm, `<div style="font-weight:700;font-size:14px;color:${C.text};margin:20px 0 10px">${"$1"}</div>`)
    .replace(/^\d+\. (.+)$/gm, `<div style="padding:5px 0 5px 16px;border-left:2px solid ${C.accentBorder};margin-bottom:5px;color:${C.textSub}">${"$1"}</div>`)
    .replace(/\n\n/g, `<div style="margin:10px 0"></div>`)
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

// ─── Primitives ───────────────────────────────────────────────────
function Badge({ label, color, bg, border, small }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      fontFamily: mono, fontSize: small ? 10 : 11, fontWeight: 600,
      letterSpacing: "0.04em",
      padding: small ? "1px 7px" : "3px 9px",
      borderRadius: 4,
      background: bg || `${color}18`,
      color: color,
      border: `1px solid ${border || color + "44"}`,
      whiteSpace: "nowrap",
    }}>{label}</span>
  );
}

function SeveritySummary({ summary: s, deepScanPerformed, deepScanCount }) {
  const bars = [
    { label: "Critical", value: s.critical_risks ?? 0, color: C.red },
    { label: "High",     value: s.high_risks    ?? 0, color: C.red },
    { label: "Medium",   value: s.medium_risks  ?? 0, color: C.yellow },
    { label: "Low",      value: s.low_risks     ?? 0, color: C.green },
  ];
  const max = Math.max(...bars.map(b => b.value), 1);

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 14,
      marginBottom: 20,
    }}>
      <div style={{
        background: C.surface, border: `1px solid ${C.border}`,
        borderRadius: 10, padding: "18px 20px", boxShadow: C.shadow,
      }}>
        <div style={{
          fontFamily: sans, fontSize: 11, fontWeight: 600,
          color: C.textFaint, textTransform: "uppercase",
          letterSpacing: "0.06em", marginBottom: 14,
        }}>Security findings</div>
        {bars.map(({ label, value, color }) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
            <span style={{ fontFamily: sans, fontSize: 12, color: C.textMuted, width: 52, flexShrink: 0 }}>
              {label}
            </span>
            <div style={{ flex: 1, height: 6, background: C.bg, borderRadius: 3, overflow: "hidden" }}>
              <div style={{
                height: "100%",
                width: `${Math.round((value / max) * 100)}%`,
                background: color,
                borderRadius: 3,
                transition: "width 0.5s cubic-bezier(0.4,0,0.2,1)",
                minWidth: value > 0 ? 6 : 0,
              }} />
            </div>
            <span style={{
              fontFamily: mono, fontSize: 12, fontWeight: 600,
              color: value > 0 ? color : C.textFaint,
              width: 16, textAlign: "right", flexShrink: 0,
            }}>{value}</span>
          </div>
        ))}
      </div>

      <div style={{
        background: C.surface, border: `1px solid ${C.border}`,
        borderRadius: 10, padding: "18px 20px", boxShadow: C.shadow,
        display: "grid", gridTemplateColumns: "1fr 1fr",
        gap: 12, alignContent: "start",
      }}>
        {[
          { label: "Tests run",      value: s.total_tests_run },
          { label: "Passed",         value: s.passed_tests    },
          { label: "Failed",         value: s.failed_tests    },
          { label: "Security score", value: s.deployment_checks_ran ? (s.deployment_security_score || "N/A") : "N/A" },
        ].map(({ label, value }) => (
          <div key={label} style={{
            background: C.surfaceHigh, border: `1px solid ${C.border}`,
            borderRadius: 8, padding: "10px 12px",
          }}>
            <div style={{ fontFamily: mono, fontSize: 20, fontWeight: 700, color: C.text, lineHeight: 1 }}>
              {value ?? "—"}
            </div>
            <div style={{ fontFamily: sans, fontSize: 11, color: C.textMuted, marginTop: 5 }}>
              {label}
            </div>
          </div>
        ))}
        {deepScanPerformed && (
          <div style={{
            background: C.purpleLight, border: `1px solid ${C.purpleBorder}`,
            borderRadius: 8, padding: "10px 12px", gridColumn: "span 2",
          }}>
            <div style={{ fontFamily: mono, fontSize: 20, fontWeight: 700, color: C.purple, lineHeight: 1 }}>
              {deepScanCount ?? 0}
            </div>
            <div style={{ fontFamily: sans, fontSize: 11, color: C.purple, marginTop: 5 }}>
              PoC exploits generated
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Btn({ onClick, children, variant = "primary", disabled, small }) {
  const map = {
    primary: {
      bg: C.accent, color: "#fff",
      border: `1px solid ${C.accent}`,
      hover: "#3d5ce6",
    },
    ghost: {
      bg: "transparent", color: C.accent,
      border: `1px solid ${C.accentBorder}`,
    },
    danger: {
      bg: C.red, color: "#fff",
      border: `1px solid ${C.red}`,
    },
    subtle: {
      bg: C.surface, color: C.textSub,
      border: `1px solid ${C.border}`,
    },
  };
  const s = map[variant] || map.primary;
  return (
    <button onClick={onClick} disabled={disabled} style={{
      fontFamily: sans, fontSize: small ? 12 : 13,
      fontWeight: 600,
      padding: small ? "6px 14px" : "9px 18px",
      borderRadius: 7,
      cursor: disabled ? "not-allowed" : "pointer",
      opacity: disabled ? 0.45 : 1,
      background: s.bg, color: s.color, border: s.border,
      transition: "all 0.15s",
      boxShadow: variant === "primary" && !disabled ? "0 1px 3px rgba(79,110,247,0.25)" : "none",
      display: "inline-flex", alignItems: "center", gap: 6,
      whiteSpace: "nowrap",
    }}>{children}</button>
  );
}

function Input({ value, onChange, placeholder, type = "text", style = {} }) {
  return (
    <input type={type} value={value} onChange={onChange}
      placeholder={placeholder}
      style={{
        fontFamily: sans, fontSize: 13,
        background: C.surface, color: C.text,
        border: `1px solid ${C.border}`, borderRadius: 7,
        padding: "9px 12px", outline: "none", width: "100%",
        boxSizing: "border-box",
        transition: "border-color 0.15s",
        ...style,
      }}
      onFocus={e => e.target.style.borderColor = C.accent}
      onBlur={e => e.target.style.borderColor = C.border}
    />
  );
}

// ─── Section header ───────────────────────────────────────────────
function SectionHeader({ title, count, color }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 10,
      marginBottom: 16,
    }}>
      <span style={{
        fontFamily: sans, fontSize: 14, fontWeight: 700, color: C.text,
      }}>{title}</span>
      {count !== undefined && (
        <span style={{
          fontFamily: mono, fontSize: 11, fontWeight: 600,
          background: color ? `${color}15` : C.surfaceHigh,
          color: color || C.textMuted,
          border: `1px solid ${color ? color + "30" : C.border}`,
          padding: "1px 8px", borderRadius: 20,
        }}>{count}</span>
      )}
    </div>
  );
}

// ─── Streaming Progress ───────────────────────────────────────────
function ScanProgress({ events }) {
  const statusMap = {};
  for (const ev of events) {
    statusMap[ev.agent] = ev.status;
  }

  const completed = AGENTS.filter(
    a => ["completed", "skipped", "error"].includes(statusMap[a.key])
  ).length;
  const pct = Math.round((completed / AGENTS.length) * 100);

  const statusColor = (s) =>
    s === "completed" ? C.green :
    s === "running"   ? C.accent :
    s === "skipped"   ? C.textFaint :
    s === "error"     ? C.red : C.border;

  const statusLabel = (s) =>
    s === "completed" ? "Done" :
    s === "running"   ? "Running…" :
    s === "skipped"   ? "Skipped" :
    s === "error"     ? "Error" : "Waiting";

  return (
    <div style={{
      background: C.surface,
      border: `1px solid ${C.border}`,
      borderRadius: 12,
      padding: "22px 24px",
      marginBottom: 20,
      boxShadow: C.shadow,
    }}>
      <div style={{
        display: "flex", justifyContent: "space-between",
        alignItems: "center", marginBottom: 20,
      }}>
        <div style={{ fontFamily: sans, fontSize: 14, fontWeight: 700, color: C.text }}>
          Scan in progress
        </div>
        <div style={{
          fontFamily: mono, fontSize: 12, fontWeight: 600, color: C.accent,
        }}>{pct}%</div>
      </div>

      {/* Progress bar */}
      <div style={{
        height: 4, background: C.bg, borderRadius: 4,
        overflow: "hidden", marginBottom: 20,
      }}>
        <div style={{
          height: "100%", width: `${pct}%`,
          background: `linear-gradient(90deg, ${C.accent}, #7c9fff)`,
          borderRadius: 4,
          transition: "width 0.5s cubic-bezier(0.4,0,0.2,1)",
          boxShadow: `0 0 12px ${C.accent}60`,
        }} />
      </div>

      <div style={{
        display: "grid", gridTemplateColumns: "1fr 1fr",
        gap: "6px 24px",
      }}>
        {AGENTS.map((agent) => {
          const status = statusMap[agent.key] || "pending";
          const color  = statusColor(status);
          const isRunning = status === "running";

          return (
            <div key={agent.key} style={{
              display: "flex", alignItems: "center", gap: 10,
              padding: "6px 0",
            }}>
              <div style={{
                width: 7, height: 7, borderRadius: "50%",
                background: color,
                flexShrink: 0,
                boxShadow: isRunning ? `0 0 0 3px ${color}30` : "none",
                animation: isRunning ? "pulse 1.4s ease infinite" : "none",
              }} />
              <span style={{
                fontFamily: sans, fontSize: 13,
                color: status === "pending" ? C.textFaint : C.textSub,
                flex: 1, fontWeight: 500,
              }}>
                {agent.label}
              </span>
              <span style={{
                fontFamily: mono, fontSize: 10, color,
                letterSpacing: "0.03em",
              }}>
                {statusLabel(status)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Login Screen ─────────────────────────────────────────────────
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
      if (res.status === 401) { setErr("Wrong API key — try again"); return; }
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
      fontFamily: sans,
    }}>
      <div style={{
        background: C.surface, border: `1px solid ${C.border}`,
        borderRadius: 16, padding: "44px 48px", width: 400,
        boxShadow: C.shadowMd,
      }}>
        <div style={{ marginBottom: 28, textAlign: "center" }}>
          <div style={{
            width: 48, height: 48, borderRadius: 12,
            background: C.accentLight,
            border: `1px solid ${C.accentBorder}`,
            display: "flex", alignItems: "center", justifyContent: "center",
            margin: "0 auto 16px",
            fontSize: 22, color: C.accent,
          }}>◈</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: C.text, marginBottom: 6 }}>
            {APP_NAME}
          </div>
          <div style={{ fontSize: 13, color: C.textMuted }}>
            Enter your API key to continue
          </div>
        </div>
        <Input value={key} onChange={e => setKey(e.target.value)}
          placeholder="sk-••••••••••••••••" type="password"
          style={{ marginBottom: 12, textAlign: "center", letterSpacing: "0.08em" }} />
        {err && (
          <div style={{
            color: C.red, fontFamily: mono, fontSize: 11, marginBottom: 12,
            background: C.redLight, border: `1px solid ${C.redBorder}`,
            borderRadius: 6, padding: "7px 10px",
          }}>{err}</div>
        )}
        <Btn onClick={tryLogin} disabled={loading || !key}>
          {loading ? "Connecting…" : "Continue →"}
        </Btn>
        <div style={{
          fontFamily: sans, fontSize: 12, color: C.textFaint, marginTop: 18,
          textAlign: "center",
        }}>
          Leave blank for dev mode (no auth)
        </div>
      </div>
    </div>
  );
}

// ─── History Sidebar ──────────────────────────────────────────────
function HistorySidebar({ apiFetch, onSelect, activeId, collapsed, onToggle }) {
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
      width: collapsed ? 48 : 260,
      minWidth: collapsed ? 48 : 260,
      background: C.sidebar,
      borderRight: `1px solid ${C.border}`,
      display: "flex", flexDirection: "column",
      height: "100vh", overflow: "hidden",
      transition: "width 0.2s cubic-bezier(0.4,0,0.2,1), min-width 0.2s cubic-bezier(0.4,0,0.2,1)",
    }}>
      {/* Sidebar header */}
      <div style={{
        padding: collapsed ? "12px 0" : "16px 16px 12px",
        borderBottom: `1px solid ${C.border}`,
        display: "flex", flexDirection: "column",
        alignItems: collapsed ? "center" : "stretch",
      }}>
        <div style={{
          display: "flex", alignItems: "center",
          justifyContent: collapsed ? "center" : "space-between",
          marginBottom: collapsed ? 0 : 12,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{
              width: 28, height: 28, borderRadius: 8,
              background: C.accentLight, border: `1px solid ${C.accentBorder}`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 14, color: C.accent, flexShrink: 0,
              cursor: "pointer",
            }} onClick={onToggle}>◈</div>
            {!collapsed && (
              <span style={{ fontFamily: sans, fontSize: 14, fontWeight: 700, color: C.text }}>
                {APP_NAME}
              </span>
            )}
          </div>
          {!collapsed && (
            <div style={{ display: "flex", gap: 4 }}>
              <button onClick={refresh} style={{
                fontFamily: mono, fontSize: 14, color: C.textMuted,
                background: "none", border: "none", cursor: "pointer",
                padding: "2px 4px", borderRadius: 4,
              }}>↻</button>
              <button onClick={onToggle} style={{
                fontFamily: mono, fontSize: 14, color: C.textMuted,
                background: "none", border: "none", cursor: "pointer",
                padding: "2px 4px", borderRadius: 4,
              }}>←</button>
            </div>
          )}
        </div>
        {!collapsed && (
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Filter scans…"
            style={{
              fontFamily: sans, fontSize: 12, background: C.sidebarBg,
              color: C.text, border: `1px solid ${C.border}`, borderRadius: 7,
              padding: "7px 10px", width: "100%", outline: "none",
              boxSizing: "border-box",
            }} />
        )}
      </div>

      {!collapsed && (
        <div style={{ padding: "6px 10px", borderBottom: `1px solid ${C.border}` }}>
          <span style={{
            fontFamily: sans, fontSize: 11, color: C.textFaint,
            textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600,
          }}>
            Scan history {scans.length > 0 && `· ${scans.length}`}
          </span>
        </div>
      )}

      <div style={{ flex: 1, overflowY: "auto", display: collapsed ? "none" : "block" }}>
        {filtered.length === 0 && !loading && (
          <div style={{
            padding: "32px 16px", textAlign: "center",
            fontFamily: sans, fontSize: 13, color: C.textFaint,
          }}>
            {search ? "No matches found" : "No scans yet"}
          </div>
        )}
        {filtered.map(s => {
          const isActive = s.id === activeId;
          return (
            <div key={s.id} onClick={() => onSelect(s)} style={{
              padding: "10px 14px", cursor: "pointer",
              background: isActive ? C.accentLight : "transparent",
              borderLeft: `2px solid ${isActive ? C.accent : "transparent"}`,
              borderBottom: `1px solid ${C.border}18`,
              transition: "background 0.12s",
            }}>
              <div style={{
                display: "flex", justifyContent: "space-between",
                alignItems: "flex-start",
              }}>
                <div style={{
                  fontFamily: sans, fontSize: 13, fontWeight: 500,
                  color: isActive ? C.accent : C.text,
                  marginBottom: 3, wordBreak: "break-all", flex: 1,
                }}>
                  {s.api_title || s.name}
                </div>
                <button onClick={e => handleDelete(e, s.id)} style={{
                  background: "none", border: "none", color: C.textFaint,
                  cursor: "pointer", fontSize: 16, lineHeight: 1,
                  marginLeft: 6, flexShrink: 0, padding: "0 2px",
                  borderRadius: 3, transition: "color 0.12s",
                }}>×</button>
              </div>
              <div style={{
                fontFamily: sans, fontSize: 11, color: C.textFaint, marginBottom: 6,
              }}>
                {s.endpoint_count} endpoints · {timeAgo(s.created_at)}
              </div>
              <Badge
                label={s.status}
                color={s.status === "completed" ? C.green : C.yellow}
                bg={s.status === "completed" ? C.greenLight : C.yellowLight}
                border={s.status === "completed" ? C.greenBorder : C.yellowBorder}
                small
              />
            </div>
          );
        })}
      </div>

      {!collapsed && (
        <div style={{
          padding: "10px 14px",
          borderTop: `1px solid ${C.border}`,
          background: C.sidebarBg,
        }}>
          <div style={{ fontFamily: mono, fontSize: 10, color: C.textFaint }}>
            {BASE.replace(/https?:\/\//, "")}
          </div>
        </div>
      )}
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
    <div style={{
      display: "flex", alignItems: "center", gap: 10,
      padding: "20px 0",
      fontFamily: sans, fontSize: 14, color: C.green,
    }}>
      <span style={{ fontSize: 18 }}>✓</span> No security findings detected.
    </div>
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

  const FilterBtn = ({ label, active, onClick, activeColor }) => (
    <button onClick={onClick} style={{
      fontFamily: sans, fontSize: 12, fontWeight: 500,
      padding: "4px 12px", borderRadius: 6,
      border: `1px solid ${active ? (activeColor || C.accent) : C.border}`,
      background: active ? (activeColor ? `${activeColor}12` : C.accentLight) : C.surface,
      color: active ? (activeColor || C.accent) : C.textMuted,
      cursor: "pointer", transition: "all 0.12s",
    }}>{label}</button>
  );

  return (
    <div>
      {/* Filters */}
      <div style={{
        display: "flex", gap: 6, marginBottom: 16, flexWrap: "wrap",
        alignItems: "center",
        padding: "10px 14px", background: C.surfaceHigh,
        border: `1px solid ${C.border}`, borderRadius: 8,
      }}>
        <span style={{
          fontFamily: sans, fontSize: 11, color: C.textFaint,
          fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em",
          marginRight: 4,
        }}>Severity</span>
        {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(s => (
          <FilterBtn key={s} label={s}
            active={severityFilter === s}
            onClick={() => setSeverityFilter(s)}
            activeColor={s === "CRITICAL" || s === "HIGH" ? C.red : s === "MEDIUM" ? C.yellow : s === "LOW" ? C.green : undefined}
          />
        ))}
        <div style={{ width: 1, height: 20, background: C.border, margin: "0 4px" }} />
        <span style={{
          fontFamily: sans, fontSize: 11, color: C.textFaint,
          fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em",
          marginRight: 4,
        }}>Type</span>
        {["ALL","STATIC","DYNAMIC"].map(t => (
          <FilterBtn key={t} label={t}
            active={typeFilter === t}
            onClick={() => setTypeFilter(t)}
            activeColor={t === "DYNAMIC" ? C.green : undefined}
          />
        ))}
        <div style={{ width: 1, height: 20, background: C.border, margin: "0 4px" }} />
        <span style={{
          fontFamily: sans, fontSize: 11, color: C.textFaint,
          fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em",
          marginRight: 4,
        }}>Sort</span>
        <FilterBtn label="Severity" active={sortBy === "severity"} onClick={() => setSortBy("severity")} />
        <FilterBtn label="Endpoint" active={sortBy === "endpoint"} onClick={() => setSortBy("endpoint")} />
      </div>

      {filtered.length === 0 && (
        <div style={{ fontFamily: sans, color: C.textMuted, fontSize: 13, padding: "16px 0" }}>
          No findings match current filters.
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {filtered.map((f, i) => {
          const vulnName = f.vulnerability || f.risk_type || "Unknown";
          const hasPoC   = !!f.exploit_poc;
          const isOpen   = exp === i;

          return (
            <div key={i} style={{
              border: `1px solid ${isOpen ? C.accentBorder : C.border}`,
              borderRadius: 8,
              background: C.surface,
              overflow: "hidden",
              transition: "border-color 0.15s",
              boxShadow: isOpen ? `0 0 0 3px ${C.accentLight}` : "none",
            }}>
              {/* Row */}
              <div onClick={() => setExp(isOpen ? null : i)} style={{
                display: "grid",
                gridTemplateColumns: "1fr 2fr auto auto 32px",
                gap: 12, alignItems: "center",
                padding: "12px 16px", cursor: "pointer",
                background: isOpen ? C.accentLight : "transparent",
              }}>
                <div style={{
                  fontFamily: mono, fontSize: 12, color: C.accent,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>
                  {f.endpoint}
                  {f.affected_methods?.length > 1 && (
                    <span style={{ fontSize: 10, color: C.textFaint, marginLeft: 6 }}>
                      [{f.affected_methods.join(", ")}]
                    </span>
                  )}
                </div>
                <div style={{ fontFamily: sans, fontSize: 13, color: C.textSub, fontWeight: 500 }}>
                  {vulnName}
                  {hasPoC && (
                    <span style={{
                      fontFamily: mono, fontSize: 10, color: C.purple,
                      marginLeft: 8, border: `1px solid ${C.purpleBorder}`,
                      padding: "1px 6px", borderRadius: 4,
                      background: C.purpleLight,
                    }}>PoC</span>
                  )}
                </div>
                <Badge
                  label={f.severity}
                  color={sevColor(f.severity)}
                  bg={sevBg(f.severity)}
                  border={sevBorder(f.severity)}
                  small
                />
                <div style={{ fontFamily: sans, fontSize: 11, fontWeight: 500 }}>
                  {f.detection_type === "DYNAMIC"
                    ? <span style={{ color: C.green }}>● Confirmed</span>
                    : <span style={{ color: C.textFaint }}>○ Static</span>
                  }
                </div>
                <div style={{ color: C.textFaint, fontSize: 12, textAlign: "center" }}>
                  {isOpen ? "▲" : "▼"}
                </div>
              </div>

              {/* Expanded */}
              {isOpen && (
                <div style={{
                  padding: "16px 20px",
                  borderTop: `1px solid ${C.border}`,
                  background: C.surfaceHigh,
                }}>
                  <p style={{
                    fontFamily: sans, fontSize: 13, color: C.textSub,
                    lineHeight: 1.7, margin: "0 0 12px",
                  }}>{f.description}</p>

                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: hasPoC ? 16 : 0 }}>
                    {f.confidence && (
                      <Badge
                        label={`Confidence: ${f.confidence}`}
                        color={f.confidence === "HIGH" ? C.red : f.confidence === "MEDIUM" ? C.yellow : C.textMuted}
                        small
                      />
                    )}
                    {f.method && <Badge label={f.method} color={C.accent} bg={C.accentLight} border={C.accentBorder} small />}
                  </div>

                  {hasPoC && (
                    <div style={{
                      marginTop: 14,
                      border: `1px solid ${C.purpleBorder}`,
                      borderRadius: 8,
                      background: C.purpleLight,
                      padding: "14px 16px",
                    }}>
                      <div style={{
                        fontFamily: sans, fontSize: 12, fontWeight: 700,
                        color: C.purple, marginBottom: 10,
                        display: "flex", alignItems: "center", gap: 6,
                      }}>
                        ◆ Proof of Concept Exploit
                      </div>
                      <p style={{
                        fontFamily: sans, fontSize: 13, color: C.textSub,
                        lineHeight: 1.6, margin: "0 0 12px",
                      }}>{f.exploit_poc.summary}</p>

                      {f.exploit_poc.steps?.length > 0 && (
                        <div style={{ marginBottom: 12 }}>
                          <div style={{
                            fontFamily: sans, fontSize: 11, fontWeight: 600,
                            color: C.textFaint, textTransform: "uppercase",
                            letterSpacing: "0.06em", marginBottom: 6,
                          }}>Steps</div>
                          {f.exploit_poc.steps.map((step, si) => (
                            <div key={si} style={{
                              fontFamily: sans, fontSize: 12, color: C.textSub,
                              lineHeight: 1.6, paddingLeft: 14, marginBottom: 5,
                              borderLeft: `2px solid ${C.purpleBorder}`,
                            }}>{step}</div>
                          ))}
                        </div>
                      )}
                      {f.exploit_poc.sample_curl && (
                        <div style={{ marginBottom: 12 }}>
                          <div style={{
                            fontFamily: sans, fontSize: 11, fontWeight: 600,
                            color: C.textFaint, textTransform: "uppercase",
                            letterSpacing: "0.06em", marginBottom: 6,
                          }}>Sample cURL</div>
                          <div style={{
                            fontFamily: mono, fontSize: 11, color: C.green,
                            background: C.surface, border: `1px solid ${C.border}`,
                            borderRadius: 6, padding: "10px 14px",
                            wordBreak: "break-all", lineHeight: 1.6,
                          }}>{f.exploit_poc.sample_curl}</div>
                        </div>
                      )}
                      {f.exploit_poc.verification_test && (
                        <div>
                          <div style={{
                            fontFamily: sans, fontSize: 11, fontWeight: 600,
                            color: C.textFaint, textTransform: "uppercase",
                            letterSpacing: "0.06em", marginBottom: 6,
                          }}>Verification</div>
                          <div style={{ fontFamily: sans, fontSize: 12, color: C.textSub, lineHeight: 1.6 }}>
                            {f.exploit_poc.verification_test}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── API Test Results ─────────────────────────────────────────────
function TestResults({ results = [] }) {
  const [open, setOpen] = useState(null);
  if (!results.length) return (
    <div style={{ fontFamily: sans, color: C.textMuted, fontSize: 13, padding: "16px 0" }}>
      No test results available.
    </div>
  );
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {results.map((ep, i) => {
        const tests  = ep.tests || [];
        const passed = tests.filter(t => t.passed === true).length;
        const failed = tests.filter(t => t.passed === false).length;
        const isOpen = open === i;
        return (
          <div key={i} style={{
            border: `1px solid ${isOpen ? C.accentBorder : C.border}`,
            borderRadius: 8, overflow: "hidden", background: C.surface,
          }}>
            <div onClick={() => setOpen(isOpen ? null : i)} style={{
              display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "12px 16px", cursor: "pointer",
              background: isOpen ? C.accentLight : "transparent",
            }}>
              <span style={{ fontFamily: mono, fontSize: 12, color: C.accent, fontWeight: 600 }}>
                {ep.method} {ep.endpoint}
              </span>
              <span style={{ display: "flex", gap: 12, alignItems: "center" }}>
                <Badge label={`${passed} passed`} color={C.green} bg={C.greenLight} border={C.greenBorder} small />
                {failed > 0 && <Badge label={`${failed} failed`} color={C.red} bg={C.redLight} border={C.redBorder} small />}
                <span style={{ color: C.textFaint, fontSize: 12 }}>{isOpen ? "▲" : "▼"}</span>
              </span>
            </div>
            {isOpen && (
              <div style={{ borderTop: `1px solid ${C.border}` }}>
                {tests.map((t, j) => {
                  if (t.test === "dynamic_fuzz_testing") return (
                    <div key={j} style={{
                      padding: "12px 16px", borderBottom: `1px solid ${C.border}18`,
                    }}>
                      <div style={{
                        display: "flex", justifyContent: "space-between",
                        alignItems: "center", marginBottom: 8,
                      }}>
                        <span style={{ fontFamily: sans, fontSize: 13, fontWeight: 600, color: C.textSub }}>
                          Fuzz testing
                        </span>
                        <Badge
                          label={`${t.vulnerable_count} / ${t.total_payloads} flagged`}
                          color={t.vulnerable_count > 0 ? C.red : C.green}
                          bg={t.vulnerable_count > 0 ? C.redLight : C.greenLight}
                          border={t.vulnerable_count > 0 ? C.redBorder : C.greenBorder}
                          small
                        />
                      </div>
                      {(t.results || []).filter(r => r.possible_vulnerability).map((r, k) => (
                        <div key={k} style={{
                          background: C.redLight, border: `1px solid ${C.redBorder}`,
                          borderRadius: 5, padding: "6px 10px", marginBottom: 4,
                          fontFamily: mono, fontSize: 11, color: C.red,
                        }}>⚠ {r.payload} → {r.status_code || r.error}</div>
                      ))}
                    </div>
                  );
                  return (
                    <div key={j} style={{
                      display: "flex", justifyContent: "space-between", alignItems: "center",
                      padding: "9px 16px", borderBottom: `1px solid ${C.border}18`,
                    }}>
                      <span style={{ fontFamily: sans, fontSize: 13, color: C.textSub }}>
                        {t.test.replace(/_/g, " ")}
                      </span>
                      <span style={{ display: "flex", gap: 10, alignItems: "center" }}>
                        {t.status_code && (
                          <span style={{ fontFamily: mono, fontSize: 12, color: C.textFaint }}>
                            HTTP {t.status_code}
                          </span>
                        )}
                        {t.error && (
                          <span style={{ fontFamily: mono, fontSize: 11, color: C.red }}>
                            {t.error.slice(0, 50)}
                          </span>
                        )}
                        <Badge
                          label={t.passed ? "Pass" : "Fail"}
                          color={t.passed ? C.green : C.red}
                          bg={t.passed ? C.greenLight : C.redLight}
                          border={t.passed ? C.greenBorder : C.redBorder}
                          small
                        />
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

// ─── Planner View ─────────────────────────────────────────────────
function PlannerView({ plan }) {
  if (!plan || !Object.keys(plan).length) return (
    <div style={{ fontFamily: sans, color: C.textMuted, fontSize: 13, padding: "16px 0" }}>
      No planner assessment available.
    </div>
  );
  const riskColor = (l) =>
    l === "CRITICAL" || l === "HIGH" ? C.red : l === "MEDIUM" ? C.yellow : C.green;
  const riskBg = (l) =>
    l === "CRITICAL" || l === "HIGH" ? C.redLight : l === "MEDIUM" ? C.yellowLight : C.greenLight;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      {/* Risk summary */}
      <div style={{
        background: C.accentLight, border: `1px solid ${C.accentBorder}`,
        borderRadius: 10, padding: "16px 18px",
      }}>
        <div style={{
          fontFamily: sans, fontSize: 12, fontWeight: 700, color: C.accent,
          textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8,
        }}>Risk Summary</div>
        <div style={{ fontFamily: sans, fontSize: 13, color: C.textSub, lineHeight: 1.7 }}>
          {plan.risk_summary}
        </div>
        {plan.auth_pattern_detected && (
          <div style={{ marginTop: 12 }}>
            <Badge
              label={`Auth: ${plan.auth_pattern_detected}`}
              color={plan.auth_pattern_detected === "none" ? C.red : C.green}
              bg={plan.auth_pattern_detected === "none" ? C.redLight : C.greenLight}
              border={plan.auth_pattern_detected === "none" ? C.redBorder : C.greenBorder}
            />
          </div>
        )}
      </div>

      {plan.high_risk_endpoints?.length > 0 && (
        <div>
          <SectionHeader title="High Risk Endpoints" count={plan.high_risk_endpoints.length} color={C.red} />
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {plan.high_risk_endpoints.map((ep, i) => (
              <div key={i} style={{
                background: C.surface, border: `1px solid ${C.border}`,
                borderLeft: `3px solid ${riskColor(ep.risk_level)}`,
                borderRadius: 8, padding: "12px 16px",
              }}>
                <div style={{
                  display: "flex", justifyContent: "space-between",
                  alignItems: "center", marginBottom: 8,
                }}>
                  <span style={{ fontFamily: mono, fontSize: 12, color: C.accent, fontWeight: 600 }}>
                    {ep.method} {ep.path}
                  </span>
                  <Badge
                    label={ep.risk_level}
                    color={riskColor(ep.risk_level)}
                    bg={riskBg(ep.risk_level)}
                    border={`${riskColor(ep.risk_level)}40`}
                    small
                  />
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: ep.attack_vectors?.length ? 8 : 0 }}>
                  {ep.risk_reasons?.map((r, ri) => (
                    <span key={ri} style={{
                      fontFamily: sans, fontSize: 11, color: C.textMuted,
                      background: C.surfaceHigh, border: `1px solid ${C.border}`,
                      borderRadius: 4, padding: "2px 8px",
                    }}>{r}</span>
                  ))}
                </div>
                {ep.attack_vectors?.length > 0 && (
                  <div style={{ fontFamily: sans, fontSize: 11, color: C.textFaint }}>
                    Vectors: {ep.attack_vectors.join(", ")}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {plan.business_logic_risks?.length > 0 && (
        <div>
          <SectionHeader title="Business Logic Risks" color={C.yellow} />
          {plan.business_logic_risks.map((r, i) => (
            <div key={i} style={{
              fontFamily: sans, fontSize: 13, color: C.textSub,
              padding: "8px 14px", borderLeft: `3px solid ${C.yellowBorder}`,
              marginBottom: 6, lineHeight: 1.6,
              background: C.yellowLight, borderRadius: "0 6px 6px 0",
            }}>{r}</div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Deployment View ──────────────────────────────────────────────
function DeploymentView({ deployment }) {
  if (!deployment || deployment.status === "unknown") return (
    <div style={{ fontFamily: sans, color: C.textMuted, fontSize: 13, padding: "16px 0" }}>
      No deployment data available.
    </div>
  );

  const scoreNum = parseInt(deployment.security_score);
  const scoreColor = !deployment.security_score || deployment.security_score === "N/A"
    ? C.textFaint
    : scoreNum >= 5 ? C.green : scoreNum >= 3 ? C.yellow : C.red;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        {/* Score */}
        <div style={{
          background: C.surface, border: `1px solid ${C.border}`,
          borderRadius: 10, padding: "16px 20px", flex: 1, minWidth: 130,
          boxShadow: C.shadow,
        }}>
          <div style={{ fontFamily: mono, fontSize: 32, fontWeight: 700, color: scoreColor, lineHeight: 1 }}>
            {deployment.security_score || "N/A"}
          </div>
          <div style={{ fontFamily: sans, fontSize: 12, color: C.textMuted, marginTop: 6, fontWeight: 500 }}>
            Security Score
          </div>
        </div>
        {/* Status */}
        <div style={{
          background: C.surface, border: `1px solid ${C.border}`,
          borderRadius: 10, padding: "16px 20px", flex: 1, minWidth: 130,
          boxShadow: C.shadow,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <div style={{
              width: 10, height: 10, borderRadius: "50%",
              background: deployment.status === "healthy" ? C.green : C.red,
              boxShadow: `0 0 6px ${deployment.status === "healthy" ? C.green : C.red}`,
            }} />
            <span style={{
              fontFamily: sans, fontSize: 14, fontWeight: 700,
              color: deployment.status === "healthy" ? C.green : C.red,
            }}>
              {(deployment.status || "unknown").charAt(0).toUpperCase() + (deployment.status || "unknown").slice(1)}
            </span>
          </div>
          <div style={{ fontFamily: sans, fontSize: 12, color: C.textMuted, fontWeight: 500 }}>
            Service Status
          </div>
          {deployment.latency_ms && (
            <div style={{ fontFamily: mono, fontSize: 11, color: C.textFaint, marginTop: 6 }}>
              {deployment.latency_ms}ms latency
            </div>
          )}
        </div>
      </div>

      {deployment.deployment_findings?.length > 0 && (
        <div>
          <SectionHeader title="Deployment Findings" count={deployment.deployment_findings.length} color={C.yellow} />
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {deployment.deployment_findings.map((df, i) => {
              const isHeader = df.check?.startsWith("security_header");
              const color = df.check === "cors" ? C.red : C.yellow;
              return (
                <div key={i} style={{
                  display: "flex", gap: 12, padding: "10px 14px",
                  background: isHeader ? C.yellowLight : C.surface,
                  border: `1px solid ${isHeader ? C.yellowBorder : C.border}`,
                  borderLeft: `3px solid ${color}`, borderRadius: 8,
                }}>
                  <span style={{ color, fontSize: 14, flexShrink: 0 }}>▲</span>
                  <span style={{ fontFamily: sans, fontSize: 13, color: C.textSub, lineHeight: 1.5 }}>
                    {df.issue}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {deployment.security_headers && (
        <div>
          <SectionHeader title="Security Headers" />
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {deployment.security_headers.present?.map(h => (
              <Badge key={h} label={`✓ ${h}`} color={C.green} bg={C.greenLight} border={C.greenBorder} small />
            ))}
            {deployment.security_headers.missing?.map(h => (
              <Badge key={h} label={`✗ ${h}`} color={C.red} bg={C.redLight} border={C.redBorder} small />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
function ScanHeader({ report }) {
  const plan = report.planner_assessment || {};
  const dep  = report.deployment || {};
  const findings = report.security_findings || [];
  const worst =
    findings.some(f => f.severity === "CRITICAL") ? { label: "Critical", color: C.red } :
    findings.some(f => f.severity === "HIGH")     ? { label: "High risk", color: C.red } :
    findings.some(f => f.severity === "MEDIUM")   ? { label: "Medium risk", color: C.yellow } :
    findings.length > 0                           ? { label: "Low risk", color: C.green } :
                                                    { label: "Clean", color: C.green };

  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 10, padding: "16px 20px",
      marginBottom: 20, boxShadow: C.shadow,
      display: "flex", alignItems: "center",
      justifyContent: "space-between", gap: 16,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <div style={{
          width: 40, height: 40, borderRadius: 10,
          background: C.accentLight, border: `1px solid ${C.accentBorder}`,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 18, color: C.accent, flexShrink: 0,
        }}>⊘</div>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
            <span style={{ fontFamily: sans, fontSize: 15, fontWeight: 700, color: C.text }}>
              {plan.title || "API Scan Report"}
            </span>
            {plan.auth_pattern_detected && (
              <Badge
                label={`Auth: ${plan.auth_pattern_detected}`}
                color={plan.auth_pattern_detected === "none" ? C.red : C.green}
                bg={plan.auth_pattern_detected === "none" ? C.redLight : C.greenLight}
                border={plan.auth_pattern_detected === "none" ? C.redBorder : C.greenBorder}
                small
              />
            )}
          </div>
          <div style={{
            display: "flex", gap: 14, alignItems: "center",
            fontFamily: sans, fontSize: 12, color: C.textFaint,
          }}>
            {report.summary?.total_security_findings !== undefined && (
              <span>{report.summary.total_security_findings} findings</span>
            )}
            {dep.status && (
              <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                <span style={{
                  width: 6, height: 6, borderRadius: "50%", display: "inline-block",
                  background: dep.status === "healthy" ? C.green : C.red,
                }} />
                {dep.status}
              </span>
            )}
            {dep.latency_ms && <span>{dep.latency_ms}ms</span>}
          </div>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
        <Badge
          label={worst.label}
          color={worst.color}
          bg={`${worst.color}12`}
          border={`${worst.color}30`}
        />
      </div>
    </div>
  );
}
// ─── Report View ──────────────────────────────────────────────────
function ReportView({ report, onRescan, specId }) {
  const [tab, setTab] = useState("security");
  const s = report.summary || {};

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const tabs = [
    { key: "security",   label: "Security",       count: s.total_security_findings },
    { key: "tests",      label: "API Tests",      count: s.total_tests_run },
    { key: "planner",    label: "Planner"         },
    { key: "deployment", label: "Deployment"      },
    { key: "recs",       label: "Recommendations", count: report.recommendations?.length },
    { key: "llm",        label: "AI Analysis"     },
  ];

  return (
    <div>

      <ScanHeader report={report} />
      {/* Stat cards */}
      <SeveritySummary
        summary={s}
        deepScanPerformed={report.deep_scan_performed}
        deepScanCount={report.deep_scan_summary?.findings_enriched}
      />

      {/* Info bar */}
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        background: C.accentLight, border: `1px solid ${C.accentBorder}`,
        borderRadius: 8, padding: "10px 16px", marginBottom: 16,
        fontFamily: sans, fontSize: 13,
      }}>
        <span style={{ color: C.accent, fontWeight: 500 }}>
          {report.test_generation?.test_cases_generated > 0
            ? `${report.test_generation.test_cases_generated} test cases · ` : ""}
          {report.deep_scan_performed ? "Deep scan performed · " : ""}
          {s.total_security_findings} findings total
        </span>
        <div style={{ display: "flex", gap: 8 }}>
          {specId && onRescan && (
            <Btn onClick={onRescan} variant="ghost" small>↺ Re-scan</Btn>
          )}
          <Btn onClick={exportJSON} variant="subtle" small>↓ Export JSON</Btn>
        </div>
      </div>

      {/* Tabs */}
      <div style={{
        display: "flex", borderBottom: `1px solid ${C.border}`,
        marginBottom: 0, gap: 0, overflowX: "auto",
      }}>
        {tabs.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)} style={{
            fontFamily: sans, fontSize: 13, fontWeight: 600,
            padding: "10px 18px",
            cursor: "pointer",
            border: "none",
            borderBottom: tab === t.key ? `2px solid ${C.accent}` : "2px solid transparent",
            background: "transparent",
            color: tab === t.key ? C.accent : C.textMuted,
            transition: "all 0.15s",
            whiteSpace: "nowrap",
            display: "flex", alignItems: "center", gap: 6,
          }}>
            {t.label}
            {t.count !== undefined && t.count > 0 && (
              <span style={{
                fontFamily: mono, fontSize: 10, fontWeight: 700,
                background: tab === t.key ? C.accent : C.border,
                color: tab === t.key ? "#fff" : C.textMuted,
                padding: "1px 6px", borderRadius: 10,
                transition: "all 0.15s",
              }}>{t.count}</span>
            )}
          </button>
        ))}
      </div>

      <div style={{
        background: C.surface,
        border: `1px solid ${C.border}`,
        borderTop: "none",
        borderRadius: "0 0 10px 10px",
        padding: "20px 20px",
        minHeight: 200,
      }}>
        {tab === "security"   && <SecurityTable findings={report.security_findings} />}
        {tab === "tests"      && <TestResults results={report.api_test_results} />}
        {tab === "planner"    && <PlannerView plan={report.planner_assessment} />}
        {tab === "deployment" && <DeploymentView deployment={report.deployment} />}
        {tab === "recs" && (
          <div>
            {!(report.recommendations || []).length
              ? <div style={{ fontFamily: sans, color: C.green, fontSize: 14, display: "flex", gap: 8, alignItems: "center" }}>
                  <span>✓</span> No recommendations — looking good!
                </div>
              : <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {(report.recommendations || []).map((r, i) => (
                    <div key={i} style={{
                      display: "flex", gap: 12, padding: "12px 16px",
                      background: C.yellowLight,
                      border: `1px solid ${C.yellowBorder}`,
                      borderLeft: `3px solid ${C.yellow}`,
                      borderRadius: 8,
                    }}>
                      <span style={{ color: C.yellow, fontSize: 16, flexShrink: 0 }}>▲</span>
                      <span style={{ fontFamily: sans, fontSize: 13, color: C.textSub, lineHeight: 1.6 }}>
                        {r}
                      </span>
                    </div>
                  ))}
                </div>
            }
          </div>
        )}
        {tab === "llm" && (
          report.llm_analysis
            ? <div
                style={{ fontFamily: sans, fontSize: 13, color: C.textSub, lineHeight: 1.8 }}
                dangerouslySetInnerHTML={{ __html: renderMarkdown(report.llm_analysis) }}
              />
            : <div style={{
                fontFamily: sans, fontSize: 13, color: C.textMuted,
                background: C.surfaceHigh, border: `1px solid ${C.border}`,
                borderRadius: 8, padding: "16px 20px",
              }}>
                Set <code style={{
                  fontFamily: mono, fontSize: 12, background: C.accentLight,
                  color: C.accent, padding: "1px 6px", borderRadius: 4,
                }}>GROQ_API_KEY</code> to enable AI analysis.
              </div>
        )}
      </div>
    </div>
  );
}

// ─── Input Panel ──────────────────────────────────────────────────
function InputPanel({ title, children }) {
  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 10, overflow: "hidden", boxShadow: C.shadow,
    }}>
      <div style={{
        padding: "12px 16px", borderBottom: `1px solid ${C.border}`,
        background: C.surfaceHigh,
        fontFamily: sans, fontSize: 13, fontWeight: 700, color: C.text,
      }}>{title}</div>
      <div style={{ padding: 16 }}>{children}</div>
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

  const [specText,     setSpecText]     = useState("");
  const [specId,       setSpecId]       = useState(null);
  const [file,         setFile]         = useState(null);
  const [apiUrl,       setApiUrl]       = useState("");
  const [report,       setReport]       = useState(null);
  const [activeScanId, setActiveScanId] = useState(null);
  const [loading,      setLoading]      = useState(false);
  const [streaming,    setStreaming]    = useState(false);
  const [streamEvents, setStreamEvents] = useState([]);
  const [error,        setError]        = useState("");
  const [sidebarKey,   setSidebarKey]   = useState(0);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

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
    catch { throw new Error("Invalid JSON — please check the spec format"); }
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
          } catch { }
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
    if (!apiUrl) throw new Error("Please enter a URL");
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
      display: "flex", height: "100vh",
      background: C.bg, fontFamily: sans, color: C.text,
      overflow: "hidden",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: ${C.borderHigh}; }
        @keyframes pulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(79,110,247,0.3); }
          50% { box-shadow: 0 0 0 5px rgba(79,110,247,0); }
        }
        button:hover { opacity: 0.88; }
      `}</style>

      <HistorySidebar
        key={sidebarKey}
        apiFetch={apiFetch}
        onSelect={loadHistoryScan}
        activeId={activeScanId}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(c => !c)}
      />

      <div style={{
        flex: 1, display: "flex", flexDirection: "column", overflow: "hidden",
      }}>
        {/* Topbar */}
        <div style={{
          height: 54, background: C.surface,
          borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", padding: "0 24px",
          flexShrink: 0, justifyContent: "space-between",
          boxShadow: "0 1px 0 rgba(0,0,0,0.04)",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{
              fontFamily: sans, fontSize: 15, fontWeight: 700, color: C.text,
            }}>
              API Security Scanner
            </span>
            <Badge label="Beta" color={C.accent} bg={C.accentLight} border={C.accentBorder} small />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            {(loading || streaming) && (
              <span style={{
                fontFamily: sans, fontSize: 12, fontWeight: 500,
                color: C.accent, display: "flex", alignItems: "center", gap: 6,
              }}>
                <span style={{
                  width: 7, height: 7, borderRadius: "50%",
                  background: C.accent, display: "inline-block",
                  animation: "pulse 1.4s ease infinite",
                }} />
                {streaming ? "Streaming…" : "Working…"}
              </span>
            )}
            {apiKey && (
              <button onClick={() => {
                sessionStorage.clear(); setApiKey(""); setNeedsAuth(true);
              }} style={{
                fontFamily: sans, fontSize: 12, color: C.textMuted,
                background: "none", border: `1px solid ${C.border}`,
                borderRadius: 6, cursor: "pointer", padding: "5px 12px",
              }}>Sign out</button>
            )}
          </div>
        </div>

        {/* Main content */}
        <div style={{ flex: 1, overflowY: "auto", padding: "24px 28px" }}>

          {/* Error */}
          {error && (
            <div style={{
              background: C.redLight, border: `1px solid ${C.redBorder}`,
              borderRadius: 8, padding: "10px 16px",
              fontFamily: sans, fontSize: 13, color: C.red,
              marginBottom: 18, display: "flex", gap: 8, alignItems: "center",
            }}>
              <span style={{ fontWeight: 700 }}>✕</span> {error}
            </div>
          )}

          {/* Input panels */}
          <div style={{
            display: "grid", gridTemplateColumns: "1fr 1fr 1fr",
            gap: 14, marginBottom: 20,
          }}>
            {/* Paste JSON */}
            <InputPanel title="Paste OpenAPI JSON">
              <textarea rows={6} value={specText}
                onChange={e => setSpecText(e.target.value)}
                placeholder={"{\n  \"openapi\": \"3.0.0\",\n  ...\n}"}
                style={{
                  fontFamily: mono, fontSize: 11,
                  background: C.surfaceHigh, color: C.text,
                  border: `1px solid ${C.border}`, borderRadius: 7,
                  padding: 10, width: "100%", resize: "vertical",
                  outline: "none", marginBottom: 12,
                  boxSizing: "border-box", lineHeight: 1.5,
                }} />
              <Btn onClick={uploadSpec} disabled={loading || streaming || !specText}>
                Upload Spec
              </Btn>
            </InputPanel>

            {/* Upload file */}
            <InputPanel title="Upload File">
              <label htmlFor="fup" style={{
                display: "flex", flexDirection: "column",
                alignItems: "center", justifyContent: "center",
                border: `2px dashed ${file ? C.accentBorder : C.border}`,
                borderRadius: 8, padding: "24px 14px",
                marginBottom: 12, cursor: "pointer",
                background: file ? C.accentLight : C.surfaceHigh,
                transition: "all 0.15s", minHeight: 100,
              }}>
                <input type="file" accept=".json,.yaml,.yml"
                  onChange={e => setFile(e.target.files[0])}
                  style={{ display: "none" }} id="fup" />
                <div style={{ fontSize: 22, marginBottom: 8 }}>{file ? "📄" : "📂"}</div>
                <div style={{
                  fontFamily: sans, fontSize: 12,
                  color: file ? C.accent : C.textMuted,
                  fontWeight: file ? 600 : 400, textAlign: "center",
                }}>
                  {file ? file.name : "Click to select .json / .yaml"}
                </div>
              </label>
              <Btn onClick={uploadFile} disabled={loading || streaming || !file}>
                Upload File
              </Btn>
            </InputPanel>

            {/* Scan URL */}
            <InputPanel title="Scan API URL">
              <div style={{ marginBottom: 12 }}>
                <Input value={apiUrl} onChange={e => setApiUrl(e.target.value)}
                  placeholder="https://api.yourcompany.com"
                  style={{ marginBottom: 8 }} />
                <div style={{
                  fontFamily: sans, fontSize: 11, color: C.textFaint, marginTop: 4,
                }}>
                  Auto-discovers OpenAPI spec at common paths
                </div>
              </div>
              <Btn onClick={scanUrl} disabled={loading || streaming || !apiUrl}>
                Scan URL
              </Btn>
            </InputPanel>
          </div>

          {/* Upload ready banner */}
          {specId && !report && !streaming && (
            <div style={{
              background: C.accentLight,
              border: `1px solid ${C.accentBorder}`,
              borderRadius: 10, padding: "14px 20px",
              display: "flex", alignItems: "center",
              justifyContent: "space-between",
              marginBottom: 20,
              boxShadow: C.shadow,
            }}>
              <div>
                <div style={{ fontFamily: sans, fontSize: 14, fontWeight: 700, color: C.text, marginBottom: 2 }}>
                  Spec uploaded successfully
                </div>
                <div style={{ fontFamily: mono, fontSize: 11, color: C.textFaint }}>
                  ID: {specId}
                </div>
              </div>
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
            <div style={{
              textAlign: "center", marginTop: 60, padding: "0 40px",
            }}>
              <div style={{
                width: 64, height: 64, borderRadius: 16,
                background: C.accentLight, border: `1px solid ${C.accentBorder}`,
                display: "flex", alignItems: "center", justifyContent: "center",
                margin: "0 auto 20px", fontSize: 28, color: C.accent,
              }}>◈</div>
              <div style={{
                fontFamily: sans, fontSize: 18, fontWeight: 700,
                color: C.text, marginBottom: 10,
              }}>
                API Security Scanner
              </div>
              <div style={{
                fontFamily: sans, fontSize: 14, color: C.textMuted, maxWidth: 400, margin: "0 auto",
                lineHeight: 1.7,
              }}>
                Upload an OpenAPI spec, drop a file, or enter an API URL above to begin a security scan.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}