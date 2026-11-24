// Scan options → request body for POST /api/run/{id}/stream.
//
// Matches backend ScanOptions / request_builder.auth_headers:
//   {"safe_mode": bool, "auth": {"type": "bearer"|"api_key"|"basic", "value", "header_name"}}
//
// The credential lives only in React state and in the request body. It is
// never written to localStorage, and the backend never puts it in the saved
// report (report.scan_options only records whether auth was used).

export const AUTH_TYPES = [
  { value: "none",    label: "None" },
  { value: "bearer",  label: "Bearer token" },
  { value: "api_key", label: "API key" },
  { value: "basic",   label: "Basic" },
];

export const DEFAULT_API_KEY_HEADER = "X-API-Key";

export const DEFAULT_SCAN_OPTIONS = {
  authType:   "none",
  authValue:  "",
  headerName: DEFAULT_API_KEY_HEADER,
  safeMode:   true,
};

export const AUTH_VALUE_PLACEHOLDER = {
  bearer:  "eyJhbGciOi… (without the 'Bearer ' prefix is fine)",
  api_key: "your API key",
  basic:   "username:password",
};

// Returns { body } or { error } (when auth is chosen but no value given).
export function buildScanRequestBody(opts = DEFAULT_SCAN_OPTIONS) {
  const body = { safe_mode: opts.safeMode !== false };
  const type = opts.authType || "none";
  if (type === "none") return { body };

  const value = (opts.authValue || "").trim();
  if (!value) {
    const label = AUTH_TYPES.find(t => t.value === type)?.label || type;
    return { error: `Enter a value for "${label}" in Scan options, or set Auth to None.` };
  }
  const auth = { type, value };
  if (type === "api_key") auth.header_name = (opts.headerName || "").trim() || DEFAULT_API_KEY_HEADER;
  return { body: { ...body, auth } };
}

// One-line summary for the collapsed panel header.
export function describeScanOptions(opts = DEFAULT_SCAN_OPTIONS) {
  const auth = opts.authType && opts.authType !== "none"
    ? AUTH_TYPES.find(t => t.value === opts.authType)?.label
    : "No auth";
  return `${opts.safeMode !== false ? "Safe mode on" : "Safe mode OFF"} · ${auth}`;
}
