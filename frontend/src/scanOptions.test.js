import { useState } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { buildScanRequestBody, describeScanOptions, DEFAULT_SCAN_OPTIONS } from "./scanOptions";
import { ScanOptionsPanel, TestResults, ScanHeader } from "./App";

jest.mock("./firebase", () => ({
  onAuth: () => () => {}, signInWithGoogle: jest.fn(), signOut: jest.fn(), getIdToken: jest.fn(),
}));

// ── Request body ──────────────────────────────────────────────────
describe("buildScanRequestBody", () => {
  test("defaults: safe mode on, no auth", () => {
    expect(buildScanRequestBody(DEFAULT_SCAN_OPTIONS)).toEqual({ body: { safe_mode: true } });
  });

  test("bearer token is trimmed; no header_name", () => {
    const { body } = buildScanRequestBody({ ...DEFAULT_SCAN_OPTIONS, authType: "bearer", authValue: "  tok123 " });
    expect(body).toEqual({ safe_mode: true, auth: { type: "bearer", value: "tok123" } });
  });

  test("api key carries header_name, defaulting to X-API-Key", () => {
    const base = { ...DEFAULT_SCAN_OPTIONS, authType: "api_key", authValue: "k" };
    expect(buildScanRequestBody({ ...base, headerName: "X-Token" }).body.auth)
      .toEqual({ type: "api_key", value: "k", header_name: "X-Token" });
    expect(buildScanRequestBody({ ...base, headerName: "  " }).body.auth.header_name).toBe("X-API-Key");
  });

  test("basic + safe mode off", () => {
    const { body } = buildScanRequestBody({ authType: "basic", authValue: "u:p", headerName: "", safeMode: false });
    expect(body).toEqual({ safe_mode: false, auth: { type: "basic", value: "u:p" } });
  });

  test("auth type chosen without a value is an error, not a silent unauthenticated scan", () => {
    const r = buildScanRequestBody({ ...DEFAULT_SCAN_OPTIONS, authType: "bearer", authValue: "   " });
    expect(r.body).toBeUndefined();
    expect(r.error).toMatch(/Bearer token/);
  });

  test("summary text", () => {
    expect(describeScanOptions(DEFAULT_SCAN_OPTIONS)).toBe("Safe mode on · No auth");
    expect(describeScanOptions({ ...DEFAULT_SCAN_OPTIONS, authType: "api_key", safeMode: false }))
      .toBe("Safe mode OFF · API key");
  });
});

// ── Panel ─────────────────────────────────────────────────────────
function Harness({ onState }) {
  const [opts, setOpts] = useState(DEFAULT_SCAN_OPTIONS);
  onState(opts);
  return <ScanOptionsPanel options={opts} onChange={setOpts} />;
}

test("panel: collapsed by default, expands, shows the right fields per auth type", () => {
  let state;
  render(<Harness onState={s => { state = s; }} />);
  expect(screen.queryByLabelText(/authentication/i)).not.toBeInTheDocument();
  expect(screen.getByText("Safe mode on · No auth")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /scan options/i }));
  const safe = screen.getByRole("checkbox", { name: /safe mode — never send delete\/put\/patch/i });
  expect(safe).toBeChecked();                                   // on by default
  expect(screen.queryByLabelText(/token|api key|credentials/i)).not.toBeInTheDocument();

  fireEvent.change(screen.getByLabelText(/authentication/i), { target: { value: "api_key" } });
  const value = screen.getByLabelText("API key");
  expect(value).toHaveAttribute("type", "password");
  expect(value).toHaveAttribute("autocomplete", "off");
  expect(screen.getByLabelText(/header name/i)).toHaveValue("X-API-Key");

  fireEvent.change(value, { target: { value: "secret-1" } });
  fireEvent.click(safe);
  expect(state).toMatchObject({ authType: "api_key", authValue: "secret-1", safeMode: false });

  fireEvent.change(screen.getByLabelText(/authentication/i), { target: { value: "bearer" } });
  expect(screen.queryByLabelText(/header name/i)).not.toBeInTheDocument();
  expect(screen.getByLabelText("Token")).toHaveAttribute("type", "password");
});

test("panel never writes to localStorage or sessionStorage", () => {
  const setItem = jest.spyOn(Storage.prototype, "setItem");
  render(<Harness onState={() => {}} />);
  fireEvent.click(screen.getByRole("button", { name: /scan options/i }));
  fireEvent.change(screen.getByLabelText(/authentication/i), { target: { value: "bearer" } });
  fireEvent.change(screen.getByLabelText("Token"), { target: { value: "top-secret" } });
  expect(setItem).not.toHaveBeenCalled();
  setItem.mockRestore();
});

// ── API Tests tab ─────────────────────────────────────────────────
test("skipped tests show as Skipped, not Fail", () => {
  const results = [
    { endpoint: "/users/{id}", method: "DELETE", tests: [
      { test: "skipped_safe_mode", passed: null, skipped: true, note: "DELETE not sent" }] },
    { endpoint: "/users", method: "GET", tests: [
      { test: "valid_request", passed: true, status_code: 200 },
      { test: "nonexistent_resource", passed: null, skipped: true, error: "time budget exceeded" },
      { test: "wrong_method", passed: false, status_code: 200 }] },
  ];
  render(<TestResults results={results} />);
  expect(screen.getByText("Skipped (safe mode)")).toBeInTheDocument();      // collapsed header
  expect(screen.getByText("1 skipped")).toBeInTheDocument();

  fireEvent.click(screen.getByText("DELETE /users/{id}"));
  expect(screen.getAllByText("Skipped (safe mode)")).toHaveLength(2);       // header + row
  expect(screen.queryByText("Fail")).not.toBeInTheDocument();

  fireEvent.click(screen.getByText("GET /users"));
  expect(screen.getByText("Skipped")).toBeInTheDocument();
  expect(screen.getAllByText("Fail")).toHaveLength(1);                      // only the real failure
  expect(screen.getAllByText("Pass")).toHaveLength(1);
});

// ── Report header ─────────────────────────────────────────────────
test("report header shows Authenticated and Safe mode badges from scan_options", () => {
  const { rerender } = render(<ScanHeader report={{
    scan_options: { safe_mode: true, authenticated: true, auth_type: "api_key" } }} />);
  expect(screen.getByText("Authenticated · API key")).toBeInTheDocument();
  expect(screen.getByText("Safe mode")).toBeInTheDocument();

  rerender(<ScanHeader report={{ scan_options: { safe_mode: false, authenticated: false, auth_type: null } }} />);
  expect(screen.queryByText(/Authenticated/)).not.toBeInTheDocument();
  expect(screen.getByText("Safe mode off")).toBeInTheDocument();

  rerender(<ScanHeader report={{}} />);                                     // older reports
  expect(screen.queryByText(/Safe mode/)).not.toBeInTheDocument();
});
