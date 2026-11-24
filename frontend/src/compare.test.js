import { fireEvent, render, screen, within } from "@testing-library/react";
import { ReportView } from "./App";

jest.mock("./firebase", () => ({
  onAuth: () => () => {}, signInWithGoogle: jest.fn(), signOut: jest.fn(), getIdToken: jest.fn(),
}));

const SCANS = [
  { id: "cur",   api_title: "Sample API", status: "completed", created_at: "2026-11-24T10:00:00", name: "http://h/openapi.json", endpoint_count: 7 },
  { id: "old1",  api_title: "Sample API", status: "completed", created_at: "2026-11-24T09:00:00", name: "http://h/openapi.json", endpoint_count: 7 },
  { id: "newer", api_title: "Sample API", status: "completed", created_at: "2026-11-24T11:00:00", name: "later", endpoint_count: 7 },
  { id: "other", api_title: "Other API",  status: "completed", created_at: "2026-11-24T08:00:00", name: "other", endpoint_count: 2 },
  { id: "pend",  api_title: "Sample API", status: "parsed",    created_at: "2026-11-24T08:30:00", name: "pending", endpoint_count: 7 },
];

const f = (id, severity, method, endpoint, vulnerability) => ({ id, severity, method, endpoint, vulnerability });
const COMPARE = {
  base:   { id: "old1", api_title: "Sample API", created_at: "2026-11-24T09:00:00" },
  target: { id: "cur",  api_title: "Sample API", created_at: "2026-11-24T10:00:00" },
  same_api: true,
  findings: {
    new:       [f("Rate|GET|/search", "LOW", "GET", "/search", "Potential Lack of Rate Limiting (Static)")],
    fixed:     [f("Auth|POST|/search", "MEDIUM", "POST", "/search", "Potential Missing Authentication (Static)"),
                f("Rate|POST|/search", "LOW", "POST", "/search", "Potential Lack of Rate Limiting (Static)")],
    unchanged: [f("BOLA|GET|/users/{user_id}", "MEDIUM", "GET", "/users/{user_id}", "Potential BOLA (Static)")],
  },
  severity: { base:   { CRITICAL: 0, HIGH: 0, MEDIUM: 4, LOW: 4 },
              target: { CRITICAL: 0, HIGH: 0, MEDIUM: 3, LOW: 4 },
              delta:  { CRITICAL: 0, HIGH: 0, MEDIUM: -1, LOW: 0 } },
  tests: { base:   { total: 19, passed: 17, failed: 2, skipped: 0 },
           target: { total: 19, passed: 18, failed: 1, skipped: 0 },
           delta:  { total: 0, passed: 1, failed: -1, skipped: 0 },
           changes: [{ method: "GET", endpoint: "/search", test: "valid_request", before: "absent", after: "passed", status_after: 200 }] },
  deployment: { base_score: "3/6", target_score: "3/6", score_delta: 0, base_status: "healthy", target_status: "healthy" },
};

const REPORT = { summary: { total_security_findings: 7 }, security_findings: [], api_test_results: [],
                 deployment: { status: "healthy", security_score: "3/6" }, recommendations: [] };

test("Compare: picker lists only earlier completed scans of the same API, then shows the diff", async () => {
  const apiFetch = jest.fn(async (path) => {
    if (path === "/api/scans") return SCANS;
    if (path.startsWith("/api/scans/compare")) return COMPARE;
    throw new Error("unexpected " + path);
  });
  render(<ReportView report={REPORT} scanId="cur" specId="cur" apiFetch={apiFetch} />);

  fireEvent.click(screen.getByRole("button", { name: /compare/i }));
  const picker = await screen.findByRole("dialog", { name: /compare with an earlier scan/i });
  await within(picker).findByText(/earlier scans of/i);
  const options = within(picker).getAllByRole("button", { name: /compare →/i });
  expect(options).toHaveLength(1);                         // only old1: not newer/other/pending/itself
  expect(within(picker).queryByText("later")).not.toBeInTheDocument();
  expect(within(picker).queryByText("other")).not.toBeInTheDocument();

  fireEvent.click(options[0]);
  expect(await screen.findByText(/what changed in sample api/i)).toBeInTheDocument();
  expect(apiFetch).toHaveBeenCalledWith("/api/scans/compare?base=old1&target=cur");

  const col = (name) => screen.getByTestId(`compare-${name}`);
  expect(within(col("new")).getByText("GET /search")).toBeInTheDocument();
  expect(within(col("fixed")).getAllByText("POST /search")).toHaveLength(2);
  expect(within(col("unchanged")).getByText("GET /users/{user_id}")).toBeInTheDocument();

  // deltas: fewer MEDIUM findings and failures are improvements (green), more passes too
  expect(screen.getByText("Medium").previousSibling).toHaveTextContent("−1");
  expect(screen.getByText("Tests failed").previousSibling).toHaveTextContent("−1");
  expect(screen.getByText("Low").previousSibling).toHaveTextContent(/^0$/);
  expect(screen.getByText("Tests passed").previousSibling).toHaveTextContent("+1");
  expect(screen.getByText("Tests passed").previousSibling).toHaveStyle({ color: "#12b76a" });
  expect(screen.getByText("Tests failed").previousSibling).toHaveStyle({ color: "#12b76a" });
  expect(screen.getByText("Medium").previousSibling).toHaveStyle({ color: "#12b76a" });
  expect(screen.getByText(/GET \/search · valid request/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /back to report/i }));
  expect(screen.queryByText(/what changed in/i)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /compare/i })).toBeInTheDocument();
});

test("Compare: empty state when there is no earlier scan", async () => {
  const apiFetch = jest.fn(async () => SCANS.filter(s => s.id !== "old1"));
  render(<ReportView report={REPORT} scanId="cur" apiFetch={apiFetch} />);
  fireEvent.click(screen.getByRole("button", { name: /compare/i }));
  expect(await screen.findByText(/no earlier completed scans of this api/i)).toBeInTheDocument();
});

test("Compare button hidden without a scan id (e.g. unsaved report)", () => {
  render(<ReportView report={REPORT} apiFetch={jest.fn()} />);
  expect(screen.queryByRole("button", { name: /compare/i })).not.toBeInTheDocument();
});
