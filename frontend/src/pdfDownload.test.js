import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ReportView } from "./App";

jest.mock("./firebase", () => ({
  onAuth: () => () => {}, signInWithGoogle: jest.fn(), signOut: jest.fn(), getIdToken: jest.fn(),
}));

const REPORT = { summary: { total_security_findings: 0 }, security_findings: [], api_test_results: [],
                 deployment: { status: "healthy", security_score: "3/6" }, recommendations: [] };

beforeEach(() => {
  global.URL.createObjectURL = jest.fn(() => "blob:report");
  global.URL.revokeObjectURL = jest.fn();
});

test("Download PDF sits next to Export JSON and saves the PDF under the server's filename", async () => {
  const blob = new Blob(["%PDF-1.4"], { type: "application/pdf" });
  const apiDownload = jest.fn(async () => ({ blob, filename: "api-sentinel-sample-2026-11-24.pdf" }));
  const clicked = [];
  const spy = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function () {
    clicked.push(this.download);
  });

  render(<ReportView report={REPORT} scanId="s1" apiFetch={jest.fn()} apiDownload={apiDownload} />);
  const json = screen.getByRole("button", { name: /export json/i });
  const pdf  = screen.getByRole("button", { name: /download pdf/i });
  expect(json.parentElement).toBe(pdf.parentElement);

  fireEvent.click(pdf);
  await waitFor(() => expect(clicked).toEqual(["api-sentinel-sample-2026-11-24.pdf"]));
  expect(apiDownload).toHaveBeenCalledWith("/api/scans/s1/report/pdf", "sentinel-report-s1.pdf");
  expect(URL.createObjectURL).toHaveBeenCalledWith(blob);
  expect(screen.getByRole("button", { name: /download pdf/i })).toBeEnabled();
  spy.mockRestore();
});

test("Download PDF shows the server's error", async () => {
  const apiDownload = jest.fn(async () => { throw new Error("Report not yet generated"); });
  render(<ReportView report={REPORT} scanId="s1" apiFetch={jest.fn()} apiDownload={apiDownload} />);
  fireEvent.click(screen.getByRole("button", { name: /download pdf/i }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Report not yet generated");
});

test("No Download PDF button for an unsaved report", () => {
  render(<ReportView report={REPORT} apiFetch={jest.fn()} />);
  expect(screen.queryByRole("button", { name: /download pdf/i })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /export json/i })).toBeInTheDocument();
});
