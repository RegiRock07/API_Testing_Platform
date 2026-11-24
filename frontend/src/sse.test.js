import { createSSEParser, SSE_DONE } from "./sse";

const ev = (obj) => `data: ${JSON.stringify(obj)}\n\n`;

// Feed `text` in pieces cut at `cuts` (character offsets); collect payloads.
function feed(text, cuts) {
  const p = createSSEParser();
  const out = [];
  let prev = 0;
  for (const c of [...cuts, text.length]) {
    out.push(...p.push(text.slice(prev, c)));
    prev = c;
  }
  out.push(...p.flush());
  return out;
}

const bigReport = { report: { summary: { total_tests_run: 19 }, padding: "x".repeat(200000) } };
const stream =
  ev({ agent: "planner", status: "running" }) +
  ev({ agent: "planner", status: "completed", data: { llm_used: true } }) +
  ev({ agent: "report", status: "completed", data: bigReport }) +
  `data: ${SSE_DONE}\n\n`;

test("one chunk with several events", () => {
  const out = feed(stream, []);
  expect(out).toHaveLength(4);
  expect(out[3]).toBe(SSE_DONE);
});

test("large report event split across many chunks is reassembled", () => {
  const cuts = [];
  for (let i = 1000; i < stream.length; i += 16384) cuts.push(i);   // ~64 KB-ish reads
  const out = feed(stream, cuts);
  expect(out).toHaveLength(4);
  const report = JSON.parse(out[2]);
  expect(report.agent).toBe("report");
  expect(report.data.report.padding).toHaveLength(200000);
});

test("split inside 'data:' prefix and between the two newlines", () => {
  const a = ev({ agent: "security", status: "running" });
  const b = ev({ agent: "security", status: "completed" });
  const text = a + b;
  // cut after "da", and between the "\n" and "\n" that end event a
  const out = feed(text, [2, a.length - 1, a.length + 3]);
  expect(out.map(s => JSON.parse(s).status)).toEqual(["running", "completed"]);
});

test("every possible single cut point yields the same events", () => {
  const text = ev({ a: 1 }) + ev({ b: "two" }) + `data: ${SSE_DONE}\n\n`;
  const expected = feed(text, []);
  for (let i = 1; i < text.length; i++) {
    expect(feed(text, [i])).toEqual(expected);
  }
});

test("CRLF line endings and multi-line data", () => {
  const out = feed('data: {"a":\r\ndata: 1}\r\n\r\ndata: [DONE]\r\n\r\n', [5]);
  expect(JSON.parse(out[0])).toEqual({ a: 1 });
  expect(out[1]).toBe(SSE_DONE);
});

test("incomplete tail is held until flush; comment/keepalive blocks ignored", () => {
  const p = createSSEParser();
  expect(p.push(": keepalive\n\n")).toEqual([]);
  expect(p.push('data: {"x":1}')).toEqual([]);   // no blank line yet
  expect(p.flush()).toEqual(['{"x":1}']);
});
