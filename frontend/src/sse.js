// Incremental Server-Sent Events parser.
//
// Network chunks don't line up with events: a large event (the final
// report) can arrive split across several reads, and one read can hold
// several events. Feed every decoded chunk to push(); it returns only the
// events that are complete (terminated by a blank line) and keeps the
// incomplete tail for the next chunk. Call flush() when the stream ends.

export const SSE_DONE = "[DONE]";

// One event block -> its data payload (multiple `data:` lines are joined
// with "\n", per the SSE spec). Returns null for blocks without data.
function blockData(block) {
  const data = [];
  for (const line of block.split("\n")) {
    if (line.startsWith("data:")) {
      data.push(line.slice(5).replace(/^ /, ""));
    }
  }
  return data.length ? data.join("\n") : null;
}

export function createSSEParser() {
  let buffer = "";

  const drain = (final) => {
    const blocks = buffer.split("\n\n");
    buffer = final ? "" : blocks.pop();   // last piece may be incomplete
    return blocks.map(blockData).filter(d => d !== null);
  };

  return {
    // Returns the data payloads of every event completed by this chunk.
    push(chunk) {
      buffer += chunk.replace(/\r\n?/g, "\n");
      return drain(false);
    },
    // End of stream: return whatever is left (a final event without the
    // trailing blank line).
    flush() {
      return drain(true);
    },
  };
}
