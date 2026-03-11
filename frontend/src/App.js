import React, { useState } from "react";

function App() {

  const [specText, setSpecText] = useState("");
  const [specId, setSpecId] = useState("");
  const [report, setReport] = useState(null);
  const [file, setFile] = useState(null);
  const [apiUrl, setApiUrl] = useState("");

  // Upload spec from textarea
  const uploadSpec = async () => {

    const res = await fetch("http://localhost:8000/api/specs/upload", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: "uploaded_spec",
        spec: JSON.parse(specText),
      }),
    });

    const data = await res.json();
    setSpecId(data.id);
  };

  // Upload OpenAPI file
  const uploadFile = async () => {

    const formData = new FormData();
    formData.append("file", file);

    const res = await fetch("http://localhost:8000/api/specs/upload-file", {
      method: "POST",
      body: formData,
    });

    const data = await res.json();
    setSpecId(data.id);
  };

  // Run scan
  const runScan = async () => {

    const res = await fetch(`http://localhost:8000/api/run/${specId}`, {
      method: "POST",
    });

    const data = await res.json();
    setReport(data.result);
  };

  // Scan API URL
  const scanUrl = async () => {

    const res = await fetch("http://localhost:8000/api/scan-url", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        base_url: apiUrl
      })
    });

    const data = await res.json();
    setReport(data.result);
  };

  const severityColor = (severity) => {
    if (severity === "HIGH") return "#ff4d4f";
    if (severity === "MEDIUM") return "#faad14";
    return "#52c41a";
  };

  return (
    <div style={{ fontFamily: "Arial", background: "#f5f6fa", minHeight: "100vh", padding: "40px" }}>

      <h1 style={{ textAlign: "center" }}>🔐 API Security Testing Dashboard</h1>

      {/* Upload JSON Spec */}

      <div style={{ background: "white", padding: 20, borderRadius: 10, marginBottom: 20 }}>
        <h2>Paste OpenAPI JSON</h2>

        <textarea
          rows="8"
          style={{ width: "100%", padding: 10 }}
          placeholder="Paste OpenAPI JSON here"
          value={specText}
          onChange={(e) => setSpecText(e.target.value)}
        />

        <br /><br />

        <button onClick={uploadSpec}>Upload Spec</button>
      </div>

      {/* Upload File */}

      <div style={{ background: "white", padding: 20, borderRadius: 10, marginBottom: 20 }}>
        <h2>Upload OpenAPI File</h2>

        <input
          type="file"
          accept=".json,.yaml,.yml"
          onChange={(e) => setFile(e.target.files[0])}
        />

        <br /><br />

        <button onClick={uploadFile}>Upload File</button>
      </div>

      {/* Scan API URL */}

      <div style={{ background: "white", padding: 20, borderRadius: 10, marginBottom: 20 }}>
        <h2>Scan API URL</h2>

        <input
          style={{ width: "60%", padding: 10 }}
          placeholder="http://localhost:8001"
          value={apiUrl}
          onChange={(e) => setApiUrl(e.target.value)}
        />

        <button style={{ marginLeft: 10 }} onClick={scanUrl}>
          Scan API
        </button>
      </div>

      {/* Run Agents */}

      {specId && (
        <div style={{ background: "white", padding: 20, borderRadius: 10, marginBottom: 20 }}>
          <p><b>Spec ID:</b> {specId}</p>
          <button onClick={runScan}>Run Scan</button>
        </div>
      )}

      {/* Results */}

      {report && (
        <>
          <div style={{ background: "white", padding: 20, borderRadius: 10, marginBottom: 20 }}>
            <h2>Scan Summary</h2>

            <p>High Risks: <b>{report.summary.high_risks}</b></p>
            <p>Total Findings: <b>{report.summary.total_security_findings}</b></p>
            <p>Failed Tests: <b>{report.summary.failed_tests}</b></p>
            <p>Deployment: <b>{report.summary.deployment_status}</b></p>
          </div>

          <div style={{ background: "white", padding: 20, borderRadius: 10, marginBottom: 20 }}>
            <h2>Security Findings</h2>

            <table width="100%" border="1" cellPadding="10">
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Risk</th>
                  <th>Severity</th>
                </tr>
              </thead>

              <tbody>
                {report.security_findings.map((f, i) => (
                  <tr key={i}>
                    <td>{f.endpoint}</td>
                    <td>{f.risk_type}</td>
                    <td>
                      <span style={{
                        background: severityColor(f.severity),
                        color: "white",
                        padding: "5px 10px",
                        borderRadius: "5px"
                      }}>
                        {f.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

    </div>
  );
}

export default App;