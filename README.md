                USER
                 │
                 │ Upload API Spec / Enter API URL
                 ▼
           React Dashboard
        (frontend UI layer)
                 │
                 │ REST API request
                 ▼
            FastAPI Backend
        (control + orchestration)
                 │
                 ▼
            Spec Parser
      (extract endpoints & params)
                 │
                 ▼
          Agent Orchestrator
           (multi‑agent system)
                 │
     ┌───────────┼───────────┐
     ▼           ▼           ▼
API Testing   Security     Deployment
   Agent        Agent         Agent
     │            │            │
     │            │            │
Send API     Analyze risks   Check service
requests     (OWASP rules)   health
     │            │            │
     └────────────┼────────────┘
                  ▼
            Report Generator
                  │
                  ▼
            React Dashboard
           (results displayed)

API Security Testing Platform
An automated API security testing platform that analyzes API specifications and dynamically tests endpoints for vulnerabilities using a multi‑agent architecture.

The system allows developers to upload an API specification or provide an API endpoint and automatically performs:

API security analysis

Dynamic API testing

Fuzz testing

Security risk reporting

System Architecture
The platform is composed of three main layers:

User
 │
 ▼
React Dashboard (Frontend UI)
 │
 ▼
FastAPI Backend (Control Layer)
 │
 ▼
Agent Orchestrator (Multi‑Agent System)
 │
 ├── Security Agent
 ├── API Testing Agent
 └── Deployment Agent
 │
 ▼
Report Generator
 │
 ▼
Dashboard Visualization
Features
The platform provides:

OpenAPI specification parsing

Automated security risk detection

Dynamic API testing

Fuzz testing with malicious payloads

Multi‑agent vulnerability analysis

Security report generation

Web dashboard visualization

Frontend (React Dashboard)
Location:

frontend/
The frontend provides a dashboard where users can interact with the system.

Key Features
Users can:

Paste an OpenAPI specification

Upload OpenAPI files

Enter an API base URL

Run security scans

View vulnerability reports

Dashboard Sections
The dashboard displays:

Scan Summary

Security Findings

API Test Results

Recommendations

Example summary:

High Risks: 4
Total Findings: 9
Failed Tests: 6
Deployment Status: Healthy
Backend (FastAPI)
Location:

backend/app
The FastAPI backend acts as the control layer responsible for:

receiving requests from the dashboard

parsing API specifications

executing security agents

generating security reports

Main API Endpoints
Upload API specification

POST /api/specs/upload
Upload OpenAPI file

POST /api/specs/upload-file
Run security agents

POST /api/run/{spec_id}
Spec Parser
Location:

services/spec_parser.py
The Spec Parser extracts API endpoints from an OpenAPI specification.

Input
Example OpenAPI specification:

{
 "paths": {
   "/users": { "get": {} },
   "/users/{user_id}": { "get": {} }
 }
}
Output
Parsed structure:

[
 { path: "/users", method: "GET" },
 { path: "/users/{user_id}", method: "GET" }
]
This data is passed to the agent system for analysis.

Agent Orchestrator
Location:

orchestrator.py
The orchestrator coordinates the execution of all security agents.

Workflow
parsed_spec
     │
     ▼
orchestrator.run_all()
     │
     ├── Security Agent
     ├── API Testing Agent
     └── Deployment Agent
Each agent performs a specialized analysis and returns its results.

The orchestrator aggregates all outputs before sending them to the report generator.

Security Agent
Location:

agents/security_agent.py
The Security Agent performs static security analysis based on API structure.

It detects several vulnerabilities inspired by the OWASP API Top 10.

Implemented Security Checks
1. Broken Object Level Authorization (BOLA)
Detects endpoints containing object identifiers.

Example:

/users/{user_id}
These endpoints may allow unauthorized access to other users’ data.

2. Excessive Data Exposure
Detects endpoints that may expose sensitive objects.

Example:

GET /users
Returning full user objects may expose private data.

3. Broken Authentication
Detects authentication‑related endpoints such as:

POST /login
POST /auth/token
These endpoints require secure authentication mechanisms.

4. Lack of Rate Limiting
Detects endpoints vulnerable to brute‑force attacks.

Example:

/login
/auth/token
/search
Without rate limiting, attackers can attempt unlimited requests.

API Testing Agent
Location:

agents/api_testing_agent.py
The API Testing Agent performs dynamic API testing by sending real HTTP requests to endpoints.

It validates API behavior and detects incorrect responses.

Implemented Tests
Valid Request Test
Sends a normal request to the endpoint.

Example:

GET /users/1
Expected response:

200 OK
Invalid Parameter Test
Tests input validation.

Example:

GET /users/abc
Expected response:

400 or 422
Nonexistent Resource Test
Tests handling of invalid resources.

Example:

GET /users/999999
Expected response:

404 Not Found
Wrong HTTP Method Test
Tests whether endpoints reject unsupported methods.

Example:

POST /users
Expected response:

405 Method Not Allowed
Fuzz Testing
The API Testing Agent performs fuzz testing using malicious payloads.

Example payloads:

' OR 1=1 --
<script>alert(1)</script>
../../etc/passwd
%00
'; DROP TABLE users;
Purpose:

detect injection vulnerabilities

identify server crashes

identify improper input validation

If the API returns:

500 Internal Server Error
the system flags a potential vulnerability.

Deployment Agent
Location:

agents/deployment_agent.py
The Deployment Agent verifies the availability of the API service.

Example check:

GET /health
Expected response:

200 OK
If the service is unreachable, the agent reports deployment issues.

Report Generator
Location:

services/report_generator.py
The Report Generator aggregates results from all agents into a single report.

Report Structure
{
 summary: {},
 security_findings: [],
 api_test_results: [],
 deployment: {},
 recommendations: []
}
Example Summary
High Risks: 4
Total Findings: 9
Failed Tests: 6
Deployment Status: Healthy
Recommendations
The system generates remediation suggestions such as:

Implement object-level authorization checks
Add authentication mechanisms (JWT or OAuth)
Limit sensitive fields in API responses
Technologies Used
Frontend

React
JavaScript
HTML/CSS
Backend

FastAPI
Python
Requests
PyYAML
Testing

Dynamic API Testing
Fuzz Testing
Security Risk Detection
Future Improvements
Planned enhancements include:

AI‑generated attack payloads

LangGraph multi‑agent workflows

Automatic API endpoint discovery

Advanced fuzzing strategies

Security scoring system

Risk visualization dashboards

Summary
This project demonstrates how automated systems can:

parse API specifications

detect security risks

dynamically test endpoints

perform fuzz testing

generate actionable security reports

The platform provides a foundation for building a fully automated API security testing tool.