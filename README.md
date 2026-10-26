# Agent X-Ray

**Map the capabilities. Find the risky edges. Understand what your AI agent can reach.**

Agent X-Ray is a local-first security workbench for reviewing Model Context Protocol (MCP) server configurations. It turns configuration metadata into an interactive topology, surfaces security review signals, and exports an evidence-oriented report.

> **Important:** Agent X-Ray performs static, heuristic analysis. It does not execute agents or MCP servers. Findings are review signals, not proof of exploitability; a clean scan is not a security guarantee.

![Agent X-Ray](frontend/src/assets/hero.png)

## Why it exists

AI agents gain capabilities through tools, servers, environment variables, and remote endpoints. These boundaries are easy to miss when they are spread across JSON configuration. Agent X-Ray puts the relationships and review priorities in one place.

## Features

- **Interactive topology:** explore configuration, server, process, endpoint, environment, credential, and tool nodes.
- **Evidence-backed findings:** each finding includes a rule ID, severity, confidence, evidence, affected node, category, and remediation.
- **Capability mapping:** heuristic signals for command execution, file access/modification, network access, credentials, and database interaction.
- **Configuration review:** flags shell-based launchers, inline shell flags, unpinned `@latest` packages, non-local HTTP endpoints, literal credential-like values, and literal authentication headers.
- **Input-schema review:** inspects nested tool schemas for command-, path-, URL-, and query-like inputs. These are intentionally labelled as low-confidence review signals.
- **Secret-aware reporting:** values are redacted from findings; reports do not include raw environment or header values.
- **Fast investigation:** filter and search findings, select the affected graph node, and inspect remediation.
- **Export:** download a JSON report or CSV findings list.
- **Local-first workflow:** upload a JSON file for analysis without running the configured agent.

## Quick start

### Requirements

- Python 3.10+
- Node.js 20.19+ or 22.12+
- npm

### 1. Start the API

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

The API health check is available at `http://127.0.0.1:8000/health`. Interactive API documentation is at `http://127.0.0.1:8000/docs`.

### 2. Start the frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite, usually `http://localhost:5173`.

### 3. Try a scan

Choose **Load demo** in the UI, or upload one of the sample configurations in `backend/`. The sample files are synthetic and contain no real credentials.

## API

### `GET /health`

Returns service health and API version.

### `GET /api/rules`

Returns analysis mode and known limitations.

### `POST /api/scan`

Accepts a multipart file field named `file` containing a JSON MCP configuration. The maximum upload size is 2 MiB.

Supported top-level keys are `mcpServers` and `servers`. The scanner can inspect an optional `tools` array when present in a fixture or enriched configuration. Typical client configuration files do **not** include tool metadata, so discovering actual tools requires a separate MCP-aware discovery process; Agent X-Ray does not connect to or execute servers during this scan.

## Detection model

| Signal | Default severity | Confidence intent |
|---|---|---|
| Shell-based launcher / inline shell flag | High | High that the configuration pattern exists; not proof of exploitability |
| Unpinned package tag | Medium | High that the moving tag is present |
| Remote HTTP endpoint | High | High that the URL uses HTTP |
| Literal credential-like value / auth header | Medium–High | Depends on the matched evidence |
| Tool capability inferred from name or description | Rule-dependent | Medium |
| Command/path/URL/query-like schema property | Medium–High | Low; review signal only |

Severity describes potential impact if the risky capability is real. Confidence describes how directly the configuration supports the specific finding. They are different dimensions.

## Test

```bash
cd backend
python -m unittest -v test_scanner
```

The tests cover plural file-read descriptions, nested schemas, capability matches, secret redaction, HTTP transport, unpinned packages, invalid input, and summary consistency.

## Architecture

```text
React + Vite
    │ multipart JSON upload
    ▼
FastAPI API
    │ validate + parse
    ▼
Static scanner
    │ findings + graph model
    ▼
Interactive React Flow topology
    ├── finding investigation
    └── JSON / CSV export
```

## Security and privacy notes

- The scanner does not invoke configured commands or contact configured endpoints.
- Uploads are processed in memory by the API route and are not intentionally persisted.
- Secret values are not included in finding evidence or report exports.
- The local development CORS allowlist is intentionally limited to Vite localhost origins. Configure the exact deployed frontend origin before production deployment.
- This is a developer review aid, not a substitute for threat modelling, code review, runtime controls, dependency auditing, or penetration testing.

## Roadmap

- MCP protocol-aware metadata discovery with explicit user consent and strict timeouts.
- Rule-pack versioning and suppression with rationale.
- SARIF export for code-scanning workflows.
- Baseline comparisons between configuration revisions.
- CI integration that can fail builds on selected high-confidence rules.

## Contributing

Issues and pull requests are welcome. Useful contributions include test fixtures for real-world configuration formats, false-positive reports with sanitized evidence, new deterministic rules, and accessibility improvements.

When reporting a finding, include a minimal sanitized fixture and expected behaviour. Never commit real API keys, access tokens, private endpoints, or customer data.

## License

MIT. See [LICENSE](LICENSE).
