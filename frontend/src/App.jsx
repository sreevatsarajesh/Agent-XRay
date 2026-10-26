
import { useCallback, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  MarkerType,
} from "@xyflow/react";
import {
  Shield,
  Server,
  Terminal,
  Globe,
  KeyRound,
  FileJson,
  AlertTriangle,
  Upload,
  Search,
  Maximize2,
  Minimize2,
  CheckCircle2,
  ChevronRight,
  X,
  RefreshCw,
  Network,
  LockKeyhole,
  ArrowUpRight,
  Activity,
  Download,
  FileText,
  Fingerprint,
} from "lucide-react";
import "@xyflow/react/dist/style.css";
import "./App.css";

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

const DEMO_CONFIG = {
  mcpServers: {
    "demo-shell": {
      command: "bash",
      args: ["-c", "echo demo"],
      env: { API_KEY: "sk-TEST000000000000000000" },
    },
    "demo-remote": {
      url: "http://example.com/mcp",
    },
    "demo-package": {
      command: "npx",
      args: ["-y", "example-server@latest"],
    },
  },
};

const ICONS = {
  config: FileJson,
  server: Server,
  process: Terminal,
  endpoint: Globe,
  environment: KeyRound,
  credential: LockKeyhole,
  tool: Fingerprint,
};

const SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function makeGraph(result) {
  const { nodes: rawNodes, edges: rawEdges } = result;
  const depths = new Map([["config", 0]]);

  for (let i = 0; i < rawNodes.length; i++) {
    let changed = false;

    for (const edge of rawEdges) {
      if (depths.has(edge.source) && !depths.has(edge.target)) {
        depths.set(edge.target, depths.get(edge.source) + 1);
        changed = true;
      }
    }

    if (!changed) break;
  }

  const layers = new Map();

  for (const node of rawNodes) {
    const depth = depths.get(node.id) ?? 1;
    if (!layers.has(depth)) layers.set(depth, []);
    layers.get(depth).push(node);
  }

  const positions = new Map();

  for (const [depth, items] of layers) {
    const spacing = 155;
    const startY = -((items.length - 1) * spacing) / 2;

    items.forEach((node, index) => {
      positions.set(node.id, {
        x: 70 + depth * 320,
        y: startY + index * spacing,
      });
    });
  }

  const nodes = rawNodes.map((node) => ({
    id: node.id,
    type: "xray",
    position: positions.get(node.id) || { x: 0, y: 0 },
    data: {
      label: node.label,
      nodeType: node.type,
      risk: node.risk,
      details: node.details,
      originalId: node.id,
    },
  }));

  const edges = rawEdges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.label,
    type: "smoothstep",
    animated: false,
    style: { stroke: "#475569", strokeWidth: 1.5 },
    labelStyle: { fill: "#94a3b8", fontSize: 10 },
    labelBgStyle: { fill: "#111827", fillOpacity: 0.95 },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: "#475569",
      width: 15,
      height: 15,
    },
  }));

  return { nodes, edges };
}

function XrayNode({ data, selected }) {
  const Icon = ICONS[data.nodeType] || Network;
  const risk = data.risk || "info";

  return (
    <div className={`graph-node risk-${risk} ${selected ? "node-selected" : ""}`}>
      <Handle type="target" position={Position.Left} className="node-handle" />
      <div className="graph-node-top">
        <div className="node-icon">
          <Icon size={16} />
        </div>
        <span className={`node-risk risk-text-${risk}`}>
          {risk === "info" ? "ASSET" : risk.toUpperCase()}
        </span>
      </div>
      <div className="graph-node-label" title={data.label}>
        {data.label}
      </div>
      <div className="graph-node-type">
        {data.nodeType.replace("_", " ")}
      </div>
      <Handle type="source" position={Position.Right} className="node-handle" />
    </div>
  );
}

const NODE_TYPES = { xray: XrayNode };

function StatCard({ label, value, icon: Icon, tone = "" }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${tone}`}>
        <Icon size={18} />
      </div>
      <div className="stat-copy">
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function FindingItem({ finding, active, onClick }) {
  return (
    <button
      className={`finding-item ${active ? "finding-active" : ""}`}
      onClick={onClick}
    >
      <div className={`finding-severity severity-${finding.severity}`}>
        <AlertTriangle size={15} />
      </div>
      <div className="finding-copy">
        <div className="finding-title">{finding.title}</div>
        <div className="finding-meta">
          <span>{finding.rule_id}</span>
          <span className={`severity-label severity-label-${finding.severity}`}>
            {finding.severity}
          </span>
          {finding.confidence && <span className={`confidence-label confidence-${finding.confidence}`}>{finding.confidence} confidence</span>}
        </div>
      </div>
      <ChevronRight size={15} className="finding-chevron" />
    </button>
  );
}

function App() {
  const [result, setResult] = useState(null);
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [fileName, setFileName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [fullscreen, setFullscreen] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");

  const scanFile = useCallback(async (file) => {
    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".json")) {
      setError("Please upload a JSON configuration file.");
      return;
    }

    setLoading(true);
    setError("");
    setSelectedFinding(null);
    setSelectedNode(null);
    setFileName(file.name);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 30000);
      let response;
      let data;

      try {
        response = await fetch(`${API_URL}/api/scan`, {
          method: "POST",
          body: formData,
          signal: controller.signal,
        });
        data = await response.json();
      } finally {
        window.clearTimeout(timeout);
      }

      if (!response.ok) {
        throw new Error(data.detail || "The scan could not be completed.");
      }

      const graph = makeGraph(data);
      setResult(data);
      setNodes(graph.nodes);
      setEdges(graph.edges);
    } catch (err) {
      const message = err.name === "AbortError"
        ? "The scan timed out after 30 seconds."
        : err.message || "The scan could not be completed.";
      setError(`${message} Check that the FastAPI backend is reachable at ${API_URL}.`);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadDemo = useCallback(() => {
    const file = new File(
      [JSON.stringify(DEMO_CONFIG, null, 2)],
      "demo-agent-config.json",
      { type: "application/json" }
    );
    scanFile(file);
  }, [scanFile]);

  const onNodeClick = useCallback((_, node) => {
    setSelectedNode(node);
    setSelectedFinding(null);
  }, []);

  const selectFinding = useCallback((finding) => {
    setSelectedFinding(finding);
    const node = nodes.find((item) => item.id === finding.node_id);
    setSelectedNode(node || null);
  }, [nodes]);

  const orderedFindings = useMemo(() => {
    if (!result) return [];

    return [...result.findings]
      .filter((item) => severityFilter === "all" || item.severity === severityFilter)
      .filter((item) =>
        `${item.title} ${item.rule_id} ${item.description} ${item.evidence} ${item.remediation} ${item.category || ""}`
          .toLowerCase()
          .includes(query.toLowerCase())
      )
      .sort(
        (a, b) =>
          (SEVERITY_ORDER[a.severity] ?? 9) -
          (SEVERITY_ORDER[b.severity] ?? 9)
      );
  }, [result, severityFilter, query]);

  const onUpload = (event) => {
    scanFile(event.target.files?.[0]);
    event.target.value = "";
  };

  const downloadReport = useCallback((format = "json") => {
    if (!result) return;
    const report = {
      product: "Agent X-Ray",
      report_version: "1.0",
      generated_at: new Date().toISOString(),
      source_file: fileName,
      disclaimer: "Static heuristic analysis only. Findings require human verification and do not prove exploitability.",
      summary: result.summary,
      findings: result.findings,
    };
    let content;
    let mime;
    let extension;
    if (format === "csv") {
      const columns = ["severity", "confidence", "category", "rule_id", "title", "description", "evidence", "remediation", "node_id"];
      const escapeCell = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
      content = [columns.join(","), ...result.findings.map((finding) => columns.map((key) => escapeCell(finding[key])).join(","))].join("\n");
      mime = "text/csv;charset=utf-8";
      extension = "csv";
    } else {
      content = JSON.stringify(report, null, 2);
      mime = "application/json";
      extension = "json";
    }
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `agent-xray-report.${extension}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }, [result, fileName]);

  const activeNode = selectedNode
    ? result?.nodes.find((node) => node.id === selectedNode.id)
    : null;

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={21} />
            <span />
          </div>
          <div>
            <div className="brand-name">AGENT<span>XRAY</span></div>
            <div className="brand-subtitle">AI AGENT SECURITY ANALYSIS</div>
          </div>
        </div>

        <div className="topbar-right">
          <div className="connection-status">
            <span className="status-dot" />
            LOCAL ANALYSIS
          </div>
          <button className="button button-secondary" onClick={loadDemo} disabled={loading}>
            <RefreshCw size={15} />
            Load demo
          </button>
          <label className="button button-primary">
            <Upload size={15} />
            Upload config
            <input type="file" accept=".json,application/json" hidden onChange={onUpload} />
          </label>
        </div>
      </header>

      <section className="page-intro">
        <div>
          <div className="eyebrow"><Activity size={13} /> SECURITY WORKSPACE / 001</div>
          <h1>See what your <span>AI agents</span> can access.</h1>
          <p>Map tools, inspect trust boundaries, and investigate configuration risks.</p>
        </div>
        <div className="intro-tag">
          <div className="intro-tag-icon"><LockKeyhole size={17} /></div>
          <div>
            <strong>Static analysis</strong>
            <span>No agent execution</span>
          </div>
        </div>
      </section>

      {error && (
        <div className="error-banner">
          <AlertTriangle size={17} />
          <span>{error}</span>
          <button onClick={() => setError("")} aria-label="Dismiss error"><X size={16} /></button>
        </div>
      )}

      <section className="stats-grid">
        <StatCard label="Servers analyzed" value={result?.summary.servers_scanned ?? "—"} icon={Server} />
        <StatCard label="Graph nodes" value={result?.summary.nodes_found ?? "—"} icon={Network} />
        <StatCard label="Security findings" value={result?.summary.findings_count ?? "—"} icon={AlertTriangle} tone="tone-amber" />
        <StatCard label="High severity" value={result?.summary.severity_counts.high ?? "—"} icon={Shield} tone="tone-red" />
      </section>

      {result && (
        <section className="posture-strip">
          <div className="posture-copy">
            <span className="posture-kicker">SCAN POSTURE</span>
            <strong>{result.summary.findings_count ? "Review recommended" : "No heuristic findings detected"}</strong>
            <span>{result.summary.assessment_note || "Static analysis complete."}</span>
          </div>
          <div className="posture-breakdown">
            {["critical", "high", "medium", "low"].map((level) => (
              <div className={`posture-segment posture-${level}`} key={level}>
                <strong>{result.summary.severity_counts?.[level] ?? 0}</strong>
                <span>{level}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className={`workspace ${fullscreen ? "workspace-fullscreen" : ""}`}>
        <div className="workspace-header">
          <div className="workspace-heading">
            <div className="workspace-heading-icon"><Network size={17} /></div>
            <div>
              <h2>Agent topology</h2>
              <p>{result ? fileName : "Configuration relationship map"}</p>
            </div>
          </div>
          <div className="graph-toolbar">
            {result && <span className="graph-count">{nodes.length} NODES <span>·</span> {edges.length} EDGES</span>}
            <button
              className="icon-button"
              onClick={() => setFullscreen((value) => !value)}
              title={fullscreen ? "Exit fullscreen" : "Fullscreen graph"}
            >
              {fullscreen ? <Minimize2 size={17} /> : <Maximize2 size={17} />}
            </button>
          </div>
        </div>

        <div
          className={`graph-area ${dragging ? "graph-dragging" : ""}`}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragging(false);
            scanFile(event.dataTransfer.files?.[0]);
          }}
        >
          {loading ? (
            <div className="empty-state">
              <div className="loading-spinner" />
              <h3>Analyzing configuration</h3>
              <p>Building the topology and evaluating security rules.</p>
            </div>
          ) : result ? (
            <>
              <div className="graph-legend">
                <span><i className="legend-dot legend-high" /> High</span>
                <span><i className="legend-dot legend-medium" /> Medium</span>
                <span><i className="legend-dot legend-low" /> Low</span>
                <span><i className="legend-dot legend-info" /> Asset</span>
              </div>
              <ReactFlow
                key={`${fileName}-${nodes.length}`}
                nodes={nodes}
                edges={edges}
                nodeTypes={NODE_TYPES}
                onNodeClick={onNodeClick}
                onNodesChange={(changes) => {
                  setNodes((current) => {
                    let next = current;
                    for (const change of changes) {
                      if (change.type === "position" && change.position) {
                        next = next.map((node) =>
                          node.id === change.id
                            ? { ...node, position: change.position }
                            : node
                        );
                      }
                      if (change.type === "select") {
                        next = next.map((node) =>
                          node.id === change.id
                            ? { ...node, selected: change.selected }
                            : node
                        );
                      }
                    }
                    return next;
                  });
                }}
                fitView
                fitViewOptions={{ padding: 0.25, maxZoom: 1.2 }}
                minZoom={0.15}
                maxZoom={2}
                proOptions={{ hideAttribution: true }}
                colorMode="dark"
              >
                <Background color="#263345" gap={24} size={1} />
                <Controls showInteractive={false} />
                <MiniMap
                  nodeColor={(node) => {
                    const risk = node.data?.risk;
                    if (risk === "critical" || risk === "high") return "#fb7185";
                    if (risk === "medium") return "#fbbf24";
                    if (risk === "low") return "#60a5fa";
                    return "#64748b";
                  }}
                  maskColor="rgba(5, 9, 18, 0.75)"
                  pannable
                  zoomable
                />
              </ReactFlow>
              {dragging && <div className="drop-overlay">Drop JSON configuration to scan</div>}
            </>
          ) : (
            <div className="empty-state">
              <div className="empty-graphic">
                <div className="orbit orbit-one" />
                <div className="orbit orbit-two" />
                <div className="empty-shield"><Shield size={35} /></div>
                <div className="orbit-node orbit-node-one"><Server size={15} /></div>
                <div className="orbit-node orbit-node-two"><Terminal size={15} /></div>
                <div className="orbit-node orbit-node-three"><Globe size={15} /></div>
              </div>
              <h3>Nothing under the lens. Yet.</h3>
              <p>Upload an MCP JSON configuration to map agent capabilities and detect security risks.</p>
              <div className="empty-actions">
                <label className="button button-primary">
                  <Upload size={15} /> Choose configuration
                  <input type="file" accept=".json,application/json" hidden onChange={onUpload} />
                </label>
                <button className="button button-secondary" onClick={loadDemo}>
                  Try sample scan <ArrowUpRight size={15} />
                </button>
              </div>
              <span className="drop-hint">or drag and drop a .json file anywhere in this panel</span>
            </div>
          )}
        </div>
        <div className="workspace-footer">
          <span><span className="footer-dot" /> {result ? "Analysis complete" : "Scanner ready"}</span>
          <span>Configuration analysis only · No commands executed</span>
        </div>
      </section>

      <section className="findings-section">
        <div className="findings-header">
          <div>
            <div className="eyebrow">DETECTION ENGINE</div>
            <h2>Security findings <span>{result?.findings.length ?? 0}</span></h2>
            <p>Evidence-backed findings from configuration analysis.</p>
          </div>
          <div className="filter-controls">
            <div className="search-box">
              <Search size={15} />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search findings..."
              />
            </div>
            <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            {result && (
              <div className="export-actions">
                <button className="button button-secondary export-button" onClick={() => downloadReport("json")} title="Download full JSON report">
                  <Download size={14} /> JSON
                </button>
                <button className="button button-secondary export-button" onClick={() => downloadReport("csv")} title="Download findings as CSV">
                  <FileText size={14} /> CSV
                </button>
              </div>
            )}
          </div>
        </div>

        {!result ? (
          <div className="findings-empty">
            <Shield size={20} />
            <span>Run a scan to populate security findings.</span>
          </div>
        ) : orderedFindings.length === 0 ? (
          <div className="findings-empty">
            <CheckCircle2 size={20} />
            <span>No findings match your filters.</span>
          </div>
        ) : (
          <div className="findings-layout">
            <div className="findings-list">
              {orderedFindings.map((finding) => (
                <FindingItem
                  key={finding.id}
                  finding={finding}
                  active={selectedFinding?.id === finding.id}
                  onClick={() => selectFinding(finding)}
                />
              ))}
            </div>

            <div className="detail-panel">
              {selectedFinding ? (
                <>
                  <div className="detail-topline">
                    <div className="detail-badges">
                      <span className={`severity-label severity-label-${selectedFinding.severity}`}>
                        {selectedFinding.severity} severity
                      </span>
                      {selectedFinding.confidence && <span className={`confidence-label confidence-${selectedFinding.confidence}`}>{selectedFinding.confidence} confidence</span>}
                    </div>
                    <button className="icon-button" onClick={() => setSelectedFinding(null)} title="Close details">
                      <X size={15} />
                    </button>
                  </div>
                  <h3>{selectedFinding.title}</h3>
                  <p className="detail-description">{selectedFinding.description}</p>
                  <div className="finding-context">
                    <span>{selectedFinding.rule_id}</span>
                    <span>{(selectedFinding.category || "configuration").replaceAll("_", " ")}</span>
                  </div>
                  <div className="detail-block">
                    <span className="detail-label">EVIDENCE</span>
                    <p>{selectedFinding.evidence}</p>
                  </div>
                  <div className="detail-block remediation-block">
                    <span className="detail-label">RECOMMENDED ACTION</span>
                    <p>{selectedFinding.remediation}</p>
                  </div>
                  <button
                    className="linked-node"
                    onClick={() => {
                      const node = nodes.find((item) => item.id === selectedFinding.node_id);
                      setSelectedNode(node || null);
                    }}
                  >
                    <Network size={15} />
                    <span><small>AFFECTED NODE</small>{selectedFinding.node_id}</span>
                    <ArrowUpRight size={15} />
                  </button>
                </>
              ) : activeNode ? (
                <>
                  <div className="detail-topline">
                    <span className="detail-label">SELECTED GRAPH NODE</span>
                    <button className="icon-button" onClick={() => setSelectedNode(null)} title="Close details">
                      <X size={15} />
                    </button>
                  </div>
                  <h3>{activeNode.label}</h3>
                  <p className="detail-description">{activeNode.type} · {activeNode.id}</p>
                  <div className="detail-block">
                    <span className="detail-label">NODE DETAILS</span>
                    <pre>{JSON.stringify(activeNode.details, null, 2)}</pre>
                  </div>
                  <div className="detail-block">
                    <span className="detail-label">ASSOCIATED FINDINGS</span>
                    <p>{result.findings.filter((finding) => finding.node_id === activeNode.id).length} finding(s) linked to this node.</p>
                  </div>
                </>
              ) : (
                <div className="detail-placeholder">
                  <div className="detail-placeholder-icon"><Network size={20} /></div>
                  <strong>Investigate a finding</strong>
                  <p>Select a finding or graph node to inspect its evidence, context and remediation.</p>
                </div>
              )}
            </div>
          </div>
        )}
      </section>

      <footer className="app-footer">
        <div className="footer-brand"><Shield size={14} /> AGENT XRAY <span>v1.0.0</span></div>
        <p>Local-first static analysis · No agent execution · Findings require human verification</p>
      </footer>
    </main>
  );
}

export default App;
