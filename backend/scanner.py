
import re
from urllib.parse import urlparse


SECRET_PATTERN = re.compile(
    r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret|private[_-]?key)",
    re.IGNORECASE,
)

SECRET_VALUE_PATTERN = re.compile(
    r"^(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"AKIA[A-Z0-9]{16}|Bearer\s+\S{12,}|eyJ[A-Za-z0-9_-]{20,}\.)"
)

SHELL_COMMANDS = {"bash", "sh", "zsh", "fish", "cmd", "powershell", "pwsh"}

CAPABILITY_RULES = [
    (
        "shell",
        re.compile(r"\b(shell|terminal|execute command|run command|subprocess|powershell)\b", re.I),
        "high",
        "Shell or command execution capability",
        "This tool description suggests that it can execute commands.",
        "Restrict command execution, validate inputs, and use an allowlist of permitted operations.",
    ),
    (
        "file_write",
        re.compile(r"\b(write file|delete file|modify file|edit file|overwrite|filesystem write)\b", re.I),
        "high",
        "File modification capability",
        "This tool description suggests that it can modify or delete files.",
        "Restrict writable paths and require explicit approval for destructive operations.",
    ),
    (
        "file_read",
        re.compile(r"\b(read file|read directory|filesystem read|search files|read document)\b", re.I),
        "medium",
        "File access capability",
        "This tool description suggests that it can access local files.",
        "Limit access to necessary directories and avoid exposing secrets or unrelated user data.",
    ),
    (
        "network",
        re.compile(r"\b(http request|web request|fetch url|network access|send request|browse website)\b", re.I),
        "medium",
        "Network access capability",
        "This tool description suggests that it can access remote services.",
        "Restrict destinations and validate URLs to reduce server-side request forgery and data exfiltration risks.",
    ),
    (
        "credentials",
        re.compile(r"\b(credential|secret|api key|access token|password|authentication token)\b", re.I),
        "high",
        "Credential-related capability",
        "This tool description suggests that it may access or handle credentials.",
        "Use least-privilege credentials, redact sensitive values, and audit access.",
    ),
]


def add_finding(findings, rule_id, severity, title, description, evidence, remediation, node_id):
    finding_id = f"{rule_id}:{node_id}"

    if any(item["id"] == finding_id for item in findings):
        return

    findings.append({
        "id": finding_id,
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "node_id": node_id,
    })


def scan_config(config):
    if not isinstance(config, dict):
        raise ValueError("The configuration root must be a JSON object.")

    servers = config.get("mcpServers")

    if not isinstance(servers, dict):
        servers = config.get("servers")

    if not isinstance(servers, dict):
        raise ValueError(
            "No supported MCP server object found. Expected 'mcpServers' or 'servers'."
        )

    nodes = [{
        "id": "config",
        "type": "config",
        "label": "MCP Configuration",
        "risk": "info",
        "details": {"server_count": len(servers)},
    }]

    edges = []
    findings = []

    for name, server in servers.items():
        if not isinstance(server, dict):
            add_finding(
                findings, "INVALID_SERVER_CONFIG", "medium",
                "Invalid server configuration",
                "The server entry is not a JSON object.",
                f"Server '{name}' has an unexpected value type.",
                "Review the entry against the relevant MCP client configuration format.",
                "config",
            )
            continue

        server_id = f"server:{name}"
        command = server.get("command")
        args = server.get("args", [])
        url = server.get("url")
        env = server.get("env", {})
        headers = server.get("headers", {})
        tools = server.get("tools", [])

        args = args if isinstance(args, list) else []
        env = env if isinstance(env, dict) else {}
        headers = headers if isinstance(headers, dict) else {}

        nodes.append({
            "id": server_id,
            "type": "server",
            "label": str(name),
            "risk": "info",
            "details": {
                "transport": "remote" if url else "stdio",
                "command": command if isinstance(command, str) else None,
                "url": url if isinstance(url, str) else None,
                "argument_count": len(args),
                "environment_variable_count": len(env),
                "capabilities_analyzed": isinstance(tools, list),
            },
        })

        edges.append({
            "id": f"config->{server_id}",
            "source": "config",
            "target": server_id,
            "label": "defines",
        })

        if isinstance(command, str) and command:
            executable = command.replace("\\", "/").split("/")[-1].lower()
            process_id = f"process:{name}"

            nodes.append({
                "id": process_id,
                "type": "process",
                "label": executable,
                "risk": "info",
                "details": {"server": str(name)},
            })

            edges.append({
                "id": f"{server_id}->{process_id}",
                "source": server_id,
                "target": process_id,
                "label": "launches",
            })

            if executable in SHELL_COMMANDS:
                add_finding(
                    findings, "SHELL_EXECUTION", "high",
                    "Shell-based server launch",
                    "The server launches through a shell, which may increase the impact of unsafe arguments or untrusted input.",
                    f"Server '{name}' uses executable '{executable}'.",
                    "Prefer a direct executable with fixed arguments and avoid passing untrusted input to shell commands.",
                    server_id,
                )

            if executable in {"curl", "wget"}:
                add_finding(
                    findings, "DOWNLOAD_EXECUTION_TOOL", "high",
                    "Download utility used as server command",
                    "Review whether the configured download utility retrieves or executes untrusted content.",
                    f"Server '{name}' uses '{executable}' as its command.",
                    "Use a trusted installation process and inspect the complete command before allowing it to run.",
                    server_id,
                )

            for arg in args:
                if isinstance(arg, str) and "@latest" in arg.lower():
                    add_finding(
                        findings, "UNPINNED_PACKAGE_VERSION", "medium",
                        "Package version is not pinned",
                        "A package reference uses a moving latest-version tag.",
                        f"Server '{name}' contains a package argument with '@latest'.",
                        "Pin a reviewed version and update it through a deliberate review process.",
                        server_id,
                    )
                    break

            for arg in args:
                if isinstance(arg, str) and arg in {"-c", "/c", "-Command", "-EncodedCommand"} and executable in SHELL_COMMANDS:
                    add_finding(
                        findings, "INLINE_SHELL_COMMAND", "high",
                        "Inline shell command configured",
                        "The configuration appears to pass a command string to a shell.",
                        f"Server '{name}' uses shell argument '{arg}'.",
                        "Review the full command and avoid dynamic command construction.",
                        server_id,
                    )
                    break

        if isinstance(url, str) and url:
            parsed = urlparse(url)
            endpoint_id = f"endpoint:{name}"

            nodes.append({
                "id": endpoint_id,
                "type": "endpoint",
                "label": parsed.hostname or "Remote endpoint",
                "risk": "info",
                "details": {
                    "scheme": parsed.scheme,
                    "host": parsed.hostname,
                    "transport": "remote",
                },
            })

            edges.append({
                "id": f"{server_id}->{endpoint_id}",
                "source": server_id,
                "target": endpoint_id,
                "label": "connects to",
            })

            if parsed.scheme.lower() == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
                add_finding(
                    findings, "INSECURE_REMOTE_TRANSPORT", "high",
                    "Remote endpoint uses HTTP",
                    "The endpoint does not use HTTPS, so traffic may lack transport encryption.",
                    f"Server '{name}' uses HTTP for a non-local endpoint.",
                    "Use HTTPS where supported and verify the endpoint identity.",
                    server_id,
                )

        for key, value in env.items():
            env_id = f"env:{name}:{key}"
            value_text = value if isinstance(value, str) else ""
            is_reference = value_text.startswith("${") and value_text.endswith("}")

            nodes.append({
                "id": env_id,
                "type": "environment",
                "label": str(key),
                "risk": "info",
                "details": {
                    "server": str(name),
                    "value_redacted": True,
                    "value_is_reference": is_reference,
                },
            })

            edges.append({
                "id": f"{server_id}->{env_id}",
                "source": server_id,
                "target": env_id,
                "label": "receives env",
            })

            if SECRET_PATTERN.search(str(key)):
                if value_text and not is_reference and SECRET_VALUE_PATTERN.search(value_text):
                    add_finding(
                        findings, "POSSIBLE_HARDCODED_SECRET", "high",
                        "Possible hardcoded credential",
                        "A credential-like field contains a value matching a token pattern.",
                        f"Server '{name}' has a possible credential in '{key}'. The value is redacted.",
                        "Rotate exposed credentials and store secrets outside shared configuration files.",
                        env_id,
                    )
                elif value_text and not is_reference:
                    add_finding(
                        findings, "REVIEW_CREDENTIAL_VALUE", "medium",
                        "Credential-like field needs review",
                        "A credential-related field contains a literal value.",
                        f"Server '{name}' has a literal value for '{key}'. The value is redacted.",
                        "Verify whether it is sensitive and use a secure reference for credentials.",
                        env_id,
                    )

        for key, value in headers.items():
            if str(key).lower() in {"authorization", "x-api-key", "api-key"} and isinstance(value, str):
                header_id = f"header:{name}:{key}"

                nodes.append({
                    "id": header_id,
                    "type": "credential",
                    "label": str(key),
                    "risk": "info",
                    "details": {"value_redacted": True, "server": str(name)},
                })

                edges.append({
                    "id": f"{server_id}->{header_id}",
                    "source": server_id,
                    "target": header_id,
                    "label": "sets header",
                })

                if value and not (value.startswith("${") and value.endswith("}")):
                    add_finding(
                        findings, "LITERAL_AUTH_HEADER", "high",
                        "Literal authentication header",
                        "An authentication header contains a literal value.",
                        f"Server '{name}' defines header '{key}'. The value is redacted.",
                        "Use a secure credential reference and rotate the value if exposed.",
                        header_id,
                    )

        if isinstance(tools, list):
            for index, tool in enumerate(tools):
                if not isinstance(tool, dict):
                    continue

                tool_name = tool.get("name")
                description = tool.get("description", "")
                schema = tool.get("inputSchema", tool.get("input_schema", {}))

                if not isinstance(tool_name, str) or not tool_name.strip():
                    continue

                if not isinstance(description, str):
                    description = ""

                if not isinstance(schema, dict):
                    schema = {}

                tool_id = f"tool:{name}:{index}"
                searchable_text = f"{tool_name} {description}"

                nodes.append({
                    "id": tool_id,
                    "type": "tool",
                    "label": tool_name,
                    "risk": "info",
                    "details": {
                        "server": str(name),
                        "description": description[:500],
                        "input_schema": schema,
                        "capabilities": [],
                    },
                })

                edges.append({
                    "id": f"{server_id}->{tool_id}",
                    "source": server_id,
                    "target": tool_id,
                    "label": "exposes",
                })

                for capability, pattern, severity, title, description_text, remediation in CAPABILITY_RULES:
                    if pattern.search(searchable_text):
                        node = nodes[-1]

                        if capability not in node["details"]["capabilities"]:
                            node["details"]["capabilities"].append(capability)

                        add_finding(
                            findings,
                            f"TOOL_CAPABILITY_{capability.upper()}",
                            severity,
                            title,
                            description_text,
                            f"Tool '{tool_name}' on server '{name}' matched capability rule '{capability}' based on its name or description.",
                            remediation,
                            tool_id,
                        )

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for finding in findings:
        for node in nodes:
            if node["id"] == finding["node_id"]:
                if severity_order.get(finding["severity"], 0) > severity_order.get(node["risk"], 0):
                    node["risk"] = finding["severity"]

    counts = {
        level: sum(f["severity"] == level for f in findings)
        for level in ["critical", "high", "medium", "low"]
    }

    return {
        "summary": {
            "servers_scanned": len(servers),
            "nodes_found": len(nodes),
            "edges_found": len(edges),
            "findings_count": len(findings),
            "severity_counts": counts,
            "assessment": "review_required" if findings else "no_findings_detected",
        },
        "nodes": nodes,
        "edges": edges,
        "findings": findings,
    }
