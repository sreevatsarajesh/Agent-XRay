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
def add_finding(findings, rule_id, severity, title, description, evidence, remediation, node_id):
    if any(item["id"] == f"{rule_id}:{node_id}" for item in findings):
        return
    findings.append({
        "id": f"{rule_id}:{node_id}",
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
    nodes = []
    edges = []
    findings = []

    nodes.append({
        "id": "config",
        "type": "config",
        "label": "MCP Configuration",
        "risk": "info",
        "details": {"server_count": len(servers)},
    })

    for name, server in servers.items():
        if not isinstance(server, dict):
            add_finding(
                findings,
                "INVALID_SERVER_CONFIG",
                "medium",
                "Invalid server configuration",
                "The server entry is not a JSON object.",
                f"Server '{name}' has an unexpected value type.",
                "Review the server entry and use the format supported by your MCP client.",
                "config",
            )
            continue

        server_id = f"server:{name}"
        command = server.get("command")
        args = server.get("args", [])
        url = server.get("url")
        headers = server.get("headers", {})
        env = server.get("env", {})

        if not isinstance(args, list):
            args = []

        if not isinstance(env, dict):
            env = {}

        if not isinstance(headers, dict):
            headers = {}

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
                    findings,
                    "SHELL_EXECUTION",
                    "high",
                    "Shell-based server launch",
                    "The server launches through a shell, which can increase the impact of unsafe arguments or untrusted input.",
                    f"Server '{name}' uses executable '{executable}'.",
                    "Prefer a direct executable with fixed arguments when possible. Review every argument and avoid passing untrusted input to shell commands.",
                    server_id,
                )

            if executable in {"curl", "wget"}:
                add_finding(
                    findings,
                    "DOWNLOAD_EXECUTION_TOOL",
                    "high",
                    "Download utility used as server command",
                    "The configured command uses a utility commonly used to retrieve remote content. Review whether it downloads or executes untrusted content.",
                    f"Server '{name}' uses '{executable}' as its command.",
                    "Use a trusted, pinned installation method and inspect the complete command before allowing it to run.",
                    server_id,
                )

            for arg in args:
                if not isinstance(arg, str):
                    continue

                if arg in {"-c", "/c", "-Command", "-EncodedCommand"} and executable in SHELL_COMMANDS:
                    add_finding(
                        findings,
                        "INLINE_SHELL_COMMAND",
                        "high",
                        "Inline shell command configured",
                        "The server configuration appears to pass a command string to a shell.",
                        f"Server '{name}' contains shell argument '{arg}'. Command contents are not executed during scanning.",
                        "Inspect the full command, avoid dynamic command construction, and use fixed arguments where possible.",
                        server_id,
                    )
                    break

            for arg in args:
                if isinstance(arg, str) and "@latest" in arg.lower():
                    add_finding(
                        findings,
                        "UNPINNED_PACKAGE_VERSION",
                        "medium",
                        "Package version is not pinned",
                        "A package reference uses a moving latest-version tag.",
                        f"Server '{name}' contains a package argument with '@latest'.",
                        "Pin a reviewed package version and update it through a deliberate review process.",
                        server_id,
                    )
                    break

        if isinstance(url, str) and url:
            endpoint_id = f"endpoint:{name}"
            parsed = urlparse(url)

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

            if parsed.scheme.lower() == "http" and parsed.hostname not in {
                "localhost", "127.0.0.1", "::1"
            }:
                add_finding(
                    findings,
                    "INSECURE_REMOTE_TRANSPORT",
                    "high",
                    "Remote endpoint uses HTTP",
                    "The configured remote endpoint does not use HTTPS, so traffic may lack transport encryption.",
                    f"Server '{name}' uses the HTTP scheme for a non-local endpoint.",
                    "Use HTTPS where supported and verify the endpoint identity before sending sensitive data.",
                    server_id,
                )

            if parsed.scheme.lower() not in {"http", "https"}:
                add_finding(
                    findings,
                    "UNEXPECTED_ENDPOINT_SCHEME",
                    "medium",
                    "Unexpected endpoint scheme",
                    "The endpoint does not use a standard HTTP or HTTPS URL scheme.",
                    f"Server '{name}' uses scheme '{parsed.scheme or 'missing'}'.",
                    "Verify that the endpoint scheme is supported and intentional.",
                    server_id,
                )

        for key, value in env.items():
            env_id = f"env:{name}:{key}"
            key_text = str(key)
            value_text = value if isinstance(value, str) else ""

            nodes.append({
                "id": env_id,
                "type": "environment",
                "label": key_text,
                "risk": "info",
                "details": {
                    "server": str(name),
                    "value_redacted": True,
                    "value_is_reference": (
                        value_text.startswith("${") and value_text.endswith("}")
                    ),
                },
            })

            edges.append({
                "id": f"{server_id}->{env_id}",
                "source": server_id,
                "target": env_id,
                "label": "receives env",
            })

            if SECRET_PATTERN.search(key_text):
                is_reference = (
                    value_text.startswith("${") and value_text.endswith("}")
                )

                if value_text and not is_reference and SECRET_VALUE_PATTERN.search(value_text):
                    add_finding(
                        findings,
                        "POSSIBLE_HARDCODED_SECRET",
                        "high",
                        "Possible hardcoded credential",
                        "An environment variable name suggests a credential, and its value resembles a token or secret.",
                        f"Server '{name}' has a value for '{key_text}' that matches a credential pattern. The value is redacted.",
                        "Rotate the credential if it has been exposed. Store secrets outside shared configuration files and reference them through environment variables or a secret manager.",
                        env_id,
                    )
                elif value_text and not is_reference:
                    add_finding(
                        findings,
                        "REVIEW_CREDENTIAL_VALUE",
                        "medium",
                        "Credential-like field needs review",
                        "A credential-related field contains a literal value that could not be confidently identified as a token.",
                        f"Server '{name}' contains a literal value for '{key_text}'. The value is redacted.",
                        "Verify whether the value is sensitive. Prefer an environment-variable reference or secret manager for credentials.",
                        env_id,
                    )

        for key, value in headers.items():
            if not isinstance(value, str):
                continue

            if key.lower() in {"authorization", "x-api-key", "api-key"}:
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

                if not (value.startswith("${") and value.endswith("}")):
                    add_finding(
                        findings,
                        "LITERAL_AUTH_HEADER",
                        "high",
                        "Literal authentication header",
                        "An authentication-related HTTP header contains a literal value instead of an obvious variable reference.",
                        f"Server '{name}' defines header '{key}'. The value is redacted.",
                        "Use a secure credential reference and rotate the credential if it has been exposed.",
                        header_id,
                    )

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for finding in findings:
        node_id = finding["node_id"]
        for node in nodes:
            if node["id"] == node_id:
                if severity_order.get(finding["severity"], 0) > severity_order.get(node["risk"], 0):
                    node["risk"] = finding["severity"]

    counts = {
        level: sum(1 for finding in findings if finding["severity"] == level)
        for level in ["critical", "high", "medium", "low"]
    }

    return {
        "summary": {
            "servers_scanned": len(servers),
            "nodes_found": len(nodes),
            "edges_found": len(edges),
            "findings_count": len(findings),
            "severity_counts": counts,
            "assessment": (
                "review_required" if findings else "no_findings_detected"
            ),
        },
        "nodes": nodes,
        "edges": edges,
        "findings": findings,
    }
