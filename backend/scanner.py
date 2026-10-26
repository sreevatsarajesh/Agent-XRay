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
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

CAPABILITY_RULES = [
    (
        "shell",
        re.compile(r"\b(shell|terminal|execute(?:s|ing)? commands?|run(?:s|ning)? commands?|subprocess|powershell|command execution|execute process)\b", re.I),
        "high",
        "Command execution capability",
        "This tool name or description suggests that it can execute operating-system commands.",
        "Prefer narrow, predefined operations over arbitrary command execution. Validate inputs and require approval for sensitive actions.",
    ),
    (
        "file_write",
        re.compile(r"\b(write|create|delete|remove|modify|edit|overwrite|upload)\b.{0,35}\b(files?|documents?|directories|folders|paths?)\b|\b(filesystem|file system)\b.{0,25}\b(write|modify|delete|access)\b", re.I),
        "high",
        "File modification capability",
        "This tool name or description suggests that it can create, modify, overwrite, or delete files.",
        "Restrict writable paths, prevent traversal outside approved directories, and require explicit approval for destructive operations.",
    ),
    (
        "file_read",
        re.compile(r"\b(read|open|list|search|find|inspect|retrieve|download|access)\b.{0,35}\b(files?|documents?|directories|folders|filesystem|file system|paths?|contents?)\b|\b(filesystem|file system)\b.{0,25}\b(read|list|search|access)\b", re.I),
        "medium",
        "File access capability",
        "This tool name or description suggests that it can read or enumerate local files.",
        "Limit access to required directories and avoid exposing secrets, configuration files, or unrelated user data.",
    ),
    (
        "network",
        re.compile(r"\b(http requests?|web requests?|fetch(?:es|ing)? urls?|network access|send(?:s|ing)? requests?|browse(?:s|ing)? websites?|web search|search the web|internet access|make api calls?)\b", re.I),
        "medium",
        "Network access capability",
        "This tool name or description suggests that it can contact remote services or websites.",
        "Restrict destinations, validate URLs, and control outbound network access to reduce SSRF and data-exfiltration risk.",
    ),
    (
        "credentials",
        re.compile(r"\b(credentials?|secrets?|api keys?|access tokens?|passwords?|authentication tokens?|private keys?)\b", re.I),
        "high",
        "Credential-related capability",
        "This tool name or description suggests that it may access or handle credentials.",
        "Use least-privilege credentials, redact sensitive values, and audit credential access.",
    ),
    (
        "database",
        re.compile(r"\b(sql|database|execute query|run query|query database|database query)\b", re.I),
        "medium",
        "Database access capability",
        "This tool name or description suggests that it can query or interact with a database.",
        "Use scoped database identities, parameterized queries, and read-only access where possible.",
    ),
]


def add_finding(
    findings,
    rule_id,
    severity,
    title,
    description,
    evidence,
    remediation,
    node_id,
    confidence="medium",
    category="configuration",
):
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
        "confidence": confidence,
        "category": category,
    })


def _schema_strings(value, path="$"):
    results = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if isinstance(key, str):
                results.append((key, child_path))
            results.extend(_schema_strings(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            results.extend(_schema_strings(child, f"{path}[{index}]"))
    elif isinstance(value, str):
        results.append((value, path))
    return results


def _is_env_reference(value):
    return isinstance(value, str) and bool(re.fullmatch(r"\$\{[^}]+\}", value.strip()))


def _safe_url(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = urlparse(value)
        if not parsed.hostname:
            return None
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme.lower()}://{parsed.hostname}{port}{parsed.path}"
    except ValueError:
        return None


def scan_config(config):
    if not isinstance(config, dict):
        raise ValueError("The configuration root must be a JSON object.")

    servers = config.get("mcpServers")
    if not isinstance(servers, dict):
        servers = config.get("servers")
    if not isinstance(servers, dict):
        raise ValueError("No supported MCP server object found. Expected 'mcpServers' or 'servers'.")

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
        name = str(name)
        if not isinstance(server, dict):
            add_finding(
                findings, "INVALID_SERVER_CONFIG", "medium",
                "Invalid server configuration",
                "The server entry is not a JSON object.",
                f"Server '{name}' has an unexpected value type.",
                "Review the entry against the relevant MCP client configuration format.",
                "config", "high",
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
            "label": name,
            "risk": "info",
            "details": {
                "transport": "remote" if url else "stdio",
                "command": command if isinstance(command, str) else None,
                "url": _safe_url(url),
                "argument_count": len(args),
                "environment_variable_count": len(env),
                "capabilities_analyzed": isinstance(tools, list),
                "tool_count": len(tools) if isinstance(tools, list) else 0,
            },
        })
        edges.append({"id": f"config->{server_id}", "source": "config", "target": server_id, "label": "defines"})

        if isinstance(command, str) and command.strip():
            executable = command.replace("\\", "/").split("/")[-1].lower()
            process_id = f"process:{name}"
            nodes.append({
                "id": process_id,
                "type": "process",
                "label": executable,
                "risk": "info",
                "details": {"server": name},
            })
            edges.append({"id": f"{server_id}->{process_id}", "source": server_id, "target": process_id, "label": "launches"})

            if executable in SHELL_COMMANDS:
                add_finding(
                    findings, "SHELL_EXECUTION", "high",
                    "Shell-based server launch",
                    "The server launches through a shell. This can increase the impact of unsafe arguments or untrusted input, although shell use alone does not prove exploitability.",
                    f"Server '{name}' uses executable '{executable}'.",
                    "Prefer a direct executable with fixed arguments and avoid passing untrusted input to shell commands.",
                    server_id, "high", "execution",
                )

            if executable in {"curl", "wget"}:
                add_finding(
                    findings, "DOWNLOAD_EXECUTION_TOOL", "high",
                    "Download utility used as server command",
                    "A download utility is configured as the server process. Review whether it retrieves untrusted content or is being used as a launcher.",
                    f"Server '{name}' uses '{executable}' as its command.",
                    "Use a trusted installation process and inspect the full command before allowing it to run.",
                    server_id, "medium", "supply_chain",
                )

            if any(isinstance(arg, str) and "@latest" in arg.lower() for arg in args):
                add_finding(
                    findings, "UNPINNED_PACKAGE_VERSION", "medium",
                    "Package version is not pinned",
                    "A package reference uses a moving latest-version tag, reducing reproducibility and supply-chain reviewability.",
                    f"Server '{name}' contains a package argument with '@latest'.",
                    "Pin a reviewed package version and update it through a deliberate review process.",
                    server_id, "high", "supply_chain",
                )

            if executable in SHELL_COMMANDS and any(
                isinstance(arg, str) and arg in {"-c", "/c", "-Command", "-EncodedCommand"}
                for arg in args
            ):
                add_finding(
                    findings, "INLINE_SHELL_COMMAND", "high",
                    "Inline shell command configured",
                    "The configuration appears to pass an inline command string to a shell.",
                    f"Server '{name}' combines shell executable '{executable}' with a command execution flag.",
                    "Review the complete command and avoid dynamic command construction or untrusted interpolation.",
                    server_id, "high", "execution",
                )

        safe_url = None
        if isinstance(url, str) and url.strip():
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname
                scheme = parsed.scheme.lower()
                port = f":{parsed.port}" if parsed.port else ""
                safe_url = f"{scheme}://{hostname}{port}{parsed.path}" if hostname else None
            except ValueError:
                hostname = None
                scheme = ""
            endpoint_id = f"endpoint:{name}"
            nodes.append({
                "id": endpoint_id,
                "type": "endpoint",
                "label": hostname or "Remote endpoint",
                "risk": "info",
                "details": {
                    "scheme": scheme,
                    "host": hostname,
                    "transport": "remote",
                },
            })
            edges.append({"id": f"{server_id}->{endpoint_id}", "source": server_id, "target": endpoint_id, "label": "connects to"})

            if not hostname or scheme not in {"http", "https"}:
                add_finding(
                    findings, "INVALID_REMOTE_URL", "medium",
                    "Remote endpoint URL needs review",
                    "The configured endpoint is missing a valid hostname or does not use HTTP(S).",
                    f"Server '{name}' has a URL whose scheme or hostname could not be validated.",
                    "Verify the endpoint URL and use a supported, trusted transport.",
                    server_id, "high", "configuration",
                )
            elif scheme == "http" and hostname.lower() not in {"localhost", "127.0.0.1", "::1"}:
                add_finding(
                    findings, "INSECURE_REMOTE_TRANSPORT", "high",
                    "Remote endpoint uses HTTP",
                    "The endpoint uses unencrypted HTTP, so traffic may be exposed to interception or modification.",
                    f"Server '{name}' uses HTTP for a non-local endpoint.",
                    "Use HTTPS where supported and verify the endpoint identity.",
                    server_id, "high", "transport",
                )

        for key, value in env.items():
            key = str(key)
            env_id = f"env:{name}:{key}"
            value_text = value if isinstance(value, str) else ""
            is_reference = _is_env_reference(value_text)
            nodes.append({
                "id": env_id,
                "type": "environment",
                "label": key,
                "risk": "info",
                "details": {
                    "server": name,
                    "value_redacted": True,
                    "value_is_reference": is_reference,
                    "value_type": type(value).__name__,
                },
            })
            edges.append({"id": f"{server_id}->{env_id}", "source": server_id, "target": env_id, "label": "receives env"})

            if SECRET_PATTERN.search(key):
                if value_text and not is_reference and SECRET_VALUE_PATTERN.search(value_text):
                    add_finding(
                        findings, "POSSIBLE_HARDCODED_SECRET", "high",
                        "Possible hardcoded credential",
                        "A credential-like field contains a value matching a known token pattern. The value is never included in the report.",
                        f"Server '{name}' has a possible credential in '{key}'. The value is redacted.",
                        "Rotate exposed credentials and store secrets outside shared configuration files.",
                        env_id, "high", "secrets",
                    )
                elif value_text and not is_reference:
                    add_finding(
                        findings, "REVIEW_CREDENTIAL_VALUE", "medium",
                        "Credential-like field needs review",
                        "A credential-related field contains a literal value that may be sensitive.",
                        f"Server '{name}' has a literal value for '{key}'. The value is redacted.",
                        "Verify whether it is sensitive and use a secure environment or secret-manager reference.",
                        env_id, "medium", "secrets",
                    )

        for key, value in headers.items():
            if str(key).lower() in {"authorization", "x-api-key", "api-key"} and isinstance(value, str):
                header_id = f"header:{name}:{key}"
                nodes.append({
                    "id": header_id,
                    "type": "credential",
                    "label": str(key),
                    "risk": "info",
                    "details": {"value_redacted": True, "server": name},
                })
                edges.append({"id": f"{server_id}->{header_id}", "source": server_id, "target": header_id, "label": "sets header"})
                if value and not _is_env_reference(value):
                    add_finding(
                        findings, "LITERAL_AUTH_HEADER", "high",
                        "Literal authentication header",
                        "An authentication header contains a literal value rather than an environment reference.",
                        f"Server '{name}' defines header '{key}'. The value is redacted.",
                        "Use a secure credential reference and rotate the value if it has been exposed.",
                        header_id, "high", "secrets",
                    )

        if not isinstance(tools, list):
            continue

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
            tool_node = {
                "id": tool_id,
                "type": "tool",
                "label": tool_name,
                "risk": "info",
                "details": {
                    "server": name,
                    "description": description[:500],
                    "input_schema": schema,
                    "capabilities": [],
                },
            }
            nodes.append(tool_node)
            edges.append({"id": f"{server_id}->{tool_id}", "source": server_id, "target": tool_id, "label": "exposes"})

            for capability, pattern, severity, title, description_text, remediation in CAPABILITY_RULES:
                match = pattern.search(searchable_text)
                if match:
                    tool_node["details"]["capabilities"].append(capability)
                    add_finding(
                        findings,
                        f"TOOL_CAPABILITY_{capability.upper()}",
                        severity,
                        title,
                        description_text,
                        f"Tool '{tool_name}' on server '{name}' matched capability rule '{capability}' based on its name or description.",
                        remediation,
                        tool_id,
                        "medium",
                        "tool_capability",
                    )

            schema_items = _schema_strings(schema)
            schema_text = " ".join(value for value, _ in schema_items)
            schema_checks = [
                (
                    "SCHEMA_COMMAND_INPUT",
                    re.compile(r"\b(command|shell_command|executable|script|code)\b", re.I),
                    "high",
                    "Potentially powerful command input",
                    "The tool input schema contains a command-, script-, or code-related field. This is a review signal, not proof of command execution.",
                    "Review the tool implementation, constrain accepted values, and avoid executing user-controlled strings.",
                ),
                (
                    "SCHEMA_PATH_INPUT",
                    re.compile(r"\b(path|filepath|file_path|directory|folder|filename)\b", re.I),
                    "medium",
                    "Filesystem path accepted as input",
                    "The tool input schema appears to accept a filesystem path, which may require traversal and access-control checks.",
                    "Canonicalize paths, enforce an allowlisted root, and reject traversal outside permitted locations.",
                ),
                (
                    "SCHEMA_URL_INPUT",
                    re.compile(r"\b(url|uri|endpoint|host|hostname)\b", re.I),
                    "medium",
                    "User-controlled destination accepted",
                    "The tool input schema appears to accept a URL or destination. Validate destinations to reduce SSRF and data-exfiltration risks.",
                    "Allowlist trusted hosts, block private and metadata ranges where appropriate, and validate redirects.",
                ),
                (
                    "SCHEMA_QUERY_INPUT",
                    re.compile(r"\b(sql|query|statement|database_query)\b", re.I),
                    "medium",
                    "Query-like input accepted",
                    "The tool input schema appears to accept a query or statement. Review whether it is safely parameterized and permission-scoped.",
                    "Use parameterized queries, restrict database permissions, and avoid executing arbitrary statements.",
                ),
            ]
            for rule_id, pattern, severity, title, description_text, remediation in schema_checks:
                matches = [(value, path) for value, path in schema_items if pattern.search(value)]
                if matches:
                    evidence_value, evidence_path = matches[0]
                    add_finding(
                        findings, rule_id, severity, title, description_text,
                        f"Tool '{tool_name}' schema includes '{evidence_value}' at {evidence_path}.",
                        remediation, tool_id, "low", "input_schema",
                    )

    for finding in findings:
        for node in nodes:
            if node["id"] == finding["node_id"] and SEVERITY_ORDER.get(finding["severity"], 0) > SEVERITY_ORDER.get(node["risk"], 0):
                node["risk"] = finding["severity"]

    counts = {level: sum(f["severity"] == level for f in findings) for level in ["critical", "high", "medium", "low"]}
    confidence_counts = {level: sum(f["confidence"] == level for f in findings) for level in ["high", "medium", "low"]}

    return {
        "summary": {
            "servers_scanned": len(servers),
            "nodes_found": len(nodes),
            "edges_found": len(edges),
            "findings_count": len(findings),
            "severity_counts": counts,
            "confidence_counts": confidence_counts,
            "assessment": "review_required" if findings else "no_findings_detected",
            "assessment_note": "Static heuristic analysis only; findings require human verification.",
        },
        "nodes": nodes,
        "edges": edges,
        "findings": findings,
    }
