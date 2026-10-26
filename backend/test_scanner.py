import unittest

from scanner import scan_config


class ScannerTests(unittest.TestCase):
    def test_reads_plural_file_descriptions(self):
        result = scan_config({
            "mcpServers": {
                "docs": {
                    "command": "python",
                    "tools": [{"name": "read_document", "description": "Read files and documents"}],
                }
            }
        })
        rules = {finding["rule_id"] for finding in result["findings"]}
        self.assertIn("TOOL_CAPABILITY_FILE_READ", rules)

    def test_detects_capabilities_and_nested_schema_signals(self):
        result = scan_config({
            "mcpServers": {
                "research": {
                    "command": "python",
                    "tools": [{
                        "name": "execute_task",
                        "description": "Run command and fetch URL",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "options": {
                                    "type": "object",
                                    "properties": {
                                        "command": {"type": "string"},
                                        "file_path": {"type": "string"},
                                        "url": {"type": "string"},
                                    },
                                }
                            },
                        },
                    }],
                }
            }
        })
        rules = {finding["rule_id"] for finding in result["findings"]}
        self.assertIn("TOOL_CAPABILITY_SHELL", rules)
        self.assertIn("TOOL_CAPABILITY_NETWORK", rules)
        self.assertIn("SCHEMA_COMMAND_INPUT", rules)
        self.assertIn("SCHEMA_PATH_INPUT", rules)
        self.assertIn("SCHEMA_URL_INPUT", rules)
        self.assertTrue(all("confidence" in finding for finding in result["findings"]))

    def test_redacts_secret_values(self):
        secret = "sk-TEST000000000000000000"
        result = scan_config({
            "mcpServers": {
                "service": {
                    "command": "python",
                    "env": {"API_KEY": secret},
                }
            }
        })
        serialized = str(result)
        self.assertNotIn(secret, serialized)
        self.assertIn("POSSIBLE_HARDCODED_SECRET", {f["rule_id"] for f in result["findings"]})

    def test_detects_http_and_unpinned_package(self):
        result = scan_config({
            "mcpServers": {
                "remote": {"url": "http://example.com/mcp"},
                "package": {"command": "npx", "args": ["-y", "demo@latest"]},
            }
        })
        rules = {finding["rule_id"] for finding in result["findings"]}
        self.assertIn("INSECURE_REMOTE_TRANSPORT", rules)
        self.assertIn("UNPINNED_PACKAGE_VERSION", rules)

    def test_rejects_invalid_roots(self):
        with self.assertRaises(ValueError):
            scan_config([])
        with self.assertRaises(ValueError):
            scan_config({"notServers": {}})

    def test_redacts_url_credentials_and_query_strings(self):
        result = scan_config({
            "mcpServers": {
                "remote": {"url": "https://user:secret@example.com/mcp?token=private#frag"}
            }
        })
        server = next(node for node in result["nodes"] if node["type"] == "server")
        self.assertEqual(server["details"]["url"], "https://example.com/mcp")
        self.assertNotIn("secret", str(result))
        self.assertNotIn("private", str(result))

    def test_summary_is_consistent(self):
        result = scan_config({"mcpServers": {"safe": {"command": "python"}}})
        self.assertEqual(result["summary"]["nodes_found"], len(result["nodes"]))
        self.assertEqual(result["summary"]["edges_found"], len(result["edges"]))
        self.assertEqual(result["summary"]["findings_count"], len(result["findings"]))


if __name__ == "__main__":
    unittest.main()
