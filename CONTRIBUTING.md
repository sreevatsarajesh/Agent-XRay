# Contributing

Thanks for helping make Agent X-Ray more useful and accurate.

## Before opening a pull request

1. Keep configuration scanning static. Do not execute configured commands or contact configured endpoints.
2. Add a sanitized fixture and a regression test for each new detection rule.
3. Explain severity and confidence separately.
4. Avoid including secret values in node details, evidence, logs, or exported reports.
5. Run the backend tests and frontend build.

```bash
cd backend && python -m unittest -v test_scanner
cd ../frontend && npm ci && npm run build
```

Please include the rule's rationale, expected false positives, and remediation guidance in the pull request.
