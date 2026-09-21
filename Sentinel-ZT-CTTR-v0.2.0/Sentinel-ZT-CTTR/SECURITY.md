# Security model

Sentinel-ZT-CTTR v0.2.0 is an experimental single-operator, local incident-response workbench.

- Run FastAPI as an unprivileged OS user on `127.0.0.1`. Local bearer-token authentication is not enterprise SSO, RBAC, tenant isolation or a production perimeter. Remote deployment requires a reviewed TLS/authentication gateway and host/origin configuration.
- The Pi process is advisory-only. It receives an allowlisted redacted case summary and three in-memory read-only tools. It has no command-execution, arbitrary file-reading, response-approval or firewall tool. It still runs as an OS process, not a kernel sandbox; use an isolated account/container for defense in depth.
- Raw logs and article content are untrusted data. React renders text, HTML exports escape fields, and the report CSP disables scripts. Do not paste credentials into Agent questions.
- Response approvals are short-lived HMAC tokens. Possession of the response key is authority to sign: operator-name allowlisting does not provide independent human identity proof or dual control. Keep the key and policy separate from the web service.
- nftables response is local peer blocking, not endpoint isolation. It may disrupt legitimate traffic to shared IPs. The supplied code requires current evidence, registered endpoint identity, protected networks and a reviewed action.
- Local JSON/SQLite evidence is not tamper-proof storage or legal chain of custody. A host administrator can alter it. The response audit's keyed chain needs externally stored head hashes to detect truncation/replacement.
- Quake findings and article links do not establish current vulnerability, maliciousness or ownership. Never auto-enroll discovered assets into an execution allowlist.
- Reports, logs, runtime databases, source documents and API keys belong in excluded private directories. Do not upload them with a public bug report.

For a suspected vulnerability, prepare a minimal synthetic reproducer and report it privately to the repository maintainer using the private reporting channel they enable. This starter repository does not claim a monitored security inbox or response SLA.

Known integration boundaries and validation gaps are recorded in `docs/VALIDATION.md`.

## Yunmai integration boundary

The Yunmai profile does not verify a real tenant connection or exchange SDK tokens. It preserves the workbench bearer token and exact Host/Origin validation. Untrusted SASE/user/device/forwarding headers never authenticate a caller. The supplied Nginx configuration requires actual private addresses, trusted certificates and verified connector-source ACLs.

Manual handoff JSON is neither a vendor import schema nor an execution approval/receipt. It can contain private user-to-asset mappings. SDK logout is not used for containment. No live cloud management endpoint is implemented. Shared workbench credentials do not provide individual SSO, RBAC or multi-analyst attribution.
