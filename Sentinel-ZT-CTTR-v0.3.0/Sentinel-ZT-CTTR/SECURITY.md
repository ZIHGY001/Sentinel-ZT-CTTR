# Security model

Sentinel-ZT-CTTR v0.3.0 is an experimental single-operator, local incident-response workbench.

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


## Operational constraints

The service refuses POSIX state directories that are not owned by the running user with mode 0700, and sensitive files that are not single-link regular files with mode 0600 or stricter. Symlink state directories, token files and databases are refused. Back up an existing workspace, inspect its ownership and permissions, and correct them before upgrading; do not run the web service as root to bypass a permission error. On Windows, directory/file ACLs still need separate operator review.

An imported investigation without a policy has an empty response asset registry. Existing saved cases retain their original analysis and plan; re-import and re-analyze their source logs with v0.3.0 before using them for a new decision. Approval and plan validity are checked again immediately before live execution, following the read-only nftables preflight. Busy response journals fail immediately.

Resource budgets are documented in `docs/DATA_CONTRACT.md`. They bound individual workbench requests, not a production denial-of-service defense. The deployment remains a single-process, single-operator workbench behind a reviewed gateway. Dependency audit results describe the database and versions checked on the review date; they do not prove the absence of vulnerabilities.

## v0.2.2 evidence and state checks

A current IOC does not refresh old behavior evidence. Executable plans bind a complete, recent behavior finding and its original observation times; approval and execution recheck both behavior and peer evidence. Plans created before v0.2.2 must be regenerated and approved again. The access CLI also requires current telemetry for the requested resource, even if the analysis was just regenerated. These checks do not attest log authenticity or prove causality.

Replay and rollback checks consult the verified keyed audit chain. Deleting a mutable action-cache row cannot authorize replay while its signed history remains. Rollback records intent before a change and records an uncertain outcome on execution failure. This does not protect against audit-tail truncation or complete replacement without an external head anchor, or compromise of the signing key. Preserve the entire response workspace when investigating inconsistencies.

Manual Yunmai handoff deadlines cannot exceed the selected behavior or mapping lifetime. Handoff storage is limited to 500 JSON files and 64 MiB per workspace. STIX import preserves included TLP labels and flags unresolved/custom/granular markings for restrictive manual review; this is not full information-sharing policy enforcement.

## v0.3.0 reviewed behavior baselines

Baselines are operator-reviewed policy, not learned truth or endpoint identity attestations. Draft, expired, future or absent profiles produce coverage gaps. Expected paths and exact, maximum-24-hour exceptions affect only the new baseline analytics; they do not suppress other detectors or IOC matches, and do not override explicit authorization-denied telemetry. Asset role is taken from the policy registry, never from imported log claims or passive discovery. Templates disable both baseline activation and live response.

The new models do not require an IOC to alert or to propose a manual Yunmai handoff. The existing local firewall adapter still requires a current IP IOC, complete recent behavior, local asset authorization and a signed approval. Approvals now bind the supporting IOC and cannot outlive that IOC, the selected evidence or its baseline review window. Pre-v0.3.0 executable plans must be regenerated and reapproved. No online revocation refresh is implied by a signed feed snapshot.

Response journal databases, lock files and keys must be single-link regular files with private ownership and permissions. Initialization failures release held locks and connections. The signed audit still needs an external head anchor to detect truncation or complete replacement. Knowledge article links are canonicalized to the configured repository's article subtree; older local indexes should be regenerated.
