# Changelog

## 0.4.0 — Evidence-bound investigation runbooks

- Add 7 original investigation workflows with 21 checks, informed by the NOP Team Linux cookbook and Bypass007 incident-response notes. Preserve chapter references without redistributing upstream text, scripts or samples.
- Match investigation guidance to existing detections, including no-IOC behavior baselines. Require analyst-declared Linux/Windows scope before adding platform-specific checks.
- Add a React runbook workspace, authenticated API, offline CLI catalog/checklist generation, SQLite review history and report exports.
- Require incident-bound events or external evidence descriptors for positive and negative conclusions. Preserve evidence gaps, reject stale revisions and retain prior observations.
- Export disabled baseline review tasks; never learn approvals, suppress detections or execute commands from notes. Existing response and Yunmai approval gates are unchanged.
- Add 20 Python/API regressions; 228 total pass. No new runtime dependencies. See `docs/INVESTIGATION_RUNBOOKS.md`.

## 0.3.0 — Behavior-first baselines and design-time response

- Add reviewed asset-role baselines for unexpected remote-service access, short-window remote fan-out, unexpected identity workflow deviations and unexpected privilege transitions, mapped to ATT&CK T1021, T1098 and T1548.
- Correlate privilege changes with subsequent lateral access on the same asset and exact activity account; retain evidence and uncertainty.
- Add draft templates, CLI/API validation, bounded review windows, precise expiring exceptions and explicit telemetry coverage gaps. Discovery and log claims do not automatically create trusted baselines.
- Add a React behavior-baseline workspace, no-IOC synthetic exercise and baseline evidence in HTML reports. Behavior-only cases can generate manual Yunmai handoffs.
- Recheck IOC and baseline validity at response approval/execution; cap approval and handoff deadlines. Regenerate and reapprove pre-v0.3.0 plans.
- Fix response journal initialization lock leaks, unsafe linked state/key files, knowledge-link path traversal and order-dependent STIX creator conflict handling.
- Add 47 Python/API regressions; 208 total pass. Existing Pi and frontend suites pass. See `docs/SECURITY_REVIEW_v0.3.0.md` and `docs/BEHAVIOR_BASELINES.md`.

## 0.2.2 — Evidence freshness and response-state hardening

- Bind executable response plans to complete, recent behavior evidence; recheck its age at approval and execution. Regenerate and reapprove older plans.
- Require current resource telemetry for access decisions; regenerating an analysis no longer refreshes old observations.
- Stop correlation-chain IOC events from satisfying behavior freshness in Yunmai handoffs; cap review deadlines by evidence and mapping expiry.
- Use verified audit history to prevent replay after action-cache deletion and to validate rollback state; persist rollback intent and uncertain outcomes.
- Reject conflicting STIX versions, retain batch revocations, preserve included TLP markings, and flag unresolved handling terms.
- Fix timestamp overflow, Unicode JSONL separators, UTF-8 line budgets, malformed CSV/STIX inputs, and ambiguous URL indicators.
- Validate suppression field types and exact Yunmai references; bound handoff storage growth.
- Add 36 Python/API regression tests. See `docs/SECURITY_REVIEW_v0.2.2.md` for conditions, validation and remaining limits.

## 0.2.1 — Secure-coding fixes

- Enforce exact permission arrays, bounded integer risk/policy values, and safe defaults for imported investigations.
- Recompute derived detection fields; reject conflicting queries and ambiguous JSON; preserve original imported-line hashes and chronological timestamp ordering.
- Bound analysis, IOC expansion, concurrent writes, Pi input, report size and workspace growth; replace quadratic correlation scans and Markdown parsing.
- Refuse unsafe private-directory/file permissions and links; close SQLite connections deterministically.
- Recheck response authorization after journal acquisition and nftables preflight; fail promptly on a busy journal; reject scoped/mapped firewall peers.
- Recover from malformed IOC uploads in the React console; pin the reviewed Python web dependency set.
- Add 37 Python/API regression tests and 3 frontend tests. See `docs/SECURITY_REVIEW_v0.2.1.md` for scope, conditions and limitations.

## 0.2.0

- Yunmai SASE deployment profile with exact HTTPS origin/host checks and independent application authentication.
- Loopback FastAPI, private HTTPS Nginx and unprivileged systemd deployment templates.
- Manual console handoff for individually mapped users and applications, evidence/mapping freshness gates, protected applications, expiry and recovery instructions.
- Dedicated Yunmai page and CLI export; no tenant management API or client SDK execution.
- Twenty-one added deployment, handoff and API tests; original tests remain passing.
- Reviewed supplied SDK/connection guides; vendor binaries and tenant-specific examples are excluded from public packages.

## 0.1.0

- React console backed by a single FastAPI service and local SQLite case history.
- Four log formats, normalized IOC inputs, 18 behavior detectors and four temporal correlations.
- Expiring threat intelligence, asset-scoped response planning, signed approvals, bounded local nftables adapter, audit and rollback.
- 360 Quake scoped query/offline import/snapshot comparison.
- wechat article title/link index and investigation references.
- Pi Agent Core with redacted summaries, three read-only tools and bounded execution budgets.
- Offline synthetic demo, HTML report and documented CLI workflows.
