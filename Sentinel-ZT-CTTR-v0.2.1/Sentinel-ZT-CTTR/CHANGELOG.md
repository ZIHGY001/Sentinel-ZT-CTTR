# Changelog

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
