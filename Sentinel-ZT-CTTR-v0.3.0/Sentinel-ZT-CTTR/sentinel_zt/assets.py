"""360 Quake passive discovery with explicit scope, budgets and offline import."""
from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .common import canonical, digest, integer, ip_literal, iso, strict_json, timestamp
from .intel import normalize

QUAKE_ENDPOINT = "https://quake.360.net/api/v3/search/quake_service"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect refused; API credentials cannot be forwarded")


def scope_config(scope):
    if not isinstance(scope, dict) or any(not isinstance(scope.get(k, []), list)
                                          for k in ("networks", "domains")):
        raise ValueError("scope networks and domains must be arrays")
    if any(not isinstance(x, str) for x in scope.get("networks", [])):
        raise ValueError("scope networks must contain CIDR strings")
    networks = [ipaddress.ip_network(x, strict=False) for x in scope.get("networks", [])]
    domains = [normalize("domain", x) for x in scope.get("domains", [])]
    if not networks and not domains:
        raise ValueError("scope requires at least one owned network or domain")
    if len(networks) + len(domains) > 100:
        raise ValueError("scope has more than 100 entries")
    return networks, domains


def scoped_query(query, scope):
    networks, domains = scope_config(scope)
    if not isinstance(query, str) or not query.strip() or len(query) > 2048:
        raise ValueError("query must contain 1..2048 characters")
    # Preserve documented DSL, but require a balanced expression before wrapping it.
    depth, quoted, escaped = 0, False, False
    for char in query:
        if ord(char) < 32:
            raise ValueError("query control character refused")
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted and char == "(":
            depth += 1
        elif not quoted and char == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("query parentheses are unbalanced")
    if depth or quoted or escaped:
        raise ValueError("query is incomplete")
    clauses = [f'ip:"{n}"' for n in networks]
    for domain in domains:
        clauses.extend([f'domain:"{domain}"', f'domain:"*.{domain}"'])
    return f"({query}) AND ({' OR '.join(clauses)})"


def quake_page(payload, token, timeout=20):
    if not token or "\n" in token or "\r" in token:
        raise ValueError("QUAKE_API_KEY is missing or invalid")
    req = urllib.request.Request(QUAKE_ENDPOINT, data=canonical(payload), method="POST",
                                 headers={"Content-Type": "application/json", "X-QuakeToken": token,
                                          "User-Agent": "Sentinel-ZT-CTTR/0.3.0"})
    opener = urllib.request.build_opener(NoRedirect())
    for attempt in range(3):
        try:
            with opener.open(req, timeout=timeout) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise ValueError("Quake response size limit exceeded")
            return strict_json(raw)
        except urllib.error.HTTPError as exc:
            if exc.code in {429, 502, 503, 504} and attempt < 2:
                time.sleep(2 ** attempt)
                continue
            # Never include echoed headers, request or API response in errors.
            raise ValueError(f"Quake HTTP {exc.code}; check account permission/quota") from None
        except urllib.error.URLError:
            raise ValueError("Quake connection failed; verify DNS, TLS and network access") from None
    raise ValueError("Quake retry budget exhausted")


def service_domains(record):
    values = record.get("domain", [])
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        values = []
    http_host = record.get("service", {}).get("http", {}).get("host", "")
    if http_host:
        values = values + [urlsplit("//" + http_host).hostname or ""]
    domains = []
    for value in values:
        try:
            value = normalize("domain", value)
            # Domain IOC normalizer accepts numeric labels; omit IP addresses here.
            try:
                ipaddress.ip_address(value)
                continue
            except ValueError:
                pass
            domains.append(value)
        except (ValueError, TypeError):
            pass
    return sorted(set(domains))


def normalize_assets(records, scope, now, config=None):
    networks, domains = scope_config(scope)
    assets, rejected, warnings = {}, 0, []
    hosts_by_ip = {ip: host for host, asset in (config or {}).get("assets", {}).items()
                   for ip in asset.get("ips", [])}
    for number, row in enumerate(records):
        try:
            ip = ip_literal(row["ip"])
            port = integer(row["port"], 1, 65535)
            found_domains = service_domains(row)
            in_network = any(ip in n for n in networks)
            domain_matches = [d for d in found_domains if any(d == root or d.endswith("." + root) for root in domains)]
            if not in_network and not domain_matches:
                rejected += 1
                continue
            service = row.get("service", {})
            transport = row.get("transport", "tcp").lower()
            if transport not in {"tcp", "udp"}:
                raise ValueError("transport must be tcp or udp")
            key = (str(ip), port, transport)
            observed = row.get("time")
            if observed:
                observed = iso(timestamp(observed))
            components = row.get("components") or []
            if not isinstance(components, list):
                components = []
            products = sorted(set(str(x.get("product_name_en") or x.get("product_name_cn") or x.get("product_name") or "")
                                  for x in components if isinstance(x, dict)) - {""})
            known = hosts_by_ip.get(str(ip))
            item = {"id": "asset-" + digest(key)[:20], "ip": str(ip), "port": port, "transport": transport,
                    "domains": found_domains, "service": str(service.get("name", "")), "products": products,
                    "title": str(service.get("http", {}).get("title", ""))[:500], "observed_at": observed,
                    "source": "360-quake", "source_record_id": str(row.get("id", "")),
                    "registered_host": known, "scope_match": "network" if in_network else "domain",
                    "ownership_status": "registered_ip_match" if known else "requires_verification",
                    "response_enabled": False}
            old = assets.get(key)
            if old is None or (item["observed_at"] or "") > (old["observed_at"] or ""):
                assets[key] = item
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            warnings.append(f"record {number + 1} skipped: {type(exc).__name__}")
    return {"schema_version": 1, "collected_at": iso(now), "scope_digest": digest(scope),
            "assets": sorted(assets.values(), key=lambda x: (x["ip"], x["port"], x["transport"])),
            "out_of_scope": rejected, "warnings": warnings,
            "limitations": ["Passive observations are not proof of current exposure or ownership.",
                            "Shared hosting/CDN IPs require manual ownership verification.",
                            "Discovery never modifies the trusted response asset registry."]}


def search(query, scope, now, config=None, limit=100, page_size=50, fetcher=quake_page, token=None):
    integer(limit, 1, 1000)
    integer(page_size, 1, 100)
    query = scoped_query(query, scope)
    records, pages = [], 0
    token = token or os.environ.get("QUAKE_API_KEY")
    for start in range(0, limit, page_size):
        size = min(page_size, limit-start)
        payload = {"query": query, "start": start, "size": size, "latest": True, "ignore_cache": False}
        page = fetcher(payload, token)
        if not isinstance(page, dict) or page.get("code") not in (0, "0"):
            raise ValueError("Quake API rejected the request; check syntax, permissions and quota")
        batch = page.get("data")
        if not isinstance(batch, list):
            raise ValueError("Quake response data must be an array")
        pages += 1
        records.extend(batch[:size])
        if len(batch) < size:
            break
    result = normalize_assets(records, scope, now, config)
    result["query"] = query
    result["pages_requested"] = pages
    result["records_received"] = len(records)
    result["limit_reached"] = len(records) >= limit
    return result


def asset_diff(before, after):
    left = {x["id"]: x for x in before["assets"]}
    right = {x["id"]: x for x in after["assets"]}
    fields = ("domains", "service", "products", "title")
    return {"added": [right[k] for k in sorted(right.keys()-left.keys())],
            "not_seen": [left[k] for k in sorted(left.keys()-right.keys())],
            "changed": [{"id": k, "before": left[k], "after": right[k]} for k in sorted(left.keys() & right.keys())
                        if any(left[k].get(f) != right[k].get(f) for f in fields)],
            "note": "not_seen does not mean remediated; compare equivalent scopes, limits and coverage"}


def enrich(analysis, snapshot, config, now):
    context = []
    hosts_by_ip = {ip: host for host, asset in config["assets"].items() for ip in asset.get("ips", [])}
    by_host = {}
    for item in snapshot.get("assets", []):
        host = hosts_by_ip.get(item.get("ip"))
        if not host:
            continue
        observed = item.get("observed_at")
        try:
            age = (now - timestamp(observed)).total_seconds()
            current = 0 <= age <= 7 * 86400
        except (ValueError, TypeError):
            current = False
        context.append({**item, "registered_host": host, "recent_observation": current})
        by_host.setdefault(host, []).append(item["id"])
    analysis["asset_context"] = context
    # Discovery affects analyst context only. It cannot itself raise execution eligibility.
    for incident in analysis["incidents"]:
        incident["exposure_context"] = by_host.get(incident["host"], [])
