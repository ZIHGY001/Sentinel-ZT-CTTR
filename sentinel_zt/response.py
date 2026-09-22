"""Explicitly approved, time-bounded LOCAL peer blocking with journaled rollback.

The OS account, root-owned configuration and signing key are trust anchors.
This is a single-operator workflow, NOT independent dual control or an IdP.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import stat
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

from .common import canonical, digest, ip_literal, iso, now_utc, private_directory, private_file, timestamp, write_json
from .engine import protected_ip
from .intel import Indicator
from .policy import validate
from .baselines import profile_status


def new_key(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(secrets.token_bytes(32))


def key_bytes(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("key must be a single-link regular file")
        if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError("key must be owned by current user with mode 0600 or stricter")
        key = stream.read(4097)
    if not 32 <= len(key) <= 4096:
        raise ValueError("key must contain 32..4096 bytes")
    return key


def sign(payload, key):
    return hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()


def selected_action(plan, action_id):
    matches = [x for x in plan["actions"] if x.get("id") == action_id]
    if len(matches) != 1:
        raise ValueError("action ID must identify exactly one action")
    return matches[0]


def validate_action(plan, action, config, now, local_asset=None):
    validate(config)
    if plan.get("schema_version") != 1 or plan.get("policy_digest") != digest(config):
        raise ValueError("plan policy changed or schema invalid; re-analyze and re-approve")
    if not timestamp(plan["created_at"]) <= now < timestamp(plan["expires_at"]):
        raise ValueError("plan is expired or not yet valid")
    if (timestamp(plan["expires_at"]) - timestamp(plan["created_at"])).total_seconds() > config.get("plan_ttl_seconds", 600):
        raise ValueError("plan validity exceeds policy")
    if not re.fullmatch(r"action-[a-f0-9]{20}", action.get("id", "")):
        raise ValueError("invalid action identifier")
    if action.get("type") != "block_peer" or action.get("executable") is not True or action.get("gates"):
        raise ValueError("action is not executable")
    host = action.get("host")
    asset = config["assets"].get(host)
    if not asset or asset.get("response_enabled") is not True or asset.get("criticality") == "critical":
        raise ValueError("asset is not enabled for bounded response")
    if local_asset is not None and local_asset != host:
        raise ValueError("wrong endpoint: action must run on its registered local asset")
    peer = str(ip_literal(action["peer_ip"]))
    if peer != action["peer_ip"] or protected_ip(peer, config) or peer in asset.get("ips", []):
        raise ValueError("peer address is protected or invalid")
    if type(action.get("ttl_seconds")) is not int or not 30 <= action["ttl_seconds"] <= config.get("block_ttl_seconds", 300):
        raise ValueError("action TTL exceeds policy")
    if action.get("scope") != "local_host_input_output" or action.get("risk", 0) < config.get("response_threshold", 75):
        raise ValueError("action scope/risk invalid")
    if not action.get("evidence_ids"):
        raise ValueError("action has no evidence")
    age = (now - timestamp(action["last_evidence_at"])).total_seconds()
    if not 0 <= age < config.get("max_evidence_age_seconds", 900):
        raise ValueError("peer evidence is stale or from the future")
    if not action.get("behavior_evidence_ids") or not re.fullmatch(r"B\d{3}", action.get("behavior_rule_id") or ""):
        raise ValueError("fresh independent behavior evidence required; re-analyze the case")
    age = (now - timestamp(action.get("behavior_evidence_at"))).total_seconds()
    if not 0 <= age < config.get("max_evidence_age_seconds", 900):
        raise ValueError("independent behavior evidence is stale or from the future")
    if action["behavior_rule_id"] in {"B101", "B102", "B103", "B104"}:
        profile = config.get("behavior_baselines", {}).get(asset.get("baseline_profile"))
        if profile_status(profile, now) != "active":
            raise ValueError("reviewed behavior baseline is no longer active")
    support = action.get("intel_evidence")
    if not isinstance(support, dict):
        raise ValueError("bound IOC validity required; re-analyze and re-approve")
    indicator = Indicator.parse(support)
    if (indicator.type != "ip" or indicator.value != peer or indicator.revoked
            or indicator.confidence < config.get("min_intel_confidence", 60)
            or support.get("evidence_id") not in action["evidence_ids"]
            or support.get("observed_at") != action["last_evidence_at"]):
        raise ValueError("IOC support does not match the approved peer evidence")
    start, end = timestamp(indicator.valid_from), timestamp(indicator.valid_until)
    if not start <= now < end or not start <= timestamp(support["observed_at"]) < end:
        raise ValueError("bound IOC is expired or not yet valid")


def approve(plan, action_id, config, operator, key, now, lifetime=300):
    if operator not in config.get("operators", []):
        raise ValueError("operator is not authorized by policy")
    action = selected_action(plan, action_id)
    validate_action(plan, action, config, now)
    if type(lifetime) is not int or not 1 <= lifetime <= 300:
        raise ValueError("approval lifetime must be 1..300 seconds")
    baseline_deadline = now + timedelta(seconds=lifetime)
    if action["behavior_rule_id"] in {"B101", "B102", "B103", "B104"}:
        baseline_deadline = timestamp(config["behavior_baselines"][config["assets"][action["host"]]["baseline_profile"]]["valid_until"])
    payload = {"version": 1, "plan_digest": digest(plan), "action_id": action_id,
               "operator": operator, "issued_at": iso(now),
               "expires_at": iso(min(now + timedelta(seconds=lifetime), baseline_deadline, timestamp(plan["expires_at"]),
                                     timestamp(action["intel_evidence"]["valid_until"]),
                                     timestamp(action["last_evidence_at"]) + timedelta(seconds=config.get("max_evidence_age_seconds", 900)),
                                     timestamp(action["behavior_evidence_at"]) + timedelta(seconds=config.get("max_evidence_age_seconds", 900)))),
               "nonce": secrets.token_hex(16)}
    return {"payload": payload, "signature": sign(payload, key)}


def verify_approval(plan, approval, config, key, now):
    payload = approval["payload"]
    if not hmac.compare_digest(sign(payload, key), str(approval.get("signature", ""))):
        raise ValueError("approval signature invalid")
    if payload.get("version") != 1 or payload.get("plan_digest") != digest(plan):
        raise ValueError("approval does not bind this plan")
    if payload.get("operator") not in config.get("operators", []):
        raise ValueError("operator no longer authorized")
    start, end = timestamp(payload["issued_at"]), timestamp(payload["expires_at"])
    if not start <= now < end or (end - start).total_seconds() > 300:
        raise ValueError("approval expired or not yet valid")
    return selected_action(plan, payload["action_id"])


def table_name(action):
    ident = action["id"]
    if not re.fullmatch(r"action-[a-f0-9]{20}", ident):
        raise ValueError("invalid action identifier")
    return "szt_" + ident[7:]


def render_nft(action):
    peer = ip_literal(action["peer_ip"])
    ttl = action["ttl_seconds"]
    if type(ttl) is not int or not 30 <= ttl <= 3600:
        raise ValueError("invalid timeout")
    family, addr_type = ("ip", "ipv4_addr") if peer.version == 4 else ("ip6", "ipv6_addr")
    table = table_name(action)
    # create (not add) ensures we NEVER adopt or overwrite an existing table.
    return (f'create table inet {table} {{ comment "sentinel-zt:{action["id"]}"; }}\n'
            f"add set inet {table} peers {{ type {addr_type}; flags timeout; timeout {ttl}s; }}\n"
            f"add element inet {table} peers {{ {peer} timeout {ttl}s }}\n"
            f"add chain inet {table} inbound {{ type filter hook input priority -10; policy accept; }}\n"
            f"add chain inet {table} outbound {{ type filter hook output priority -10; policy accept; }}\n"
            f"add rule inet {table} inbound {family} saddr @peers counter drop\n"
            f"add rule inet {table} outbound {family} daddr @peers counter drop\n")


class Journal:
    """SQLite provides local writer serialization; audit entries form a keyed chain."""
    def __init__(self, directory, key):
        path = private_directory(directory)
        db = path / "response.sqlite3"
        private_file(db)
        self.lock_fd = self.db = None
        try:
            if os.name == "posix":
                import fcntl
                private_file(path / "response.lock")
                self.lock_fd = os.open(path / "response.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.key = key
            self.db = sqlite3.connect(db, timeout=10)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("CREATE TABLE IF NOT EXISTS actions (id TEXT PRIMARY KEY, status TEXT, receipt TEXT)")
            self.db.execute("CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, payload TEXT, mac TEXT)")
            self.db.commit()
        except BlockingIOError:
            self.close()
            raise ValueError("response journal busy; retry with a fresh approval") from None
        except BaseException:
            self.close()
            raise

    def close(self):
        try:
            if self.db is not None:
                self.db.close()
                self.db = None
        finally:
            if self.lock_fd is not None:
                os.close(self.lock_fd)
                self.lock_fd = None

    def append(self, event):
        last = self.db.execute("SELECT mac FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        previous = last[0] if last else "0" * 64
        payload = canonical(event).decode()
        mac = sign({"previous": previous, "event": event}, self.key)
        self.db.execute("INSERT INTO audit(payload,mac) VALUES (?,?)", (payload, mac))

    def verify(self):
        previous, count = "0" * 64, 0
        for seq, payload, mac in self.db.execute("SELECT seq,payload,mac FROM audit ORDER BY seq"):
            expected = sign({"previous": previous, "event": json.loads(payload)}, self.key)
            if seq != count + 1 or not hmac.compare_digest(expected, mac):
                raise ValueError("audit chain verification failed")
            previous, count = mac, count + 1
        return {"entries": count, "head_mac": previous, "verified": True,
                "limitation": "Export head_mac externally to detect tail truncation or full replacement."}

    def history(self, action_id):
        """Call after verify(); the signed audit, not the mutable cache, is authoritative."""
        return [event for (payload,) in self.db.execute("SELECT payload FROM audit ORDER BY seq")
                if (event := json.loads(payload)).get("action_id") == action_id]


def run_nft(script, check=False):
    binary = next((x for x in ("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft") if Path(x).is_file()), None)
    if not binary:
        raise ValueError("nftables executable not found")
    command = [binary] + (["--check"] if check else []) + ["--file", "-"]
    result = subprocess.run(command, input=script, text=True, capture_output=True,
                            timeout=15, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if result.returncode:
        raise RuntimeError(f"nftables failed ({result.returncode}): {result.stderr[:1000]}")


def require_root():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("live response requires Linux root privileges on the target endpoint")


def apply(plan, approval, config, key, now, state, local_asset, live=False, runner=run_nft, clock=now_utc):
    action = verify_approval(plan, approval, config, key, now)
    validate_action(plan, action, config, now, local_asset)
    script = render_nft(action)
    if not live:
        return {"status": "dry_run", "action_id": action["id"], "nft_script": script,
                "changes_applied": False}
    require_root()
    if config["assets"][local_asset].get("local_hostname") != socket.gethostname():
        raise ValueError("registered local_hostname does not match this machine")
    journal = Journal(state, key)
    try:
        journal.verify()
        now = clock()
        verify_approval(plan, approval, config, key, now)
        validate_action(plan, action, config, now, local_asset)
        journal.db.execute("BEGIN IMMEDIATE")
        if (journal.history(action["id"])
                or journal.db.execute("SELECT 1 FROM actions WHERE id=?", (action["id"],)).fetchone()):
            raise ValueError("action already journaled; inspect/rollback instead of replaying")
        receipt = {"action": action, "plan_digest": digest(plan), "operator": approval["payload"]["operator"],
                   "created_at": iso(now), "table": table_name(action),
                   "expires_at": iso(now + timedelta(seconds=action["ttl_seconds"]))}
        journal.db.execute("INSERT INTO actions VALUES (?,?,?)", (action["id"], "pending", json.dumps(receipt)))
        journal.append({"event": "apply_intent", "action_id": action["id"], "receipt": receipt})
        journal.db.commit()
        try:
            runner(script, check=True)
            current = clock()
            verify_approval(plan, approval, config, key, current)
            validate_action(plan, action, config, current, local_asset)
        except Exception as exc:
            journal.db.execute("UPDATE actions SET status=? WHERE id=?", ("not_applied", action["id"]))
            journal.append({"event": "apply_preflight_failed", "action_id": action["id"], "error_type": type(exc).__name__})
            journal.db.commit()
            raise RuntimeError("preflight failed or authorization expired; no firewall change was requested") from exc
        try:
            runner(script, check=False)
        except Exception as exc:
            # A timeout can occur AFTER the kernel transaction commits. Never claim no change.
            journal.db.execute("UPDATE actions SET status=? WHERE id=?", ("uncertain", action["id"]))
            journal.append({"event": "apply_uncertain", "action_id": action["id"], "error_type": type(exc).__name__})
            journal.db.commit()
            raise RuntimeError("apply outcome uncertain; inspect nft table and use rollback; kernel timeout remains bounded") from exc
        journal.db.execute("UPDATE actions SET status=? WHERE id=?", ("applied", action["id"]))
        journal.append({"event": "apply_success", "action_id": action["id"]})
        journal.db.commit()
        return {"status": "applied", "changes_applied": True, **receipt}
    finally:
        journal.close()


def owned_table(action):
    """Require the action-specific ownership comment before deleting anything."""
    binary = next((x for x in ("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft") if Path(x).is_file()), None)
    if not binary:
        raise ValueError("nftables executable not found")
    result = subprocess.run([binary, "--json", "list", "table", "inet", table_name(action)],
                            text=True, capture_output=True, timeout=10, check=False,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if result.returncode:
        raise ValueError("table missing or inaccessible; inspect manually before changing journal")
    tables = [x["table"] for x in json.loads(result.stdout).get("nftables", []) if "table" in x]
    return any(t.get("name") == table_name(action) and t.get("family") == "inet" and
               t.get("comment") == "sentinel-zt:" + action["id"] for t in tables)


def rollback(action_id, key, state, now, local_asset, live=False, runner=run_nft, ownership=owned_table):
    journal = Journal(state, key)
    try:
        journal.verify()
        journal.db.execute("BEGIN IMMEDIATE")
        row = journal.db.execute("SELECT status,receipt FROM actions WHERE id=?", (action_id,)).fetchone()
        if not row:
            raise ValueError("no local action receipt")
        receipt = json.loads(row[1])
        # Check receipt against authenticated audit intent, not only the mutable actions table.
        history = journal.history(action_id)
        intents = [x for x in history if x.get("event") == "apply_intent"]
        if len(intents) != 1 or intents[0].get("receipt") != receipt:
            raise ValueError("receipt does not match signed audit intent")
        states = {"apply_intent": "pending", "apply_success": "applied", "apply_uncertain": "uncertain",
                  "apply_preflight_failed": "not_applied", "rollback_intent": "rollback_pending",
                  "rollback_success": "rolled_back", "rollback_uncertain": "rollback_uncertain"}
        signed_state = next((states[x["event"]] for x in reversed(history) if x.get("event") in states), None)
        if row[0] != signed_state:
            raise ValueError("action state does not match signed audit history")
        action = receipt["action"]
        if action["host"] != local_asset:
            raise ValueError("rollback asset mismatch")
        script = f"delete table inet {table_name(action)}\n"
        if row[0] == "rolled_back":
            return {"status": "already_rolled_back", "changes_applied": False}
        if row[0] == "not_applied":
            return {"status": "not_applied", "changes_applied": False}
        if not live:
            return {"status": "dry_run", "nft_script": script, "changes_applied": False}
        require_root()
        if not ownership(action):
            raise ValueError("table ownership comment mismatch")
        journal.db.execute("UPDATE actions SET status=? WHERE id=?", ("rollback_pending", action_id))
        journal.append({"event": "rollback_intent", "action_id": action_id, "at": iso(now)})
        journal.db.commit()
        try:
            runner(script, check=False)
        except Exception as exc:
            journal.db.execute("UPDATE actions SET status=? WHERE id=?", ("rollback_uncertain", action_id))
            journal.append({"event": "rollback_uncertain", "action_id": action_id, "error_type": type(exc).__name__})
            journal.db.commit()
            raise RuntimeError("rollback outcome uncertain; inspect the action-owned nft table before retrying") from exc
        journal.db.execute("UPDATE actions SET status=? WHERE id=?", ("rolled_back", action_id))
        journal.append({"event": "rollback_success", "action_id": action_id, "at": iso(now)})
        journal.db.commit()
        return {"status": "rolled_back", "changes_applied": True, "action_id": action_id}
    finally:
        journal.close()
