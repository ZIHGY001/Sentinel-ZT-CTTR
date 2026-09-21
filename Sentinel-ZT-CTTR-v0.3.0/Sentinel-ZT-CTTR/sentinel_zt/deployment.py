"""Explicit public origin for a console published behind a Yunmai connector."""
import os
import re
from urllib.parse import urlsplit


def https_origin(value):
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        raise ValueError("SENTINEL_PUBLIC_ORIGIN must be an exact HTTPS origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        raise ValueError("invalid public origin") from None
    if (parsed.scheme != "https" or not host or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]*", host)
            or ".." in host or host.endswith(".") or (port is not None and not 1 <= port <= 65535)):
        raise ValueError("public origin requires HTTPS, an exact DNS/IPv4 host, and no path or credentials")
    origin = "https://" + host.lower() + (f":{port}" if port and port != 443 else "")
    return origin, host.lower()


def settings(env=None, testing=False):
    env = os.environ if env is None else env
    mode = env.get("SENTINEL_DEPLOYMENT_MODE", "local")
    if mode not in {"local", "yunmai"}:
        raise ValueError("SENTINEL_DEPLOYMENT_MODE must be local or yunmai")
    if mode == "yunmai":
        origin, host = https_origin(env.get("SENTINEL_PUBLIC_ORIGIN", ""))
        return {"mode": mode, "public_origin": origin, "hosts": [host], "origins": {origin}}
    origins = {"http://127.0.0.1:8000", "http://localhost:8000"}
    origins.update(x.strip() for x in env.get("SENTINEL_ALLOWED_ORIGINS", "").split(",") if x.strip())
    return {"mode": mode, "public_origin": None,
            "hosts": ["127.0.0.1", "localhost", "[::1]"] + (["testserver"] if testing else []),
            "origins": origins}
