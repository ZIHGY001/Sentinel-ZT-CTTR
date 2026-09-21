"""Read-only article-title index for izj007/wechat. No third-party code execution."""
import hashlib
import re
import urllib.error
import urllib.request
from urllib.parse import quote, unquote, urljoin, urlsplit

from .assets import NoRedirect
from .common import iso, read_bytes

REPOSITORY = "https://github.com/izj007/wechat"


def valid_revision(value):
    return isinstance(value, str) and value not in {".", ".."} and re.fullmatch(r"[A-Za-z0-9._-]{1,100}", value)


def article_url(target, revision):
    """Decode once, validate path components, then emit a canonical repository URL."""
    try:
        target = unquote(target, errors="strict")
        if any(ord(c) < 32 or c == "\\" for c in target) or "%" in target:
            return None
        parsed = urlsplit(target)
        if parsed.query or parsed.fragment:
            return None
        if parsed.scheme or parsed.netloc:
            if parsed.scheme != "https" or parsed.netloc != "github.com":
                return None
            parts = parsed.path.split("/")
            if len(parts) < 7 or parts[:4] != ["", "izj007", "wechat", "blob"] or not valid_revision(parts[4]):
                return None
            revision, parts = parts[4], parts[5:]
        else:
            parts = parsed.path.removeprefix("./").split("/")
        if len(parts) < 2 or parts[0] != "articles" or any(p in {"", ".", ".."} for p in parts):
            return None
        return REPOSITORY + "/blob/" + revision + "/" + "/".join(quote(p, safe="") for p in parts)
    except ValueError:
        return None


def index_readme(raw, revision, now):
    if not valid_revision(revision):
        raise ValueError("revision must be a simple branch, tag or commit SHA")
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("knowledge index input exceeds 8 MiB")
    text = raw.decode("utf-8-sig")
    entries, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not re.match(r"^[-*]\s+\[", line) or not line.endswith(")"):
            continue
        # Linear delimiter parsing avoids greedy-regex backtracking on imported text.
        opening, middle = line.find("["), line.rfind("](")
        if middle <= opening + 1:
            continue
        title, target = line[opening + 1:middle], line[middle + 2:-1]
        if not target or len(target) > 2048:
            continue
        url = article_url(target, revision)
        if url is None:
            continue
        if url in seen:
            continue
        seen.add(url)
        if len(entries) >= 10000:
            raise ValueError("knowledge index exceeds 10000 entries")
        entries.append({"title": title[:500], "url": url, "source": "izj007/wechat",
                        "trust": "unreviewed_reference", "executable": False})
    return {"schema_version": 1, "repository": REPOSITORY, "revision": revision,
            "retrieved_at": iso(now), "readme_sha256": hashlib.sha256(raw).hexdigest(), "entries": entries,
            "notice": "Title/link index only. Article text and code are not redistributed or executed."}


def sync(revision, now):
    if not valid_revision(revision):
        raise ValueError("invalid revision")
    url = f"https://raw.githubusercontent.com/izj007/wechat/{revision}/README.md"
    request = urllib.request.Request(url, headers={"User-Agent": "Sentinel-ZT-CTTR/0.3.0"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as res:
            raw = res.read(8 * 1024 * 1024 + 1)
    except urllib.error.URLError:
        raise ValueError("knowledge source unavailable; use knowledge-index with a local README") from None
    return index_readme(raw, revision, now)


def tokens(text):
    result = set(re.findall(r"[a-z0-9][a-z0-9._-]+", text.lower()))
    for word in re.findall(r"[\u4e00-\u9fff]+", text):
        result.update(word[i:i+2] for i in range(len(word)-1))
        result.add(word)
    return result


def search(index, query, limit=10):
    if not isinstance(query, str) or not query.strip() or not 1 <= limit <= 50:
        raise ValueError("query required; limit must be 1..50")
    terms = tokens(query)
    ranked = []
    for row in index.get("entries", []):
        score = len(terms & tokens(row["title"]))
        if query.lower() in row["title"].lower():
            score += 10
        if score:
            ranked.append({**row, "relevance": score})
    return sorted(ranked, key=lambda x: (-x["relevance"], x["title"]))[:limit]


def enrich(analysis, index):
    queries = {"B001": "钓鱼", "B002": "Webshell 应急响应", "B003": "Agent 安全", "B004": "Agent 安全",
               "B005": "凭据 排查", "B006": "Nacos KubePi", "B008": "Jeecg SQL", "B011": "持久化 排查",
               "B014": "Webshell 查杀", "B016": "横向 日志", "B018": "CobaltStrike 流量"}
    cache = {}
    for case in analysis["incidents"]:
        query = " ".join(queries[x] for x in case["rule_ids"] if x in queries)
        if query not in cache:
            cache[query] = search(index, query, 5) if query else []
        case["knowledge_references"] = cache[query]
