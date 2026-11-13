"""Optional tag/branch -> commit SHA lookup through the GitHub REST API (unauthenticated, or GITHUB_TOKEN if set).
Everything here is best-effort: a network or API failure yields an error string, never an exception, so offline scans still work."""
from __future__ import annotations
import json, os, urllib.error, urllib.parse, urllib.request

API = "https://api.github.com"


def _get(path: str, timeout: float = 15.0) -> dict:
    h = {"Accept": "application/vnd.github+json", "User-Agent": "gha-pin-check"}
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    with urllib.request.urlopen(urllib.request.Request(API + path, headers=h), timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def lookup(owner_repo: str, ref: str, get=_get) -> tuple[str | None, str | None]:
    """Return (sha, error). Tries tags, then branches; dereferences annotated tags to the commit."""
    if not ref:
        return None, "no ref to resolve"
    q = urllib.parse.quote(ref, safe="/")
    last = "not found"
    for kind in ("tags", "heads"):
        try:
            o = get(f"/repos/{owner_repo}/git/ref/{kind}/{q}")["object"]
            if o["type"] == "tag":
                o = get(f"/repos/{owner_repo}/git/tags/{o['sha']}")["object"]
            return o["sha"], None
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}" + (" (rate limited; set GITHUB_TOKEN)" if e.code in (403, 429) else "")
            if e.code in (403, 429):
                break
        except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
            return None, f"{type(e).__name__}: {e}"
    return None, last


def suggest(findings, get=_get) -> None:
    """Fill extra['suggested'] (a pinned uses: line) or extra['resolve_error'] on every GHA001 finding."""
    cache: dict[tuple[str, str], tuple[str | None, str | None]] = {}
    for f in findings:
        if f.rule != "GHA001":
            continue
        action, ref = f.extra.get("action", ""), f.extra.get("ref", "")
        parts = action.split("/")
        if len(parts) < 2:
            f.extra["resolve_error"] = "not an owner/repo action"; continue
        key = ("/".join(parts[:2]), ref)
        if key not in cache:
            cache[key] = lookup(key[0], ref, get)
        sha, err = cache[key]
        if sha:
            f.extra["suggested"] = f"uses: {action}@{sha} # {ref}"
        else:
            f.extra["resolve_error"] = err
