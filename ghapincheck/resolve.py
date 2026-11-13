"""Resolve `owner/repo@ref` to a full commit SHA through the GitHub REST API (urllib only)."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


class ResolveError(Exception):
    pass


def resolve_sha(owner_repo: str, ref: str, token: str | None = None, timeout: int = 20) -> str:
    """One call: GET /repos/{o}/{r}/commits/{ref} with the sha media type. Annotated tags are dereferenced by GitHub."""
    token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    req = urllib.request.Request(
        f"https://api.github.com/repos/{owner_repo}/commits/{ref}",
        headers={"Accept": "application/vnd.github.sha", "User-Agent": "gha-pin-check", "X-GitHub-Api-Version": "2022-11-28"},
    )
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            sha = r.read().decode().strip()
    except urllib.error.HTTPError as e:
        hint = " (rate limited: set GITHUB_TOKEN)" if e.code in (403, 429) else ""
        raise ResolveError(f"{owner_repo}@{ref}: HTTP {e.code}{hint}") from None
    except (urllib.error.URLError, OSError) as e:
        raise ResolveError(f"{owner_repo}@{ref}: {e}") from None
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        raise ResolveError(f"{owner_repo}@{ref}: unexpected response {sha[:60]!r}")
    return sha


def make_cached(fn=resolve_sha):
    cache: dict = {}

    def go(owner_repo, ref):
        k = (owner_repo, ref)
        if k not in cache:
            cache[k] = fn(owner_repo, ref)
        return cache[k]
    return go
