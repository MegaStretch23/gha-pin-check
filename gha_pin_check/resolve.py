"""Optional tag/branch -> commit SHA lookup through the GitHub REST API (the only network use; off unless --resolve)."""
from __future__ import annotations

import urllib.error
import urllib.request


def fetch_sha(repo: str, ref: str, token: str = "", timeout: int = 20) -> str:
    """Commit SHA that `ref` currently points to (annotated tags are dereferenced by the API). Raises RuntimeError with the cause."""
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/commits/{ref}",
                                 headers={"Accept": "application/vnd.github.sha", "User-Agent": "gha-pin-check",
                                          "X-GitHub-Api-Version": "2022-11-28", **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            sha = r.read().decode().strip()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} for {repo}@{ref}" + (" (rate limited; set GITHUB_TOKEN)" if e.code in (403, 429) else ""))
    except OSError as e:
        raise RuntimeError(f"network error for {repo}@{ref}: {e}")
    if len(sha) not in (40, 64):
        raise RuntimeError(f"unexpected answer for {repo}@{ref}")
    return sha
