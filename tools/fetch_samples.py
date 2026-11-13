#!/usr/bin/env python3
"""Download .github/workflows/*.y*ml of public repos at their current default-branch commit into samples/<owner>__<repo>/ and record the commit in samples/MANIFEST.json.
usage: python3 tools/fetch_samples.py psf/requests sindresorhus/ky   (GITHUB_TOKEN used if set; standard library only)"""
import datetime, json, os, sys, urllib.request
from pathlib import Path

def get(url, raw=False):
    h = {"User-Agent": "gha-pin-check", "Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN") and "api.github.com" in url:
        h["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=30) as r:
        b = r.read()
    return b if raw else json.loads(b)

def main(repos):
    out = Path(__file__).resolve().parent.parent / "samples"
    mf = out / "MANIFEST.json"
    manifest = json.loads(mf.read_text()) if mf.exists() else {}
    for repo in repos:
        sha = get(f"https://api.github.com/repos/{repo}/commits/HEAD")["sha"]
        listing = get(f"https://api.github.com/repos/{repo}/contents/.github/workflows?ref={sha}")
        d = out / repo.replace("/", "__") / ".github" / "workflows"; d.mkdir(parents=True, exist_ok=True)
        names = []
        for e in listing:
            if e["name"].endswith((".yml", ".yaml")):
                (d / e["name"]).write_bytes(get(f"https://raw.githubusercontent.com/{repo}/{sha}/.github/workflows/{e['name']}", raw=True)); names.append(e["name"])
        manifest[repo] = {"commit": sha, "fetched": datetime.date.today().isoformat(), "files": sorted(names)}
        print(repo, sha, len(names), "workflow files")
    mf.write_text(json.dumps(manifest, indent=2) + "\n")

if __name__ == "__main__":
    main(sys.argv[1:]) if len(sys.argv) > 1 else sys.exit(__doc__)
