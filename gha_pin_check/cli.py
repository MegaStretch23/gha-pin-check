from __future__ import annotations

import argparse
import glob
import json
import os
import sys

from . import __version__, parse, rules
from .resolve import fetch_sha


def discover(path: str):
    if os.path.isfile(path):
        return [path]
    pats = [".github/workflows/*.yml", ".github/workflows/*.yaml", "action.yml", "action.yaml",
            ".github/actions/**/action.yml", ".github/actions/**/action.yaml"]
    found = sorted({p for pat in pats for p in glob.glob(os.path.join(path, pat), recursive=True)})
    return found


def scan(paths, resolver=None, root=""):
    findings, totals, errors, files = [], {}, [], 0
    cache = {}
    for p in paths:
        try:
            with open(p, encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError) as e:
            errors.append(f"{p}: cannot read ({e})")
            continue
        files += 1
        rel = os.path.relpath(p, root) if root else p
        facts = parse.read(text)
        f, counts = rules.check_uses(facts, rel)
        for k, v in counts.items():
            totals[k] = totals.get(k, 0) + v
        if resolver:
            for fd in f:
                kind, repo, ref = rules.classify(fd.uses)
                if kind in ("tag", "branch") and repo:
                    key = (repo, ref)
                    if key not in cache:
                        try:
                            cache[key] = resolver(repo, ref)
                        except RuntimeError as e:
                            cache[key] = None
                            errors.append(f"{rel}:{fd.line}: could not resolve {fd.uses}: {e}")
                    if cache[key]:
                        target = fd.uses.rsplit("@", 1)[0]
                        fd.suggestion = f"{target}@{cache[key]} # {ref}"
        findings += f + rules.check_risks(facts, rel)
    findings.sort(key=lambda x: (x.file, x.line, -rules.SEV[x.severity]))
    return findings, totals, errors, files


def summary(files, totals, findings):
    sev = {s: sum(1 for f in findings if f.severity == s) for s in ("high", "medium", "low")}
    n = sum(totals.values())
    return (f"{files} file(s), {n} uses: {totals.get('sha', 0)} pinned to a commit SHA, {totals.get('tag', 0)} on a tag, "
            f"{totals.get('branch', 0)} on a branch, {totals.get('short-sha', 0) + totals.get('other', 0)} other unpinned, "
            f"{totals.get('docker', 0)} docker, {totals.get('local', 0)} local or expression-built. Findings: high {sev['high']}, medium {sev['medium']}, low {sev['low']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gha-pin-check", description="Check GitHub Actions workflows for unpinned actions and risky patterns.")
    ap.add_argument("paths", nargs="*", default=["."], help="repo folders or workflow files (default: .)")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--resolve", action="store_true", help="look up the commit SHA behind each tag/branch via the GitHub API and print a pinned replacement line")
    ap.add_argument("--fail-on", choices=["low", "medium", "high"], help="exit 1 if any finding is at least this severity")
    ap.add_argument("--min-severity", choices=["low", "medium", "high"], default="low", help="hide findings below this severity")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN", "")
    resolver = (lambda repo, ref: fetch_sha(repo, ref, token)) if a.resolve else None
    allf, tot, errs, nfiles = [], {}, [], 0
    for path in a.paths:
        files = discover(path)
        if not files:
            errs.append(f"{path}: no workflow or action files found (looked for .github/workflows/*.yml|yaml, action.yml)")
            continue
        f, t, e, n = scan(files, resolver, root=path if os.path.isdir(path) else "")
        allf += f; errs += e; nfiles += n
        for k, v in t.items():
            tot[k] = tot.get(k, 0) + v
    shown = [f for f in allf if rules.SEV[f.severity] >= rules.SEV[a.min_severity]]
    if a.format == "json":
        print(json.dumps({"files": nfiles, "uses": tot, "findings": [f.as_dict() for f in shown], "errors": errs}, indent=2))
    else:
        for f in shown:
            print(f"{f.file}:{f.line}  {f.severity:<6} {f.rule}  {f.message}")
            if f.suggestion:
                print(f"    -> {f.suggestion}")
        print(summary(nfiles, tot, allf))
    for e in errs:
        print(f"error: {e}", file=sys.stderr)
    if errs:
        return 2
    if a.fail_on and any(rules.SEV[f.severity] >= rules.SEV[a.fail_on] for f in allf):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
