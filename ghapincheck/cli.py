"""gha-pin-check: pinning and risk checker for GitHub Actions workflows."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .fix import pin_text
from .resolve import make_cached
from .scan import SEV_ORDER, discover, scan_paths


def render_text(res, quiet=False):
    lines = []
    for f in res["findings"]:
        lines.append(f"{f['file']}:{f['line']}: {f['severity'].upper():6} {f['rule']}: {f['message']}")
    c = {s: sum(1 for f in res["findings"] if f["severity"] == s) for s in ("high", "medium", "low")}
    lines.append(f"{len(res['files'])} files, {res['uses']} uses: lines, {len(res['findings'])} findings "
                 f"({c['high']} high, {c['medium']} medium, {c['low']} low)")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="gha-pin-check", description="Check GitHub Actions workflows for unpinned actions and risky patterns.")
    ap.add_argument("paths", nargs="*", default=["."], help="repo folders or workflow files (default: .)")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--fail-on", choices=("none", "low", "medium", "high"), default="medium", help="exit 1 if a finding at or above this severity exists (default medium)")
    ap.add_argument("--first-party", default="actions,github", help="owners treated as first-party, tag pins on them are 'low' (default actions,github)")
    ap.add_argument("--fix", action="store_true", help="rewrite tag/branch uses: lines to full commit SHAs (needs network; set GITHUB_TOKEN to avoid rate limits)")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    fp = tuple(x.strip().lower() for x in a.first_party.split(",") if x.strip())
    try:
        if a.fix:
            resolver = make_cached()
            n_changed, n_err = 0, 0
            for full, _ in discover(a.paths):
                with open(full, encoding="utf-8", newline="") as fh:
                    text = fh.read()
                new, changes, errors = pin_text(text, resolver)
                for e in errors:
                    print(f"{full}: could not resolve: {e}", file=sys.stderr)
                n_err += len(errors)
                if changes:
                    with open(full, "w", encoding="utf-8", newline="") as fh:
                        fh.write(new)
                    n_changed += len(changes)
                    for c in changes:
                        print(f"{full}:{c['line']}: {c['from']} -> {c['to']}")
            print(f"pinned {n_changed} uses: lines, {n_err} could not be resolved", file=sys.stderr)
            if n_err:
                return 2
        res = scan_paths(a.paths, fp)
    except FileNotFoundError as e:
        print(f"gha-pin-check: no such file or folder: {e}", file=sys.stderr)
        return 2
    if not res["files"]:
        print("gha-pin-check: no workflow files found (looked for .github/workflows/*.yml and action.yml)", file=sys.stderr)
        return 2
    print(json.dumps(res, indent=2) if a.format == "json" else render_text(res))
    if a.fail_on != "none" and any(SEV_ORDER[f["severity"]] >= SEV_ORDER[a.fail_on] for f in res["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
