from __future__ import annotations
import argparse, sys
from pathlib import Path
from . import __version__
from .scanner import scan_text, SEV_ORDER, RULES
from . import report, resolve


def discover(paths: list[str]) -> list[Path]:
    """Files given as-is; a directory means <dir>/.github/workflows if present, else the *.yml/*.yaml directly inside <dir>."""
    found: list[Path] = []
    for p in map(Path, paths):
        if p.is_file():
            found.append(p)
        elif p.is_dir():
            base = p / ".github" / "workflows"
            base = base if base.is_dir() else p
            found += sorted(x for x in base.iterdir() if x.is_file() and x.suffix in (".yml", ".yaml"))
        else:
            raise FileNotFoundError(str(p))
    return found


def run(paths, fmt="text", fail_on=None, do_resolve=False, ignore=(), get=None) -> tuple[str, int]:
    files = discover(paths)
    findings = []
    for f in files:
        findings += scan_text(f.read_text(encoding="utf-8", errors="replace"), f.as_posix())
    findings = [f for f in findings if f.rule not in set(ignore)]
    if do_resolve:
        resolve.suggest(findings, **({"get": get} if get else {}))
    out = {"text": report.to_text, "json": report.to_json, "sarif": report.to_sarif}[fmt](findings, len(files))
    code = 1 if fail_on and any(SEV_ORDER[f.severity] >= SEV_ORDER[fail_on] for f in findings) else 0
    return out, code


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gha-pin-check", description="Check GitHub Actions workflows for unpinned uses: refs and risky patterns.")
    ap.add_argument("paths", nargs="*", default=["."], help="workflow files, or a repo/workflows directory (default: .)")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--fail-on", choices=["low", "medium", "high"], help="exit 1 if any finding has at least this severity")
    ap.add_argument("--resolve", action="store_true", help="look up commit SHAs for unpinned tag/branch refs via the GitHub API (GITHUB_TOKEN used if set)")
    ap.add_argument("--ignore", action="append", default=[], metavar="RULE", help=f"skip a rule id ({', '.join(RULES)}); repeatable")
    ap.add_argument("--version", action="version", version=f"gha-pin-check {__version__}")
    a = ap.parse_args(argv)
    try:
        out, code = run(a.paths, a.format, a.fail_on, a.resolve, a.ignore)
    except FileNotFoundError as e:
        print(f"gha-pin-check: no such path: {e}", file=sys.stderr); return 2
    print(out)
    return code


if __name__ == "__main__":
    sys.exit(main())
