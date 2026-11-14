#!/usr/bin/env python3
"""actions-pin-check: a line-based check of GitHub Actions workflow files (Python standard library only).

  python3 -I actions_pin_check.py [PATH ...] [--json] [--resolve] [--fail-on warn|fail]

PATH is a workflow file, a directory (its .github/workflows/*.yml|*.yaml, else the directory's own *.yml|*.yaml) or - for stdin.
No PATH = .github/workflows in the current directory. Exit code: 0 PASS, 1 WARN, 2 FAIL, 3 usage or unreadable file
(--fail-on fail turns WARN into exit 0). Only --resolve touches the network (api.github.com, tag/branch -> commit SHA, GITHUB_TOKEN used if set).

Rules (finding codes): AP_UNPINNED_BRANCH / AP_NO_REF (FAIL), AP_UNPINNED_TAG / AP_SHORT_SHA / AP_UNPINNED_DOCKER (WARN), AP_PRT_CHECKOUT_HEAD (FAIL),
AP_SCRIPT_INJECTION (FAIL) / AP_EVENT_IN_RUN (WARN), AP_PERMS_WRITE_ALL (FAIL), AP_PERMS_MISSING (WARN), AP_CURL_PIPE_SH (FAIL), AP_NOT_WORKFLOW (WARN).
This is a heuristic, line-based reader, not a YAML parser and not a security audit. The same rules run in the browser page (core.js).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.1.0"
TOOL = "actions-pin-check"
LIMITS = ("Heuristic line-based check, not a YAML parser and not a security audit. It reads the text only: it does not follow reusable workflows or composite actions, "
          "does not read github-script 'script:' blocks, and cannot tell whether a pinned SHA is a commit you trust.")

SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
SHORT_SHA = re.compile(r"^[0-9a-fA-F]{7,39}$")
TAGLIKE = re.compile(r"^v?\d+(\.\d+){0,3}([-.+][\w.]+)?$")
DOCKER_PIN = re.compile(r"@sha256:[0-9a-fA-F]{64}$")
BLOCK = re.compile(r"""^(\s*)((?:-\s+)*)(["']?[\w.-]+["']?)\s*:\s*[|>][+-]?\d*\s*(?:#.*)?$""")
USES = re.compile(r"^(\s*)((?:-\s+)*)uses\s*:\s*(.+)$")
RUN = re.compile(r"^(\s*)((?:-\s+)*)run\s*:\s*(.*)$")
HEADREF = re.compile(r"github\.event\.pull_request\.head\.|github\.head_ref|refs/pull/.*/(?:head|merge)")
UNTRUSTED = re.compile(
    r"github\.head_ref|github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch|repo\.description|repo\.homepage))"
    r"|comment\.body|review\.body|review_comment\.body|pages\.[\w\[\]*.]*page_name|commits\.[\w\[\]*.]*(?:message|author\.email|author\.name)"
    r"|head_commit\.(?:message|author\.email|author\.name)|workflow_run\.(?:head_branch|head_commit\.(?:message|author\.email|author\.name))"
    r"|discussion\.(?:title|body)|release\.(?:name|body|tag_name)|client_payload)")
CURL_PIPE = re.compile(r"\b(?:curl|wget)\b[^\n]*?\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b")
CURL_SUBST = re.compile(r"\b(?:ba|z|da|k)?sh\b[^|\n]*<\(\s*(?:curl|wget)\b")


def strip_comment(s: str) -> str:
    q = None
    for i, c in enumerate(s):
        if q:
            if c == q:
                q = None
        elif c in "'\"" and (i == 0 or s[i - 1] in " \t:[{,-"):
            q = c
        elif c == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
    return s.rstrip()


def indent(ln: str) -> int:
    return len(ln) - len(ln.lstrip(" "))


def blank_or_comment(ln: str) -> bool:
    t = ln.strip()
    return t == "" or t.startswith("#")


def find_scalars(lines: list[str]):
    """Block scalars (key: | or >): returns (content line indexes set, {header index: [content indexes]})."""
    inscalar: set[int] = set()
    heads: dict[int, list[int]] = {}
    i = 0
    while i < len(lines):
        m = BLOCK.match(lines[i]) if i not in inscalar else None
        if m:
            kc = len(m.group(1)) + len(m.group(2))
            j = i + 1
            content = []
            while j < len(lines):
                if lines[j].strip() == "" or indent(lines[j]) > kc:
                    content.append(j)
                    j += 1
                else:
                    break
            heads[i] = content
            inscalar.update(content)
            i = j
        else:
            i += 1
    return inscalar, heads


def suggest(name: str, ref: str, sha: str | None = None) -> str:
    return f"uses: {name}@{sha or '<40-char commit SHA>'} # {ref}"


def scan_text(text: str, name: str = "workflow.yml") -> dict:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    inscalar, heads = find_scalars(lines)
    F: list[dict] = []

    def add(level, code, line, msg, **extra):
        d = {"level": level, "code": code, "line": line + 1, "message": msg}
        d.update(extra)
        F.append(d)

    n_uses = n_pinned = n_run = 0
    # --- uses: pinning
    for i, ln in enumerate(lines):
        if i in inscalar:
            continue
        m = USES.match(ln)
        if not m:
            continue
        val = strip_comment(m.group(3)).strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
            val = val[1:-1]
        if not val or val.startswith("./") or val.startswith("../") or "${{" in val:
            continue
        n_uses += 1
        if val.startswith("docker://"):
            if DOCKER_PIN.search(val):
                n_pinned += 1
            else:
                add("WARN", "AP_UNPINNED_DOCKER", i, f"docker image '{val}' is not pinned to an @sha256: digest; tags can be re-pointed", uses=val, ref=None)
            continue
        if "@" not in val:
            add("FAIL", "AP_NO_REF", i, f"'{val}' has no @ref at all", uses=val, ref=None)
            continue
        nm, _, ref = val.rpartition("@")
        if SHA40.match(ref):
            n_pinned += 1
        elif SHORT_SHA.match(ref):
            add("WARN", "AP_SHORT_SHA", i, f"'{val}' uses an abbreviated SHA; pin the full 40-character commit SHA", uses=val, ref=ref, suggestion=suggest(nm, ref))
        elif TAGLIKE.match(ref):
            add("WARN", "AP_UNPINNED_TAG", i, f"'{val}' is pinned to the tag '{ref}'; a tag can be moved to different code", uses=val, ref=ref, suggestion=suggest(nm, ref))
        else:
            add("FAIL", "AP_UNPINNED_BRANCH", i, f"'{val}' follows the branch or ref '{ref}', so every run can execute different code", uses=val, ref=ref, suggestion=suggest(nm, ref))
    # --- run: steps (script injection, curl | sh)
    for i, ln in enumerate(lines):
        if i in inscalar:
            continue
        m = RUN.match(ln)
        if not m:
            continue
        n_run += 1
        if i in heads:
            body = [(j, lines[j]) for j in heads[i] if lines[j].strip() and not lines[j].lstrip().startswith("#")]
        else:
            v = strip_comment(m.group(3))
            body = [(i, v)] if v else []
        for j, t in body:
            for em in re.finditer(r"\$\{\{(.*?)\}\}", t):
                expr = em.group(1).strip()
                if UNTRUSTED.search(expr):
                    add("FAIL", "AP_SCRIPT_INJECTION", j, f"${{{{ {expr} }}}} is pasted into a shell script; its value is attacker-controlled text. Pass it through env: and quote \"$VAR\" instead")
                elif "github.event." in expr:
                    add("WARN", "AP_EVENT_IN_RUN", j, f"${{{{ {expr} }}}} is pasted into a shell script; pass event data through env: and quote \"$VAR\" instead")
        merged: list[tuple[int, str]] = []
        for j, t in body:
            if merged and merged[-1][1].endswith("\\"):
                merged[-1] = (merged[-1][0], merged[-1][1][:-1] + " " + t.strip())
            else:
                merged.append((j, t))
        for j, t in merged:
            if CURL_PIPE.search(t) or CURL_SUBST.search(t):
                add("FAIL", "AP_CURL_PIPE_SH", j, "downloads a script and runs it in one step (curl or wget piped into a shell); download, verify a checksum, then run")
    # --- trigger + checkout of the PR head
    prt_line = None
    for i, ln in enumerate(lines):
        if i in inscalar or indent(ln) != 0 or not re.match(r"""^(?:on|"on"|'on'|true)\s*:""", ln):
            continue
        j = i
        while j < len(lines) and (j == i or blank_or_comment(lines[j]) or indent(lines[j]) > 0):
            if j not in inscalar and re.search(r"\bpull_request_target\b", strip_comment(lines[j] if j > i else lines[j].split(":", 1)[1])):
                prt_line = j
                break
            j += 1
        break
    if prt_line is not None:
        for i, ln in enumerate(lines):
            if i in inscalar:
                continue
            m = USES.match(ln)
            if not m or not re.match(r"""^['"]?actions/checkout\b""", strip_comment(m.group(3)).strip()):
                continue
            kc = len(m.group(1)) + len(m.group(2))
            start = i
            if not m.group(2):
                j = i - 1
                start = j + 1 if j < 0 else i
                while j >= 0:
                    t = lines[j]
                    if t.strip() == "":
                        j -= 1
                        continue
                    m2 = re.match(r"^(\s*)-(\s+)\S", t)
                    if m2 and len(m2.group(1)) + 1 + len(m2.group(2)) == kc:
                        start = j
                        break
                    if indent(t) < kc:
                        start = j + 1
                        break
                    start = j
                    j -= 1
            end = i + 1
            while end < len(lines) and (lines[end].strip() == "" or indent(lines[end]) >= kc):
                end += 1
            for k in range(start, end):
                if k in inscalar or lines[k].lstrip().startswith("#"):
                    continue
                mr = re.match(r"^\s*(?:-\s+)*(ref|repository)\s*:\s*(.+)$", lines[k])
                if mr and HEADREF.search(strip_comment(mr.group(2))):
                    add("FAIL", "AP_PRT_CHECKOUT_HEAD", k,
                        f"pull_request_target (line {prt_line + 1}) runs with the base repository's secrets and a write token, and this checkout takes the pull request's code ({mr.group(1)}: {strip_comment(mr.group(2))})")
    # --- permissions
    for i, ln in enumerate(lines):
        if i not in inscalar and re.match(r"""^\s*permissions\s*:\s*['"]?write-all['"]?\s*$""", strip_comment(ln)):
            add("FAIL", "AP_PERMS_WRITE_ALL", i, "permissions: write-all gives the workflow token every write scope; list only the scopes the job needs")
    top_perm = any(i not in inscalar and indent(ln) == 0 and re.match(r"^permissions\s*:", ln) for i, ln in enumerate(lines))
    jobs_at = next((i for i, ln in enumerate(lines) if i not in inscalar and indent(ln) == 0 and re.match(r"^jobs\s*:\s*(?:#.*)?$", ln)), None)
    jobs: list[tuple[str, int, bool]] = []
    if jobs_at is not None:
        end = jobs_at + 1
        ci = None
        while end < len(lines):
            t = lines[end]
            if not blank_or_comment(t):
                if ci is None:
                    ci = indent(t)
                if indent(t) < ci or ci == 0:
                    break
            end += 1
        heads_idx = [k for k in range(jobs_at + 1, end) if k not in inscalar and not blank_or_comment(lines[k]) and indent(lines[k]) == ci and re.match(r"""^\s*["']?[\w.-]+["']?\s*:""", lines[k])]
        for n, h in enumerate(heads_idx):
            seg_end = heads_idx[n + 1] if n + 1 < len(heads_idx) else end
            child = next((indent(lines[k]) for k in range(h + 1, seg_end) if not blank_or_comment(lines[k])), None)
            has = child is not None and any(k not in inscalar and indent(lines[k]) == child and re.match(r"^\s*permissions\s*:", lines[k]) for k in range(h + 1, seg_end))
            jobs.append((re.match(r"""^\s*["']?([\w.-]+)["']?""", lines[h]).group(1), h, has))
    if not top_perm and jobs:
        missing = [j for j in jobs if not j[2]]
        if missing:
            add("WARN", "AP_PERMS_MISSING", missing[0][1], "no top-level permissions: block and no permissions: on job(s) " + ", ".join(j[0] for j in missing)
                + "; the token then gets the repository default scope, which can be read and write")
    if jobs_at is None:
        add("WARN", "AP_NOT_WORKFLOW", 0, "no top-level jobs: key, so this does not look like a GitHub Actions workflow")
    F.append({"level": "INFO", "code": "AP_SUMMARY", "line": 0,
              "message": f"{n_uses} uses: reference(s), {n_pinned} pinned to a full commit SHA; {n_run} run: step(s); {len(jobs)} job(s)"})
    F.sort(key=lambda f: (f["line"], f["code"], f["message"]))
    counts = {k: sum(1 for f in F if f["level"] == k) for k in ("FAIL", "WARN", "INFO")}
    verdict = "FAIL" if counts["FAIL"] else "WARN" if counts["WARN"] else "PASS"
    return {"file": {"name": name, "lines": len(lines)}, "verdict": verdict, "counts": counts, "findings": F}


# ---------------------------------------------------------------- resolve (the only network use)
def github_resolve(owner: str, repo: str, ref: str, token: str | None = None, timeout: float = 15.0) -> str | None:
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{urllib.parse.quote(ref, safe='/')}"
    h = {"Accept": "application/vnd.github.sha", "User-Agent": TOOL}
    if token:
        h["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
        sha = r.read().decode("ascii", "replace").strip()
    return sha if SHA40.match(sha) else None


def apply_resolve(report: dict, resolver) -> None:
    """resolver(owner, repo, ref) -> 40-char sha or None; raises are caught per finding."""
    for f in report["findings"]:
        if f["code"] not in ("AP_UNPINNED_TAG", "AP_UNPINNED_BRANCH", "AP_SHORT_SHA") or not f.get("ref"):
            continue
        nm = f["uses"].rpartition("@")[0]
        parts = nm.split("/")
        if len(parts) < 2:
            continue
        try:
            sha = resolver(parts[0], parts[1], f["ref"])
        except Exception as e:   # noqa: BLE001 - reported on the finding, never fatal
            f["resolve_error"] = f"{type(e).__name__}: {str(e)[:80]}"
            continue
        if sha:
            f["resolved_sha"] = sha
            f["suggestion"] = suggest(nm, f["ref"], sha)
        else:
            f["resolve_error"] = "API returned no commit SHA"


# ---------------------------------------------------------------- CLI
def discover(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths or [os.path.join(".github", "workflows")]:
        if p == "-":
            out.append(p)
        elif os.path.isdir(p):
            d = os.path.join(p, ".github", "workflows")
            d = d if os.path.isdir(d) else p
            out += sorted(os.path.join(d, n) for n in os.listdir(d) if n.endswith((".yml", ".yaml")))
        else:
            out.append(p)
    return out


def render_text(rep: dict) -> str:
    c = rep["counts"]
    o = [f"{rep['verdict']}  {rep['file']['name']}  ({c['FAIL']} fail, {c['WARN']} warn)"]
    for f in rep["findings"]:
        at = f"line {f['line']} " if f["line"] else ""
        o.append(f"  [{f['level']}] {at}{f['code']}: {f['message']}")
        if f.get("suggestion"):
            o.append(f"      fix: {f['suggestion']}")
        if f.get("resolve_error"):
            o.append(f"      (could not resolve: {f['resolve_error']})")
    return "\n".join(o)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog=TOOL, description="Check GitHub Actions workflows for unpinned actions and risky patterns.")
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--json", action="store_true", help="print one JSON report")
    ap.add_argument("--resolve", action="store_true", help="look up commit SHAs for unpinned references through the public GitHub API (network)")
    ap.add_argument("--fail-on", choices=("warn", "fail"), default="warn", help="lowest verdict that gives a non-zero exit code (default warn)")
    ap.add_argument("--version", action="version", version=f"{TOOL} {VERSION}")
    a = ap.parse_args(argv)
    files = discover(a.paths)
    if not files:
        print("no workflow files found", file=sys.stderr)
        return 3
    reps = []
    token = os.getenv("GITHUB_TOKEN") or None
    cache: dict = {}

    def resolver(o, r, ref):
        k = (o, r, ref)
        if k not in cache:
            cache[k] = github_resolve(o, r, ref, token)
        return cache[k]
    for f in files:
        try:
            if f == "-":
                text, name = sys.stdin.read(), "<stdin>"
            else:
                with open(f, "rb") as fh:
                    text, name = fh.read().decode("utf-8", "replace"), f
        except OSError as e:
            print(f"cannot read {f}: {e}", file=sys.stderr)
            return 3
        rep = scan_text(text, name)
        if a.resolve:
            apply_resolve(rep, resolver)
        reps.append(rep)
    worst = "FAIL" if any(r["verdict"] == "FAIL" for r in reps) else "WARN" if any(r["verdict"] == "WARN" for r in reps) else "PASS"
    code = {"PASS": 0, "WARN": 1, "FAIL": 2}[worst]
    if a.fail_on == "fail" and code == 1:
        code = 0
    if a.json:
        tot = {k: sum(r["counts"][k] for r in reps) for k in ("FAIL", "WARN", "INFO")}
        print(json.dumps({"tool": TOOL, "version": VERSION, "verdict": worst, "counts": tot, "files": reps, "limits": LIMITS}, indent=2))
    else:
        print("\n\n".join(render_text(r) for r in reps))
        print("Heuristic check of the workflow text, not a security audit.")
    return code


if __name__ == "__main__":
    sys.exit(main())
