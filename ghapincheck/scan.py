"""Line-based scanner for GitHub Actions workflow and composite-action files.

There is no YAML parser in the standard library, so this reads the few shapes that matter
(`uses:`, `run:` / `script:` blocks, `on:` triggers, `permissions:`) line by line. It is
deliberately conservative: anything it cannot classify is reported as a finding, not skipped.
"""
from __future__ import annotations

import fnmatch
import os
import re

SEV_ORDER = {"low": 1, "medium": 2, "high": 3}

USES_RE = re.compile(r"""^(?P<pre>\s*(?:-\s+)?uses:\s*)(?P<q>['"]?)(?P<val>[^\s'"#]+)(?P=q)(?P<post>\s*(?:#(?P<comment>.*))?)$""")
BLOCK_KEY_RE = re.compile(r"^(?P<ind>\s*(?:-\s+)?)(?P<key>run|script):\s*(?P<val>.*?)\s*$")
BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?\d*\s*(#.*)?$")
EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHORT_SHA_RE = re.compile(r"^[0-9a-f]{7,39}$")
VERSION_RE = re.compile(r"^v?\d+(\.\d+){0,3}([-+.][0-9A-Za-z.\-]+)?$")
BRANCH_NAMES = {"main", "master", "develop", "dev", "trunk", "head", "latest", "stable", "release", "nightly"}

# Attacker-controlled context values: a `${{ }}` of one of these inside run:/script: is shell/JS injection.
INJECTABLE = [
    r"github\.event\.issue\.(title|body)",
    r"github\.event\.pull_request\.(title|body|head\.ref|head\.label|head\.repo\.default_branch)",
    r"github\.event\.(comment|review|review_comment)\.body",
    r"github\.event\.discussion\.(title|body)",
    r"github\.event\.pages\.[^.\s]*\.page_name",
    r"github\.event\.commits\.[^.\s]*\.(message|author\.(email|name))",
    r"github\.event\.head_commit\.(message|author\.(email|name))",
    r"github\.event\.workflow_run\.(head_branch|display_title|head_commit\.message|head_repository\.description)",
    r"github\.head_ref",
]
INJECTABLE_RE = re.compile("|".join(f"(?:{p})" for p in INJECTABLE))


def finding(path, line, rule, sev, msg, ref=None):
    return {"file": path, "line": line, "rule": rule, "severity": sev, "message": msg, "ref": ref}


def parse_uses(value: str):
    """-> (kind, owner_repo, path, ref). kind: local | docker | action."""
    if value.startswith("./") or value == ".":
        return ("local", value, "", "")
    if value.startswith("docker://"):
        return ("docker", value[len("docker://"):], "", "")
    name, _, ref = value.partition("@")
    parts = name.split("/")
    owner_repo = "/".join(parts[:2])
    return ("action", owner_repo, "/".join(parts[2:]), ref)


def classify_ref(ref: str) -> str:
    if SHA_RE.match(ref):
        return "sha"
    if not ref:
        return "missing"
    if VERSION_RE.match(ref):
        return "tag"
    if SHORT_SHA_RE.match(ref) and re.search(r"\d", ref) and re.search(r"[a-f]", ref):
        return "short-sha"
    return "branch"


def check_uses(path, lineno, value, first_party):
    kind, name, sub, ref = parse_uses(value)
    if kind == "local":
        return []
    if kind == "docker":
        if "@sha256:" in name:
            return []
        return [finding(path, lineno, "unpinned-docker", "medium",
                        f"docker image {name} is a mutable tag; pin it with @sha256:<digest>", value)]
    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/\S*)?$", name):
        return [finding(path, lineno, "unrecognized-uses", "low",
                        f"cannot check '{value}': not ./local, docker:// or owner/repo@ref", value)]
    cls = classify_ref(ref)
    owner = name.split("/")[0].lower()
    fp = owner in first_party
    if cls == "sha":
        return []
    if cls == "missing":
        return [finding(path, lineno, "unpinned-branch", "high", f"{value} has no @ref (default branch is used)", value)]
    if cls == "short-sha":
        return [finding(path, lineno, "short-sha", "high",
                        f"{value}: an abbreviated SHA is ambiguous with a branch or tag of that name; use the full 40-character SHA", value)]
    if cls == "branch":
        return [finding(path, lineno, "unpinned-branch", "high",
                        f"{value} follows the branch or moving ref '{ref}'; every run can execute different code", value)]
    sev = "low" if fp else "medium"
    who = "first-party" if fp else "third-party"
    return [finding(path, lineno, "unpinned-tag", sev,
                    f"{value} is a {who} tag; the tag can be moved to other code. Pin the commit SHA and keep the tag in a comment", value)]


def block_lines(lines, i, key_indent):
    """Yield (lineno, text) of the block-scalar body that follows lines[i]."""
    j = i + 1
    while j < len(lines):
        t = lines[j]
        if t.strip() == "":
            j += 1
            continue
        ind = len(t) - len(t.lstrip(" "))
        if ind <= key_indent:
            break
        yield j + 1, t
        j += 1


def check_injection(path, lines, first_party=None):
    out = []
    for i, raw in enumerate(lines):
        m = BLOCK_KEY_RE.match(raw)
        if not m:
            continue
        val = m.group("val")
        targets = []
        if val and not BLOCK_SCALAR_RE.match(val):
            targets.append((i + 1, val))
        else:
            targets.extend(block_lines(lines, i, len(m.group("ind").replace("-", " "))))
        for ln, text in targets:
            for e in EXPR_RE.finditer(text):
                inner = e.group(1).strip()
                hit = INJECTABLE_RE.search(inner)
                if hit:
                    out.append(finding(path, ln, "script-injection", "high",
                                       f"${{{{ {inner} }}}} is attacker-controlled text pasted into a {m.group('key')}: block; pass it through env: and quote the variable",
                                       hit.group(0)))
    return out


def triggers(lines):
    found = set()
    for raw in lines:
        s = raw.split("#", 1)[0]
        if re.match(r"^jobs:\s*$", s):
            break
        for t in ("pull_request_target", "workflow_run", "issue_comment", "issues"):
            if re.search(rf"\b{t}\b", s):
                found.add(t)
    return found


PR_HEAD_REF_RE = re.compile(r"^\s*(?:-\s+)?ref:\s*['\"]?\$\{\{.*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(sha|branch)).*\}\}")


def check_pwn(path, lines):
    t = triggers(lines)
    out = []
    if "pull_request_target" in t or "workflow_run" in t:
        for i, raw in enumerate(lines):
            m = PR_HEAD_REF_RE.match(raw)
            if m:
                trig = "pull_request_target" if "pull_request_target" in t else "workflow_run"
                out.append(finding(path, i + 1, "pwn-request", "high",
                                   f"{trig} runs with repo secrets and a write token, and this step checks out code from the pull request; that code can read them",
                                   m.group(1)))
    return out


def check_permissions(path, lines, is_workflow):
    if not is_workflow:
        return []
    out = []
    has = False
    for i, raw in enumerate(lines):
        s = raw.split("#", 1)[0]
        m = re.match(r"^\s*permissions:\s*(.*?)\s*$", s)
        if not m:
            continue
        has = True
        if m.group(1) in ("write-all", "'write-all'", '"write-all"'):
            out.append(finding(path, i + 1, "permissions-write-all", "high", "permissions: write-all gives the job token every write scope", "write-all"))
    if not has:
        out.append(finding(path, 1, "permissions-missing", "low",
                           "no permissions: key; the token gets the repository or organization default, which may be read-write", None))
    return out


def scan_text(path, text, first_party=("actions", "github"), is_workflow=True):
    lines = text.splitlines()
    out = []
    uses = []
    for i, raw in enumerate(lines):
        m = USES_RE.match(raw)
        if not m:
            bare = re.match(r"^\s*(?:-\s+)?uses:\s*(\S.*?)\s*$", raw)
            if bare:
                uses.append({"line": i + 1, "value": bare.group(1)})
                out.append(finding(path, i + 1, "unrecognized-uses", "low", f"cannot check '{bare.group(1)}': not ./local, docker:// or owner/repo@ref", bare.group(1)))
            continue
        val = m.group("val")
        uses.append({"line": i + 1, "value": val})
        out.extend(check_uses(path, i + 1, val, set(first_party)))
    out.extend(check_injection(path, lines))
    out.extend(check_pwn(path, lines))
    out.extend(check_permissions(path, lines, is_workflow))
    out.sort(key=lambda f: (f["line"], f["rule"]))
    return out, uses


def discover(paths):
    """Workflow files and composite actions under each path (a file is taken as is)."""
    found = []
    for p in paths:
        if os.path.isfile(p):
            found.append((p, True))
            continue
        if not os.path.isdir(p):
            raise FileNotFoundError(p)
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv")]
            rel = os.path.relpath(root, p).replace(os.sep, "/")
            for f in sorted(files):
                if not f.endswith((".yml", ".yaml")):
                    continue
                full = os.path.join(root, f)
                if rel == ".github/workflows":
                    found.append((full, True))
                elif f in ("action.yml", "action.yaml") and (rel == "." or rel.startswith(".github/actions")):
                    found.append((full, False))
    return sorted(set(found))


def scan_paths(paths, first_party=("actions", "github")):
    findings, files, total_uses = [], [], 0
    for full, is_wf in discover(paths):
        with open(full, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        shown = os.path.relpath(full) if not os.path.isabs(full) else full
        f, u = scan_text(shown.replace(os.sep, "/"), text, first_party, is_wf)
        findings.extend(f)
        files.append(shown.replace(os.sep, "/"))
        total_uses += len(u)
    return {"files": files, "uses": total_uses, "findings": findings}
