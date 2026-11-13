"""Line-based GitHub Actions workflow scanner. No YAML library: it reads keys, `uses:` values and `run:` text line by line.

Known limits (by design of a line-based parser): flow-style mappings spanning lines, anchors/aliases, and multi-line plain or
quoted `run:` scalars are not followed; only block scalars (`run: |`, `>`) and single-line `run:` values are read."""
from __future__ import annotations
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable

SEV_ORDER = {"low": 1, "medium": 2, "high": 3}

RULES = {
    "GHA001": ("unpinned-action", "medium", "uses: ref is not a 40-character commit SHA (tag or branch refs can move)"),
    "GHA002": ("docker-not-digest", "medium", "docker:// image is not pinned by @sha256 digest"),
    "GHA003": ("prt-checkout-pr-head", "high", "pull_request_target workflow checks out code from the pull request"),
    "GHA004": ("script-injection", "high", "github.event / head_ref expression interpolated inside run: (shell injection)"),
    "GHA005": ("permissions", "medium", "permissions: missing (default token scope) or set to write-all"),
    "GHA006": ("curl-pipe-shell", "medium", "run: downloads a script and pipes it into a shell or interpreter"),
}

SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
KEYLINE = re.compile(r"^(\s*)(-\s+)?([A-Za-z0-9_.\"'-]+)\s*:(?:\s+(.*)|\s*)$")
BLOCK = re.compile(r"^(\s*)(-\s+)?([A-Za-z0-9_.-]+):\s*[|>][+-]?\d?\s*(?:#.*)?$")
EXPR = re.compile(r"\$\{\{(.*?)\}\}")
EVENT_REF = re.compile(r"github\.event\.[A-Za-z0-9_.\[\]'*-]+|github\.head_ref")
SAFE_SUFFIX = re.compile(r"\.(number|id|sha|after|before|action|author_association|html_url|created_at|updated_at|merged|draft|node_id)$")
HEAD_PAT = re.compile(r"github\.event\.pull_request\.head\.|github\.head_ref|github\.event\.workflow_run\.head_|refs/pull/|merge_commit_sha")
CURL_PIPE = re.compile(r"\b(?:curl|wget)\b[^\n;&]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b|\b(?:curl|wget)\b[^\n;&]*\|\s*(?:sudo\s+)?python3?\b|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b")


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    message: str
    snippet: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["name"] = RULES[self.rule][0]
        return d


def strip_comment(v: str) -> str:
    """Value of a scalar with a trailing ` # comment` removed; quoted values are unquoted."""
    v = v.strip()
    if v[:1] and v[:1] in "\"'":
        q = v[0]; end = v.find(q, 1)
        return v[1:end] if end > 0 else v[1:]
    m = re.search(r"\s#", v)
    return (v[:m.start()] if m else v).strip()


class Doc:
    def __init__(self, text: str):
        self.raw = text.splitlines()
        self.skip: set[int] = set()          # 0-based lines inside block scalars
        self.run_text: list[tuple[int, str]] = []   # (1-based first line, text) of every run: value
        self._scan_scalars()

    def indent(self, i: int) -> int:
        s = self.raw[i]; return len(s) - len(s.lstrip(" "))

    def blank(self, i: int) -> bool:
        s = self.raw[i].strip(); return not s or s.startswith("#")

    def _scan_scalars(self):
        i, n = 0, len(self.raw)
        while i < n:
            if i in self.skip:
                i += 1; continue
            m = BLOCK.match(self.raw[i])
            if m:
                keycol = len(m.group(1)) + (len(m.group(2)) if m.group(2) else 0)
                j = i + 1; body = []
                while j < n and (not self.raw[j].strip() or self.indent(j) > keycol):
                    body.append(self.raw[j]); self.skip.add(j); j += 1
                if m.group(3) == "run":
                    self.run_text.append((i + 2, "\n".join(body)))
                i = j; continue
            m = KEYLINE.match(self.raw[i])
            if m and m.group(3) == "run" and m.group(4):
                self.run_text.append((i + 1, strip_comment(m.group(4))))
            i += 1

    def keyline(self, i: int):
        if i in self.skip or self.blank(i):
            return None
        m = KEYLINE.match(self.raw[i])
        if not m:
            return None
        col = len(m.group(1)) + (len(m.group(2)) if m.group(2) else 0)
        return {"col": col, "dash": bool(m.group(2)), "key": m.group(3).strip("\"'"), "val": m.group(4) or "", "line": i + 1}


def scan_text(text: str, path: str = "workflow.yml") -> list[Finding]:
    d = Doc(text); out: list[Finding] = []
    kl = [d.keyline(i) for i in range(len(d.raw))]

    def add(rule, line, msg, snippet="", sev=None, **extra):
        out.append(Finding(rule, sev or RULES[rule][1], path, line, msg, snippet.strip(), extra))

    # --- uses: pinning (GHA001 / GHA002)
    for k in kl:
        if not k or k["key"] != "uses":
            continue
        v = strip_comment(k["val"]); line = d.raw[k["line"] - 1]
        if not v or v.startswith("./") or "${{" in v and "@" not in v:
            continue
        if v.startswith("docker://"):
            if "@sha256:" not in v:
                add("GHA002", k["line"], f"docker image not pinned by digest: {v}", line, uses=v)
            continue
        name, _, ref = v.partition("@")
        if not SHA40.match(ref):
            msg = f"{name} is not pinned to a commit SHA (ref: {ref or 'none'})"
            add("GHA001", k["line"], msg, line, uses=v, action=name, ref=ref)

    # --- sections: on:, permissions:, jobs:
    top = {k["key"]: k for k in kl if k and k["col"] == 0 and not k["dash"]}
    first_job_line = top["jobs"]["line"] if "jobs" in top else len(d.raw) + 1
    has_prt = False
    if "on" in top or "true" in top:
        s = (top.get("on") or top["true"])["line"] - 1
        e = next((x["line"] - 1 for x in kl if x and x["col"] == 0 and x["line"] - 1 > s), len(d.raw))
        for i in range(s, e):
            if i in d.skip or d.blank(i):
                continue
            if re.search(r"\bpull_request_target\b", re.sub(r"\s#.*$", "", d.raw[i])):
                has_prt = True

    # --- GHA003: pull_request_target + checkout of the PR head
    if has_prt:
        for k in kl:
            if not k or k["key"] != "uses" or not strip_comment(k["val"]).startswith("actions/checkout"):
                continue
            m = k["col"]; i = k["line"] - 1
            s = i
            while s > 0 and (d.blank(s) or d.indent(s) >= m) and not (kl[s] and kl[s]["dash"] and kl[s]["col"] == m):
                s -= 1
            e = i + 1
            while e < len(d.raw) and (d.blank(e) or d.indent(e) >= m):
                e += 1
            for j in range(s, e):
                kj = kl[j]
                if kj and kj["key"] in ("ref", "repository") and kj["col"] > m and HEAD_PAT.search(kj["val"]):
                    add("GHA003", kj["line"], f"pull_request_target workflow checks out the PR head ({kj['key']}: {strip_comment(kj['val'])}); untrusted code runs with a privileged token and secrets", d.raw[j])

    # --- GHA004 / GHA006 over run: text
    for first, body in d.run_text:
        lines = body.split("\n")
        for off, ln in enumerate(lines):
            for em in EXPR.finditer(ln):
                for r in EVENT_REF.finditer(em.group(1)):
                    ref = r.group(0)
                    if SAFE_SUFFIX.search(ref):
                        sev, why = "low", "not a free-text field"
                    elif ref.startswith("github.event.inputs") or ref.startswith("github.event.client_payload"):
                        sev, why = "medium", "set by whoever can trigger the workflow"
                    else:
                        sev, why = "high", "can carry attacker-chosen text"
                    add("GHA004", first + off, f"${{{{ {ref} }}}} is expanded into a shell command ({why}); pass it through env: and quote it", ln, sev=sev, expression=ref)
        joined = re.sub(r"\\\n\s*", " ", body)
        for cm in CURL_PIPE.finditer(joined):
            pos = joined[:cm.start()].count("\n")
            add("GHA006", first + pos, "script is downloaded and piped into an interpreter; pin and verify the download", cm.group(0)[:160])

    # --- GHA005: permissions
    def perm_val(k): return strip_comment(k["val"]) if k else None
    toplevel = top.get("permissions")
    if toplevel and perm_val(toplevel) == "write-all":
        add("GHA005", toplevel["line"], "top-level permissions: write-all grants every scope", d.raw[toplevel["line"] - 1], sev="high")
    jobs_idx = [k for k in kl if k and k["line"] > first_job_line and k["col"] > 0]
    if "jobs" in top and jobs_idx:
        jcol = jobs_idx[0]["col"]
        jobs = [k for k in jobs_idx if k["col"] == jcol and not k["dash"] and not k["val"].strip().startswith("#") and not k["val"].strip()]
        for n, j in enumerate(jobs):
            end = jobs[n + 1]["line"] if n + 1 < len(jobs) else len(d.raw) + 1
            pk = next((k for k in jobs_idx if j["line"] < k["line"] < end and k["col"] == jcol + 2 and k["key"] == "permissions"), None)
            if pk and perm_val(pk) == "write-all":
                add("GHA005", pk["line"], f"job '{j['key']}' sets permissions: write-all", d.raw[pk["line"] - 1], sev="high")
            elif not pk and not toplevel:
                add("GHA005", j["line"], f"no permissions: at workflow level or on job '{j['key']}'; the token gets the repository default scope", d.raw[j["line"] - 1], job=j["key"])
    elif "jobs" not in top and not toplevel:
        pass
    out.sort(key=lambda f: (f.line, f.rule))
    return out
