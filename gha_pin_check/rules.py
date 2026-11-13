"""Pinning and risk rules. Severity: high > medium > low."""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict

from .parse import Facts

SEV = {"low": 1, "medium": 2, "high": 3}
SHA_RX = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHORT_SHA_RX = re.compile(r"^[0-9a-f]{7,39}$")
BRANCHY = {"main", "master", "develop", "dev", "trunk", "head", "latest", "stable", "release", "next", "nightly"}
FIRST_PARTY = ("actions/", "github/")

# Contexts an outsider controls (issue / PR / branch / commit text). Expanded into a shell script by
# `${{ }}` they become shell injection.
UNTRUSTED = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))"
    r"|(?:comment|review|review_comment)\.body|discussion\.(?:title|body)|head_commit\.(?:message|author\.(?:email|name))"
    r"|commits\[[^\]]*\]\.(?:message|author\.(?:email|name))|pages\[[^\]]*\]\.page_name"
    r"|workflow_run\.(?:head_branch|head_commit\.(?:message|author\.(?:email|name))|pull_requests\[[^\]]*\]\.head\.ref))"
    r"|github\.head_ref)\s*\}\}")
HEAD_CHECKOUT = re.compile(
    r"\b(?:ref|repository):\s*['\"]?\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref|repo\.full_name)"
    r"|event\.workflow_run\.(?:head_sha|head_branch|head_repository\.full_name)|head_ref)")
PIPE_SHELL = re.compile(r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str
    message: str
    uses: str = ""
    suggestion: str = ""

    def as_dict(self):
        return {k: v for k, v in asdict(self).items() if v not in ("", None)}


def classify(value: str):
    """-> (kind, owner_repo, ref). kind: local | dynamic | docker-digest | docker-tag | sha | short-sha | branch | tag | no-ref."""
    if value.startswith("./") or value.startswith("../"):
        return "local", "", ""
    if value.startswith("$") or "${{" in value:
        return "dynamic", "", ""
    if value.startswith("docker://"):
        return ("docker-digest" if "@sha256:" in value else "docker-tag"), "", ""
    if "@" not in value:
        return "no-ref", value, ""
    target, ref = value.rsplit("@", 1)
    parts = target.split("/")
    repo = "/".join(parts[:2])
    if SHA_RX.match(ref):
        return "sha", repo, ref
    if SHORT_SHA_RX.match(ref) and re.search(r"\d", ref) and re.search(r"[a-f]", ref):
        return "short-sha", repo, ref
    if ref.lower() in BRANCHY or "/" in ref or not re.search(r"\d", ref):
        return "branch", repo, ref
    return "tag", repo, ref


def check_uses(facts: Facts, path: str):
    out, counts = [], {"sha": 0, "tag": 0, "branch": 0, "short-sha": 0, "local": 0, "docker": 0, "other": 0}
    for u in facts.uses:
        kind, repo, ref = classify(u.value)
        if kind == "sha":
            counts["sha"] += 1
        elif kind in ("local", "dynamic"):   # dynamic = built from an expression, cannot be judged statically
            counts["local"] += 1
        elif kind == "docker-digest":
            counts["docker"] += 1
        elif kind == "docker-tag":
            counts["docker"] += 1
            out.append(Finding(path, u.line, "unpinned-docker", "medium", f"{u.value} uses a mutable image tag, no @sha256 digest", u.value))
        elif kind == "short-sha":
            counts["short-sha"] += 1
            out.append(Finding(path, u.line, "short-sha", "high", f"{u.value}: an abbreviated commit SHA is not accepted as a pin; use the full 40 characters", u.value))
        elif kind == "branch":
            counts["branch"] += 1
            out.append(Finding(path, u.line, "branch-ref", "high", f"{u.value} follows branch '{ref}': every push to it runs here", u.value))
        elif kind == "tag":
            counts["tag"] += 1
            sev = "low" if repo.startswith(FIRST_PARTY) else "medium"
            out.append(Finding(path, u.line, "unpinned-action", sev, f"{u.value} is a tag, which its owner can move; pin the commit SHA", u.value))
        else:
            counts["other"] += 1
            out.append(Finding(path, u.line, "no-ref", "high", f"{u.value} has no @ref at all", u.value))
    return out, counts


def check_risks(facts: Facts, path: str):
    out = []
    code = facts.code
    jobs_at = next((n for n, t in code if re.match(r"^jobs:\s*$", t)), 10 ** 9)
    trig = {}
    for n, t in code:
        if n < jobs_at:
            for name in ("pull_request_target", "workflow_run"):
                if re.search(rf"\b{name}\b", t):
                    trig.setdefault(name, n)
    if "pull_request_target" in trig:
        out.append(Finding(path, trig["pull_request_target"], "pull-request-target", "low",
                           "pull_request_target runs with write token and secrets on code from forks; keep it away from untrusted checkouts"))
    if trig:
        for n, t in code:
            if HEAD_CHECKOUT.search(t):
                trig_name = "pull_request_target" if "pull_request_target" in trig else "workflow_run"
                out.append(Finding(path, n, "untrusted-checkout", "high",
                                   f"checks out the pull request / triggering branch under {trig_name}, so fork code runs with the privileged token"))
    perms = [(n, t) for n, t in code if re.match(r"^\s*permissions:", t)]
    if not perms and any(re.match(r"^jobs:", t) for _, t in code):
        out.append(Finding(path, 1, "no-permissions", "low",
                           "no `permissions:` block: the GITHUB_TOKEN gets the repository/org default, which may include write"))
    for n, t in perms:
        if re.search(r"permissions:\s*write-all\b", t):
            out.append(Finding(path, n, "write-all", "medium", "permissions: write-all grants every scope; list only the scopes the job needs"))
    for n, t in code:
        if re.search(r"\bsecrets:\s*inherit\b", t):
            out.append(Finding(path, n, "secrets-inherit", "low", "secrets: inherit hands every secret to the called workflow"))
        if re.search(r"\bACTIONS_ALLOW_UNSECURE_COMMANDS:\s*['\"]?true", t):
            out.append(Finding(path, n, "unsecure-commands", "medium", "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables the deprecated set-env / add-path commands"))
        if re.search(r"\bruns-on:.*\bself-hosted\b", t) or re.match(r"^\s*-\s*self-hosted\s*$", t):
            out.append(Finding(path, n, "self-hosted", "low", "self-hosted runner: jobs from forks or untrusted triggers can persist on that machine"))
    for n, key, body in facts.scripts:
        for k, line in enumerate(body.splitlines()):
            for m in UNTRUSTED.finditer(line):
                out.append(Finding(path, n + k, "script-injection", "high",
                                   f"{m.group(0)} is expanded into the {key} script before the shell sees it; pass it through an env: variable"))
            if PIPE_SHELL.search(line):
                out.append(Finding(path, n + k, "pipe-to-shell", "medium", "downloads a script and pipes it into a shell without a checksum"))
    return out
