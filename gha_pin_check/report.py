from __future__ import annotations
import json
from . import __version__
from .scanner import RULES

SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}
REPO_URL = "https://github.com/MegaStretch23/gha-pin-check"


def to_text(findings, files_scanned: int) -> str:
    out = []
    for f in findings:
        out.append(f"{f.file}:{f.line}: [{f.severity}] {f.rule} {f.message}")
        if f.extra.get("suggested"):
            out.append(f"    suggested: {f.extra['suggested']}")
        elif f.extra.get("resolve_error"):
            out.append(f"    could not resolve: {f.extra['resolve_error']}")
    c = {s: sum(1 for f in findings if f.severity == s) for s in ("high", "medium", "low")}
    out.append(f"{len(findings)} finding(s) in {files_scanned} file(s): {c['high']} high, {c['medium']} medium, {c['low']} low")
    return "\n".join(out)


def to_json(findings, files_scanned: int) -> str:
    return json.dumps({"tool": "gha-pin-check", "version": __version__, "files_scanned": files_scanned,
                       "findings": [f.to_dict() for f in findings]}, indent=2)


def to_sarif(findings, files_scanned: int) -> str:
    used = sorted({f.rule for f in findings} | set(RULES))
    rules = [{"id": r, "name": RULES[r][0], "shortDescription": {"text": RULES[r][2]},
              "defaultConfiguration": {"level": SARIF_LEVEL[RULES[r][1]]}} for r in used]
    results = []
    for f in findings:
        res = {"ruleId": f.rule, "ruleIndex": used.index(f.rule), "level": SARIF_LEVEL[f.severity], "message": {"text": f.message},
               "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file.replace("\\", "/")},
                                                   "region": {"startLine": f.line}}}]}
        if f.extra.get("suggested"):
            res["properties"] = {"suggested": f.extra["suggested"]}
        results.append(res)
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "gha-pin-check", "version": __version__, "informationUri": REPO_URL, "rules": rules}},
                     "results": results}]}
    return json.dumps(doc, indent=2)
