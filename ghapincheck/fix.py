"""Rewrite unpinned `uses:` lines to full-SHA pins, keeping the original ref as a comment."""
from __future__ import annotations

from .scan import USES_RE, classify_ref, parse_uses


def pin_text(text, resolver):
    """-> (new_text, changes, errors). resolver(owner_repo, ref) -> sha; may raise (message in errors)."""
    out, changes, errors = [], [], []
    for i, raw in enumerate(text.split("\n")):
        m = USES_RE.match(raw.rstrip("\r"))
        if not m:
            out.append(raw)
            continue
        kind, name, sub, ref = parse_uses(m.group("val"))
        if kind != "action" or classify_ref(ref) not in ("tag", "branch", "short-sha") or not ref:
            out.append(raw)
            continue
        try:
            sha = resolver(name, ref)
        except Exception as e:  # reported, never silently skipped
            errors.append(f"line {i + 1}: {e}")
            out.append(raw)
            continue
        spec = name + (("/" + sub) if sub else "")
        old = (m.group("comment") or "").strip()
        note = f"# {ref}" + (f" ({old})" if old else "")
        q = m.group("q")
        out.append(f"{m.group('pre')}{q}{spec}@{sha}{q} {note}")
        changes.append({"line": i + 1, "from": m.group("val"), "to": f"{spec}@{sha}"})
    return "\n".join(out), changes, errors
