"""Line-based reader for GitHub Actions YAML. Not a YAML parser: it finds `uses:` lines,
block scalars (`run: |`, `script: |`) and plain code lines, which is all the rules need."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

BLOCK_RX = re.compile(r"^(?P<indent>\s*)(?P<dash>-\s+)?(?P<key>[\w.-]+):\s*[|>][+-]?\d?\s*(?:#.*)?$")
KEYVAL_RX = re.compile(r"^(?P<indent>\s*)(?P<dash>-\s+)?(?P<key>[\w.-]+):(?:\s+(?P<val>.*))?$")
INJECT_KEYS = {"run", "script"}


@dataclass
class Use:
    line: int
    value: str
    comment: str


@dataclass
class Facts:
    uses: list = field(default_factory=list)       # [Use]
    scripts: list = field(default_factory=list)    # [(first_line, key, text)] run:/script: bodies, inline or block (line of the first text line)
    code: list = field(default_factory=list)       # [(line, text)] outside block scalars, comments stripped


def split_value(raw: str):
    """`'actions/x@v1' # note` -> ("actions/x@v1", "note")."""
    raw = raw.strip()
    if raw[:1] in "\"'":
        q = raw[0]
        end = raw.find(q, 1)
        if end != -1:
            rest = raw[end + 1:].strip()
            return raw[1:end], rest[1:].strip() if rest.startswith("#") else ""
    m = re.search(r"\s#", raw)
    if m:
        return raw[:m.start()].strip(), raw[m.end():].strip()
    return raw, ""


def strip_comment(text: str) -> str:
    if text.lstrip().startswith("#"):
        return ""
    return re.split(r"\s#", text, maxsplit=1)[0].rstrip()


def indent_of(s: str) -> int:
    return len(s) - len(s.lstrip(" "))


def read(text: str) -> Facts:
    f = Facts()
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        n = i + 1
        m = BLOCK_RX.match(raw)
        if m:
            key_col = len(m.group("indent")) + (len(m.group("dash")) if m.group("dash") else 0)
            body, j = [], i + 1
            while j < len(lines) and (not lines[j].strip() or indent_of(lines[j]) > key_col):
                body.append(lines[j]); j += 1
            if m.group("key") in INJECT_KEYS:
                f.scripts.append((n + 1, m.group("key"), "\n".join(body)))
            f.code.append((n, strip_comment(raw)))
            i = j
            continue
        code = strip_comment(raw)
        if code.strip():
            f.code.append((n, code))
            kv = KEYVAL_RX.match(raw)
            if kv and kv.group("val"):
                val, comment = split_value(kv.group("val"))
                if kv.group("key") == "uses" and val:
                    f.uses.append(Use(n, val, comment))
                elif kv.group("key") in INJECT_KEYS and val:
                    f.scripts.append((n, kv.group("key"), val))
        i += 1
    return f
