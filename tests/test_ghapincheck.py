import json
import os
import textwrap

import pytest

from ghapincheck import cli
from ghapincheck.fix import pin_text
from ghapincheck.scan import classify_ref, parse_uses, scan_paths, scan_text

SHA = "a" * 40


def rules(text, **kw):
    f, _ = scan_text("w.yml", textwrap.dedent(text), **kw)
    return [(x["rule"], x["severity"]) for x in f]


def test_classify_ref():
    assert classify_ref(SHA) == "sha"
    assert classify_ref("v4") == "tag" and classify_ref("1.2.3") == "tag" and classify_ref("v1.2.3-rc.1") == "tag"
    assert classify_ref("main") == "branch" and classify_ref("release/v1") == "branch"
    assert classify_ref("abc1234") == "short-sha"
    assert classify_ref("") == "missing"


def test_parse_uses_forms():
    assert parse_uses("./local")[0] == "local"
    assert parse_uses("docker://alpine:3.19")[:2] == ("docker", "alpine:3.19")
    assert parse_uses("o/r/sub/dir@v1") == ("action", "o/r", "sub/dir", "v1")


def test_pinned_and_local_are_clean():
    r = rules(f"""
        permissions: read-all
        jobs:
          a:
            steps:
              - uses: actions/checkout@{SHA} # v4
              - uses: ./.github/actions/x
              - uses: docker://alpine@sha256:{'b' * 64}
    """)
    assert r == []


def test_tag_severity_first_vs_third_party():
    r = rules("""
        permissions: {}
        jobs:
          a:
            steps:
              - uses: actions/checkout@v4
              - uses: "acme/deploy@v2"
    """)
    assert r == [("unpinned-tag", "low"), ("unpinned-tag", "medium")]
    r2 = rules("permissions: {}\nsteps:\n  - uses: actions/checkout@v4\n", first_party=())
    assert r2 == [("unpinned-tag", "medium")]


def test_branch_missing_and_short_sha_and_docker():
    r = rules("""
        permissions: {}
        steps:
          - uses: acme/a@main
          - uses: acme/b
          - uses: acme/c@1a2b3c4
          - uses: docker://node:20
    """)
    assert r == [("unpinned-branch", "high"), ("unpinned-branch", "high"), ("short-sha", "high"), ("unpinned-docker", "medium")]


def test_unrecognized_uses_is_not_called_unpinned():
    assert rules("permissions: {}\nsteps:\n  - uses: $/.github/actions/x\n  - uses: ${{ matrix.action }}\n") == [("unrecognized-uses", "low")] * 2


def test_reusable_workflow_path_checked():
    assert rules("permissions: {}\njobs:\n  c:\n    uses: acme/wf/.github/workflows/ci.yml@v3\n") == [("unpinned-tag", "medium")]


def test_script_injection_block_and_inline_and_safe_env():
    t = """
        permissions: {}
        on: issues
        jobs:
          a:
            steps:
              - name: bad
                run: |
                  echo "${{ github.event.issue.title }}"
                  echo ok
              - run: echo ${{ github.head_ref }}
              - name: good
                env:
                  TITLE: ${{ github.event.issue.title }}
                run: |
                  echo "$TITLE"
                  echo ${{ github.sha }}
    """
    f, _ = scan_text("w.yml", textwrap.dedent(t))
    inj = [x for x in f if x["rule"] == "script-injection"]
    assert [x["line"] for x in inj] == [9, 11]


def test_script_block_ends_at_dedent():
    t = """
        permissions: {}
        steps:
          - run: |
              echo hi
          - name: later
            with:
              x: ${{ github.event.issue.title }}
    """
    assert rules(t) == []


def test_github_script_injection():
    t = """
        permissions: {}
        steps:
          - uses: actions/github-script@v7
            with:
              script: |
                console.log("${{ github.event.comment.body }}")
    """
    assert ("script-injection", "high") in rules(t)


def test_pwn_request():
    t = """
        permissions: {}
        on:
          pull_request_target:
        jobs:
          a:
            steps:
              - uses: actions/checkout@%s
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
    """ % SHA
    assert rules(t) == [("pwn-request", "high")]
    assert rules(t.replace("pull_request_target", "pull_request")) == []


def test_permissions():
    assert rules("jobs:\n  a:\n    steps: []\n") == [("permissions-missing", "low")]
    assert rules("permissions: write-all\n") == [("permissions-write-all", "high")]
    assert rules("jobs:\n  a:\n    permissions:\n      contents: read\n") == []
    assert rules("steps: []\n", is_workflow=False) == []


def test_comments_are_ignored_for_triggers():
    t = "permissions: {}\n# on: pull_request_target\non: push\njobs:\n  a:\n    steps:\n      - with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    assert rules(t) == []


def make_repo(tmp_path, files):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return str(tmp_path)


def test_discovery_and_exit_codes(tmp_path, capsys):
    root = make_repo(tmp_path, {
        ".github/workflows/ci.yml": "permissions: {}\njobs:\n  a:\n    steps:\n      - uses: acme/x@main\n",
        ".github/workflows/notes.txt": "uses: acme/ignored@main\n",
        "action.yml": "runs:\n  using: composite\n  steps:\n    - uses: acme/y@v1\n",
        "src/other/action.yml": "uses: acme/ignored@main\n",
    })
    res = scan_paths([root])
    assert len(res["files"]) == 2 and res["uses"] == 2
    assert cli.main([root]) == 1
    out = capsys.readouterr().out
    assert "unpinned-branch" in out and "2 files, 2 uses: lines, 2 findings" in out
    assert cli.main([root, "--fail-on", "none"]) == 0
    assert cli.main([root, "--format", "json", "--fail-on", "none"]) == 0


def test_json_format(tmp_path, capsys):
    root = make_repo(tmp_path, {".github/workflows/ci.yml": "permissions: {}\nsteps:\n  - uses: acme/x@v1\n"})
    assert cli.main([root, "--format", "json"]) == 1
    d = json.loads(capsys.readouterr().out)
    assert d["findings"][0]["rule"] == "unpinned-tag" and d["uses"] == 1


def test_no_files_and_missing_path_exit_2(tmp_path, capsys):
    assert cli.main([str(tmp_path)]) == 2
    assert cli.main([str(tmp_path / "nope")]) == 2


def test_clean_repo_exit_0(tmp_path):
    root = make_repo(tmp_path, {".github/workflows/ci.yml": f"permissions: {{}}\nsteps:\n  - uses: acme/x@{SHA}\n"})
    assert cli.main([root]) == 0


def test_pin_text_rewrites_keeps_comment_and_quotes():
    calls = []

    def res(name, ref):
        calls.append((name, ref))
        return SHA

    src = 'steps:\n  - uses: actions/checkout@v4\n  - uses: "acme/x/sub@main" # old note\n  - uses: ./local\n  - uses: acme/y@%s\n' % ("c" * 40)
    new, ch, err = pin_text(src, res)
    lines = new.split("\n")
    assert lines[1] == f"  - uses: actions/checkout@{SHA} # v4"
    assert lines[2] == f'  - uses: "acme/x/sub@{SHA}" # main (old note)'
    assert lines[3] == "  - uses: ./local" and lines[4].endswith("c" * 40)
    assert len(ch) == 2 and not err and calls == [("actions/checkout", "v4"), ("acme/x", "main")]
    # the rewritten file scans clean
    assert [f["rule"] for f in scan_text("w", new)[0] if f["rule"].startswith(("unpinned", "short"))] == []


def test_pin_text_resolver_error_is_reported_not_swallowed():
    def boom(n, r):
        raise RuntimeError("HTTP 404")

    new, ch, err = pin_text("- uses: acme/x@v1\n", boom)
    assert new == "- uses: acme/x@v1\n" and not ch and err and "HTTP 404" in err[0]


def test_fix_cli_with_stub_resolver(tmp_path, monkeypatch, capsys):
    root = make_repo(tmp_path, {".github/workflows/ci.yml": "permissions: {}\nsteps:\n  - uses: acme/x@v1\n"})
    monkeypatch.setattr(cli, "make_cached", lambda: (lambda n, r: SHA))
    assert cli.main([root, "--fix"]) == 0
    assert (tmp_path / ".github/workflows/ci.yml").read_text().count(f"acme/x@{SHA} # v1") == 1


def test_fix_cli_error_exit_2(tmp_path, monkeypatch):
    root = make_repo(tmp_path, {".github/workflows/ci.yml": "permissions: {}\nsteps:\n  - uses: acme/x@v1\n"})

    def boom(n, r):
        raise RuntimeError("offline")

    monkeypatch.setattr(cli, "make_cached", lambda: boom)
    assert cli.main([root, "--fix"]) == 2
