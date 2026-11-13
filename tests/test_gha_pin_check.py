import json
import os
import textwrap

import pytest

from gha_pin_check import cli, parse, rules

SHA = "a" * 40

WF = f"""\
name: ci
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - uses: "thirdparty/tool@v1.2" # pinned later
      - uses: other/thing@main
      - uses: ok/pinned@{SHA} # v3
      - uses: ./local-action
      - uses: docker://alpine:3.19
      - uses: docker://alpine@sha256:{'b' * 64}
      - uses: x/y@abc1234
      - run: echo "${{{{ github.event.issue.title }}}}"
      - run: |
          echo hello
          echo "${{{{ github.head_ref }}}}"
          curl -fsSL https://example.com/i.sh | sudo bash
      - name: not a use
        run: |
          # uses: fake/inside-script@v1
          echo done
"""


def facts():
    return parse.read(WF)


def by_rule(findings, rule):
    return [f for f in findings if f.rule == rule]


def test_classify():
    c = rules.classify
    assert c(f"a/b@{SHA}")[0] == "sha"
    assert c("a/b@v4")[0] == "tag"
    assert c("a/b@v4.1.2")[0] == "tag"
    assert c("a/b@main")[0] == "branch"
    assert c("a/b@release/v1")[0] == "branch"
    assert c("a/b@abc1234")[0] == "short-sha"
    assert c("./x")[0] == "local"
    assert c("docker://alpine:3")[0] == "docker-tag"
    assert c("docker://a@sha256:" + "c" * 64)[0] == "docker-digest"
    assert c("a/b/sub/dir@v1") == ("tag", "a/b", "v1")
    assert c("a/b")[0] == "no-ref"
    assert c("${{ github.workspace }}/act")[0] == "dynamic" and c("$/x")[0] == "dynamic"


def test_uses_found_and_script_text_ignored():
    vals = [u.value for u in facts().uses]
    assert "actions/checkout@v4" in vals and "thirdparty/tool@v1.2" in vals
    assert not any("fake/inside-script" in v for v in vals)
    assert [u.comment for u in facts().uses if u.value == "thirdparty/tool@v1.2"] == ["pinned later"]


def test_pinning_findings_and_counts():
    f, counts = rules.check_uses(facts(), "w.yml")
    assert counts["sha"] == 1 and counts["tag"] == 2 and counts["branch"] == 1 and counts["local"] == 1 and counts["docker"] == 2
    sev = {x.uses: x.severity for x in f}
    assert sev["actions/checkout@v4"] == "low"          # first party tag
    assert sev["thirdparty/tool@v1.2"] == "medium"      # third party tag
    assert sev["other/thing@main"] == "high"
    assert sev["x/y@abc1234"] == "high"
    assert sev["docker://alpine:3.19"] == "medium"
    assert len(f) == 5


def test_untrusted_checkout_under_pull_request_target():
    r = rules.check_risks(facts(), "w.yml")
    assert len(by_rule(r, "pull-request-target")) == 1
    assert len(by_rule(r, "untrusted-checkout")) == 1


def test_script_injection_lines():
    r = by_rule(rules.check_risks(facts(), "w.yml"), "script-injection")
    lines = sorted(x.line for x in r)
    text = WF.splitlines()
    assert len(lines) == 2
    for ln in lines:
        assert "${{" in text[ln - 1]
    assert any("issue.title" in text[ln - 1] for ln in lines) and any("head_ref" in text[ln - 1] for ln in lines)


def test_pipe_to_shell_line():
    r = by_rule(rules.check_risks(facts(), "w.yml"), "pipe-to-shell")
    assert len(r) == 1 and "curl" in WF.splitlines()[r[0].line - 1]


def test_safe_workflow_has_only_clean_result():
    wf = textwrap.dedent(f"""\
        on: push
        permissions:
          contents: read
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{SHA} # v4
              - run: echo "${{{{ github.sha }}}}"
              - env:
                  TITLE: ${{{{ github.event.issue.title }}}}
                run: echo "$TITLE"
        """)
    fa = parse.read(wf)
    f, _ = rules.check_uses(fa, "s.yml")
    assert f == [] and rules.check_risks(fa, "s.yml") == []


def test_no_permissions_and_write_all():
    a = parse.read("on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: ls\n")
    assert [f.rule for f in rules.check_risks(a, "a.yml")] == ["no-permissions"]
    b = parse.read("on: push\npermissions: write-all\njobs:\n  j:\n    runs-on: x\n")
    assert [f.rule for f in rules.check_risks(b, "b.yml")] == ["write-all"]


def test_self_hosted_secrets_inherit_unsecure():
    t = "on: push\npermissions: {}\njobs:\n  j:\n    runs-on: [self-hosted, linux]\n    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n  k:\n    uses: o/r/.github/workflows/x.yml@" + SHA + "\n    secrets: inherit\n"
    got = sorted(f.rule for f in rules.check_risks(parse.read(t), "c.yml"))
    assert got == ["secrets-inherit", "self-hosted", "unsecure-commands"]


def test_cli_dir_json_and_fail_on(tmp_path, capsys):
    wd = tmp_path / ".github" / "workflows"
    wd.mkdir(parents=True)
    (wd / "ci.yml").write_text(WF)
    assert cli.main([str(tmp_path), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["files"] == 1 and out["uses"]["sha"] == 1
    assert {f["rule"] for f in out["findings"]} >= {"branch-ref", "script-injection", "untrusted-checkout"}
    assert all(f["file"] == os.path.join(".github", "workflows", "ci.yml") for f in out["findings"])
    assert cli.main([str(tmp_path), "--fail-on", "high"]) == 1
    assert cli.main([str(tmp_path), "--min-severity", "high", "--fail-on", "high"]) == 1


def test_cli_no_files_is_an_error_not_clean(tmp_path, capsys):
    assert cli.main([str(tmp_path)]) == 2
    assert "no workflow or action files" in capsys.readouterr().err


def test_resolve_suggestion_and_failure(tmp_path, capsys):
    p = tmp_path / "w.yml"
    p.write_text("on: push\npermissions: {}\njobs:\n  j:\n    runs-on: x\n    steps:\n      - uses: a/b@v1\n      - uses: c/d@v2\n")

    def fake(repo, ref):
        if repo == "c/d":
            raise RuntimeError("HTTP 404 for c/d@v2")
        return "1" * 40

    f, tot, errs, n = cli.scan([str(p)], resolver=fake)
    sugg = {x.uses: x.suggestion for x in f}
    assert sugg["a/b@v1"] == "a/b@" + "1" * 40 + " # v1"
    assert sugg["c/d@v2"] == "" and len(errs) == 1 and "HTTP 404" in errs[0]


def test_module_entry_point(tmp_path):
    import subprocess, sys
    p = tmp_path / "w.yml"
    p.write_text("on: push\npermissions: {}\njobs:\n  j:\n    runs-on: x\n    steps:\n      - uses: a/b@main\n")
    r = subprocess.run([sys.executable, "-m", "gha_pin_check", str(p), "--fail-on", "high"],
                       capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
    assert r.returncode == 1 and "branch-ref" in r.stdout
