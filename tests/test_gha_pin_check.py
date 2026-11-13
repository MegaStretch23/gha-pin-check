import json, subprocess, sys, urllib.error
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from gha_pin_check.scanner import scan_text, strip_comment  # noqa: E402
from gha_pin_check import cli, resolve, report  # noqa: E402

REAL = ROOT / "tests" / "fixtures" / "real"
SYN = ROOT / "tests" / "fixtures" / "synthetic"


def scan(p):
    return scan_text(p.read_text(encoding="utf-8"), p.name)


def rules(fs):
    return [f.rule for f in fs]


def test_real_psf_requests_publish_is_fully_pinned_and_clean():
    assert scan(REAL / "psf_requests__publish.yml") == []


def test_all_psf_requests_workflows_have_no_unpinned_actions():
    for p in REAL.glob("psf_requests__*.yml"):
        assert "GHA001" not in rules(scan(p)), p.name


def test_real_ky_flags_four_unpinned_refs_with_names():
    fs = [f for f in scan(REAL / "sindresorhus_ky__main.yml") if f.rule == "GHA001"]
    assert [f.extra["uses"] for f in fs] == ["actions/checkout@v6", "actions/setup-node@v6"] * 2
    assert [f.line for f in fs] == [17, 18, 28, 29]


def test_real_ky_missing_permissions_per_job():
    fs = [f for f in scan(REAL / "sindresorhus_ky__main.yml") if f.rule == "GHA005"]
    assert sorted(f.extra["job"] for f in fs) == ["browser", "test"]


def test_real_nextjs_curl_pipe_sh_line():
    fs = [f for f in scan(REAL / "vercel_next.js__build_and_deploy.yml") if f.rule == "GHA006"]
    assert [f.line for f in fs] == [532]


def test_real_rust_curl_pipe_sh_inside_block_scalar():
    fs = [f for f in scan(REAL / "rust-lang_rust__ci.yml") if f.rule == "GHA006"]
    assert [f.line for f in fs] == [112]


def test_real_deno_dispatch_input_is_medium_injection():
    fs = [f for f in scan(REAL / "denoland_deno__start_release.generated.yml") if f.rule == "GHA004"]
    assert len(fs) == 1 and fs[0].severity == "medium" and fs[0].extra["expression"] == "github.event.inputs.releaseKind"


def test_real_event_numbers_and_shas_are_low_not_high():
    fs = [f for f in scan(REAL / "nodejs_node__nix-changes.yml") if f.rule == "GHA004"]
    assert fs and all(f.severity == "low" for f in fs)


def test_real_prt_without_head_checkout_is_not_flagged():
    for n in ("nodejs_node__commit-lint.yml", "tiangolo_fastapi__guard-dependencies.yml"):
        assert "GHA003" not in rules(scan(REAL / n)), n


def test_synthetic_prt_head_checkout_is_high():
    fs = [f for f in scan(SYN / "prt_checkout_head.yml") if f.rule == "GHA003"]
    assert len(fs) == 1 and fs[0].severity == "high" and fs[0].line == 15


def test_synthetic_prt_base_checkout_is_not_flagged():
    assert rules(scan(SYN / "prt_checkout_base.yml")) == []


def test_free_text_event_field_is_high_and_script_body_uses_ignored():
    fs = scan(SYN / "injection_and_docker.yml")
    inj = [f for f in fs if f.rule == "GHA004"]
    assert len(inj) == 1 and inj[0].severity == "high" and inj[0].line == 13
    assert not [f for f in fs if f.rule == "GHA001"]   # "uses: not/a-real@v1" sits inside a run: block


def test_docker_digest_pinning_and_local_actions():
    fs = scan(SYN / "injection_and_docker.yml")
    assert [f.extra["uses"] for f in fs if f.rule == "GHA002"] == ["docker://alpine:3.19"]


def test_write_all_job_and_top_level():
    assert [(f.rule, f.severity) for f in scan(SYN / "injection_and_docker.yml") if f.rule == "GHA005"] == [("GHA005", "high")]
    assert [(f.rule, f.severity, f.line) for f in scan(SYN / "permissions_variants.yml")] == [("GHA005", "high", 4)]


def test_multiline_curl_pipe_sudo_bash_detected():
    assert "GHA006" in rules(scan(SYN / "injection_and_docker.yml"))


def test_strip_comment_and_quotes():
    assert strip_comment('"actions/checkout@abc" # v7') == "actions/checkout@abc"
    assert strip_comment("x@y   # note") == "x@y"
    assert strip_comment("") == ""


def test_sha_with_uppercase_and_short_sha_cases():
    ok = "jobs:\n  a:\n    permissions: {}\n    steps:\n      - uses: a/b@" + "A" * 40 + "\n"
    short = ok.replace("A" * 40, "abc1234")
    assert rules(scan_text(ok)) == [] and rules(scan_text(short)) == ["GHA001"]


def test_json_format_and_fail_on(tmp_path):
    out, code = cli.run([str(REAL / "sindresorhus_ky__main.yml")], "json", "medium")
    d = json.loads(out)
    assert code == 1 and d["files_scanned"] == 1 and {f["rule"] for f in d["findings"]} == {"GHA001", "GHA005"}
    assert cli.run([str(REAL / "sindresorhus_ky__main.yml")], "text", "high")[1] == 0
    assert cli.run([str(REAL / "sindresorhus_ky__main.yml")], "text", None)[1] == 0


def test_sarif_structure():
    out, _ = cli.run([str(SYN / "prt_checkout_head.yml")], "sarif")
    d = json.loads(out)
    run = d["runs"][0]
    assert d["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "gha-pin-check"
    r = run["results"][0]
    assert r["ruleId"] == "GHA003" and r["level"] == "error"
    assert r["locations"][0]["physicalLocation"]["region"]["startLine"] == 15
    assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == "GHA003"


def test_directory_discovery_uses_dot_github_workflows(tmp_path):
    wf = tmp_path / ".github" / "workflows"; wf.mkdir(parents=True)
    (wf / "a.yml").write_text("on: push\njobs:\n  x:\n    permissions: {}\n    steps:\n      - uses: a/b@v1\n")
    (wf / "b.yaml").write_text("on: push\n"); (wf / "notes.txt").write_text("uses: a/b@v1")
    out, _ = cli.run([str(tmp_path)], "json")
    d = json.loads(out)
    assert d["files_scanned"] == 2 and len(d["findings"]) == 1


def test_missing_path_exit_code_2():
    r = subprocess.run([sys.executable, "-m", "gha_pin_check.cli", "/nonexistent/x"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 2


def test_resolve_with_fake_api_tag_and_annotated_tag():
    calls = []
    def fake(path):
        calls.append(path)
        if path.endswith("/git/ref/tags/v6"):
            return {"object": {"type": "tag", "sha": "t" * 40}}
        if path.endswith("/git/tags/" + "t" * 40):
            return {"object": {"type": "commit", "sha": "c" * 40}}
        raise urllib.error.HTTPError(path, 404, "nf", {}, None)
    out, _ = cli.run([str(REAL / "sindresorhus_ky__main.yml")], "text", None, True, get=fake)
    assert f"uses: actions/checkout@{'c' * 40} # v6" in out
    assert len([c for c in calls if c.endswith("/git/ref/tags/v6")]) == 2   # one per action, cached across the 2 files' repeats


def test_resolve_offline_degrades_without_crashing():
    def dead(path):
        raise urllib.error.URLError("no network")
    out, code = cli.run([str(REAL / "sindresorhus_ky__main.yml")], "text", "medium", True, get=dead)
    assert "could not resolve: URLError" in out and code == 1


def test_resolve_falls_back_to_branch_and_reports_rate_limit():
    def branch_only(path):
        if "/git/ref/heads/main" in path:
            return {"object": {"type": "commit", "sha": "d" * 40}}
        raise urllib.error.HTTPError(path, 404, "nf", {}, None)
    assert resolve.lookup("a/b", "main", branch_only) == ("d" * 40, None)
    def limited(path):
        raise urllib.error.HTTPError(path, 403, "rl", {}, None)
    sha, err = resolve.lookup("a/b", "v1", limited)
    assert sha is None and "rate limited" in err


def test_ignore_rule():
    out, _ = cli.run([str(REAL / "sindresorhus_ky__main.yml")], "json", None, False, ["GHA001"])
    assert {f["rule"] for f in json.loads(out)["findings"]} == {"GHA005"}
