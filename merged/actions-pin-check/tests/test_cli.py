"""run: python3 -I tests/test_cli.py   (stdlib unittest; no network: --resolve is tested with a fake resolver)"""
import io, json, os, sys, unittest, contextlib
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(here))
import actions_pin_check as A  # noqa: E402

FX = os.path.join(here, "fixtures")
SHA = "a" * 40


def scan(n):
    with open(os.path.join(FX, n), encoding="utf-8") as f:
        return A.scan_text(f.read(), n)


def run(argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    old = sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = A.main(argv)
    finally:
        sys.stdin = old
    return rc, out.getvalue(), err.getvalue()


class T(unittest.TestCase):
    def test_exit_codes_and_json(self):
        self.assertEqual(run([os.path.join(FX, "good.yml")])[0], 0)
        self.assertEqual(run([os.path.join(FX, "unpinned_tag.yml")])[0], 1)
        self.assertEqual(run([os.path.join(FX, "unpinned_tag.yml"), "--fail-on", "fail"])[0], 0)
        rc, out, _ = run([os.path.join(FX, "unpinned_branch.yml"), "--json"])
        j = json.loads(out)
        self.assertEqual((rc, j["verdict"], j["tool"]), (2, "FAIL", "actions-pin-check"))
        self.assertEqual(j["files"][0]["counts"]["FAIL"], 2)
        self.assertEqual(run([os.path.join(FX, "missing.yml")])[0], 3)
        self.assertEqual(run(["-"], "name: x\njobs:\n  a:\n    steps:\n      - uses: o/r@main\n")[0], 2)

    def test_directory_and_worst_verdict(self):
        rc, out, _ = run([FX, "--json"])
        j = json.loads(out)
        self.assertEqual(rc, 2)
        self.assertEqual(len(j["files"]), 18)
        self.assertEqual(j["verdict"], "FAIL")

    def test_directory_with_github_workflows(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            w = os.path.join(d, ".github", "workflows"); os.makedirs(w)
            with open(os.path.join(w, "a.yml"), "w") as f: f.write("on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: o/r@" + SHA + "\n")
            with open(os.path.join(w, "notes.txt"), "w") as f: f.write("x")
            rc, out, _ = run([d, "--json"])
            self.assertEqual((rc, len(json.loads(out)["files"])), (0, 1))

    def test_resolve_with_fake_resolver(self):
        rep = scan("unpinned_tag.yml")
        calls = []
        A.apply_resolve(rep, lambda o, r, ref: calls.append((o, r, ref)) or SHA)
        self.assertEqual(calls, [("actions", "checkout", "v4"), ("actions", "setup-python", "v5.1.0")])
        sug = [f["suggestion"] for f in rep["findings"] if f.get("resolved_sha")]
        self.assertEqual(sug, [f"uses: actions/checkout@{SHA} # v4", f"uses: actions/setup-python@{SHA} # v5.1.0"])
        rep = scan("unpinned_branch.yml")
        def boom(o, r, ref): raise OSError("offline")
        A.apply_resolve(rep, boom)
        self.assertTrue(all("resolve_error" in f for f in rep["findings"] if f["code"] == "AP_UNPINNED_BRANCH"))
        # sub-path actions resolve against owner/repo only
        rep = scan("unpinned_branch.yml"); seen = []
        A.apply_resolve(rep, lambda o, r, ref: seen.append((o, r, ref)) or None)
        self.assertIn(("other-org", "tools", "release/v2"), seen)

    def test_no_network_without_resolve(self):
        import urllib.request
        old = urllib.request.urlopen
        urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used"))
        try:
            run([os.path.join(FX, "unpinned_tag.yml")])
        finally:
            urllib.request.urlopen = old

    def test_comment_and_text_not_flagged(self):
        t = "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      # - uses: o/r@main\n      - run: echo 'uses: o/r@main'\n      - uses: o/r@" + SHA + " # main\n"
        r = A.scan_text(t)
        self.assertEqual(r["verdict"], "PASS", r["findings"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
