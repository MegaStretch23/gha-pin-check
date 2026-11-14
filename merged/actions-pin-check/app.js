/* Actions Pin Check - UI. The pasted workflow is only read in this tab; the page code makes no network calls. */
(function () {
  "use strict";
  var P = window.ActionsPin, $ = function (id) { return document.getElementById(id); };
  var last = null;
  var EXAMPLE = [
    "name: example", "on:", "  pull_request_target:", "    types: [opened]", "jobs:", "  build:", "    runs-on: ubuntu-latest", "    steps:",
    "      - uses: actions/checkout@v4", "        with:", "          ref: ${{ github.event.pull_request.head.sha }}",
    "      - uses: some-org/some-action@main",
    "      - name: greet", "        run: echo \"PR title: ${{ github.event.pull_request.title }}\"",
    "      - name: install", "        run: curl -sSL https://example.com/install.sh | sh", ""].join("\n");

  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
  function say(text, ok) { var m = $("status"); m.textContent = text; m.className = "msg " + (ok === true ? "ok" : ok === false ? "err" : ""); }

  function render(r) {
    last = r; $("report").hidden = false;
    var v = $("verdict"); v.className = "verdict v-" + r.verdict; v.textContent = "";
    v.appendChild(el("b", "", r.verdict));
    v.appendChild(el("span", "", r.counts.FAIL + " fail, " + r.counts.WARN + " warn"));
    $("fileinfo").textContent = r.file.lines + " lines checked";
    var box = $("findings"); box.textContent = "";
    r.findings.forEach(function (f) {
      var d = el("div", "f l-" + f.level); d.appendChild(el("span", "tag l-" + f.level, f.level));
      d.appendChild(el("b", "", f.code + (f.line ? " (line " + f.line + ") " : " ")));
      d.appendChild(document.createTextNode(f.message));
      if (f.suggestion) d.appendChild(el("span", "fix", "fix: " + f.suggestion));
      box.appendChild(d);
    });
    $("limits").textContent = r.limits + " This page does not look up SHAs; the CLI does with --resolve.";
  }

  function check() {
    var t = $("wf").value;
    if (!t.trim()) { say("Paste a workflow first.", false); return; }
    var r = P.scanText(t, "pasted-workflow.yml"); r.tool = P.TOOL; r.version = P.VERSION; r.limits = P.LIMITS;
    render(r); say("Done: " + r.verdict + ".", r.verdict !== "FAIL");
  }
  function reportText() { return JSON.stringify(last, null, 2); }
  function download() {
    if (!last) return;
    var a = document.createElement("a"), url = URL.createObjectURL(new Blob([reportText() + "\n"], { type: "application/json" }));
    a.href = url; a.download = "actions-pin-check.json"; document.body.appendChild(a); a.click(); document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  function copy() {
    if (!last) return;
    var t = reportText();
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(t).then(function () { say("Report copied.", true); }, function () { say("Copy was blocked; use Download.", false); });
    else say("Copy is not available here; use Download.", false);
  }

  $("check").addEventListener("click", check);
  $("example").addEventListener("click", function () { $("wf").value = EXAMPLE; say("Example loaded. Press Check.", null); });
  $("clear").addEventListener("click", function () { $("wf").value = ""; last = null; $("report").hidden = true; say("", null); });
  $("dljson").addEventListener("click", download);
  $("cpjson").addEventListener("click", copy);
})();
