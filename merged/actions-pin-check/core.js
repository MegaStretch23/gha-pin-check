/* actions-pin-check core: line-based checks of GitHub Actions workflow text. Runs in the browser and in Node. No network, nothing is uploaded.
 * Heuristic check, not a security audit. Mirrors actions_pin_check.py (same rules, finding codes, line numbers and messages). */
(function (root) {
  'use strict';
  var VERSION = '0.1.0', TOOL = 'actions-pin-check';
  var LIMITS = 'Heuristic line-based check, not a YAML parser and not a security audit. It reads the text only: it does not follow reusable workflows or composite actions, ' +
    "does not read github-script 'script:' blocks, and cannot tell whether a pinned SHA is a commit you trust.";
  var SHA40 = /^[0-9a-fA-F]{40}$/, SHORT_SHA = /^[0-9a-fA-F]{7,39}$/, TAGLIKE = /^v?\d+(\.\d+){0,3}([-.+][\w.]+)?$/, DOCKER_PIN = /@sha256:[0-9a-fA-F]{64}$/;
  var BLOCK = /^(\s*)((?:-\s+)*)(["']?[\w.-]+["']?)\s*:\s*[|>][+-]?\d*\s*(?:#.*)?$/;
  var USES = /^(\s*)((?:-\s+)*)uses\s*:\s*(.+)$/, RUN = /^(\s*)((?:-\s+)*)run\s*:\s*(.*)$/;
  var HEADREF = /github\.event\.pull_request\.head\.|github\.head_ref|refs\/pull\/.*\/(?:head|merge)/;
  var UNTRUSTED = new RegExp('github\\.head_ref|github\\.event\\.(?:issue\\.(?:title|body)|pull_request\\.(?:title|body|head\\.(?:ref|label|repo\\.default_branch|repo\\.description|repo\\.homepage))' +
    '|comment\\.body|review\\.body|review_comment\\.body|pages\\.[\\w\\[\\]*.]*page_name|commits\\.[\\w\\[\\]*.]*(?:message|author\\.email|author\\.name)' +
    '|head_commit\\.(?:message|author\\.email|author\\.name)|workflow_run\\.(?:head_branch|head_commit\\.(?:message|author\\.email|author\\.name))' +
    '|discussion\\.(?:title|body)|release\\.(?:name|body|tag_name)|client_payload)');
  var CURL_PIPE = /\b(?:curl|wget)\b[^\n]*?\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b/, CURL_SUBST = /\b(?:ba|z|da|k)?sh\b[^|\n]*<\(\s*(?:curl|wget)\b/;

  function stripComment(s) {
    var q = null;
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (q) { if (c === q) q = null; }
      else if ((c === "'" || c === '"') && (i === 0 || ' \t:[{,-'.indexOf(s[i - 1]) >= 0)) q = c;
      else if (c === '#' && (i === 0 || s[i - 1] === ' ' || s[i - 1] === '\t')) return s.slice(0, i).replace(/\s+$/, '');
    }
    return s.replace(/\s+$/, '');
  }
  function indent(ln) { var n = 0; while (n < ln.length && ln[n] === ' ') n++; return n; }
  function blankOrComment(ln) { var t = ln.trim(); return t === '' || t[0] === '#'; }
  function lstripped(ln) { return ln.replace(/^\s+/, ''); }

  function findScalars(lines) {
    var inscalar = {}, heads = {}, i = 0;
    while (i < lines.length) {
      var m = inscalar[i] ? null : BLOCK.exec(lines[i]);
      if (m) {
        var kc = m[1].length + m[2].length, j = i + 1, content = [];
        while (j < lines.length) {
          if (lines[j].trim() === '' || indent(lines[j]) > kc) { content.push(j); j++; } else break;
        }
        heads[i] = content; content.forEach(function (k) { inscalar[k] = true; }); i = j;
      } else i++;
    }
    return { inscalar: inscalar, heads: heads };
  }
  function suggest(name, ref, sha) { return 'uses: ' + name + '@' + (sha || '<40-char commit SHA>') + ' # ' + ref; }

  function scanText(text, name) {
    name = name || 'workflow.yml';
    var lines = String(text).replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
    var sc = findScalars(lines), inscalar = sc.inscalar, heads = sc.heads, F = [];
    function add(level, code, line, msg, extra) {
      var d = { level: level, code: code, line: line + 1, message: msg };
      if (extra) for (var k in extra) d[k] = extra[k];
      F.push(d);
    }
    var nUses = 0, nPinned = 0, nRun = 0, i, m;
    for (i = 0; i < lines.length; i++) {
      if (inscalar[i]) continue;
      m = USES.exec(lines[i]); if (!m) continue;
      var val = stripComment(m[3]).trim();
      if (val.length >= 2 && val[0] === val[val.length - 1] && (val[0] === "'" || val[0] === '"')) val = val.slice(1, -1);
      if (!val || val.indexOf('./') === 0 || val.indexOf('../') === 0 || val.indexOf('${{') >= 0) continue;
      nUses++;
      if (val.indexOf('docker://') === 0) {
        if (DOCKER_PIN.test(val)) nPinned++;
        else add('WARN', 'AP_UNPINNED_DOCKER', i, "docker image '" + val + "' is not pinned to an @sha256: digest; tags can be re-pointed", { uses: val, ref: null });
        continue;
      }
      var at = val.lastIndexOf('@');
      if (at < 0) { add('FAIL', 'AP_NO_REF', i, "'" + val + "' has no @ref at all", { uses: val, ref: null }); continue; }
      var nm = val.slice(0, at), ref = val.slice(at + 1);
      if (SHA40.test(ref)) nPinned++;
      else if (SHORT_SHA.test(ref)) add('WARN', 'AP_SHORT_SHA', i, "'" + val + "' uses an abbreviated SHA; pin the full 40-character commit SHA", { uses: val, ref: ref, suggestion: suggest(nm, ref) });
      else if (TAGLIKE.test(ref)) add('WARN', 'AP_UNPINNED_TAG', i, "'" + val + "' is pinned to the tag '" + ref + "'; a tag can be moved to different code", { uses: val, ref: ref, suggestion: suggest(nm, ref) });
      else add('FAIL', 'AP_UNPINNED_BRANCH', i, "'" + val + "' follows the branch or ref '" + ref + "', so every run can execute different code", { uses: val, ref: ref, suggestion: suggest(nm, ref) });
    }
    for (i = 0; i < lines.length; i++) {
      if (inscalar[i]) continue;
      m = RUN.exec(lines[i]); if (!m) continue;
      nRun++;
      var body = [], j, t;
      if (heads[i]) heads[i].forEach(function (k) { if (lines[k].trim() && lstripped(lines[k])[0] !== '#') body.push([k, lines[k]]); });
      else { var v = stripComment(m[3]); if (v) body.push([i, v]); }
      body.forEach(function (b) {
        var re = /\$\{\{(.*?)\}\}/g, em;
        while ((em = re.exec(b[1])) !== null) {
          var expr = em[1].trim();
          if (UNTRUSTED.test(expr)) add('FAIL', 'AP_SCRIPT_INJECTION', b[0], '${{ ' + expr + ' }} is pasted into a shell script; its value is attacker-controlled text. Pass it through env: and quote "$VAR" instead');
          else if (expr.indexOf('github.event.') >= 0) add('WARN', 'AP_EVENT_IN_RUN', b[0], '${{ ' + expr + ' }} is pasted into a shell script; pass event data through env: and quote "$VAR" instead');
        }
      });
      var merged = [];
      body.forEach(function (b) {
        var last = merged[merged.length - 1];
        if (last && last[1].slice(-1) === '\\') last[1] = last[1].slice(0, -1) + ' ' + b[1].trim(); else merged.push([b[0], b[1]]);
      });
      merged.forEach(function (b) {
        if (CURL_PIPE.test(b[1]) || CURL_SUBST.test(b[1])) add('FAIL', 'AP_CURL_PIPE_SH', b[0], 'downloads a script and runs it in one step (curl or wget piped into a shell); download, verify a checksum, then run');
      });
    }
    var prt = null;
    for (i = 0; i < lines.length; i++) {
      if (inscalar[i] || indent(lines[i]) !== 0 || !/^(?:on|"on"|'on'|true)\s*:/.test(lines[i])) continue;
      var jj = i;
      while (jj < lines.length && (jj === i || blankOrComment(lines[jj]) || indent(lines[jj]) > 0)) {
        var piece = jj > i ? lines[jj] : lines[jj].slice(lines[jj].indexOf(':') + 1);
        if (!inscalar[jj] && /\bpull_request_target\b/.test(stripComment(piece))) { prt = jj; break; }
        jj++;
      }
      break;
    }
    if (prt !== null) {
      for (i = 0; i < lines.length; i++) {
        if (inscalar[i]) continue;
        m = USES.exec(lines[i]);
        if (!m || !/^['"]?actions\/checkout\b/.test(stripComment(m[3]).trim())) continue;
        var kc = m[1].length + m[2].length, start = i;
        if (!m[2]) {
          var q = i - 1; start = q < 0 ? 0 : i;
          while (q >= 0) {
            var tt = lines[q];
            if (tt.trim() === '') { q--; continue; }
            var m2 = /^(\s*)-(\s+)\S/.exec(tt);
            if (m2 && m2[1].length + 1 + m2[2].length === kc) { start = q; break; }
            if (indent(tt) < kc) { start = q + 1; break; }
            start = q; q--;
          }
        }
        var end = i + 1;
        while (end < lines.length && (lines[end].trim() === '' || indent(lines[end]) >= kc)) end++;
        for (var k = start; k < end; k++) {
          if (inscalar[k] || lstripped(lines[k])[0] === '#') continue;
          var mr = /^\s*(?:-\s+)*(ref|repository)\s*:\s*(.+)$/.exec(lines[k]);
          if (mr && HEADREF.test(stripComment(mr[2])))
            add('FAIL', 'AP_PRT_CHECKOUT_HEAD', k, "pull_request_target (line " + (prt + 1) + ") runs with the base repository's secrets and a write token, and this checkout takes the pull request's code (" + mr[1] + ': ' + stripComment(mr[2]) + ')');
        }
      }
    }
    for (i = 0; i < lines.length; i++)
      if (!inscalar[i] && /^\s*permissions\s*:\s*['"]?write-all['"]?\s*$/.test(stripComment(lines[i])))
        add('FAIL', 'AP_PERMS_WRITE_ALL', i, 'permissions: write-all gives the workflow token every write scope; list only the scopes the job needs');
    var topPerm = false, jobsAt = null;
    for (i = 0; i < lines.length; i++) {
      if (inscalar[i] || indent(lines[i]) !== 0) continue;
      if (/^permissions\s*:/.test(lines[i])) topPerm = true;
      if (jobsAt === null && /^jobs\s*:\s*(?:#.*)?$/.test(lines[i])) jobsAt = i;
    }
    var jobs = [];
    if (jobsAt !== null) {
      var e = jobsAt + 1, ci = null;
      while (e < lines.length) {
        var tl = lines[e];
        if (!blankOrComment(tl)) { if (ci === null) ci = indent(tl); if (indent(tl) < ci || ci === 0) break; }
        e++;
      }
      var hs = [];
      for (var h = jobsAt + 1; h < e; h++) if (!inscalar[h] && !blankOrComment(lines[h]) && indent(lines[h]) === ci && /^\s*["']?[\w.-]+["']?\s*:/.test(lines[h])) hs.push(h);
      hs.forEach(function (hh, n) {
        var segEnd = n + 1 < hs.length ? hs[n + 1] : e, child = null, x;
        for (x = hh + 1; x < segEnd; x++) if (!blankOrComment(lines[x])) { child = indent(lines[x]); break; }
        var has = false;
        if (child !== null) for (x = hh + 1; x < segEnd; x++) if (!inscalar[x] && indent(lines[x]) === child && /^\s*permissions\s*:/.test(lines[x])) { has = true; break; }
        jobs.push([/^\s*["']?([\w.-]+)["']?/.exec(lines[hh])[1], hh, has]);
      });
    }
    if (!topPerm && jobs.length) {
      var missing = jobs.filter(function (x) { return !x[2]; });
      if (missing.length) add('WARN', 'AP_PERMS_MISSING', missing[0][1], 'no top-level permissions: block and no permissions: on job(s) ' + missing.map(function (x) { return x[0]; }).join(', ') +
        '; the token then gets the repository default scope, which can be read and write');
    }
    if (jobsAt === null) add('WARN', 'AP_NOT_WORKFLOW', 0, 'no top-level jobs: key, so this does not look like a GitHub Actions workflow');
    F.push({ level: 'INFO', code: 'AP_SUMMARY', line: 0, message: nUses + ' uses: reference(s), ' + nPinned + ' pinned to a full commit SHA; ' + nRun + ' run: step(s); ' + jobs.length + ' job(s)' });
    F.sort(function (a, b) {
      if (a.line !== b.line) return a.line - b.line;
      if (a.code !== b.code) return a.code < b.code ? -1 : 1;
      return a.message < b.message ? -1 : a.message > b.message ? 1 : 0;
    });
    var counts = { FAIL: 0, WARN: 0, INFO: 0 }; F.forEach(function (f) { counts[f.level]++; });
    return { file: { name: name, lines: lines.length }, verdict: counts.FAIL ? 'FAIL' : counts.WARN ? 'WARN' : 'PASS', counts: counts, findings: F };
  }

  var api = { VERSION: VERSION, TOOL: TOOL, LIMITS: LIMITS, scanText: scanText };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.ActionsPin = api;
})(typeof self !== 'undefined' ? self : this);
