// run: node tests/core.test.js   (needs python3 for the CLI parity check; no other dependencies)
// For every fixture workflow: the browser logic (core.js) and the stdlib CLI (actions_pin_check.py --json) must return the same verdict and the same findings.
const assert = require('assert'), fs = require('fs'), path = require('path'), cp = require('child_process'), os = require('os');
const P = require('../core.js');
const FX = path.join(__dirname, 'fixtures'), CLI = path.join(__dirname, '..', 'actions_pin_check.py');
const scan = (n) => P.scanText(fs.readFileSync(path.join(FX, n), 'utf8'), n);
const key = (r) => r.findings.map((f) => f.level + ':' + f.code + '@' + f.line);
// fixture -> [verdict, codes that must be present (one fixture per rule)]
const EXPECT = {
  'good.yml': ['PASS', []], 'unpinned_tag.yml': ['WARN', ['AP_UNPINNED_TAG']], 'unpinned_branch.yml': ['FAIL', ['AP_UNPINNED_BRANCH']], 'no_ref.yml': ['FAIL', ['AP_NO_REF']],
  'short_sha.yml': ['WARN', ['AP_SHORT_SHA']], 'docker_tag.yml': ['WARN', ['AP_UNPINNED_DOCKER']], 'prt_checkout.yml': ['FAIL', ['AP_PRT_CHECKOUT_HEAD']], 'prt_safe.yml': ['PASS', []],
  'injection.yml': ['FAIL', ['AP_SCRIPT_INJECTION']], 'event_in_run.yml': ['WARN', ['AP_EVENT_IN_RUN']], 'injection_env_safe.yml': ['PASS', []], 'write_all.yml': ['FAIL', ['AP_PERMS_WRITE_ALL']],
  'missing_perms.yml': ['WARN', ['AP_PERMS_MISSING']], 'job_perms.yml': ['PASS', []], 'curl_sh.yml': ['FAIL', ['AP_CURL_PIPE_SH']], 'curl_continuation.yml': ['FAIL', ['AP_CURL_PIPE_SH']],
  'curl_safe.yml': ['PASS', []], 'not_workflow.yml': ['WARN', ['AP_NOT_WORKFLOW']],
};
const files = fs.readdirSync(FX).filter((n) => n.endsWith('.yml')).sort();
assert.deepStrictEqual(files, Object.keys(EXPECT).sort(), 'fixture list changed: update EXPECT');
for (const n of files) {
  const r = scan(n), [v, codes] = EXPECT[n];
  assert.strictEqual(r.verdict, v, n + ' verdict ' + JSON.stringify(r.findings));
  codes.forEach((c) => assert(r.findings.some((f) => f.code === c), n + ' should carry ' + c));
  const py = cp.spawnSync('python3', ['-I', CLI, path.join(FX, n), '--json'], { encoding: 'utf8', cwd: os.tmpdir() });
  assert.strictEqual(py.status, { PASS: 0, WARN: 1, FAIL: 2 }[v], n + ' CLI exit code');
  const pr = JSON.parse(py.stdout).files[0];
  assert.strictEqual(pr.verdict, r.verdict, n + ' CLI verdict');
  assert.deepStrictEqual(pr.counts, r.counts, n + ' counts');
  assert.deepStrictEqual(pr.findings, r.findings, n + ' CLI/JS findings differ');   // same code, line, message, uses, ref, suggestion
}
console.log('fixtures: ' + files.length + ' workflows, JS and CLI agree on verdict, counts and every finding');

// the real public sample too
const real = fs.readFileSync(path.join(__dirname, 'samples', 'node.js.yml'), 'utf8');
const rr = P.scanText(real, 'node.js.yml');
assert.deepStrictEqual(key(rr), ['INFO:AP_SUMMARY@0', 'WARN:AP_PERMS_MISSING@13', 'WARN:AP_UNPINNED_TAG@23', 'WARN:AP_UNPINNED_TAG@25']);
const pj = JSON.parse(cp.spawnSync('python3', ['-I', CLI, path.join(__dirname, 'samples', 'node.js.yml'), '--json'], { encoding: 'utf8', cwd: os.tmpdir() }).stdout).files[0];
assert.deepStrictEqual(pj.findings, rr.findings.map((f) => f));

// details
const t = (s) => { const r = P.scanText(s, 'x.yml'); r.findings = r.findings.filter((f) => f.level !== 'INFO' || f.code !== 'AP_SUMMARY' ? true : false).sort((a, b) => (a.level === 'INFO') - (b.level === 'INFO')); return r; };
const base = 'on: push\npermissions: {}\njobs:\n  a:\n    steps:\n';
assert.strictEqual(t(base + '      - uses: o/r@' + 'a'.repeat(40) + ' # main\n').verdict, 'PASS', 'trailing comment on a pinned ref');
assert.strictEqual(t(base + '      - uses: o/r@' + 'A'.repeat(40) + '\n').verdict, 'PASS', 'upper-case SHA');
assert.strictEqual(t(base + '      # - uses: o/r@main\n      - run: echo ok\n').verdict, 'PASS', 'commented uses');
assert.strictEqual(t(base + '      - run: |\n          echo "uses: o/r@main"\n').verdict, 'PASS', 'uses inside a run block');
assert.strictEqual(t(base + '      - uses: ${{ matrix.action }}@v1\n').verdict, 'PASS', 'dynamic uses is skipped');
assert.strictEqual(t(base + '      - uses: o/r@HEAD\n').findings[0].code, 'AP_UNPINNED_BRANCH');
assert.strictEqual(t('on:\n  pull_request_target:\njobs:\n  a:\n    permissions: {}\n    steps:\n      - uses: actions/checkout@' + 'a'.repeat(40) + '\n        with:\n          ref: refs/pull/${{ github.event.number }}/merge\n').verdict, 'FAIL', 'PRT + refs/pull merge');
assert.strictEqual(t('on: [push, pull_request_target]\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@' + 'a'.repeat(40) + '\n        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n').verdict, 'FAIL', 'inline on + head repo');
assert.strictEqual(t('on: pull_request\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@' + 'a'.repeat(40) + '\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n').verdict, 'PASS', 'head checkout under plain pull_request is not flagged');
assert.strictEqual(t('').findings.some((f) => f.code === 'AP_NOT_WORKFLOW'), true, 'empty text');
assert.strictEqual(t('on: push\r\npermissions: {}\r\njobs:\r\n  a:\r\n    steps:\r\n      - uses: o/r@v1\r\n').findings[0].line, 6, 'CRLF');
assert.strictEqual(t(base + '      - run: curl -fsSL https://x/i.sh | bash\n').findings[0].code, 'AP_CURL_PIPE_SH');
assert.strictEqual(t(base + '      - run: curl -fsSL https://x | shasum\n').verdict, 'PASS', 'shasum is not a shell');
assert.strictEqual(t(base + '      - run: bash <(curl -s https://x/i.sh)\n').verdict, 'FAIL', 'process substitution');
console.log('core tests passed');
