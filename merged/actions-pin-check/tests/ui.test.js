// run: node tests/ui.test.js   -- drives app.js + core.js against a tiny fake DOM (no browser, no dependencies)
const assert = require('assert'), fs = require('fs'), path = require('path'), vm = require('vm');
class N {
  constructor(tag) { this.tag = tag; this.children = []; this.l = {}; this.hidden = false; this.value = ''; this.className = ''; this._t = ''; }
  set textContent(v) { this._t = String(v); this.children = []; } get textContent() { return this._t + this.children.map((c) => c.textContent).join(''); }
  appendChild(c) { this.children.push(c); return c; } removeChild(c) { this.children = this.children.filter((x) => x !== c); }
  addEventListener(e, f) { (this.l[e] = this.l[e] || []).push(f); } fire(e) { (this.l[e] || []).forEach((f) => f({})); } click() { this.fire('click'); }
}
const ids = {}; const get = (id) => ids[id] = ids[id] || new N('div'); get('report').hidden = true;
const made = []; let blobText = null;
const sandbox = { document: { getElementById: get, createElement: (t) => { const n = new N(t); made.push(n); return n; }, createTextNode: (t) => { const n = new N('#text'); n._t = t; return n; }, body: new N('body') },
  navigator: { clipboard: { writeText: (t) => { sandbox.copied = t; return Promise.resolve(); } } },
  Blob: class { constructor(parts) { blobText = parts.join(''); } }, URL: { createObjectURL: () => 'blob:x', revokeObjectURL() {} }, setTimeout: (f) => f(), JSON, Object, Math, String, Array, RegExp, Number, Promise, console };
sandbox.window = sandbox; sandbox.self = sandbox; vm.createContext(sandbox);
for (const f of ['core.js', 'app.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, '..', f), 'utf8'), sandbox);
const tick = () => new Promise((r) => setTimeout(r, 20));
(async () => {
  get('check').fire('click'); assert(/Paste a workflow/.test(get('status').textContent)); assert(/err/.test(get('status').className));
  get('example').fire('click'); assert(/pull_request_target/.test(get('wf').value));
  get('check').fire('click');
  assert(/FAIL/.test(get('verdict').textContent) && /v-FAIL/.test(get('verdict').className) && get('report').hidden === false);
  const txt = get('findings').textContent;
  ['AP_PRT_CHECKOUT_HEAD', 'AP_SCRIPT_INJECTION', 'AP_CURL_PIPE_SH', 'AP_UNPINNED_BRANCH', 'AP_UNPINNED_TAG', 'AP_PERMS_MISSING'].forEach((c) => assert(txt.includes(c), c + ' in ' + txt));
  assert(/fix: uses: some-org\/some-action@<40-char commit SHA> # main/.test(txt));
  // a clean workflow -> PASS
  get('wf').value = 'on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: o/r@' + 'a'.repeat(40) + '\n'; get('check').fire('click');
  assert(/PASS/.test(get('verdict').textContent) && /v-PASS/.test(get('verdict').className));
  // export: download and copy carry the same report
  get('dljson').fire('click'); const rep = JSON.parse(blobText); assert.strictEqual(rep.tool, 'actions-pin-check'); assert.strictEqual(rep.verdict, 'PASS');
  get('cpjson').fire('click'); await tick(); assert.strictEqual(JSON.parse(sandbox.copied).verdict, 'PASS');
  // hostile text stays text, never markup
  get('wf').value = 'on: push\njobs:\n  a:\n    steps:\n      - uses: <img src=x onerror=alert(1)>@main\n'; get('check').fire('click');
  assert(/<img src=x/.test(get('findings').textContent)); assert(!made.some((n) => n.tag === 'img'));
  // clear
  get('clear').fire('click'); assert.strictEqual(get('wf').value, ''); assert.strictEqual(get('report').hidden, true);
  console.log('ui tests passed');
})().catch((e) => { console.error(e); process.exit(1); });
