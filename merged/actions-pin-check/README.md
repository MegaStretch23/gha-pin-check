# Actions Pin Check (browser + stdlib CLI)

Checks a GitHub Actions workflow for `uses:` lines that are not pinned to a full commit SHA, and for a few risky patterns. Paste a workflow into the page, or run the CLI on `.github/workflows/`.
Output is text or JSON, and the exit code is meant for CI.

**This is a heuristic, line-based check, not a security audit.** A PASS means none of the rules below matched the text; it says nothing about whether the actions you pin are trustworthy.

- **Private**: the page runs in your tab. Your workflow is not uploaded, and the page code makes no network calls (`grep -E "fetch|XMLHttpRequest|sendBeacon|WebSocket" core.js app.js` finds nothing).
- **Standard library only**: `actions_pin_check.py` is one file with no third-party packages (tested on Python 3.12). The CLI only touches the network with `--resolve`.

## What is checked

| code | level | what |
|---|---|---|
| `AP_UNPINNED_BRANCH`, `AP_NO_REF` | FAIL | `uses: owner/repo@main` (any ref that is not a version-looking tag or a SHA), or no `@ref` at all |
| `AP_UNPINNED_TAG`, `AP_SHORT_SHA`, `AP_UNPINNED_DOCKER` | WARN | `@v4`, `@v1.2.3`; an abbreviated SHA; `docker://image` without an `@sha256:` digest. Local `./` actions are skipped |
| `AP_PRT_CHECKOUT_HEAD` | FAIL | the workflow is triggered by `pull_request_target` and an `actions/checkout` step takes `github.event.pull_request.head.*`, `github.head_ref` or `refs/pull/.../merge` as its `ref:` or `repository:` |
| `AP_SCRIPT_INJECTION` | FAIL | `${{ ... }}` in a `run:` step with a value an outsider controls (issue / PR title and body, comment bodies, `github.head_ref`, commit messages, author names, ...) |
| `AP_EVENT_IN_RUN` | WARN | any other `${{ github.event.* }}` in a `run:` step; pass it through `env:` and quote the variable |
| `AP_PERMS_WRITE_ALL` | FAIL | `permissions: write-all` |
| `AP_PERMS_MISSING` | WARN | no top-level `permissions:` block and at least one job without its own |
| `AP_CURL_PIPE_SH` | FAIL | `curl` or `wget` piped into `sh` / `bash` / `zsh` (also `bash <(curl ...)`), including across `\` line continuations |
| `AP_NOT_WORKFLOW` | WARN | no top-level `jobs:` key |

## Quickstart (CLI)

```
python3 -I actions_pin_check.py [PATH ...] [--json] [--resolve] [--fail-on warn|fail]
```

PATH is a workflow file, a directory (its `.github/workflows/*.yml|*.yaml`) or `-` for stdin; no PATH means `.github/workflows` in the current directory.
Exit code: 0 PASS, 1 WARN, 2 FAIL, 3 usage or unreadable file (`--fail-on fail` makes a WARN exit 0). In CI: `python3 actions_pin_check.py --fail-on fail`.

The run below is on a real public workflow, GitHub's own "Node.js" starter workflow from `actions/starter-workflows` at commit `e3c451d60f119b71caebf13c98ac45da6e15b4b7`, saved unmodified as `tests/samples/node.js.yml` (see `tests/samples/SOURCE.txt`).

```
$ python3 -I actions_pin_check.py node.js.yml
WARN  node.js.yml  (0 fail, 3 warn)
  [INFO] AP_SUMMARY: 2 uses: reference(s), 0 pinned to a full commit SHA; 3 run: step(s); 1 job(s)
  [WARN] line 13 AP_PERMS_MISSING: no top-level permissions: block and no permissions: on job(s) build; the token then gets the repository default scope, which can be read and write
  [WARN] line 23 AP_UNPINNED_TAG: 'actions/checkout@v4' is pinned to the tag 'v4'; a tag can be moved to different code
      fix: uses: actions/checkout@<40-char commit SHA> # v4
  [WARN] line 25 AP_UNPINNED_TAG: 'actions/setup-node@v4' is pinned to the tag 'v4'; a tag can be moved to different code
      fix: uses: actions/setup-node@<40-char commit SHA> # v4
Heuristic check of the workflow text, not a security audit.
(exit code 1)
```

`tests/readme.test.js` fails if this transcript stops matching what the CLI prints.

### `--resolve` (network)

`--resolve` asks the public GitHub API (`GET /repos/{owner}/{repo}/commits/{ref}`, and `GITHUB_TOKEN` if you set it) for the commit behind each tag or branch and fills in the pin line. It is the only network use, and it is not part of the tested transcript above because the answer changes whenever a tag moves. A saved run of the same file with `--resolve` on 2026-11-13:

```
$ python3 -I actions_pin_check.py node.js.yml --resolve
WARN  node.js.yml  (0 fail, 3 warn)
  [INFO] AP_SUMMARY: 2 uses: reference(s), 0 pinned to a full commit SHA; 3 run: step(s); 1 job(s)
  [WARN] line 13 AP_PERMS_MISSING: no top-level permissions: block and no permissions: on job(s) build; the token then gets the repository default scope, which can be read and write
  [WARN] line 23 AP_UNPINNED_TAG: 'actions/checkout@v4' is pinned to the tag 'v4'; a tag can be moved to different code
      fix: uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
  [WARN] line 25 AP_UNPINNED_TAG: 'actions/setup-node@v4' is pinned to the tag 'v4'; a tag can be moved to different code
      fix: uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
Heuristic check of the workflow text, not a security audit.
(exit code 1)
```

Check that the SHA you paste is a commit you trust before you rely on it; the tool only reports where the tag pointed when it ran.

## Limits (read these)

- A line-based reader, not a YAML parser: anchors, flow-style `steps: [...]` and unusual indentation can hide a line from it.
- Reusable workflows, composite actions and `github-script` `script:` blocks are not read.
- Script injection is only looked for in `run:` steps. The list of attacker-controlled values is hand-made and short; an unlisted `github.event.*` value gets a WARN.
- `curl | sh` is matched on one command (after joining `\` continuations); `curl -o f && sh f` is not flagged.
- Pinning to a SHA does not make an action safe, and a tag is not always wrong. This tool counts references that can move.

## Files

`index.html`, `style.css`, `app.js` (UI), `core.js` (the rules; also loads in Node), `actions_pin_check.py` (the CLI, same rules, finding codes, line numbers and messages), `tests/` (`node tests/core.test.js && node tests/ui.test.js && node tests/readme.test.js && python3 -I tests/test_cli.py`; `tests/fixtures/` holds one workflow per rule, and `core.test.js` requires the browser logic and the CLI to return identical findings on each).

## Related

- [OpenVuln CVE Scanner](https://apify.com/johnveds15/openvuln-cve-scanner) on Apify (paid, per use): queries the NIST NVD for recent CVEs by product or keyword and returns one row per CVE.
- [AI App Secrets Scanner](https://gumroad.com/l/dnkrjd) on Gumroad: a browser tool that checks pasted code for leaked keys.
- [pdfguard](https://gumroad.com/l/gvvcsh) on Gumroad (US$19): a Python tool that looks for hidden text in PDFs before an LLM reads them.
- [modelscan-lite](https://github.com/MegaStretch23/modelscan-lite): a separate open-source Python CLI that scans downloaded AI model files. Different tool, same author.
