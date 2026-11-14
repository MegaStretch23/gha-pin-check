# gha-pin-check

Checks GitHub Actions workflows for `uses:` references that are not pinned to a commit SHA, and for a few common risky patterns. Python 3.9+, standard library only (no PyYAML), text / JSON / SARIF output.

A tag or branch such as `actions/checkout@v4` can be re-pointed by whoever controls the action's repository. A 40-character commit SHA cannot. Pinning is the usual mitigation; this tool finds the lines that are not pinned and, optionally, looks up the SHA for you.

## Quickstart

```
git clone https://github.com/MegaStretch23/gha-pin-check
cd gha-pin-check
python3 -m gha_pin_check.cli /path/to/your/repo            # scans <repo>/.github/workflows/*.yml|*.yaml
python3 -m gha_pin_check.cli path/to/workflow.yml --format sarif > results.sarif
python3 -m gha_pin_check.cli . --fail-on medium            # exit 1 in CI if anything is medium or higher
python3 -m gha_pin_check.cli . --resolve                   # also print a pinned `uses:` line for each tag/branch ref
```

Or `pip install .` and run `gha-pin-check`. Run the tests with `python3 -m pytest` (needs pytest only for the tests).

## What it flags

| rule | severity | meaning |
|---|---|---|
| GHA001 | medium | `uses: owner/repo@ref` where `ref` is not a 40-character hex SHA (also reusable workflows). `./local` actions and `docker://` are skipped |
| GHA002 | medium | `uses: docker://image` without an `@sha256:` digest |
| GHA003 | high | workflow triggered by `pull_request_target` that runs `actions/checkout` with a `ref:`/`repository:` taken from the pull request (`github.event.pull_request.head.*`, `github.head_ref`, `refs/pull/...`, `merge_commit_sha`, `workflow_run.head_*`) |
| GHA004 | high / medium / low | `${{ github.event.* }}` or `github.head_ref` expanded inside `run:`. High for fields that can carry free text (titles, bodies, branch names, ...), medium for `inputs` / `client_payload`, low for numbers, SHAs and similar fields |
| GHA005 | medium / high | no `permissions:` at workflow level or on a job (default token scope applies); high for `permissions: write-all` |
| GHA006 | medium | `curl`/`wget` piped into `sh`/`bash`/`zsh`/`python`, or `bash <(curl ...)` inside `run:` |

`--ignore GHA005` skips a rule (repeatable). Exit codes: 0 ok, 1 findings at or above `--fail-on`, 2 bad path.

## Real sample run

Workflows were downloaded at the commit recorded in `samples/MANIFEST.json` (fetched 2026-11-13 with `tools/fetch_samples.py`) and scanned with this version. Outputs are saved in `samples/`.

```
$ python3 -m gha_pin_check.cli samples/psf__requests
0 finding(s) in 8 file(s): 0 high, 0 medium, 0 low

$ python3 -m gha_pin_check.cli samples/sindresorhus__ky --resolve
samples/sindresorhus__ky/.github/workflows/main.yml:6: [medium] GHA005 no permissions: at workflow level or on job 'test'; the token gets the repository default scope
samples/sindresorhus__ky/.github/workflows/main.yml:17: [medium] GHA001 actions/checkout is not pinned to a commit SHA (ref: v6)
    suggested: uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
samples/sindresorhus__ky/.github/workflows/main.yml:18: [medium] GHA001 actions/setup-node is not pinned to a commit SHA (ref: v6)
    suggested: uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6
...
6 finding(s) in 1 file(s): 0 high, 6 medium, 0 low

$ python3 -m gha_pin_check.cli samples/rust-lang__rust
samples/rust-lang__rust/.github/workflows/ci.yml:112: [medium] GHA006 script is downloaded and piped into an interpreter; pin and verify the download
1 finding(s) in 3 file(s): 0 high, 1 medium, 0 low
```

Combined JSON and SARIF for the three repos: `samples/all.json`, `samples/all.sarif`.

What this does and does not show: psf/requests has no finding **for these six rules**; that is not a security audit of the project. The `suggested:` SHAs are what the tag pointed to when the run was made. `--resolve` only prints them; nothing edits your files, and you should check that the SHA belongs to the release you intend.

## `--resolve` and offline use

Scanning never touches the network. `--resolve` asks the GitHub REST API (`/git/ref/tags/<ref>`, then `/heads/<ref>`, following annotated tags to the commit) once per `owner/repo@ref`, using `GITHUB_TOKEN` if set (unauthenticated requests are rate-limited to 60/hour per IP). If the lookup fails, the finding is kept and marked `could not resolve: <reason>`.

## Limits

- Line-based parser: block scalars (`run: |`) and single-line `run:` values are read; multi-line plain/quoted scalars, YAML anchors and flow mappings spanning lines are not followed.
- GHA004 looks only at `run:`; expressions in `actions/github-script` `script:` inputs are not checked.
- GHA005 does not judge which scopes a job needs, only that none are declared.
- Pinned SHAs still need updating; pair with Dependabot or Renovate.

## Tests

`tests/` holds 25 pytest tests. `tests/fixtures/real/` are unmodified workflow files from psf/requests, sindresorhus/ky, vercel/next.js, denoland/deno, facebook/react, nodejs/node, tiangolo/fastapi and rust-lang/rust. No real public file I found combined `pull_request_target` with a PR-head checkout or used `docker://`, so those cases are hand-written files in `tests/fixtures/synthetic/`, marked as synthetic in their first line.

## Related

I also run hosted data tools on Apify, for example the pay-per-event [SEC Form 4 insider cluster scanner](https://apify.com/johnveds15/sec-form4-insider-clusters). They do something different from this tool; there is no paid version of gha-pin-check.

MIT license.

## Merged from actions-pin-check

`actions-pin-check` was the same idea built twice. Its own files are kept in [`merged/actions-pin-check/`](merged/actions-pin-check/) (unique parts: see that folder's README and tests); the old repo now points here: https://github.com/MegaStretch23/actions-pin-check
