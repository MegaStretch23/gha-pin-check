# gha-pin-check

Find the GitHub Actions in your workflows that are **not pinned to a commit SHA**, and a few patterns that make a workflow risky. One small command, **Python 3.9+, standard library only**, no network unless you ask for it.

A `uses: owner/action@v4` line runs whatever that tag points to *today*. Tags and branches can be moved by the action's owner (or by whoever takes over the account), and your workflow runs the new code with your token and secrets. Pinning to the full 40-character commit SHA fixes the code you run. This tool lists every `uses:` that is not pinned and what to change.

## Quickstart

```bash
git clone https://github.com/MegaStretch23/gha-pin-check.git
cd gha-pin-check

# check any repo checkout: reads .github/workflows/*.yml|yaml, action.yml and .github/actions/**/action.yml
python -m gha_pin_check /path/to/some/repo

# also look up the commit SHA behind each tag/branch and print the pinned replacement line
GITHUB_TOKEN=... python -m gha_pin_check /path/to/some/repo --resolve

# for CI: exit 1 when anything of severity high (or medium, low) is found; JSON for other tools
python -m gha_pin_check . --fail-on high
python -m gha_pin_check . --format json
```

Exit codes: `0` ran (and nothing at/above `--fail-on`), `1` findings at/above `--fail-on`, `2` a problem (no workflow files found, unreadable file, a `--resolve` lookup that failed). It never reports "clean" when it could not look.

## What it reports

| rule | severity | meaning |
|---|---|---|
| `branch-ref` | high | `uses: x/y@main`: every push to that branch runs in your workflow |
| `short-sha` | high | an abbreviated SHA is not a valid pin; use all 40 characters |
| `no-ref` | high | `uses: x/y` with no `@ref` |
| `unpinned-action` | low for `actions/*` and `github/*`, medium for everyone else | a tag such as `@v4`, which its owner can move |
| `unpinned-docker` | medium | `docker://image:tag` without an `@sha256:` digest |
| `untrusted-checkout` | high | `pull_request_target` / `workflow_run` workflow that checks out the pull request's head or branch |
| `script-injection` | high | `${{ github.event.pull_request.title }}`, `github.head_ref`, issue/comment bodies, commit messages... expanded inside a `run:` or `script:` body; pass them through `env:` instead |
| `pipe-to-shell` | medium | `curl ... \| bash` in a `run:` body |
| `write-all`, `unsecure-commands` | medium | `permissions: write-all`; `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` |
| `pull-request-target`, `no-permissions`, `secrets-inherit`, `self-hosted` | low | worth a look: privileged trigger, no `permissions:` block (the token then gets the repo/org default), `secrets: inherit`, self-hosted runner |

Pinned to a full SHA, local (`./path`) and `docker://...@sha256:` uses produce no finding. A `uses:` built from an expression is counted but cannot be judged.

## Real sample runs

Cloned with `--depth 1` on 2026-11-13 and run with exactly this code. Full outputs are in [`examples/`](examples/).

**`psf/requests` @ `3c7baaa`** (8 workflow files): every action is pinned.

```text
8 file(s), 24 uses: 24 pinned to a commit SHA, 0 on a tag, 0 on a branch, 0 other unpinned, 0 docker, 0 local or expression-built. Findings: high 0, medium 0, low 0
```

**`sindresorhus/ky` @ `3541888`**, with `--resolve`:

```text
.github/workflows/main.yml:1  low    no-permissions  no `permissions:` block: the GITHUB_TOKEN gets the repository/org default, which may include write
.github/workflows/main.yml:17  low    unpinned-action  actions/checkout@v6 is a tag, which its owner can move; pin the commit SHA
    -> actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
.github/workflows/main.yml:18  low    unpinned-action  actions/setup-node@v6 is a tag, which its owner can move; pin the commit SHA
    -> actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6
...
1 file(s), 4 uses: 0 pinned to a commit SHA, 4 on a tag, 0 on a branch, ...  Findings: high 0, medium 0, low 5
```

The two SHAs were checked against `git ls-remote https://github.com/actions/checkout refs/tags/v6` and the same for `actions/setup-node` on the day of the run. `encode/httpx` @ `b5addb6` gives 4 tag uses and 6 low findings ([`examples/httpx.txt`](examples/httpx.txt)).

**A constructed workflow** ([`examples/risky-workflow.yml`](examples/risky-workflow.yml), written for this README, not taken from a real project) that trips the high-severity rules: see [`examples/risky-workflow.txt`](examples/risky-workflow.txt).

## Limits

- It reads workflow text line by line; it is **not a YAML parser** and does not expand anchors, matrices, reusable-workflow inputs or `${{ }}` expressions. Odd formatting can hide a `uses:` line from it; it reads only the files it lists.
- A SHA pin fixes which code runs. It does not tell you the code is safe, and it does not pin what an action downloads itself. Pinned actions also need updates (Dependabot or Renovate can bump SHAs).
- The injection and checkout rules look for a fixed list of well-known contexts. A clean result is not a security review.
- `--resolve` makes one request per distinct `owner/repo@ref` to `api.github.com`. Unauthenticated calls are rate limited; set `GITHUB_TOKEN` (read only is enough). Nothing else uses the network.

## Tests

`pip install pytest && python -m pytest` (13 tests, build their own workflow fixtures; the `--resolve` tests use a fake resolver, no network).

## Related, hosted

If you would rather not run scanners yourself, the author runs two pay-per-event Apify actors (prices read from the Apify API on 2026-11-13; check each page for current prices):

- **[AI API Key Leak Scanner: GitHub Repos + URLs](https://apify.com/johnveds15/ai-api-key-leak-scanner)**: checks public GitHub repos and JS/text URLs for leaked API keys. $0.01 per repository or URL scanned.
- **[CVE Vulnerability Scraper: NIST NVD](https://apify.com/johnveds15/openvuln-cve-scanner)**: recent CVEs by product, vendor or keyword. $0.002 per CVE result.

MIT licensed.
