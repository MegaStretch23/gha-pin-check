# gha-pin-check

Pinning and risk checker for GitHub Actions. Point it at a repo and it lists every `uses:` that is not pinned to a full commit SHA, plus a few workflow patterns that are known ways to leak secrets. It can also rewrite the tag pins into SHA pins.

- Python 3.9+, **standard library only**. Nothing to `pip install` to run it.
- Reads `.github/workflows/*.yml|yaml`, `action.yml` at the repo root and `.github/actions/**/action.yml`. There is no YAML parser in the standard library, so it reads the few shapes it needs line by line. A `uses:` line it cannot classify is reported (`unrecognized-uses`), never skipped.
- Checking is offline. Only `--fix` uses the network (GitHub REST API, `GITHUB_TOKEN` optional, 60 requests/hour without it).

## Quickstart

```bash
git clone https://github.com/MegaStretch23/gha-pin-check.git
cd gha-pin-check

# check any repo checkout (default: current folder); exit 1 if a medium or high finding exists
python -m ghapincheck /path/to/repo

# JSON for scripts, or choose the exit-code threshold (none|low|medium|high)
python -m ghapincheck /path/to/repo --format json --fail-on high

# rewrite tag and branch pins to full commit SHAs (the tag is kept as a comment)
GITHUB_TOKEN=... python -m ghapincheck /path/to/repo --fix
```

Exit codes: `0` clean at the chosen threshold, `1` findings at or above it, `2` bad path, no workflow files, or a `--fix` ref that could not be resolved.

## What it reports

| rule | severity | meaning |
|---|---|---|
| `unpinned-branch` | high | `@main`, `@stable`, a non-version ref, or no `@ref`: every run can execute different code |
| `short-sha` | high | abbreviated SHA, ambiguous with a branch or tag of that name |
| `unpinned-tag` | medium (low for `actions` and `github`, see `--first-party`) | a tag such as `@v4`; tags can be moved |
| `unpinned-docker` | medium | `docker://image:tag` without `@sha256:` |
| `pwn-request` | high | `pull_request_target` or `workflow_run` plus a checkout of the pull request's head |
| `script-injection` | high | `${{ github.event.issue.title }}`, `github.head_ref` and similar attacker-controlled values inside a `run:` or `script:` block |
| `permissions-write-all` | high | `permissions: write-all` |
| `permissions-missing` | low | no `permissions:` key anywhere in a workflow |
| `unrecognized-uses` | low | a `uses:` value that is not `./local`, `docker://` or `owner/repo@ref` |

## Real sample runs

These runs were made with this exact code on public checkouts.

**`django/django` @ `6c8143c`**: 18 workflow files, 71 `uses:` lines. Full output: [`examples/django-6c8143c.txt`](examples/django-6c8143c.txt).

```text
.github/workflows/benchmark.yml:17: LOW    unpinned-tag: actions/checkout@v7 is a first-party tag; the tag can be moved to other code. Pin the commit SHA ...
.github/workflows/benchmark.yml:31: LOW    unpinned-tag: actions/cache@v6 is a first-party tag; the tag can be moved to other code. Pin the commit SHA ...
.github/workflows/check-migrations.yml:44: LOW    unpinned-tag: actions/checkout@v7 is a first-party tag; the tag can be moved to other code. Pin the commit SHA ...
...
.github/workflows/linters.yml:71: HIGH   unpinned-branch: psf/black@stable follows the branch or moving ref 'stable'; every run can execute different code
18 files, 71 uses: lines, 66 findings (1 high, 0 medium, 65 low)
```

The one high finding was checked by hand: `psf/black` has a branch named `stable` (`git ls-remote https://github.com/psf/black.git refs/heads/stable` -> `258e7dbf348bc23cb70b8cdf693481c04634ebcc`), so `psf/black@stable` runs whatever that branch points to on the day. The 65 low ones are `actions/*` tags.

**`--fix` on `sindresorhus/ky` @ `3541888`** (4 first-party tag pins; [`examples/ky-3541888-fix.diff`](examples/ky-3541888-fix.diff)):

```diff
@@ -14,8 +14,8 @@ jobs:
           - 24
           - 22
     steps:
-      - uses: actions/checkout@v6
-      - uses: actions/setup-node@v6
+      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
+      - uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6
         with:
           node-version: ${{ matrix.node-version }}
```

`d23441a48e516b6c34aea4fa41551a30e30af803` matches `git ls-remote https://github.com/actions/checkout.git refs/tags/v6`. Re-running the check after `--fix` leaves only `permissions-missing` for that file.

**Not every repo has findings.** On the same day `psf/requests` @ `3c7baaa`, `pallets/flask` @ `49943b5` and `fastapi/fastapi` @ `5add7a4` came back with zero findings (every `uses:` is a full SHA).

**The risk rules** on a constructed workflow ([`examples/injection-demo`](examples/injection-demo/.github/workflows/triage.yml), written for this README, not taken from a real repo):

```text
.github/workflows/triage.yml:1: LOW    permissions-missing: no permissions: key; the token gets the repository or organization default, which may be read-write
.github/workflows/triage.yml:11: LOW    unpinned-tag: actions/checkout@v4 is a first-party tag; the tag can be moved to other code. Pin the commit SHA and keep the tag in a comment
.github/workflows/triage.yml:13: HIGH   pwn-request: pull_request_target runs with repo secrets and a write token, and this step checks out code from the pull request; that code can read them
.github/workflows/triage.yml:15: HIGH   script-injection: ${{ github.event.issue.title }} is attacker-controlled text pasted into a run: block; pass it through env: and quote the variable
1 files, 1 uses: lines, 4 findings (2 high, 0 medium, 2 low)
```

## Limits

- Static text matching, not a YAML parse and not an execution model. It does not follow reusable workflows into the called file, evaluate `if:` conditions, or see actions fetched at runtime.
- `script-injection` only knows the context values in `ghapincheck/scan.py` (`INJECTABLE`); a custom `workflow_dispatch` input pasted into `run:` is not flagged.
- A SHA pin is only as good as the SHA: `--fix` pins what the tag points to *now*, and it does not verify that commit is trustworthy.
- `--fix` does not resolve `docker://` tags, and it rewrites files in place (use git to review the diff).
- `permissions-missing` is a hint: an organization default of read-only makes it harmless.

Tests: `pip install pytest && python -m pytest` (21 tests; the network step is tested with a stub resolver).

## Related

I also run hosted tools on Apify with pay-per-event pricing, for example the [SEC Form 4 insider cluster scanner](https://apify.com/johnveds15/sec-form4-insider-clusters) and the [OpenVuln CVE scanner](https://apify.com/johnveds15/openvuln-cve-scanner) (CVEs from NIST NVD by product, keyword or CVSS severity, JSON output). They do something different from this tool; there is no paid version of gha-pin-check.

## License

MIT.
