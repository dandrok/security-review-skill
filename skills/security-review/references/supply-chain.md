# Pack: Supply chain and release

Applies to dependency graphs, install hooks, the publishing path, CI/CD, and anything that runs with your credentials before a human reads the diff.

This is the pack that most often produces *critical* findings in otherwise clean codebases, because the attack happens at `install` time, before any code review or test runs.

## Why this changed: the Shai-Hulud class

The 2025–2026 npm worms are the reference model. Understand the shape, then grep for it:

- **Entry:** compromised maintainer account (phishing, stolen PAT, token in a leaked `.npmrc`). Multiple packages published at once.
- **Execution:** `preinstall`/`postinstall`/`prepare` script in `package.json`, or a git/tarball dependency whose prepare script runs. In Shai-Hulud 2.0 the hook was `setup_bun.js`, which bootstrapped a Bun runtime and ran an obfuscated 2 MB stealer; `&& exit 1` made npm treat the install as failed so the developer saw nothing.
- **Harvest:** `~/.npmrc`, `~/.aws/*`, `~/.config/gcloud`, env vars, GitHub PATs, SSH keys, `.env` files, shell history. TruffleHog was bundled to find them.
- **Exfil:** to attacker-controlled endpoints (often `webhook.site`), sometimes *publicly* — creating a public repo via the GitHub API.
- **Persistence + spread:** new self-hosted GitHub Actions runner (`SHA1Hulud`), malicious workflow files committed to reachable repos, then republish to the maintainer's other packages.
- **2026 escalation ("Mini Shai-Hulud"):** 170+ npm packages plus PyPI packages in one campaign, malicious `optionalDependencies` cloned from a GitHub fork into the npm cache, silent `exit 1` again.

Signals to look for in a repo you are reviewing:

```bash
rg -n '"(pre|post)?install"\s*:\s*"' package.json */package.json
rg -n "bun_environment|setup_bun|trufflehog|webhook\.site|trycloudflare" -g '!node_modules'
find . -name "*.yml" -path "*workflows*" -newer package.json -print      # unexpected workflow edits
rg -n "runs-on:.*self-hosted" .github/workflows
git log --oneline --author=".*\[bot\]" --since="3 months ago"
```

## Dependency graph

| Check | Why |
|---|---|
| Lockfile committed and used (`npm ci`, `pnpm install --frozen-lockfile`, `uv sync --locked`) | without it, resolution is a moving target |
| `package.json` uses exact versions or `~`, not `^`/`*` for sensitive deps | range = future compromise delivered automatically |
| No `git+https://` or `github:user/repo#branch` deps | mutable source, runs `prepare` scripts, no registry review |
| No tarball URLs (`https://…/x.tgz`) | same, plus no integrity metadata |
| `overrides`/`resolutions` not silently downgrading patched transitive deps | common way to reintroduce a CVE |
| Typosquats in the diff | `crossenv`/`cros-env`, `event-stream` precedent, `@tanstack/setup` in 2026 |
| New deps in the diff reviewed by name, publisher, age, weekly downloads, repo link | a 2-day-old package with 3 downloads and a postinstall is the whole attack |
| `npm audit`/`osv-scanner` output triaged, not pasted | CVE count is not a finding list; reachability decides |
| Python: `requirements.txt` unpinned, `--extra-index-url` present (dependency confusion), setup.py `install_requires` from URLs | same class, other ecosystem |

Dependency CVEs: run `osv-scanner` and map each hit to *usage*. A vulnerable `lodash.template` in a code path nobody calls is low. `scripts/scan.sh` collects this; report exploitable ones only, and list the rest as a count. Its exit 3 means a scanner was missing or crashed — a coverage hole, not a clean lockfile; say so instead of writing "no advisories".

## Install-time execution

- Any `preinstall`/`postinstall`/`prepare` script in a dependency is arbitrary code with your user's credentials. In the target repo's own `package.json`, check whether the script is needed and whether `--ignore-scripts` is viable.
- CI: `npm install` (not `ci`), `--ignore-scripts` absent, install steps running with a write-scoped token.
- Editor/agent tooling that runs on install (`.vscode` tasks, `husky`, `lint-staged`, `simple-git-hooks`) — a hook installed from a dependency executes on commit.

## Publishing and provenance

- npm publish with a long-lived token in CI (`NPM_TOKEN` classic) instead of **trusted publishing / OIDC provenance** (`npm publish --provenance`).
- 2FA on the publisher account is TOTP, not WebAuthn/passkeys (TOTP phishing is how maintainers get owned).
- Published artifact built from a different commit than the tagged source; no `npm pack` diff review; `files` field dragging in `.env`, tests, or keys.
- `prepublishOnly`/`prepack` scripts that mutate the artifact.
- Container images: `:latest` in production, unsigned images (no cosign/sigstore), no digest pinning, base image from a personal namespace.
- Terraform/module sourcing from a branch instead of a tag, registry modules unverified.
- SLSA/attestations absent on artifacts you deploy — worth a line, rarely a critical.

## CI/CD permissions and secrets

- Workflow `permissions:` missing → default token may be write. Correct: top-level `permissions: contents: read`, elevated only per job.
- `pull_request_target` + checkout of the PR head → arbitrary code with secrets and a write token. This is the single highest-value CI finding; check every workflow that has it.
- `workflow_run` chains escalating from fork PRs.
- Fork PR jobs with `secrets.*` available, or secrets passed as `env` to a step that runs repo code.
- Actions pinned by tag (`@v4`) rather than full SHA — a compromised tag re-points the action. Line-level finding in security-sensitive repos.
- Self-hosted runners on public repos (fork PRs execute on your infra).
- Caches shared across branches in a way that lets one PR poison the next build; `actions/cache` key derived from lockfile *content* is the fix.
- Artifacts uploaded from untrusted builds then executed by a privileged job.
- Long-lived cloud keys in CI (`AWS_SECRET_ACCESS_KEY`) instead of OIDC role assumption with a scoped trust policy.
- Deploy jobs that build from a PR-controlled Dockerfile with production secrets in scope.

## Repo and maintainer posture (light pass)

Only worth reporting when the repo *is* the product (a library, an action, a container image):

- Branch protection on default branch, signed commits where the org requires it.
- Secret scanning + push protection enabled; Dependabot/Renovate enabled with grouping.
- `SECURITY.md` / disclosure path; private vulnerability reporting on.
- Release artifacts checksummed and published alongside a changelog.
- Vendored code identified; a vendored `jquery.min.js` is a maintenance finding, not a vuln.

## Remediation shape

- Compromised dependency: pin to the last clean version (record the exact version and date), remove the package, rotate **every** credential reachable from the build and dev machine, audit for new deploy keys/OAuth apps/runners/repo collaborators, then re-add a reviewed version.
- Provenance: OIDC trusted publishing + `--provenance`, 2FA → WebAuthn.
- CI: `permissions` block, SHA-pinned actions, OIDC cloud auth, no `pull_request_target` with head checkout.
- Prevention gate: `npm ci --ignore-scripts` where possible, lockfile lint in CI, `osv-scanner` on PR, block install scripts via `allow-scripts`/`ignored-scripts` config.

## False positives

- `npm audit` high/critical on a dev-only dependency with no runtime exposure — say "dev-only, no production path" and keep it out of the headline.
- Lockfile churn without a version change; generated files.
- A `postinstall` in the repo's own package.json that runs a local build step (`husky install`) — normal.
- Missing `permissions:` in a workflow that only reads, where the default is read-only org-wide (verify the org setting before claiming otherwise).
