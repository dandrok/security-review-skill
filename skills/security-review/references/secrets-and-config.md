# Pack: Secrets and config

Applies to env handling, config files, build output, logging/telemetry, CI logs, containers, and anything that leaves the local machine with a credential inside it.

Secrets are different from other findings: the fix is rotation plus removal, in that order, and a "revoked" key that is still live invalidates the whole review. Never paste a value.

## Where secrets actually leak

| Surface | How it leaks | Check |
|---|---|---|
| `.env*` committed | git history, forks, CI caches | `git log --all -- .env*`, `.gitignore` coverage, and whether history was ever rewritten |
| Client bundle | `NEXT_PUBLIC_*`, `VITE_*`, any var referenced in browser code, source maps | grep build output, not just source |
| Error tracking | `sendDefaultPii`, breadcrumbs with headers, `beforeSend` absent | Sentry/Datadog/Rollbar init config |
| Session replay | DOM + inputs captured | masking config on forms |
| Logs | token in URL, `Authorization` header logged, `console.log(user)` | logger middleware, request logging |
| CI | `set -x`, `echo $SECRET`, secrets in build args, artifact upload of `.env` | workflow YAML |
| Container images | `ENV SECRET=...`, `COPY .env`, layer history | `docker history`, Dockerfile |
| Public repos/pastes | `.env.example` with real values, notebook outputs, test fixtures with real keys | full-tree entropy scan |
| Client-side storage / URLs | token in query param → Referer, screenshots, shared links | see `client-react.md` |

## Entropy and pattern scan

`scripts/scan.sh` runs gitleaks. If it is unavailable:

```bash
gitleaks dir . --report-format json --report-path /tmp/gitleaks.json --no-banner -l error
# legacy (<8.19): gitleaks detect --no-git -s . --report-format json -r /tmp/gitleaks.json
```

Then triage, because gitleaks is noisy by design:

- **Live or dead?** A key is only a finding if it authenticates. Check the provider's key format/prefix and whether the project's own docs mark it as a test key. Do not test the credential against the provider — that is a live target. Ask, or mark `needs_validation` with the exact question.
- **Reachability:** a test fixture using `sk_test_...`, a documented placeholder (`changeme`, `your-key-here`), or a `ci-` key scoped to a test account is not the same finding.
- **Realm:** did it ever reach a commit? `git log -S '<first 8 chars>'` answers whether it is in history versus only the working tree — different remediation (rotate only, vs rotate + purge history + notify).

## Config posture

- `NODE_ENV=development` / `DEBUG=True` / `APP_ENV=local` shipped in prod config → verbose errors, stack traces, Werkzeug console, open CORS.
- Feature flags that disable auth ("dev bypass", `if (process.env.SKIP_AUTH)`, seeded admin with a known password, `backdoor` routes).
- `.env.example` / README containing real values instead of placeholders.
- Secrets committed in IaC state or `terraform.tfvars` with real values.
- Default credentials anywhere (`admin/admin`, `postgres:postgres`, `minioadmin`) — a finding if the service is reachable beyond localhost.
- `.dockerignore` missing → `.env`, `.git`, `node_modules` copied into the image.
- Backup/dump files in the web root (`db.sql`, `backup.zip`, `.DS_Store`, `*.sql.gz`) reachable via static serving.
- Source maps served in production (`.map`) → full source + any inlined config.

## Logging and data handling

- Logging tokens, passwords, card data, session ids, full request bodies, or `Authorization` headers.
- PII in application logs without retention policy (email, IP, name, address) — a finding only where a regulation or stated policy applies; say which.
- Error responses containing stack traces, SQL, file paths, internal hostnames, dependency versions.
- Analytics/telemetry shipping identifiers off-site without consent or masking.
- PII in URLs (`/user/:email`) → logs, Referer, caches, browser history.

## Remediation shape

For each secret, deliver all four — a partial fix is how secrets survive a review:

1. **Rotate now** — the provider action (revoke, reissue, re-scope). Rotation before removal, always; the old value is compromised the moment it was written.
2. **Remove** — from working tree, then history (`git filter-repo` / BFG), then any cache/artifact/registry copy. Note that forks and clones may retain it.
3. **Prevent** — pre-commit hook (`gitleaks protect`/`dir` on staged files), CI secret scanning, `.gitignore` entry, and a check that fails the build.
4. **Verify** — the old credential returns 401/403; the new one is present in the deployment environment and not in the repo.

If the exposure window included a CI runner or a developer machine, add: audit for follow-on activity (new deploy keys, new OAuth apps, new repo collaborators, unusual outbound calls). This is what Shai-Hulud-class malware does with harvested credentials — see `supply-chain.md`.

## False positives

- Test/CI credentials scoped to a sandbox account with no data, clearly marked — report as low/hardening at most, and say why.
- Public-by-design values: publishable keys (Stripe `pk_`, Supabase anon, Firebase API key, PostHog project key, Sentry DSN). Verify the *policy* behind them (RLS, restricted key, allowed origins); the value itself is not the finding.
- High-entropy strings that are hashes, base64 fixtures, content hashes in lockfiles, or minified code — check how gitleaks classified them before reporting.
- `.env.local` in `.gitignore`, never committed: not a finding; mention only if a hook is missing.

## Greps

```bash
git log --all --oneline -- .env .env.* '*.pem' '*.p12' '*.keystore' | head -20
rg -n "NEXT_PUBLIC_[A-Z_]*(SECRET|KEY|TOKEN|PASSWORD)" .env*
rg -n "console\.log\([^)]*(token|password|secret|key|authorization)"
rg -n "SKIP_AUTH|DISABLE_AUTH|dev.?bypass|DEBUG\s*=\s*True|password.*=.*['\"](admin|test|changeme)"
rg -n "sendDefaultPii|beforeSend|captureConsole|sessionReplay|maskAllInputs"
rg -n "process\.env\.[A-Z_]+" --glob '!*.test.*' | rg -i "secret|token|key|pass"
```
