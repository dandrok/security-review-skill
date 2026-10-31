# Pack: Cloud and deployment

Applies to IAM, object storage, managed databases, containers, edge/serverless config, reverse proxies, and the difference between what the app checks and what the platform allows.

The recurring theme: **the app is a thin layer over permissive infrastructure**, and every control you verify in code can be bypassed by hitting the platform directly.

## Identity and IAM

- Wildcard actions on wildcard resources (`"Action":"*"`, `s3:*`, `iam:PassRole` without conditions) on a role that untrusted code can assume.
- `iam:PassRole` + `lambda:CreateFunction`/`ec2:RunInstances` on the same principal → privilege escalation to any role in the account. This pair is a real finding even in "internal" roles.
- Trust policies that allow `Principal: "*"` with a condition that is missing or `StringLike` on a forgeable value; OIDC trust policies whose `sub` condition is not scoped to a repo+branch (`repo:org/*:*`).
- Long-lived access keys in the codebase or CI instead of OIDC/instance roles; keys older than 90 days with no rotation.
- Over-broad service accounts in GCP (`roles/editor` on the project, `iam.serviceAccountTokenCreator` on self), AAD app registrations with `Directory.ReadWrite.All`.
- Cross-account trust without `ExternalId` (confused deputy).
- Kubernetes: `cluster-admin` bound to a workload SA, `automountServiceAccountToken` default on, RBAC verbs `*` on `*`, `hostPath`/`privileged: true`/`hostNetwork`.

## Object storage

- Public bucket or public objects: `ACL: public-read`, bucket policy `Principal:*`, GCS `allUsers`, Azure container `Blob` anonymous access.
- Path guessability as the only control (`/invoices/2024/acme.pdf`) — enumerate-by-name with public listing or no listing but predictable keys.
- Signed URLs: no expiry, expiry > 24 h, signed for `PutObject`, signed with a long-lived key, or a signer endpoint that will sign any key the client asks for (SSRF-shaped).
- `ListBucket` granted to a role that only needs `GetObject`.
- Uploads: content-type trusted from the client, no server-side `Content-Disposition: attachment`, no size cap, same-origin serving of user content (stored XSS / HTML sniffing).
- Bucket versioning / MFA delete absent on data that is only protected by app-level deletes (ransomware + insider deletion).

## Databases and managed services

- Publicly reachable Postgres/MySQL/Redis/Mongo (`0.0.0.0/0` in security group, `PubliclyAccessible: true`, Atlas/Neon allow-all). Redis with no `requirepass` is an RCE path via `CONFIG SET dir`.
- Admin/studio endpoints (pgAdmin, Prisma Studio, Metabase, phpMyAdmin) exposed without IP restriction.
- DB superuser used by the app; migrations run as superuser in production.
- Backups: unencrypted, public, or never tested. A restore that has never been performed is `needs_validation`, not a pass.
- Elasticsearch/OpenSearch/ClickHouse without auth on a public interface.
- Storage of secrets in a DB column in plaintext where the threat model includes DB read (or backups) — a design finding, judged by blast radius.

## Serverless and edge config

- Vercel/Netlify: env vars without the "sensitive" flag are readable in build logs and by any collaborator; `NEXT_PUBLIC_` handled per `client-react.md`.
- Preview deployments: publicly accessible, built with production env vars, and unprotected by SSO — this leaks data and is a common real finding.
- Function timeouts/memory unbounded and a public route that does heavy work → cost amplification (a finding when the cost is nameable).
- Edge middleware caching personalized responses; `Cache-Control: s-maxage` on authenticated JSON.
- CORS at the edge (`Access-Control-Allow-Origin: *` with `Allow-Credentials`) that contradicts a stricter app-level config — the browser obeys the header, not the code.

## Containers and runtime

- Image runs as root, `read-only` rootfs absent, no `securityContext`, capabilities not dropped (`CAP_SYS_ADMIN`, `NET_RAW`), seccomp/AppArmor unset.
- Secrets baked into the image (`ENV`, `COPY .env`), or mounted as files readable by the app process (acceptable) vs env vars visible in `/proc/1/environ` and crash dumps.
- `:latest` tag in production, unsigned images, unpinned base, base image from a personal namespace, `apt-get install` without version pinning.
- Docker socket mounted into a container (`/var/run/docker.sock`) → host root.
- Health/debug endpoints unauthenticated; `--inspect` enabled in prod (Node inspector = RCE with a port).
- Logs shipped to a shared sink with credentials from multiple tenants.

## Network and transport

- TLS terminated somewhere that does not redirect HTTP → HTTPS; HSTS absent or with `includeSubDomains` missing where subdomains are used.
- Internal services reachable from the public LB because of path routing (`/internal/*` proxied).
- Trusting `X-Forwarded-For` / `X-Real-IP` for authz or rate limiting without verifying the ingress strips client-supplied copies — the app-level rate limiter then becomes bypassable per request.
- Undocumented admin/metrics ports (`:9090`, `:3000`, `:8080`) exposed on a public interface.
- Webhook endpoints reachable without signature verification (see `auth-and-sessions.md`).

## Cloud metadata SSRF (the payout path)

Any SSRF (see `api-and-injection.md`) escalates here:

- AWS IMDSv1 enabled → `http://169.254.169.254/latest/meta-data/iam/security-credentials/` returns temporary credentials. Require IMDSv2 (`http_tokens: required`) and hop limit 1.
- GCP: `http://metadata.google.internal/computeMetadata/v1/...` with `Metadata-Flavor: Google` — needs an SSRF that can set headers, or an open redirect that strips it.
- Azure: `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01` with `Metadata: true`.
- ECS task metadata `http://169.254.170.2` (no header needed) — the easiest to exploit and the most overlooked.
- Fix at the platform: require IMDSv2, block link-local egress from workloads, use a proxy with an allowlist.

## Deployment hygiene that belongs in the report

Only when the review covers the deploy path:

- Migrations that run automatically on deploy against a shared DB (no rollback plan, locks).
- Feature flags and debug modes flipped by env; staging pointed at prod data.
- No `Content-Security-Policy` at the edge while the app sets one (the intersection is what applies).
- Rollback story absent: can you deploy the previous artifact without rebuilding?
- Access to production: shared accounts, no audit trail, no break-glass procedure.

## False positives

- S3 buckets whose policy allows `*` on `GetObject` for keys under a public prefix (`public/assets/*`) — intended, confirm with the caller.
- Security groups `0.0.0.0/0` on port 443 behind a WAF — the finding is the WAF bypass path, not the rule.
- `readinessProbe`/`livenessProbe` endpoints without auth — normal.
- Env vars in a container on a single-tenant, non-shared host — blast radius may make this a note rather than a finding.
- IaC that is not what is deployed (drift) — you cannot conclude from the repo alone; mark `needs_validation` with the exact state question.
