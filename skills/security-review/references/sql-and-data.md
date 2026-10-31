# Pack: SQL and the data layer

Applies to the database layer of a web app: schema, grants, row-level security, migrations, ORM escape hatches, and the connection between the app and the engine.

Three engines, three different threat models. Read the section that matches the repo; the cross-engine sections apply to all.

| Engine | Where the security actually lives |
|---|---|
| **Postgres** (Supabase, Neon, RDS, self-hosted) | real access control exists — roles, grants, RLS, `SECURITY DEFINER`. Most findings are *misconfiguration*, not app bugs |
| **SQLite** (local, Turso/libSQL, Litestream, Drizzle/Prisma dev) | no users, no grants, no RLS. Every authz rule is app-side; the DB is a file |
| **MySQL/MariaDB** | grants exist but are coarse; `FILE` privilege, `SECURITY DEFINER` views/triggers, `sql_mode` changing escaping |

## Injection is not only values

Binding parameters fixes values. These stay injectable and are the ones that survive code review:

- **Identifiers**: `ORDER BY ${col}`, `SELECT * FROM ${table}`, `LIMIT ${n}` (in some drivers), `jsonb_path_query(..., '${path}')`. Parameter placeholders cannot be used for identifiers — use an allowlist map (`{created:'created_at'}`) and reject unknown keys.
- **Direction and nulls**: `ORDER BY x ${dir} NULLS ${last}` — both halves need allowlisting.
- **Dynamic SQL in functions**: `EXECUTE 'SELECT ... ' || user_input` inside plpgsql; `format()` without `%I`/`%L`; `quote_ident` applied to the *value* instead of the identifier.
- **PostgREST filter injection** (Supabase client): `.or(\`name.eq.${q}\`)`, `.filter('col', 'eq', userInput)` where `userInput` contains `,` or `)` — injects additional predicates, including on other columns. Build filters from structured values, not interpolated strings.
- **`LIKE`/`ILIKE`**: `%` and `_` from user input are wildcards; escape them or the "search" becomes enumeration.
- **`IN (...)`** built by string join, and array/JSON path construction from user keys.

ORM escape hatches to grep for:

| Stack | Dangerous |
|---|---|
| Prisma | `$queryRawUnsafe`, `$executeRawUnsafe` (tagged `$queryRaw` is parameterized) |
| Drizzle | `sql.raw()`, string building into `.append()` |
| Knex | `.whereRaw()`, `.orderByRaw()`, `.havingRaw()` with interpolation |
| TypeORM | `.query()`, `createQueryBuilder().where(\`... ${x}\`)` |
| Sequelize | `sequelize.query()` with concatenation; `replacements` is safe, `bind` differs |
| SQLAlchemy | `text()` with f-strings; `text().bindparams()` is safe |
| Django | `.raw()`, `.extra(where=[...])`, `RawSQL()`, `cursor.execute(f"...")` |
| Supabase JS | `.rpc()` calling a function that concatenates; `.or()` string filters |

## Postgres: access control

**Roles and grants**

- The app connects as the schema **owner** or `postgres` in most small projects. Then RLS is inert (owners bypass policies unless `FORCE`), and any injection is full control. Correct: a dedicated `app_user` with `CONNECT`, `USAGE` on schema, and the specific DML grants it needs.
- `GRANT ALL ON ALL TABLES IN SCHEMA public TO app_user` (or `ALTER DEFAULT PRIVILEGES`) hands over every future table too.
- Check: `BYPASSRLS`, `SUPERUSER`, `CREATEDB`, `CREATEROLE` on the app role (`\du+` / `pg_roles`).
- `pg_hba.conf`: `trust` lines, `0.0.0.0/0` in `listen_addresses` or in the provider's IP allowlist ("public database").
- Public schema `CREATE` for `PUBLIC` was revoked by default in PG15+ — on older servers it still lets any role create objects that shadow functions.
- Sequences: a role needs `USAGE` on sequences to insert — often granted with `ALL`, which also allows `setval` and id prediction.

**Row-level security**

- `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` alone is not enough: the **owner** and any `BYPASSRLS` role skip it. Add `FORCE ROW LEVEL SECURITY`.
- Policies need both halves: `USING` (which rows are visible) and `WITH CHECK` (which rows may be written). A policy with only `USING` lets an `INSERT`/`UPDATE` write rows the user cannot then see — the cross-tenant write bug that looks impossible.
- `TO PUBLIC` applies to every role including `app_user` and `anon`; be explicit.
- The tenant identity usually comes from `current_setting('app.tenant_id')`. If the client can run `SET app.tenant_id = 'other'` (any pooled connection where the app issues `SET` from request input), the policy enforces nothing. Use `SET LOCAL` inside a transaction, from a value the app derived from the session, and reset on connection return (`DISCARD ALL`).
- `SECURITY DEFINER` functions bypass RLS by design; `SECURITY INVOKER` does not. Check every function's `prosecdef` flag (`pg_proc`).
- **Views**: before PG15 views run as the owner (`security_invoker=false`) and therefore bypass RLS. On PG15+ set `security_invoker=true`; check `pg_class.reloptions` or `\d+ view`. A "RLS-protected table" with a permissive view on top is a common false sense of security.
- Supabase: `service_role` bypasses RLS entirely — it must never reach the browser. `anon` is the public key: RLS is the only thing protecting data. Check every table in the exposed schema has RLS enabled *and* policies, and that `SECURITY DEFINER` helper functions aren't callable with `anon`.

**Server-side escape hatches**

- `pg_read_server_files`, `pg_write_server_files`, `COPY ... FROM PROGRAM` (superuser) → filesystem read and RCE on the DB host.
- `COPY TO/FROM` with client-controlled paths.
- `postgres_fdw`/`dblink` connecting outward with stored credentials; `plpythonu`/`plperlu` untrusted language functions.
- `pg_stat_activity` / `pg_stat_statements` readable by the app role → other tenants' query text, including literals.
- Extensions installed into `public` (search-path hijack of function calls).

## SQLite

No authz layer exists — so the checks are about the *file* and the app:

- File permissions and location: `0644` on a `.db` in a container image, a backups directory, or anything a static handler can reach. Never serve the database directory.
- `ATTACH DATABASE` with a client-controlled path in dynamic SQL → read/write arbitrary files (and it is injectable even when values are bound).
- `PRAGMA trusted_schema` (3.31+): with it `ON` (older default), triggers and views can invoke unsafe functions; with `OFF`, they cannot. Check the pragma if the schema has triggers.
- `load_extension` is disabled by default — verify nobody enabled it and exposed the path.
- Turso/libSQL: the auth token scope (read vs write) and whether it's embedded in a client bundle or mobile app. A write token in the browser is a full database compromise.
- Litestream/backup files, WAL and `-shm` files, and copies in `node_modules` fixtures or test snapshots.
- Foreign keys are off by default (`PRAGMA foreign_keys=ON` needed) — integrity, not security, but it changes what a "cannot happen" assumption is worth.

## MySQL / MariaDB

- `FILE` privilege (`LOAD_FILE`, `INTO OUTFILE`) on the app user → file read/write on the server.
- `sql_mode`: `NO_BACKSLASH_ESCAPES` changes what escaping means; code that escapes with backslashes and a server without it (or vice versa) is injectable.
- `SECURITY DEFINER` views and triggers created without a fixed `DEFINER` → executed as whoever wrote them, sometimes root.
- Grants on `*.*` or `GRANT ALL` to the app user; `mysql.user` rows with legacy `mysql_native_password`.
- `general_log`/`slow_query_log` files readable and containing literals (passwords in INSERTs).

## Migrations, backups, and lifecycle

- Migrations running as the **owner or superuser** while the app runs as `app_user` — normal, but it means a migration that drops a policy is invisible in app code review. Check the latest migrations for `DROP POLICY`, `ALTER TABLE ... DISABLE ROW LEVEL SECURITY`, `GRANT`.
- Backfills that touch every tenant (`UPDATE invoices SET ...` with no `WHERE`) — correctness bug with a data-exposure flavour when combined with triggers or audit rows.
- Seed/demo data with real PII; fixtures committed with production dumps.
- Backups: unencrypted dumps in object storage, a bucket without a policy, a restore never tested. Untested restore = `needs_validation`, not a pass.
- Deletion: soft delete (`deleted_at`) while the requirement is erasure; backups retaining deleted PII beyond the stated retention.
- Column encryption for special-category data; key management (a key in the same `.env` as the DB password protects nothing).
- Audit trail: trigger-based audit tables are harder to bypass than app-level logging; check the app role cannot `UPDATE`/`DELETE` audit rows.

## Connection and configuration

- Connection string with superuser/owner credentials; `sslmode=disable` or `?ssl=false` for a remote database.
- Credentials in the repo, in `schema.prisma` comments, in Dockerfiles, or in client-exposed env (`NEXT_PUBLIC_`, `VITE_`).
- Pooling via PgBouncer in transaction mode with session-level `SET` → tenant identity bleeding between requests (the classic multi-tenant RLS failure).
- ORM logging at `query` level in production (literals, including tokens, in logs).
- Read replicas with weaker auth used for reports and exports.

## Greps

```bash
rg -n "queryRawUnsafe|executeRawUnsafe|sql\.raw|whereRaw|orderByRaw|createQueryBuilder|\.extra\(|RawSQL|sequelize\.query" --type ts --type py
rg -n "ENABLE ROW LEVEL SECURITY|FORCE ROW LEVEL SECURITY|CREATE POLICY|WITH CHECK|SECURITY DEFINER|security_invoker" --glob '*.sql'
rg -n "service_role|anon_key|SUPABASE_SERVICE|pg_read_server_files|COPY .* PROGRAM|load_extension|ATTACH DATABASE" 
rg -n "GRANT ALL|ALTER DEFAULT PRIVILEGES|BYPASSRLS|SUPERUSER|sslmode=disable" 
rg -n "\.or\(|\.filter\('|\.rpc\(" --type ts
rg -n "DROP POLICY|DISABLE ROW LEVEL SECURITY|ALTER TABLE" --glob 'migrations/**'
```

## False positives

- Raw SQL with only constant fragments and bound values — safe; say so in "checked and clean" so the next reviewer doesn't re-flag it.
- `$queryRaw`, `.bindparams()`, `replacements`, `?`/`$1` placeholders — parameterized by construction.
- RLS enabled without `FORCE` on a table whose app role is *not* the owner — the policy does apply; verify the role, not the keyword.
- A local SQLite file in `dev/` or a test fixture — no boundary crossed.
- Public read-only tables (plans, countries) without RLS on purpose — check they contain nothing per-tenant.
