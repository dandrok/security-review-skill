# Pack: API and injection

Applies to HTTP handlers, RPC/GraphQL, message consumers, and CLI surfaces in Node/TS, Python, Go, PHP, Ruby, Java.

Read `SKILL.md` steps 2–4 first. This pack is a sink list, not a checklist to tick: each entry names the invariant and the way it is usually half-enforced.

## Map input to sink before reading further

| Sink | Ask |
|---|---|
| SQL / query builder | is every interpolation a bound parameter, including `ORDER BY`, `LIMIT`, column names, JSON paths? |
| Shell / `child_process` / `eval` | does any string reaching it contain request data? |
| Filesystem | is the path joined to a fixed root and canonicalized after joining? |
| Outbound HTTP | is the host allowlisted, or only the scheme checked? |
| Template / HTML / markdown | is it auto-escaped, and is the escape the same one the sink needs? |
| Deserializer | is the format trusted (JSON) or capable (pickle/yaml.load/node-serialize)? |
| ORM object | is it bound from a client-supplied object, or from an explicit field list? |

## SQL / NoSQL injection

**Invariant:** request data never becomes query *structure*.

- Grep: `query(`, `execute(`, `raw(`, `$queryRaw`, `createQueryBuilder`, `\.where\(`, `.find(` with `$where`, Mongo `.aggregate(` with client operators.
- The usual miss: parameters are bound in `WHERE`, but identifiers are concatenated — `ORDER BY ${sort}`, `LIMIT ${limit}`, `SELECT * FROM ${table}`, `column=${col}`. Binding does not apply to identifiers. Use an allowlist map (`{created: 'created_at'}`) and reject unknown keys.
- Prisma: `$queryRawUnsafe`/`$executeRawUnsafe` with a template argument is injection; `$queryRaw\`...\`` tagged template is parameterized. Check which one is used.
- Mongo: `find(req.query)` lets the client pass `{ "$ne": null }` or `$where` JS. Coerce to string, or use a schema validator (zod/joi) that rejects objects. Also check `$regex` from user input → ReDoS.
- DynamoDB/Firestore: injection looks like a client-supplied field path or index name; same allowlist answer.

Fix: bound parameters for values, allowlist maps for identifiers, a single data-access helper so future queries inherit the safe path.

## Command injection

**Invariant:** no request-derived string is ever parsed as a command line.

- Grep: `exec(`, `execSync(`, `spawn(`, `spawnSync(`, `system(`, `popen`, `Runtime.exec`, `os/exec`, backticks, `shell=True`.
- High-risk signatures: `spawn(cmd, { shell: true })`, `exec` with a template literal, `sh -c` with concatenation, ImageMagick/ffmpeg/pandoc/git wrappers, `child_process` inside a route handler.
- Safe shape: `spawn('git', ['log', '--author', user])` — argv array, no shell. If a shell is unavoidable, `execFile` with an argv array.
- Second-order: a value validated at input, then `$EDITOR`/`--upload-pack`/`-o` style flags reach a CLI. Leading `-` argument injection is injection even with no shell; prefix with `--` and reject values starting with `-`.

## Path traversal and file handling

**Invariant:** the final resolved path is inside the intended root, checked *after* resolution.

- Grep: `path.join(`, `path.resolve(`, `fs.readFile`, `sendFile`, `readFileSync`, `os.path.join`, `open(`, `filepath.Join`, `File(`, `ZipFile`, `tarfile`, `extractall`.
- The usual miss: `path.join(root, req.params.name)` — `join` normalizes but does not constrain; `../../etc/passwd` escapes. Must be `const full = path.resolve(root, name); if (!full.startsWith(root + path.sep)) reject;` and the root itself must already be `path.resolve`d. Watch `%2e%2e%2f`, double-encoding, unicode separators, and Windows `C:` / `\\?\` forms.
- Uploads: filename from client → server path (traversal); extension trusted → served as HTML/SVG (stored XSS); no size cap (disk exhaustion); archive extraction without symlink/`..` checks (zip-slip).
- Download endpoints keyed by id: check the object is *owned by* the requester, not merely that it exists.
- Static serving: confirm `dotfiles:'deny'`, no source maps, no `.git`, no `.env` reachable via the static root.

## SSRF

**Invariant:** the destination is chosen by the server, or validated against a strict allowlist, after DNS resolution.

- Grep: `fetch(`, `axios`, `got(`, `requests.get`, `http.Get`, `urllib`, `new URL(`, webhook URL fields, image/PDF fetchers, "import from URL" features.
- The usual miss: scheme check only (`http`/`https`), or a blocklist of `127.0.0.1` that misses `0.0.0.0`, `[::1]`, `169.254.169.254`, decimal/octal IPs, `*.localtest.me`, redirect chains, or DNS rebinding (validate the resolved IP, then connect to that IP).
- Cloud metadata is the payout: `169.254.169.254` (AWS/Azure/GCP), `metadata.google.internal`, `fd00:ec2::254`. On AWS require IMDSv2 (token, `X-Forwarded-For` hop limit 1); the absence of IMDSv2 turns any SSRF into credential theft.
- Redirects: `fetch` follows by default. `redirect: 'manual'` or re-validate each hop.
- PDF/render pipelines (`puppeteer`, `wkhtmltopdf`, headless Chrome) fetch subresources — restrict to a local proxy allowlist.

## Template, HTML, and encoding

- **SSTI:** user data passed as the *template* rather than as a variable (`ejs.render(userStr)`, `Handlebars.compile(input)`, `render_template_string`, Jinja `Template(...)`). Data belongs in the context argument.
- **XSS is a sink mismatch** — see `client-react.md`; here the server-side cases are: echoing `req.query` into an HTML error page, `res.send('<h1>' + name)` without escaping, JSON served as `text/html`.
- **Header injection:** any request value written into a header must reject `\r`/`\n` (Node's `setHeader` throws, `res.writeHead` with a raw object may not).
- **Log injection:** user input into logs without newline stripping — forges audit lines. Same class, low severity, still worth a line.

## Deserialization

- Capable formats are the finding, not the payload: `node-serialize`, `serialize-javascript` with `eval`, Python `pickle`/`marshal`/`yaml.load` (no `SafeLoader`), Java `ObjectInputStream`, PHP `unserialize`, .NET `BinaryFormatter`, `JSON.parse` + `eval`.
- YAML: `yaml.load(x)` vs `yaml.safe_load(x)`; JS `js-yaml` `load` on untrusted input has had code-exec gadgets via `!!js/function` in older versions — check the version floor too.
- `JSON.parse` is safe by itself; the finding appears when its output is used as an object path, spread into a model, or fed to a template engine.

## Mass assignment / overposting

**Invariant:** the persisted field set is explicit, never derived from the request body.

- Grep: `req.body` passed into `create(`/`update(`/`save(`, `Object.assign(entity, req.body)`, `new Model(req.body)`, `**request.json()`, `setattr(obj, k, v)` loops.
- Attack shapes: `{"role":"admin"}`, `{"isVerified":true}`, `{"tenantId":"other"}`, `{"balance":1e9}`, price/quantity on an order.
- Fix: explicit picks (`pick(body, ['name','email'])`), DTO/schema with `.strict()`, ORM-level guarded fields.

## XXE and file parsers

- XML parsers with external entities enabled: libxml (PHP `<8`, Python `lxml` with `resolve_entities=True`, Java `DocumentBuilderFactory` without `disallow-doctype-decl`), `xml2js`, SVG uploads parsed server-side.
- Also: SVG → server-side rasterization executes; CSV → spreadsheet formula injection (`=CMD|`); image → decompression bomb; PDF → JS callbacks.

## ReDoS and resource abuse

- Grep for nested quantifiers `(a+)+`, `(.*)*`, user-supplied patterns compiled (`new RegExp(userInput)`), `$regex` from query params.
- Unbounded loops over client-sized input (`limit` from the request with no max), recursive JSON depth, `JSON.parse` on a 100 MB body, GraphQL query depth/aliases without limits, `?expand=` recursive includes.
- These are real findings only with a named cost: CPU pinning per request, memory per connection, or a bill. Otherwise they belong in "hardening", not the report.

## Transport, headers, CORS, CSRF

| Check | The miss |
|---|---|
| CORS | `origin: true` reflection, `credentials: true` with reflected origin, `null` origin accepted, regex `/example\.com/` matching `example.com.evil.tld` |
| CSRF | cookie-auth state-changing endpoints without token/`SameSite`; `SameSite=None` without `Secure`; GET performing writes |
| Security headers | missing HSTS on an HTTPS-only site, `X-Frame-Options` absent on authenticated UI (clickjacking), `Content-Security-Policy` absent or `unsafe-inline`, `X-Content-Type-Options` absent |
| Cookies | no `HttpOnly`/`Secure`, `Path=/`, no `__Host-` prefix, session id in URL or localStorage |
| Method/verb | `PUT`/`DELETE` routes registered without the auth middleware the `GET` uses |
| Cache | authenticated JSON with `Cache-Control: public`, or missing `Vary` — CDN cross-user leak |

## Error handling and leaks

- Stack traces, ORM errors, and file paths returned to clients (Django `DEBUG=True` in prod config, Express default handler, `console.error(err); res.send(err)`).
- Distinguishable responses: `404` vs `403` leaking object existence; login timing or message differences leaking account existence (only a finding if it matters for the threat model — enumeration of a public directory often does not).
- Verbose debug routes (`/graphql` introspection in prod, `/actuator/env`, `/_debug`, Hono/Express playground) exposed without auth.

## Starter greps

```bash
rg -n "exec\(|execSync|spawn\(|shell:\s*true" --type ts --type js
rg -n "queryRawUnsafe|executeRawUnsafe|\$where|new RegExp\("
rg -n "path\.join\([^)]*(req|params|query)|readFile\([^)]*(req|params)"
rg -n "fetch\([^)]*(req|params|query|body)|axios\.(get|post)\([^)]*(req|params)"
rg -n "Object\.assign\([^,]+,\s*req\.body|new \w+\(req\.body\)"
rg -n "origin:\s*true|credentials:\s*true|allowedOrigins.*\*"
rg -n "pickle\.load|yaml\.load\(|unserialize\("
```

## False positives specific to this pack

- `exec(`${fixed} ${validatedEnum}`)` where the variable is drawn from a constant map — record it as hardening, not injection.
- ORMs that escape identifiers (`knex` with `.orderBy(col)` is still concatenation; `drizzle` `sql.raw` is; plain `where({col: val})` is not).
- `fetch(userUrl)` in a local-only admin tool with no credentials in the process — reachability kills it; note the assumption.
- Rate limiting absent on an endpoint whose cost is a single indexed read — not a finding without an abuse story.
