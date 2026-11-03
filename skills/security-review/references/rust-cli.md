# Rust: CLI tools, services and parsers

Read this when the repo is Rust (`Cargo.toml`, `*.rs`, `build.rs`). Rust removes the
memory-safety class — no buffer overflow, no use-after-free, no type confusion — so a
review that stops at "it is Rust, therefore safe" reports nothing. The bugs that
remain are about **trusting a number, a path, a string or a child process**, and they
are just as reachable here as in any language.

## What is not a finding in Rust (do not report)

- `unsafe` merely appearing. Read it: if it is a well-known crate, or a `#[repr(C)]`
  handoff with a documented invariant, it is not a finding on its own.
- Memory-safety classes: overflow, UAF, double free, uninitialised reads. The
  compiler owns those; report them only inside an `unsafe` block you can trace.
- Missing null checks, missing `free`, "should use a smart pointer" — the type system
  already answers these.
- `unwrap()` in a test, in `main` with a documented invariant, or after an explicit
  emptiness check three lines above.

## Sink catalogue

### 1. Panic as denial of service

A panic in a library is safe for memory and fatal for the process: a CLI aborts, a
server task dies, a `catch_unwind`-less thread takes the handler with it.

| Sink | What to check |
|---|---|
| `unwrap()` / `expect()` | Is the `Option`/`Result` reachable from untrusted input? A user-supplied path, a book file, a config value |
| `[i]`, `a..b`, `&s[n..m]` | Index bounds and **UTF-8 char boundaries** — `&text[0..n]` panics when `n` splits a multi-byte char, which is book text in a non-English language |
| `as` casts | `u64 as usize` truncates on 32-bit; `len() as u32` wraps. Truncation decides sizes and offsets |
| Integer arithmetic | Overflow panics in debug, wraps in release — different behaviour per profile is a bug either way |
| `Duration::from_secs(a - b)` | Subtraction underflow from two untrusted values |
| Recursion over untrusted nesting | XML/JSON/zip nesting depth is attacker-chosen: deep recursion is a stack overflow, not an error |

### 2. Unbounded allocation from an untrusted length

The most common real finding in Rust file parsers:

```rust
let mut buf = String::with_capacity(entry.size() as usize);  // header says 40 GB
reader.read_to_string(&mut buf)                              // or inflates to 40 GB
```

Any length that arrives from a file header, an HTTP `Content-Length`, a protobuf
varint or a `Vec` length prefix is attacker-controlled. Check for a ceiling on both
the declared size *and* the actual read (`Read::take(limit)`), plus a per-document
total. Decompression (zip, gzip, brotli) amplifies by 1000× and is the classic vector.

### 3. Paths

- Traversal is only a finding when an attacker-controlled **relative** path reaches a
  filesystem call (`File::open`, `fs::write`, `remove_dir_all`). Indexing an in-memory
  archive by such a name is not traversal — say so and move on.
- Symlinks: `canonicalize()` resolves them; a check on the path *before* the operation
  and the operation itself are a TOCTOU pair. For "must stay inside this root", compare
  the canonicalized result against the canonicalized root, then open the same handle.
- Predictable temp paths in a shared `/tmp` are symlink bait; `tempfile` exists.
- Creating files inherits the umask — a cache of book text written `0644` in a
  multi-user box is a disclosure.

### 4. Subprocess

```rust
Command::new("mpv").arg(&user_supplied)      // safe: argv, no shell
Command::new("sh").arg("-c").arg(format!(…)) // the whole injection class is back
```

- `Command::new("x").arg(t)` never interprets metacharacters; `sh -c` with
  interpolation does. Flag only the second.
- A binary resolved from `PATH` can be shadowed by a writable directory earlier in
  `PATH`. For a tool that runs as the user this is low severity; for anything with more
  privilege it is not.
- Inherited environment reaches the child: `LD_PRELOAD`, `MPV_*`, proxy variables.

### 5. Deserialisation

- `serde` with a size/depth-unbounded reader is the allocation issue again, plus
  unbounded recursion on nested structures.
- Without `#[serde(deny_unknown_fields)]`, a typo'd or attacker-added field is silently
  ignored — that is a correctness issue, not a vulnerability, unless the field controls
  authorisation.
- Defaults: `Option<T>` fields that fall back to "allow" are the reject-by-default bug.

### 6. Terminal output (CLI-specific, and usually missed)

Untrusted text printed to a TTY is interpreted by the terminal: ANSI CSI/OSC sequences
can move the cursor, rewrite the prompt, or set the clipboard (OSC 52) with attacker
text. A book title from an EPUB is untrusted. Strip or escape control characters before
printing anything that came from a file or the network.

### 7. Local network surface

- A server bound to `127.0.0.1` is still reachable by every local process, and by a web
  page via DNS rebinding if it sends no `Origin`/`Host` check. "Localhost only" is not
  an authorisation boundary.
- TLS: `danger_accept_invalid_certs`, `danger_accept_invalid_hostnames`, or a custom
  verifier that returns `Ok(())` disables the only control that exists.
- Redirects to a different scheme/host, and proxies read from the environment, turn a
  configured endpoint into an SSRF pivot.

### 8. Supply chain and build

- `build.rs` and proc macros execute **at build time**, with network and full filesystem
  access, before any of your code runs. A new dependency that ships one deserves a read.
- `cargo audit` (RustSec advisories) and `cargo deny` (advisories, licences, bans,
  sources) are the two deterministic passes; run both. `yanked = "deny"` matters: a
  yanked crate is a maintainer saying "do not use this build".
- Typosquats: check that a newly added crate name matches the one in the docs you were
  reading. `serde_json` vs `serde-json` is a real published pair.
- `unsafe` count in a dependency is a signal, not a verdict; `cargo geiger` gives the
  number per crate in seconds.
- Features are attack surface: a default feature that opens a socket, shells out, or
  pulls native code should be disabled (`default-features = false`).

### 9. Secrets

`env::var` for tokens, values in `Debug` output (a `#[derive(Debug)]` struct holding a
key prints it), panic messages carrying connection strings, and `RUST_LOG=trace` dumps.
Reference the `file:line` and the kind of secret; never paste the value.

## Method notes for Rust reviews

- The trust boundary is usually **a file, a socket, or a child process**, not an HTTP
  session. Write the boundary map anyway: it is what stops you reporting clippy advice.
- Prefer `forbid(unsafe_code)`/`deny(unsafe_code)` presence as a fact to record, not a
  finding to raise.
- Run `cargo deny check` and `cargo audit` before hunting: a dependency advisory is the
  cheapest finding you will ever produce (a `zip` crate that preserves SUID bits on
  extract is a good example of one we would otherwise have missed).
- A panic that a request can trigger is a denial of service; a panic that only a
  developer can trigger is a test gap. Distinguish them explicitly.
