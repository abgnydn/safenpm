# Changelog

All notable changes to safenpm are recorded here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The
project follows [Semantic Versioning](https://semver.org/), with the
explicit caveat that pre-1.0 (`0.x`) releases may break compatibility
on any minor bump.

## [Unreleased] — security hardening sprint, 2026-05-22

Four-phase sprint that closes the largest items from the 0.1.0
SECURITY.md "Misses (important)" section, deliberately ahead of the
0.2 release because the gaps were too tractable to defer.

### Added

- **Symlink audit** (`src/analysis/symlinks.ts`) — walks every
  installed package, flags symlinks whose target escapes the
  package directory or uses an absolute path. Closes the "ship a
  symlink to /etc/passwd, then read it from postinstall" pattern
  that path-allow-list sandboxes can leak.
- **Native `.node` byte scanner** (`src/analysis/native.ts`) — for
  every compiled addon under node_modules, scans the binary for
  dangerous imported symbol names (`execvp` / `socket` / `dlopen` /
  `LoadLibraryA` / …) as null-terminated string-table matches.
  Works across Mach-O / ELF / PE without parsing the file format.
  Closes the dlopen-blind-spot in the install sandbox.
- **Runtime enforcement** (`src/runtime/{policy,enforce}.ts` +
  `safenpm run --enforce-runtime`) — `node --require`-loaded hook
  that intercepts every CJS `require()`, looks up the calling
  package via the existing `packageOfFile()` helper, consults a
  policy file, and throws `SafenpmDenied` for any disallowed
  builtin. Default deny-list: `child_process`, `https`, `http`,
  `http2`, `net`, `dgram`, `tls`, `dns`, `vm`, `worker_threads`,
  `cluster`, `inspector`, `module`, `wasi`, `v8`. Per-package
  overrides via `.safenpm-policy.json`. Denies logged to
  `~/.safenpm/enforce-denies/<ts>-<pid>.json`. End-to-end verified
  on a fixture that does `require('child_process')`.
- **`safenpm run --generate-policy [--from-trace]`** — writes a
  `.safenpm-policy.json` from either the built-in defaults or the
  most recent runtime trace, locking each package to exactly the
  dangerous builtins it was already using.
- **`(trace …)` directive in the macOS strict sandbox profile** —
  defence-in-depth on top of the SIGABRT fix. The sandbox-exec
  trace log is parsed after the run; any `deny` line escalates a
  classifier "clean" verdict to "blocked". Catches the narrow
  "kernel denied a syscall but the child handled the error
  gracefully (exit 0, empty stderr)" case.
- **11 new static-analysis rules** covering ESM-aware require
  forms (`node:` prefix), HTTP/2, WebSocket, TLS, IPv4 literals,
  vm module, `process.binding()`, worker_threads, cluster,
  Buffer-from-hex obfuscation, `bash -c "$(...)"` shell-command-
  substitution, and (the cheapest pattern-matcher bypass)
  **dynamic require/import with non-literal arguments**.
- **Nested-dependency static analysis** — `findInstallScripts`
  recurses into `node_modules/<a>/node_modules/<b>/...` up to 8
  levels deep. Sandbox already executed nested install scripts;
  only the static analyzer was missing them.
- **Env-var regex stripping** — `cleanEnv` now strips any var
  matching `*_TOKEN` / `*_SECRET` / `*_KEY` / `*_PASSWORD` / `*_PWD`
  / `*_CREDENTIALS` in addition to the existing explicit list.
  Keep-list (`SSH_AUTH_SOCK`, `XDG_*`) prevents native-compile
  breakage.

### Tests

- **373 unit tests** total (+45 from this sprint: 17 policy, 10
  native, 9 symlinks, 7 env, 2 steps).
- **24 / 24 golden snapshots** (regenerated for the expanded help
  text covering `safenpm run`).
- **90 / 90 integration tests.**

### Changed

- SECURITY.md "What's in scope" / "What's NOT in scope" sections
  rewritten to reflect what just landed. The "Misses (important)"
  list shrunk by 4 items: runtime code execution, compiled-payload
  symbol scan, escape symlinks, and the `process.binding()` /
  dynamic-require bypass. New misses surfaced: ESM enforcement
  (deferred to 0.4), syscall-literal native backdoors, build-time
  bundler plugins.



This is the first pre-release after the in-tree refactor. The package
was previously labeled `1.0.0` on npm; that version label was retired
because the project had not earned the stability implied by `1.0`.
Functionality is broadly preserved (golden snapshots enforce
byte-identical CLI output through the refactor) but the version label
now reflects pre-1.0 status.

### Note on npm versions

`@abgunaydin/safenpm@1.0.0` (published 2026-04-02) is deprecated in
favour of `0.1.0` to reset SemVer. npm doesn't permit downgrading
version numbers, so **the next published version will jump back into
the `1.x` range** (`1.0.1` or later). Consult this CHANGELOG and the
GitHub releases page for the canonical version timeline — the npm
`@latest` tag may show a higher number than the GitHub release
sequence implies, by design.

### Added

- **SECURITY.md** with the honest threat model — what's in scope
  (install-time scripts, typosquats, lockfile, maintainer changes)
  versus what isn't (runtime code execution, native binary backdoors,
  Sybil attacks beyond stated mitigations, targeted attacks).
- **CHANGELOG.md** (this file).
- **Reporter** strategy (`src/report/{reporter,human,json}.ts`) —
  decouples emit from JSON-mode gating. Every visual emit goes through
  the injected reporter; JSON mode is a literal no-op.
- **Pipeline + Step** abstraction (`src/pipeline/`) — pre-script and
  post-script analyses run as declarative step arrays with a typed
  discriminated-union `Finding` shape.
- **OS-specific sandbox strategies** under `src/sandbox/` —
  `macos.ts` / `linux.ts` / `windows.ts` / `unsandboxed.ts` with a
  shared `classify` outcome layer and a cached backend selector.
- **Validators** for the Cloudflare Pages handlers
  (`functions/_lib/validate.ts`) — every `as any` on Redis reads is
  gone; `parseSignal` / `parseIntelQuery` / `parseFlaggedEntry`
  enforce the wire shape.
- **297 unit tests across 28 files** (up from zero coverage before
  the refactor). Major suites: analyzer, lockfile, reputation,
  typosquat, allowlist (incl. scope-wildcard injection cases),
  package-name validation (path traversal, shell metas, unicode
  lookalikes), audit-log round-trip, pkgdiff snapshot/diff, sandbox
  env stripping, sandbox result classification, sandbox dispatch,
  Linux firejail args, macOS profile invariants, pipeline runner +
  step list, CLI arg parser, threat-intel validators (Sybil-
  resistance cases), Reporter rendering, runtime tracer utils.
- **Golden snapshot harness** at `test/golden/` — captures 24
  fixture-based runs and re-runs them on every check, normalizing
  timestamps / `$HOME` / mktemp paths.
- **CI workflow** at `.github/workflows/ci.yml` — matrix unit job
  across Ubuntu + macOS + Windows × Node 18/20/22, separate golden
  job (Unix-path snapshots), macOS integration job, Ubuntu coverage
  job with artifact upload.
- **`.safenpmrc` typosquat allowlist** — lines starting with `!` in
  `.safenpmrc` suppress typosquat flags for that exact name. Reduces
  false-positive friction on internal mono-repos.
- **`safenpm trace -- <command>`** — observe-only runtime tracer.
  Runs the user's command with a `node --require` loader that
  monkey-patches `Module.prototype.require` to record, per package,
  which Node builtins and which downstream packages each dependency
  reaches for at runtime. Trace JSON is written to
  `~/.safenpm/pkg-traces/`. CJS only; ESM `import` is not captured.
  Closes the first concrete step from `docs/runtime-isolation.md`.
- **`safenpm trace --diff`** — compares the two most recent traces,
  reports per-package new builtin / package requires, color-tiers
  newly-appearing builtins by severity (critical: child_process,
  http/s, net, vm, dgram, tls, dns, cluster, worker_threads,
  inspector, module; high: fs, crypto, os, process; medium: rest).
  Exits 1 if any critical-tier builtin newly appears so CI can gate
  on post-takeover dependency mutation. Verified end-to-end on a
  fixture that adds `require('https')` + `require('child_process')`
  between two trace runs.
- **`safenpm trace --list`** — lists recent traces in
  `~/.safenpm/pkg-traces/` (most recent first, with package count
  and file size). Supports `--json` for CI.
- **`diffTraces()` / `categorizeBuiltin()` / `listTraceFiles()` /
  `readTraceFile()`** in `src/runtime/utils.ts` — exported pure
  helpers for consumers that want to roll their own diff tooling.

### Changed

- **Version label `1.0.0` → `0.1.0`** across `package.json`, the CLI
  `--version` output, the User-Agent on outgoing signal reports, the
  site (`index.html`, `showcase.html`, `privacy.html`, `og.svg`,
  `og.png`, `og-render.html`), and the integration assertion.
- **Reputation scoring is now honest about what it is.** The README
  framing changed from "scores every package" (with implied
  authority) to "package.json-only heuristic." Real CVE data comes
  from the new `npm audit` integration (see Added).
- **Lucide is now vendored locally** at `site/vendor/lucide.min.js`
  (pinned to v0.456.0). The previous `https://unpkg.com/lucide@latest`
  CDN reference would have allowed a lucide/unpkg compromise to
  execute arbitrary JS on safenpm.dev.
- **TypeScript flags tightened** — `noUncheckedIndexedAccess` and
  `exactOptionalPropertyTypes` are now on. The Levenshtein matrix in
  typosquat detection moved to a flat row-major buffer to satisfy the
  stricter flag without unsafe assertions in the hot loop.
- **`<main>` landmark + skip-to-content link + `prefers-reduced-motion`
  guard** added to all three site pages.
- **fonts.gstatic preconnect** added to the site (was preconnecting
  only the CSS host).
- **README** rewritten to match reality — pre-release status badge,
  honest framing of the threat-intel network as "experimental opt-in"
  rather than "live community", actual threshold numbers and
  Sybil-resistance caveat, and a "Misses (important)" section that
  leads with runtime code execution.

### Security

- **Sybil-resistance on threat-intel `distinctReporters`.** Previously,
  the counter incremented on every non-deduped report, so an attacker
  controlling N machineIds could fire N reports and trip the flag
  threshold of 3. Now:
  - `MIN_MACHINE_ID_LEN = 16` and a strict `[a-zA-Z0-9_-]` character
    class are enforced server-side. Short or symbol-laced machineIds
    are rejected outright.
  - `distinctReporters` is backed by a Redis SET keyed on the
    package version. `SADD` returns 1 only for genuinely-new
    machineIds, so repeat reports never inflate the count.
  - Reports under `machineId: 'anonymous'` are accepted but never
    increment the counter — anonymous is treated as one shared
    identity to prevent trivial inflation.
  - Flag threshold raised **3 → 5** for non-curated packages
    (`FLAG_THRESHOLD_DEFAULT`); curated stays at 15.
- **`exactOptionalPropertyTypes` + `noUncheckedIndexedAccess`** are
  on. The audit log now conditionally spreads optional fields rather
  than passing `undefined`, eliminating an entire class of
  shape-pollution bugs in the persisted JSON-lines format.
- **`functions/api/v1/*` no longer uses `as any`** on Redis reads —
  every entry passes through `parseFlaggedEntry` and is rejected if
  the `reasons` or `platforms` field isn't an object.

### Fixed

- **The pre-existing "Did not block phone-home" sandbox flake** was a
  bug in `src/sandbox/classify.ts`: `killedBySignal` only checked for
  `SIGKILL` / `SIGTERM`. macOS sandbox-exec terminates violators that
  hit a denied syscall during libc/libuv init (e.g. DNS resolution
  via mach services) with `SIGABRT`, not SIGKILL — so the
  classifier treated the kill as a plain "error" and returned
  `blocked: false`. The predicate now flags every non-null signal as
  a sandbox violation, and `SIGABRT` has a dedicated regression
  test. All 90 integration tests pass.

### Removed

- The legacy `src/sandbox.ts` monolith (replaced by the `src/sandbox/`
  directory).
- The legacy `src/cli.ts` monolith (replaced by `src/cli/index.ts` +
  per-command modules).
- The legacy `src/report/logger.ts` module (replaced by the Reporter
  strategy).
- The legacy `api/` Vercel handlers (replaced by `functions/` for
  Cloudflare Pages).
- `vercel.json` (replaced by `wrangler.toml`).
- Implicit `as any` casts in the Pages Functions.
- The `https://unpkg.com/lucide@latest` script tags from the site.

### Known issues

- The threat-intelligence network has low adoption; flags are rare.
  Sybil-resistance mitigations raise the cost of manipulation but
  cannot eliminate it.

[0.1.0]: https://github.com/abgnydn/safenpm/releases/tag/v0.1.0
