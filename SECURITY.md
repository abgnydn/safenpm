# Security policy

safenpm is an experimental, pre-1.0 supply-chain hardening tool by a solo
maintainer. This document is the honest answer to *what does it actually
defend against, and what doesn't it*.

## What's in scope

safenpm operates across both install-time and (optionally) runtime:

**Install-time (every `safenpm install`):**

- **Install-time script execution** (`preinstall`, `install`,
  `postinstall`, `prepare`) is run inside an OS sandbox
  (`sandbox-exec` on macOS, `firejail` on Linux, Windows Firewall on
  Windows). Network egress and (in strict mode) writes outside the
  package directory are denied. The macOS profile uses sandbox-exec
  tracing to escalate quiet-deny → blocked, so a kernel-side block
  that the child handled gracefully (exit 0, empty stderr) still
  classifies as a sandbox violation.
- **Static analysis** of every install script in the dep tree
  (including nested `node_modules/<a>/node_modules/<b>/...` up to
  8 levels deep). Covers: curl/wget/nc, raw HTTP/HTTPS/HTTP2/WS/TLS
  requires, fetch/dns/net/dgram, eval, base64, Buffer.from(…,'hex'),
  curl-piped-to-shell, `bash -c "$(...)"`, hex/unicode obfuscation,
  vm module, `process.binding()`, worker_threads, cluster,
  *dynamic require/import* (any non-literal argument), and IPv4
  literals that aren't loopback/wildcard.
- **Symlink audit** flags any symlink whose target escapes its
  owning package directory or uses an absolute path. Catches the
  "ship a symlink to /etc/passwd, then read it from postinstall"
  pattern that path-allow-list sandboxes leak.
- **Native-addon byte scan** of every `.node` file under
  node_modules. Looks for dangerous imported symbols (exec /
  network / dlopen) regardless of file format (Mach-O / ELF / PE).
  Closes the dlopen-blind-spot.
- **Typosquat detection** flags package names suspiciously close to
  popular packages (scope confusion, transposition, common
  substitutions, edit distance ≤ 2).
- **Lockfile audit** flags non-registry resolved URLs (git+, file:,
  custom tarballs), missing or weak integrity hashes, and stale
  lockfiles.
- **`npm audit` integration** surfaces real CVE advisories from the
  npm registry, severity-tiered.
- **Env-var stripping** removes the explicit credential list (NPM,
  AWS, GCP, Azure, GitHub) plus any var matching `*_TOKEN` /
  `*_SECRET` / `*_KEY` / `*_PASSWORD` / `*_PWD` / `*_CREDENTIALS`
  via regex. SSH_AUTH_SOCK / XDG_* explicitly kept to avoid
  breaking native compiles.
- **Maintainer change detection** surfaces npm publisher swaps
  between the previous and current version of a dependency.
- **Threat intelligence network** (`/api/v1/signal`, `/intel`)
  aggregates anonymous reports across machines and surfaces packages
  that crossed a distinct-reporter threshold.

**Runtime (opt-in via `safenpm run` / `safenpm trace`):**

- **Runtime require() tracing** records what each package
  `require()`s at runtime; `trace --diff` exits 1 if a previously-
  clean package suddenly starts using critical builtins between
  versions (CI-gateable post-takeover detection).
- **Runtime enforcement** (`safenpm run --enforce-runtime`) loads
  a `node --require` hook that intercepts every CJS `require()`
  and throws `SafenpmDenied` when the calling package isn't
  allow-listed for the requested builtin. Default deny-list:
  `child_process`, `https`, `http`, `http2`, `net`, `dgram`, `tls`,
  `dns`, `vm`, `worker_threads`, `cluster`, `inspector`, `module`,
  `wasi`, `v8`. Per-package overrides via `.safenpm-policy.json`.

## What's NOT in scope

These are the **important holes**. Read this before assuming safenpm
covers a class of attack:

- **ESM runtime enforcement.** The runtime-enforce hook is CJS only.
  An attacker who uses `import { spawn } from 'node:child_process'`
  in an ESM module bypasses the hook. CJS still covers most of the
  npm ecosystem; ESM enforcement (via `--experimental-loader`) is
  the 0.4 milestone. Tracked in
  [`docs/runtime-isolation.md`](./docs/runtime-isolation.md).
- **Compiled-payload native backdoors.** The native-addon scanner
  catches imported-symbol names. A binary that uses `syscall(2)`
  directly with literal syscall numbers, or that calls dangerous
  functions via obfuscated names / dlsym-from-string, won't trip
  the scan. Defence in depth, not absolute.
- **Build-time plugin attacks.** Webpack / Vite / esbuild plugin
  loading happens after install with full Node permissions and
  outside `safenpm run`. Bundler integration is the 0.8 milestone.
- **Sybil attacks against the threat intel network.** The server
  validates a minimum machineId entropy and uses a Redis SET for
  distinct-reporter counting, but cannot cryptographically prevent
  an attacker from generating many machineIds. Flag thresholds are
  set conservatively for this reason; do **not** rely on community
  flagging alone to make security decisions.
- **Targeted attacks at a specific developer.** safenpm raises the
  cost of opportunistic mass attacks; a determined attacker who
  knows you use it can craft payloads that defer to runtime via
  ESM, use `process.binding()` to reach native code, or hide in
  bundler config.
- **Tarball poisoning where the lockfile and tarball are both
  rewritten.** npm itself verifies integrity-field-matches-tarball
  during install. safenpm doesn't currently re-verify against the
  live npm registry; an attacker who controls both the on-disk
  lockfile AND the tarball clears npm's check. Tracked for 0.6.

## Operational caveats

- The CLI is shipped on npm as `@abgunaydin/safenpm`. The package has
  not been independently audited.
- The threat intel network runs on a single Cloudflare Pages +
  Workers KV deployment operated by the maintainer. There is no SLA.
  If it is down, `safenpm install` falls through to the local-only
  checks (sandbox + static analysis + lockfile + typosquat).
  Reports are fire-and-forget.
- The `--no-report` flag disables outgoing signal reports. Use it if
  the destination of a single anonymous package@version + reason tag
  is sensitive in your context.
- Treat install sandboxing as defense-in-depth, not a guarantee. The
  macOS profile denies network and the DNS-related mach-lookup
  services; the classifier flags any signal-based process death as
  a sandbox violation; and sandbox-exec's `(trace …)` directive is
  parsed post-run to catch quiet kernel-side denies that the child
  handled silently. But no sandbox profile we ship can be a
  substitute for not running untrusted code at all.
- Runtime enforcement (`safenpm run --enforce-runtime`) is opt-in.
  Default deny-lists are conservative; bcrypt / sharp / node-gyp
  / similar native-builder packages will need entries in
  `.safenpm-policy.json` allow-listing their legitimate uses of
  `child_process` / `fs`. Use `safenpm run --generate-policy
  --from-trace` to bootstrap a policy from observed behavior.

## Reporting a vulnerability

Open an issue at <https://github.com/abgnydn/safenpm/issues> for
non-sensitive bugs. For anything that could compromise users —
sandbox escape, validator bypass, enforcement-hook bypass,
threat-intel poisoning beyond what's documented above — please
**do not file a public issue**. Email the maintainer at the address
listed in `package.json` and allow a reasonable embargo window
before public disclosure.

## Versioning posture

safenpm follows pre-1.0 semantics: any release in the 0.x range can
introduce breaking changes to the CLI surface, JSON output shape,
the `.safenpmrc` format, or the `.safenpm-policy.json` format. The
CLI output is pinned by golden snapshots to keep short-range
changes auditable, but the contract itself is not stable across
0.x minor versions.
