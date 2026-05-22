# Security policy

safenpm is an experimental, pre-1.0 supply-chain hardening tool by a solo
maintainer. This document is the honest answer to *what does it actually
defend against, and what doesn't it*.

## What's in scope

safenpm intercepts the package-manager **install** step:

- **Install-time script execution** (`preinstall`, `install`,
  `postinstall`, `prepare`) is run inside an OS sandbox
  (`sandbox-exec` on macOS, `firejail` on Linux, Windows Firewall on
  Windows). Network egress and (in strict mode) writes outside the
  package directory are denied.
- **Static analysis** of those scripts looks for high-risk patterns
  (eval, raw HTTP requests, shell exec, env exfiltration).
- **Typosquat detection** flags package names suspiciously close to
  popular packages (scope confusion, transposition, common
  substitutions, edit distance ≤ 2).
- **Lockfile audit** flags non-registry resolved URLs (git+, file:,
  custom tarballs), missing or weak integrity hashes, and stale
  lockfiles.
- **Threat intelligence network** (`/api/v1/signal`, `/intel`)
  aggregates anonymous reports across machines and surfaces packages
  that crossed a distinct-reporter threshold.

## What's NOT in scope

These are the **important holes**. Read this before assuming safenpm
covers a class of attack:

- **Runtime code execution.** Many of the most damaging npm supply-chain
  incidents (e.g. event-stream, ua-parser-js, xz-style backdoors)
  execute their malicious payload at **`require()` / import time** in
  the consuming application, not at install time. safenpm does not
  isolate runtime code; once an install finishes, the package's code
  runs with full Node permissions inside your app. The design space
  for runtime isolation is captured in
  [`docs/runtime-isolation.md`](./docs/runtime-isolation.md); nothing
  in that doc is currently implemented.
- **Native binary backdoors.** A native module that compiles cleanly
  inside the sandbox can still contain backdoored compiled code that
  runs when your application loads it.
- **Compromised maintainer accounts on legitimate packages.** safenpm
  can detect a maintainer change for a package you've already
  installed (see `safenpm diff`), but a brand-new install of a
  compromised legitimate package will not trip typosquat or reputation
  heuristics.
- **Sybil attacks against the threat intel network.** The server
  validates a minimum machineId entropy and uses a Redis SET for
  distinct-reporter counting, but cannot cryptographically prevent an
  attacker from generating many machineIds. Flag thresholds are set
  conservatively for this reason; do **not** rely on community
  flagging alone to make security decisions.
- **Targeted attacks at a specific developer.** safenpm raises the
  cost of opportunistic mass attacks; a determined attacker who knows
  you use it can craft payloads that defer to runtime, sidestep the
  static patterns, or live in non-script package contents.

## Operational caveats

- The CLI is shipped on npm as `@abgunaydin/safenpm`. The package has
  not been independently audited.
- The threat intel network runs on a single Cloudflare Pages + Upstash
  Redis deployment operated by the maintainer. There is no SLA. If it
  is down, `safenpm install` falls through to the local-only checks
  (sandbox + static analysis + lockfile + typosquat). Reports are
  fire-and-forget.
- The `--no-report` flag disables outgoing signal reports. Use it if
  the destination of a single anonymous package@version + reason tag
  is sensitive in your context.
- Treat install sandboxing as defense-in-depth, not a guarantee. The
  macOS profile denies network and the most relevant DNS-related
  mach-lookup services, and the classifier flags any signal-based
  process death as a sandbox violation — but no sandbox profile we
  ship can be a substitute for not running untrusted code at all.

## Reporting a vulnerability

Open an issue at <https://github.com/abgnydn/safenpm/issues> for
non-sensitive bugs. For anything that could compromise users — sandbox
escape, validator bypass, threat-intel poisoning beyond what's
documented above — please **do not file a public issue**. Email the
maintainer at the address listed in `package.json` and allow a
reasonable embargo window before public disclosure.

## Versioning posture

safenpm follows pre-1.0 semantics: any release in the 0.x range can
introduce breaking changes to the CLI surface, JSON output shape, or
threat-intel API. The CLI output is pinned by golden snapshots to keep
short-range changes auditable, but the contract itself is not stable
across 0.x minor versions.
