<p align="center">
  <img src="./docs/diagrams/hero.svg" alt="safenpm — sandboxed npm installs" width="100%">
</p>

<p align="center">
  <a href="https://github.com/abgnydn/safenpm/actions/workflows/ci.yml"><img src="https://github.com/abgnydn/safenpm/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.npmjs.com/package/@abgunaydin/safenpm"><img src="https://img.shields.io/npm/v/@abgunaydin/safenpm" alt="npm version"></a>
  <a href="https://safenpm.dev"><img src="https://img.shields.io/badge/live-safenpm.dev-6ea8ff" alt="Live"></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue" alt="Platform">
  <img src="https://img.shields.io/badge/node-%3E%3D20-green" alt="Node">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="License"></a>
</p>

<p align="center"><strong>
  Drop-in <code>npm install</code> replacement that runs every postinstall script inside an OS sandbox<br>
  with no network access and a restricted filesystem.
</strong></p>

<p align="center">
  <a href="https://safenpm.dev"><strong>Website</strong></a> ·
  <a href="./SECURITY.md"><strong>Threat model</strong></a> ·
  <a href="./docs/architecture.md"><strong>Architecture</strong></a> ·
  <a href="./docs/roadmap.md"><strong>Roadmap</strong></a> ·
  <a href="#quick-start"><strong>Quick start</strong></a> ·
  <a href="./CHANGELOG.md"><strong>Changelog</strong></a>
</p>

> [!IMPORTANT]
> **Status: `0.1.0` — pre-release, solo-maintained, unaudited, zero known external users.** Useful as a belt-and-suspenders layer in front of `npm install`. **Does not** replace runtime sandboxing or formal supply-chain review. See [SECURITY.md](./SECURITY.md) and [`docs/runtime-isolation.md`](./docs/runtime-isolation.md) for the honest scope.

---

## Quick start

```bash
# install
npm install -g @abgunaydin/safenpm

# use instead of `npm install`
safenpm install
```

That's it. Install scripts now run inside an OS sandbox with no network and restricted filesystem. If anything tries to phone home, write to `~/.ssh`, or trip the static-analysis heuristics, safenpm blocks it and tells you exactly what happened.

```bash
# also useful
safenpm install --scan         # full deep scan (typosquat / lockfile / reputation / npm audit)
safenpm trace -- node app.js   # record what every dep require()s at runtime
safenpm trace --diff           # compare two newest traces, exit 1 on critical builtin drift
safenpm doctor                 # health report with letter grade
safenpm fix --dry-run          # preview auto-fixes for typosquats and blocked packages
```

---

## How it works

<p align="center">
  <img src="./docs/diagrams/pipeline.svg" alt="safenpm install pipeline" width="100%">
</p>

Every step before phase 10 runs against `node_modules` with **scripts disabled** — nothing the package author wrote has executed yet. Phase 10 is the only place untrusted code runs, and it runs inside the OS sandbox.

| # | Phase | When | What it catches |
|---|---|---|---|
| 1 | `npm install --ignore-scripts` | always | dependency resolution, nothing executes |
| 2 | **typosquats** | `--scan` | `axois` for `axios`, `@evil/lodash` for `lodash`, `c0lors` for `colors`, `rnoment` for `moment` |
| 3 | **lockfile audit** | `--scan` | `git+`/`file:`/custom-registry resolved URLs, missing or weak integrity hashes |
| 4 | **reputation** | `--scan` | offline `package.json` heuristic (maintainer count, license, repo, age) — not a substitute for CVE data |
| 5 | **`npm audit`** | `--scan` | real CVE advisories from the npm registry, severity-tiered |
| 6 | **static analysis** | always | `curl`/`wget`/`nc`, `~/.ssh` reads, `eval()`, `\| sh`, base64 + hex/unicode obfuscation |
| 7 | **behavioural diff** | `--scan` | new install scripts vs. the cached previous version |
| 8 | **threat intel** | always | the safenpm community network (opt-in, default-on, low-adoption today) |
| 9 | **maintainer change** | `--scan` | npm publisher changed between the previous version and this one |
| 10 | **sandboxed execution** | always | the only step that actually runs the install script |

---

## Sandbox layer

| Platform | Backend | Status |
|---|---|---|
| macOS | `sandbox-exec` (built-in) — TinyScheme deny-default profile + explicit DNS-related mach-service denies | full support |
| Linux | `firejail` | full support |
| Windows (admin) | Windows Firewall + ACLs | experimental |
| Windows (WSL) | WSL + firejail | experimental |
| none of the above | last-resort fallback (warned to user) | no sandboxing |

The macOS profile denies network egress and the specific Mach services (`com.apple.dnssd-uds`, `mDNSResponder`, `networkd`, `cfnetwork.AuthBrokerAgent`, …) that an attacker would use to resolve a hostname before the broader `(deny network*)` rule fires. Sensitive env vars (`NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, …) are stripped before exec.

---

## Runtime tracer (observe-only)

The largest gap in install-time sandboxing is that it doesn't isolate code at `require()` time. `safenpm trace` partially closes that:

<p align="center">
  <img src="./docs/diagrams/trace-diff.svg" alt="safenpm trace --diff" width="100%">
</p>

```bash
safenpm trace -- node app.js         # record one trace
safenpm trace -- npm test            # record another (or run after a version bump)
safenpm trace --diff                 # report new builtins/packages per dep
safenpm trace --list                 # show recent traces in ~/.safenpm/pkg-traces/
```

`trace --diff` exits **1** if any dependency starts touching a critical builtin (`child_process`, `https`, `http2`, `net`, `dns`, `vm`, `worker_threads`, `cluster`, `tls`, `dgram`, `http`, `inspector`, `module`) that it didn't touch before. Drop it into CI as a regression detector for post-takeover dependency mutation.

CJS only — ESM `import` goes through a different mechanism and is not currently captured. See [`docs/runtime-isolation.md`](./docs/runtime-isolation.md) for the full roadmap.

---

## Threat model

<p align="center">
  <img src="./docs/diagrams/threat-model.svg" alt="threat model — catches vs misses" width="100%">
</p>

Short form above; the long form is in [`SECURITY.md`](./SECURITY.md). The most important entry on the right side is **runtime code execution** — many famous npm incidents (event-stream, ua-parser-js, xz-style backdoors) execute their payload at `require()` time, not install time. Mitigated partially by the runtime tracer (observe-only); enforcement is on the roadmap, not in 0.1.

---

## Threat-intelligence network

Hosted at [safenpm.dev](https://safenpm.dev) — Cloudflare Pages + Upstash Redis, single-region, no SLA, **adoption ≈ 0** today. Opt-in by default; disable outgoing reports with `--no-report`. Signal flow on a block: `block → anonymous report → other safenpm users querying the same pkg@version see the aggregate`.

When a flagged package is detected:

```text
  → querying threat intelligence network...

  ⚠ COMMUNITY ALERT  evil-pkg@0.0.1
    INTEL  47 reports from other developers
    INTEL  top reason: credential exfiltration
           also: network access, reverse shell
           first seen: 2026-03-28  last report: 4m ago
    → This package was flagged by the safenpm community network.
    → Consider removing it or verifying it is legitimate.
```

Sybil-resistance is partial — **do not rely on community flagging as your only signal**:

- **Rate limit** — 20 signals per machineId per hour
- **24-hour dedup** — repeat reports of the same `(machineId, pkg@version)` collapse
- **Distinct-reporter set** — `distinctReporters` is a Redis SET, so the same machine cannot inflate the count across windows
- **MachineId entropy floor** — `< 16 chars` or outside `[a-zA-Z0-9_-]` rejected
- **Threshold-based flagging** — `≥ 5` distinct reporters for non-curated, `≥ 15` for the curated ~50 high-value-target list
- **Script-hash consistency** — `> 3` distinct script hashes treated as inconsistent and not flagged

---

## Configuration

`.safenpmrc` (project root or `$HOME`):

```ini
# packages allowed to run their install scripts without sandboxing
bcrypt
sharp
@mapbox/*

# packages whose typosquat warnings should be suppressed
!my-internal-react-thing
!@acme/lodash-utils
```

CLI flags (full list: `safenpm --help`):

| Flag | Description |
|---|---|
| `--dry-run`, `-n` | preview what would be sandboxed without running anything |
| `--allow <pkgs>` | comma-separated allowlist (in addition to `.safenpmrc`) |
| `--scan`, `-S` | enable deep-scan analyses (typosquat / lockfile / reputation / npm audit) |
| `--json` | machine-readable JSON output for CI |
| `--interactive`, `-I` | prompt on each blocked package: retry / skip / abort |
| `--loose` | network-only sandbox (filesystem stays unrestricted) — needed for some native-compile flows |
| `--no-report` | disable anonymous threat-intel reports |

---

## CI integration

```yaml
# GitHub Actions
- name: Secure install
  run: npx @abgunaydin/safenpm install --json --no-report > safenpm-report.json

- name: Fail on block
  run: |
    blocked=$(jq '.summary.blocked' safenpm-report.json)
    if [ "$blocked" -gt 0 ]; then
      echo "::error::Supply-chain risk detected"
      jq '.packages[] | select(.result=="blocked")' safenpm-report.json
      exit 1
    fi
```

For longer-term hardening, snapshot a baseline trace per environment and `safenpm trace --diff` on every PR:

```yaml
- name: Runtime tracer baseline (cached)
  uses: actions/cache@v4
  with:
    path: ~/.safenpm/pkg-traces
    key: safenpm-trace-${{ hashFiles('package-lock.json') }}

- name: Re-trace and diff
  run: |
    safenpm trace -- npm test
    safenpm trace --diff  # exits 1 if any dep starts using child_process etc.
```

---

## Development

```bash
git clone https://github.com/abgnydn/safenpm
cd safenpm
npm ci
npm run build
npm test                # unit + integration + golden
npm run test:unit       # vitest only
npm run test:golden     # CLI byte-identity snapshots
npm run test:coverage   # v8 coverage report
```

Architecture map: [`docs/architecture.md`](./docs/architecture.md). Contributions welcome — every check inside [`src/analysis/`](./src/analysis) is a pure function over a fixture; that's the easiest place to add a new detector. Trickier work lives in [`src/sandbox/`](./src/sandbox) (OS-specific) and [`functions/`](./functions) (the Cloudflare Pages Functions backend).

---

## What's NOT shipping yet

- **ESM runtime enforcement** — the `safenpm run --enforce-runtime` hook covers CJS `require()` only. ESM `import` resolution goes through a different mechanism (`--experimental-loader`) and is the 0.2 milestone. CJS is still the majority of npm.
- **Tarball re-verification against the live npm registry** — npm itself checks integrity-field-matches-tarball during install; the case where an attacker rewrites both the lockfile and the tarball together is uncovered. 0.6 milestone.
- **Bundler-time plugin attacks** — webpack/vite/esbuild plugins run with full Node permissions outside `safenpm run`. 0.8 milestone.
- **Syscall-literal native backdoors** — the `.node` byte scanner catches imported symbol names. A binary that calls `syscall(2)` with literal syscall numbers (or uses obfuscated dlsym lookups) won't trip the scan. Defence in depth, not absolute.
- **External security audit** — none has happened. The macOS sandbox profile in particular is one person's hand-written TinyScheme. Audit is the gating item for 1.0.

Full version path, exit criteria per milestone, and the "what could kill this project" honest section live in [`docs/roadmap.md`](./docs/roadmap.md). The runtime-isolation design surface specifically is in [`docs/runtime-isolation.md`](./docs/runtime-isolation.md).

---

## License

MIT. See [`LICENSE`](./LICENSE).

Built by [Ahmet Barış Günaydın](https://github.com/abgnydn). Issues at [`abgnydn/safenpm`](https://github.com/abgnydn/safenpm/issues).
