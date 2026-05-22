<p align="center">
  <a href="https://github.com/abgnydn/safenpm/actions/workflows/ci.yml"><img src="https://github.com/abgnydn/safenpm/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.npmjs.com/package/@abgunaydin/safenpm"><img src="https://img.shields.io/npm/v/@abgunaydin/safenpm" alt="npm version"></a>
  <a href="https://safenpm.dev"><img src="https://img.shields.io/badge/live-safenpm.dev-6ea8ff" alt="Live"></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue" alt="Platform">
  <img src="https://img.shields.io/badge/node-%3E%3D18-green" alt="Node">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="License"></a>
</p>

# safenpm

**Drop-in `npm install` replacement that runs every postinstall script inside an OS sandbox with no network access and a restricted filesystem, plus static-analysis, typosquat, lockfile, and reputation checks.**

Many malicious npm packages exfiltrate credentials, open reverse shells, or steal SSH keys via install-time scripts. safenpm wraps `npm install` with a defense-in-depth pipeline: static analysis, sandboxed execution, typosquat detection, maintainer-change alerts, lockfile integrity, and an experimental opt-in threat-intelligence network.

> **Status: 0.1.0 — pre-release, solo-maintained, unaudited.** safenpm is useful as a belt-and-suspenders layer in front of `npm install`. It does **not** replace runtime sandboxing or formal supply-chain reviews. See [SECURITY.md](./SECURITY.md) for the honest threat model — including what it doesn't catch.

<p align="center">
  <a href="https://safenpm.dev"><strong>Website</strong></a> · <a href="https://safenpm.dev/showcase.html"><strong>Showcase</strong></a> · <a href="./SECURITY.md"><strong>Threat model</strong></a> · <a href="#quick-start"><strong>Quick start</strong></a>
</p>

---

## Quick Start

```bash
npm install -g @abgunaydin/safenpm

# Use instead of npm install
safenpm install
```

That's it. Your install scripts now run inside a sandbox with no network access and restricted filesystem. If anything suspicious is detected, safenpm blocks it and tells you exactly what happened.

## How It Works

```
safenpm install
    │
    ├─ 1. npm install --ignore-scripts     (safe — nothing executes)
    ├─ 2. Threat intel query               (check community network — always runs)
    ├─ 3. Static analysis                  (scan scripts for red flags)
    ├─ 4. Typosquat detection              (catch axois → axios)
    ├─ 5. Maintainer change alerts         (flag account takeovers)
    ├─ 6. Lockfile integrity check         (detect URL/hash tampering)
    ├─ 7. Reputation scoring               (rate each package 0-100)
    ├─ 8. Sandboxed execution              (run scripts with no network/fs)
    ├─ 9. Anonymous signal reporting        (alert the network if blocked)
    └─ 10. Audit logging                   (everything to ~/.safenpm/)
```

Threat intelligence runs on **every install** — not just in scan mode. If any dependency has been flagged by the community, you will see a warning immediately.

## Key Features

### Sandbox Isolation
Every postinstall script runs inside an OS-level sandbox. Network access is fully denied. Filesystem access is restricted — scripts cannot read `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.npmrc`, or shell histories. Sensitive env vars (`NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, etc.) are stripped before execution.

### Static Analysis Engine
Before anything runs, scripts are scanned for: network tools (`curl`, `wget`, `nc`), credential access (`~/.ssh`, `process.env`), code execution patterns (`eval()`, base64 decoding, `| sh`), and obfuscation (hex/unicode escapes). Each package receives a risk score (0-100).

### Typosquat Detection
Catches common squatting patterns — character swaps, missing hyphens, scope confusion (`@evil/lodash`) — using edit-distance analysis and a curated list of popular packages.

### Maintainer Change Monitoring
Flags packages where maintainers changed recently, a common indicator of account takeover attacks.

### Lockfile Integrity
Validates `package-lock.json` for non-registry URLs, missing integrity hashes, and other signs of lockfile injection.

### Reputation Scoring
Scores every package 0-100 based on maintainer count, license, repository presence, dependency weight, and maturity. Aggregates into a project-level health grade.

### Experimental threat-intelligence network

**Hosted at [safenpm.dev](https://safenpm.dev).** The network is opt-in (default-on), runs on a single Cloudflare Pages + Upstash Redis deployment, has no SLA, and is operated by the maintainer. **Adoption is currently low, so flags are rare.** Disable outgoing reports with `--no-report`.

Signal flow on a block: `block → anonymous report → other safenpm users querying the same pkg@version see the aggregate`. The blocked package name, script hash, and block reason are sent. No personally-identifying information leaves your machine.

When a flagged package is detected:

```
  -> querying threat intelligence network...

  ! COMMUNITY ALERT  evil-pkg@0.0.1
    INTEL  47 reports from other developers
    INTEL  top reason: credential exfiltration
           also: network access, reverse shell
           first seen: 2026-03-28  last report: 4m ago
    -> This package was flagged by the safenpm community network.
    -> Consider removing it or verifying it is legitimate.
```

**Sybil-resistance is partial — do not rely on community flagging as your only signal.** Anti-abuse safeguards in place:
- **Rate limit** — 20 signals per machineId per hour.
- **24-hour dedup** — repeat reports of the same `(machineId, pkg@version)` collapse.
- **Distinct-reporter set** — `distinctReporters` is a Redis SET of machineIds, so the same machine cannot inflate the count across windows.
- **MachineId entropy floor** — reports with machineIds shorter than 16 chars or outside `[a-zA-Z0-9_-]` are rejected, raising the cost of trivial Sybil generation.
- **Threshold-based flagging** — a non-curated package requires **≥5** distinct reporters; a curated "high-value-target" package requires **≥15**. The curated list is a hand-maintained set of ~50 names; there is no live download-count check.
- **Script-hash consistency** — packages reported with >3 distinct script hashes are treated as inconsistent and not flagged.

These mitigations raise the cost of manipulation; they do not eliminate it. A motivated attacker can still generate enough valid machineIds to flag a target.

### Doctor Command
Run `safenpm doctor` for a full project health report — letter grade, actionable fixes, and a breakdown of every risk signal across your dependency tree.

## Usage

```bash
safenpm install                     # sandboxed install
safenpm i                           # shorthand
safenpm i --dry-run                 # preview what would be sandboxed
safenpm i --allow bcrypt,sharp      # trust specific packages
safenpm i --json                    # CI-friendly JSON output
safenpm i --interactive             # prompt on each block
safenpm audit                       # view past runs
safenpm doctor                      # project health report
safenpm scan                        # scan without installing
```

## Platform Support

| Platform | Sandbox Backend | Status |
|----------|----------------|--------|
| **macOS** | `sandbox-exec` (built-in) | Full support |
| **Linux** | `firejail` | Full support |
| **Windows** (admin) | Firewall + ACLs | Experimental |
| **Windows** (WSL) | WSL + firejail | Experimental |

## CI Integration

```yaml
# GitHub Actions
- name: Secure install
  run: npx safenpm install --json --no-report > safenpm-report.json

- name: Check for blocks
  run: |
    blocked=$(jq '.summary.blocked' safenpm-report.json)
    if [ "$blocked" -gt 0 ]; then
      echo "::error::Supply chain risk detected"
      exit 1
    fi
```

## Options

| Flag | Description |
|------|-------------|
| `--dry-run`, `-n` | Preview without executing |
| `--allow <pkgs>` | Comma-separated allowlist |
| `--json` | JSON output for CI |
| `--interactive`, `-I` | Prompt on each block |
| `--loose` | Network-only sandbox (skip filesystem restrictions) |
| `--no-report` | Disable anonymous reporting |

## Allowlisting

Trust packages via CLI or config file:

```bash
safenpm i --allow bcrypt,sharp,@mapbox/*
```

Or create a `.safenpmrc` in your project root (or `~/.safenpmrc`):

```
bcrypt
sharp
@mapbox/*
```

## Threat Model

See [SECURITY.md](./SECURITY.md) for the full version. Short form:

**Catches:**
- Malicious `preinstall` / `install` / `postinstall` / `prepare` scripts that exfiltrate credentials, open reverse shells, or touch sensitive paths.
- Typosquat names (e.g. `axois` for `axios`, scope confusion like `@evil/lodash`).
- Maintainer-change anomalies on packages you've already snapshotted.
- Lockfile tampering — non-registry URLs, missing integrity hashes, weak hashes.

**Misses (important):**
- **Runtime code execution.** safenpm does not isolate code that runs when your app imports a package. Many high-profile npm attacks (event-stream, ua-parser-js, xz-style backdoors) execute at `require()` time, not install time. Once an install finishes, the package's code runs with full Node permissions inside your app.
- Build-time attacks in webpack / babel / esbuild plugins.
- Pre-existing compromised packages already in your lockfile and matching the legitimate publisher.
- Targeted attacks crafted with knowledge that you use safenpm (deferred to runtime, sidestep the static patterns, hide in package data).
- Registry-level compromise.
- Native binary backdoors that pass the install sandbox but ship pre-compiled malicious code.

## Architecture

Zero production dependencies. Built with TypeScript, compiled to standalone JS. The sandbox layer uses OS-native mechanisms — no Docker, no VMs, no heavy runtimes.

## License

MIT
