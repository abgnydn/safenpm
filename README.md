<p align="center">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue" alt="Platform">
  <img src="https://img.shields.io/badge/node-%3E%3D18-green" alt="Node">
  <img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="License">
  <img src="https://img.shields.io/badge/version-0.5.0-orange" alt="Version">
</p>

# safenpm

**Drop-in `npm install` replacement that sandboxes postinstall scripts, blocks network access, and catches supply-chain attacks before they execute — backed by a live community threat intelligence network.**

Every year, thousands of malicious packages slip into npm — exfiltrating credentials via postinstall scripts, opening reverse shells, or stealing SSH keys. `safenpm` wraps `npm install` with a security-first pipeline: static analysis, sandboxed execution, typosquat detection, maintainer change alerts, lockfile integrity checks, and real-time threat intelligence — all in one command.

<p align="center">
  <a href="https://safenpm.dev"><strong>Website</strong></a> · <a href="https://safenpm.dev/showcase.html"><strong>Showcase</strong></a> · <a href="#quick-start"><strong>Quick Start</strong></a> · <a href="#docs"><strong>Docs</strong></a>
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

### Decentralized Threat Intelligence Network

**Live now at [safenpm.dev](https://safenpm.dev).**

When safenpm blocks a suspicious package, the signal flow is: **block -> anonymous report -> community warned**. The blocked package name, script hash, and block reason are reported to the safenpm community network — no identifying information leaves your machine. On **every install**, safenpm queries this network to check if any of your dependencies have been flagged by other developers. If one developer gets hit by a malicious package, every safenpm user is warned automatically.

When a flagged package is detected in your dependencies, you will see:

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

**Anti-abuse safeguards** prevent manipulation of the threat network:
- **Rate limiting** — per-IP and global rate limits prevent flood attacks
- **Deduplication** — repeated reports from the same source are collapsed
- **Threshold-based flagging** — a package requires at least 3 independent reports before it triggers community alerts (15 reports for popular packages with >10k weekly downloads)
- **Script hash consistency** — reports are validated against the actual script hash to prevent false flagging of legitimate packages

The live transparent stats dashboard at [safenpm.dev](https://safenpm.dev) shows real-time network activity, total reports, unique packages flagged, and active contributors.

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

**Protects against:**
- Malicious postinstall/preinstall scripts that exfiltrate credentials or open reverse shells
- Typosquatting attacks (`axois` instead of `axios`)
- Dependency confusion via scope confusion
- Maintainer account takeovers
- Lockfile manipulation (non-registry URLs, missing integrity hashes)

**Does NOT protect against:**
- Malicious code in package source (not in install scripts)
- Build-time attacks in webpack/babel plugins
- Pre-existing compromised packages in your lockfile
- Registry-level compromise

## Architecture

Zero production dependencies. Built with TypeScript, compiled to standalone JS. The sandbox layer uses OS-native mechanisms — no Docker, no VMs, no heavy runtimes.

## License

MIT
