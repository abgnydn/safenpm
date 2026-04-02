# safenpm

Drop-in `npm install` replacement that sandboxes postinstall scripts. Blocks network access, restricts filesystem reads, and catches supply-chain attacks before they land.

## Install

```bash
npm install -g safenpm
```

## Usage

```bash
# instead of npm install
safenpm install axios lodash express

# shorthand
safenpm i

# preview what would be sandboxed
safenpm i --dry-run

# trust specific packages
safenpm i --allow bcrypt,sharp

# CI mode — machine-readable JSON
safenpm i --json

# prompt on each block: retry / skip / abort
safenpm i --interactive

# view past runs
safenpm audit
```

## What it does

1. Runs `npm install --ignore-scripts` (safe — no code runs)
2. Scans all install scripts for red flags (curl, eval, base64, ~/.ssh access, etc.)
3. Runs each script inside a sandbox with **no network access** and **restricted filesystem**
4. Logs everything to `~/.safenpm/audit.log`
5. Reports blocked packages anonymously to the safenpm network
6. Exits non-zero if anything was blocked

## Platform support

| Platform | Backend | Status |
|----------|---------|--------|
| macOS | `sandbox-exec` (built-in) | Full support (deny-default profile) |
| Linux | `firejail` | Full support (`sudo apt install firejail`) |
| Windows (admin) | Firewall + ACLs | Experimental — blocks network via `New-NetFirewallRule`, restricts filesystem via `icacls` |
| Windows (non-admin) | WSL + firejail | Experimental — requires WSL with firejail installed |
| Windows (no WSL) | — | Falls back to plain npm (env vars still stripped) |

> **Note:** safenpm is invoked as `safenpm install`, not as a transparent `npm` alias. It is a separate command that wraps npm.

## Sandbox protections

**Network** — All outbound/inbound network access is denied. Packages that try to `curl`, `wget`, `fetch()`, or open sockets are blocked and reported.

**Filesystem** (strict mode, default) — Install scripts cannot read `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.npmrc`, `~/.docker`, `~/.kube`, or shell histories. Writes are restricted to the package directory and `/tmp`.

**Environment** — Sensitive env vars are stripped: `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, and 7 others.

Use `--loose` to disable filesystem restrictions (network-only sandbox).

## Static analysis

Before running anything, safenpm scans scripts for:

- Network tools: `curl`, `wget`, `nc`, `fetch()`, `require('https')`
- Credential access: `~/.ssh`, `~/.aws`, `process.env`
- Code execution: `eval()`, base64 decoding, `| sh` piping
- Obfuscation: hex/unicode escape sequences

Each package gets a risk score (0-100) shown before execution.

## Allowlisting

Trust packages via CLI or config file:

```bash
# CLI
safenpm i --allow bcrypt,sharp,@mapbox/*

# .safenpmrc (project root or ~/.safenpmrc)
bcrypt
sharp
@mapbox/*
```

Supports exact names and `@scope/*` wildcards.

## CI integration

```yaml
# GitHub Actions
- run: npx safenpm i --json --no-report > safenpm-report.json
- run: |
    blocked=$(jq '.summary.blocked' safenpm-report.json)
    if [ "$blocked" -gt 0 ]; then
      echo "Supply chain risk detected"
      exit 1
    fi
```

## Audit log

Every run is logged to `~/.safenpm/audit.log` (JSONL format, auto-rotates at 5MB).

```bash
safenpm audit          # human-readable
safenpm audit --json   # machine-readable
```

## Options

| Flag | Description |
|------|-------------|
| `--dry-run`, `-n` | Preview without executing |
| `--allow <pkgs>` | Comma-separated allowlist |
| `--json` | JSON output for CI |
| `--interactive`, `-I` | Prompt on blocks |
| `--loose` | Network-only sandbox |
| `--no-report` | Disable anonymous reporting |

## Threat model

**What safenpm protects against:**

- Malicious postinstall/preinstall scripts that exfiltrate credentials or open reverse shells
- Typosquatting attacks (e.g., `axois` instead of `axios`)
- Dependency confusion via scope confusion (`@evil/lodash`)
- Sudden maintainer changes that may indicate account takeover
- Lockfile manipulation (non-registry URLs, missing integrity hashes)

**What safenpm does NOT protect against:**

- Malicious code in the package source itself (not in install scripts)
- CI/CD pipeline attacks or registry mirror tampering
- Build-time attacks in webpack/babel plugins that execute at `npm run build`
- Pre-existing compromised packages already in your lockfile before safenpm was adopted
- Time-of-check-to-time-of-use (TOCTOU) attacks between scanning and execution

**Assumptions:**

- The attacker delivers their payload via npm install hooks (preinstall, install, postinstall)
- The local npm registry (registry.npmjs.org) is not compromised
- The host OS sandbox mechanisms (sandbox-exec, firejail) are functioning correctly

## License

MIT
