# Runtime isolation — design + status

This document captures the design space for the **largest open gap**
in safenpm's threat model: install-time sandboxing does not isolate
code that runs when your application later `require()`s / `import`s
a dependency.

## Status (0.1.0)

- **Observe-only `safenpm trace`** — **shipped**. Runs your command
  with a `--require` loader that records every CJS `require()` call,
  attributing each one to the package whose file made the call. Trace
  JSON is written to `~/.safenpm/pkg-traces/`. CJS only; ESM `import`
  is not captured.
- **Trace diff** — **shipped**. `safenpm trace --diff` reads the two
  most recent traces, computes per-package new builtin / package
  requires, severity-tiers newly-appearing builtins, and returns
  exit 1 if any critical-tier builtin appears (so CI can gate on
  it). The standalone `diffTraces()` helper is also exported for
  consumers that want to roll their own.

- **Trace list** — `safenpm trace --list` surfaces what's in
  `~/.safenpm/pkg-traces/`.
- **Enforcement** (proxy-wrapped exports, permissions, blocking
  loader) — still design-only. See "Mechanism candidates" below.

The actual high-profile npm supply-chain attacks (event-stream,
ua-parser-js, ctx, the recent xz-style backdoors) execute their
malicious payload at runtime in the consumer's process, not at install
time. Nothing safenpm currently ships defends against that.

This is here so the gap is documented and so a future contributor (or
future-me) doesn't have to start from a blank page. **None of this is
implemented yet.** Filing it would be the first real PR toward 0.2 /
1.0.

## What would have to be true

For runtime isolation to be useful in real terms, we'd need to:

1. **Intercept every `require()` and `import` call** in the consumer's
   process before the loaded module executes.
2. **Apply a per-package permission policy** — what each package is
   allowed to do (network, FS reads outside its own dir, child-process
   spawn, dynamic eval, native addons).
3. **Enforce that policy without breaking legitimate code.** Most
   packages need *some* dangerous capability; the policy can't be
   "deny everything" by default or nothing runs.
4. **Be opt-in and easy to back out of** when the policy is wrong —
   getting paged at 3am because safenpm denied a legit `https.get` is
   worse than the attack we're preventing.

## Mechanism candidates

### 1. Node loader hooks (`--experimental-loader`)

Node ≥ 20 supports custom ESM loaders that can intercept every
`import` resolution. A loader could:

- Read a per-package policy file (`.safenpm-policy.json` next to
  `package.json`) generated during `safenpm install --scan`.
- Wrap the loaded module in a `Proxy` that gates access to dangerous
  globals (`fetch`, `https`, `child_process`, `fs`, `process.env`).
- Refuse to load packages whose hash doesn't match the install-time
  hash stored by safenpm.

**Strengths:** built-in mechanism, no native code, works with bundlers
that go through Node's resolver.

**Weaknesses:**
- ESM-only — does not intercept CommonJS `require()` calls. Most of
  the npm ecosystem is still CJS. Loader hooks for CJS were the old
  `require.extensions` API which is deprecated and unsafe.
- Proxy-wrapping every export has measurable runtime cost.
- Once a malicious module runs inside the loader, the loader's own
  permissions are compromised. A determined attacker can escape.
- Doesn't catch native addons (`.node` files) which run outside the
  JS sandbox entirely.

### 2. Permissions API (Node ≥ 20.0, stable in 24)

Node ships `--permission` / `--allow-fs-read` / `--allow-net` flags
that gate syscalls at the process level. Could spawn the consumer's
app under safenpm with permissions derived from the install-time
analysis.

**Strengths:** kernel-adjacent enforcement, not bypassable from JS.

**Weaknesses:**
- Per-process granularity, not per-module. A trusted module and an
  untrusted dependency share the same permission set.
- Still experimental at the time of writing for some categories.
- Forces the consumer to launch their app via `safenpm run` instead
  of `node`, which is a real DX cost.

### 3. Runtime-only inspection (no enforcement)

Don't try to block anything. Just observe: instrument every module
load with a wrapper that records which APIs the package touches, and
flag *changes* in that fingerprint across version bumps. Pair with
the existing `pkgdiff` snapshot mechanism so a maintainer-takeover
event surfaces as "this package suddenly started calling
`child_process.exec`".

**Strengths:** zero performance cliff, no false positives that break
builds, useful even when the policy is "do nothing".

**Weaknesses:** detection is post-hoc — the malicious code has
already run by the time we report it. Limits the value to forensic
analysis and bug-bounty-style "we caught this on day X" claims.

## Path so far

1. **DONE — `safenpm trace -- <cmd>` (option 3, observe-only).** A
   CJS `Module.prototype.require` monkeypatch records what each
   package requires at runtime, attributing by the calling file's
   `node_modules/<name>/...` path. Writes per-run JSON to
   `~/.safenpm/pkg-traces/`. The `diffTraces()` helper can compare
   two trace files and report new builtin / package requires.

2. **DONE — `safenpm trace --diff` (CLI surface for the diff).**
   Reads the two most recent traces from
   `~/.safenpm/pkg-traces/`, surfaces API-surface changes per
   package, severity-tiers new builtins (critical: child_process /
   https / net / vm / …; high: fs / crypto / os / process; medium:
   the rest), and returns exit 1 if any critical-tier builtin newly
   appears.

3. **LATER — `safenpm run -- <cmd>` with `--experimental-loader`**
   for ESM consumers, using a policy file generated at install
   time. Document loudly that it's ESM-only and best-effort.

4. **Hard rule — do not ship a hardened-default that breaks
   builds.** Enforcement stays opt-in via an explicit
   `--enforce-runtime` flag.

## Why enforcement isn't shipping in 0.1

Designing a runtime-isolation layer that doesn't paper over real
attacks while also not breaking the npm ecosystem's existing
expectations is a multi-month project, not a single PR. 0.1 ships
the observe-only piece — useful for forensic analysis and
post-mortem diffs — and is honest about the gap (in `SECURITY.md`
and the README's "Misses (important)" section). Enforcement is a
0.2+ concern.

## Usage

```bash
# Trace a Node app:
safenpm trace -- node app.js

# Trace a longer-running command — npm test, build, whatever:
safenpm trace -- npm test

# Each run writes one JSON file to ~/.safenpm/pkg-traces/:
ls ~/.safenpm/pkg-traces/
# 2026-05-21T13-32-20-311Z-58921.json

# Read a trace:
cat ~/.safenpm/pkg-traces/2026-05-21T13-32-20-311Z-58921.json
# {
#   "timestamp": "2026-05-21T13:32:20.311Z",
#   "cwd": "/path/to/project",
#   "durationMs": 6,
#   "packages": {
#     "<root>": { "builtin": [], "package": ["demo-pkg"], "relative": 0, "absolute": 0 },
#     "demo-pkg": { "builtin": ["child_process", "fs", "https"], "package": [], "relative": 0, "absolute": 0 }
#   }
# }
```

The trace's most useful field is `packages.<name>.builtin` —
seeing `child_process` or `https` appear under a package that
previously didn't use them is a strong "this changed under your
feet" signal.
