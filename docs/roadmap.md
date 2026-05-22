# Roadmap

The honest plan from `0.1.0` to `1.0.0` (and beyond), written so that
future contributors and future-me know what we're committing to vs.
what we're deliberately punting.

This is a **living document** — versions slip, scope changes, real
users reveal that something we thought was important isn't. Open a
PR or an issue to argue with anything here.

---

## TL;DR

| | What | Done when |
|---|---|---|
| **0.1.0** ✓ shipped 2026-05-22 | install-time sandbox + static analysis + lockfile / typosquat / npm-audit / CJS runtime tracer | (this) |
| **0.2.0** target Q3 2026 | ESM trace coverage · pkg-manager-agnostic install · safenpm diff integrates trace-diff · linux sandbox hardening | the runtime tracer no longer caveats "CJS only"; `safenpm install` works for projects using `yarn` / `pnpm` lockfiles |
| **0.3.0** target Q1 2027 | optional runtime *enforcement* (deny-list policies, ESM loader) · per-dep policy in `.safenpmrc` · audit log review UI | a malicious dep that gets past install sandbox + static analysis can be denied `child_process` at `require()` time via a documented policy |
| **0.4.x – 0.9.x** | hardening, external audit, real adoption work, real-attack-fixture tests | the SECURITY.md "Misses (important)" list has shrunk |
| **1.0.0** | when the audit completes + N real third-party users + M months without a critical bug in the last release | see ["graduation criteria" below](#10-graduation-criteria) |

**Versioning policy:** any 0.x → 0.(x+1) release can break the CLI
surface, the JSON output, or the `.safenpmrc` format. The CLI golden
snapshots pin short-range output but minor bumps can change them.
1.0.0 will commit to no-breaking-changes for the documented public
surface.

---

## Where we are (0.1.0)

What's in the box, validated by tests / live behavior:

- **Install-time sandbox** with strict / loose profiles on macOS
  (`sandbox-exec`) and Linux (`firejail`); experimental on Windows.
- **Static analysis** flagging `curl/wget/nc`, `~/.ssh` access,
  `eval()`, `| sh`, base64 obfuscation.
- **Typosquat detection** — edit distance ≤ 2, transpositions,
  scope confusion, common substitutions.
- **Lockfile audit** — non-registry resolved URLs (`git+`, `file:`,
  custom registries), missing or weak integrity hashes.
- **`npm audit` integration** — real CVE advisories surfaced in the
  scan flow, severity-tiered.
- **Maintainer-change detection** — npm publisher swap between the
  previous installed version and this one.
- **Threat-intel network** — Cloudflare KV-backed, Sybil-resistant
  via machineId entropy + distinct-reporter Redis-style SET,
  threshold ≥5 (≥15 for the curated protected-package list).
- **CJS runtime tracer** — `safenpm trace -- <cmd>` records what
  each dep `require()`s; `--diff` flags new critical builtins
  between two trace runs (exits 1 for CI gating).
- **CI / tests** — 326 unit, 90 integration, 24 golden snapshots,
  Ubuntu + macOS + Windows × Node 20/22 matrix.

What's deliberately *not* in 0.1.0 (and why):

- ESM runtime trace coverage — needs a separate loader-hook
  pipeline. ([see 0.2](#020--esm-coverage-and-package-manager-parity))
- Runtime *enforcement* — observe-only is shipped; deny-by-default
  is a multi-month architectural exercise. ([0.3](#030--optional-runtime-enforcement))
- External security audit — costs money, requires a credible
  surface to audit. ([0.4–0.9](#04--09--hardening-real-adoption-and-audit))
- Real adoption — there's no path to 1.0 without users finding bugs
  we don't know about. ([cross-cutting](#cross-cutting-themes)).

---

## 0.2.0 — ESM coverage and package-manager parity

**Target:** end of Q3 2026. Backwards-compatible additions only on
the CLI surface; no breaking changes to existing flags or
`.safenpmrc`.

### Ships

- **ESM-aware runtime tracer.** Today `safenpm trace -- node app.js`
  uses `node --require` + a CJS `Module.prototype.require`
  monkeypatch. Add an `--experimental-loader` that intercepts ESM
  `import` resolution, normalizes both sets of observations into the
  same `RuntimeTrace` shape, and merges them so `trace --diff`
  reports one diff per package regardless of module system.
- **`yarn` and `pnpm` install support.** Detect the lockfile in
  `cwd` and shell out to the right package manager with
  `--ignore-scripts`, then run the same Phase 1 / Phase 2 pipeline.
  No new CLI flags — `safenpm install` Just Works.
- **`safenpm diff` integrates with `trace --diff`.** When a behavioural
  snapshot exists from a prior `safenpm diff --snapshot` run AND
  recent traces exist in `~/.safenpm/pkg-traces/`, surface API-
  surface drift alongside script changes in one combined report.
- **Linux sandbox hardening.** Document the `firejail` profile
  invariants the way `src/sandbox/macos.profile.test.ts` pins the
  macOS profile. Add regression tests for known Linux escape
  patterns.
- **Real-attack fixture library.** Pull down the
  `event-stream@3.3.6`, `ua-parser-js@0.7.29`, `ctx@1.0.0` malicious
  tarballs (archived; not on npm any more). Add a
  `test/historical-attacks/` directory that runs `safenpm install`
  against each and asserts the expected detection.

### Doesn't ship

- Runtime enforcement (0.3).
- Browser / bundler integration.
- `safenpm doctor` enhancements beyond what's already there.
- Web dashboard for the threat-intel network (the JSON `/api/v1/stats`
  is enough until adoption exists).

### Done when

- The `safenpm trace --diff` output includes ESM-imported builtins
  with the same severity tiering as CJS requires.
- A test fixture using `yarn install` produces the same Findings
  shape as the npm equivalent.
- `event-stream@3.3.6` blocks under `safenpm install` and the
  fixture passes in CI on macOS + Linux.

### Rough effort estimate

- ESM loader: ~2 weeks (mostly figuring out the right loader API
  surface for Node 22+ and what gets stripped when bundlers
  pre-process imports).
- Yarn / pnpm: ~1 week.
- Real-attack fixtures: ~1 week (downloading + sanitising; we don't
  want to commit live malware to the repo, so the fixtures store
  hashes + URLs and CI fetches at runtime in a sandbox).
- Linux profile hardening: ongoing; one or two iteration cycles
  driven by real `firejail` bug reports.

---

## 0.3.0 — Optional runtime enforcement

**Target:** Q1 2027. Adds a new opt-in mode; default behavior
unchanged.

### Ships

- **`safenpm run -- <cmd>` with `--enforce-runtime`.** Spawns the
  command under a custom `--require` + `--experimental-loader` that:
  1. Reads a policy file (`.safenpm-policy.json`) per package, or
     falls back to a sensible default deny-list.
  2. Wraps `child_process`, `https`, `http`, `net`, `dns`, `vm`,
     `cluster`, `worker_threads`, `dgram`, `tls`, `inspector`,
     `module` exports in a Proxy that throws `SafenpmDenied` when
     called from a package that hasn't been granted that capability.
  3. Honors per-package allow-lists from `.safenpmrc` (e.g.
     `bcrypt: [child_process]` to permit the native-bind use case).
- **Policy generation from traces.** `safenpm trace --policy-from-
  latest` writes a `.safenpm-policy.json` matching the most recent
  trace's observed capabilities. Locking what *currently* runs is
  a strictly safer baseline than a hand-written allow-list.
- **Native addon gate.** Loading a `.node` file is treated as
  always-deny under `--enforce-runtime` unless the package has
  `nativeAddons: true` in its policy. Most malicious packages don't
  ship native code; legit ones (sharp, bcrypt) declare it.
- **Per-dep policy syntax in `.safenpmrc`.** Format TBD; aim for
  TOML-ish key/value because the current `.safenpmrc` parser is
  one-package-per-line and we want a structured extension.

### Doesn't ship

- Full V8 isolate per dependency. Cool but it's a 6-month project
  and the proxy-wrap approach is 95% of the value at 5% of the cost.
- ESM-only enforcement. The 0.3 enforcement runs in both module
  systems via the loader+require combo.

### Done when

- A fixture package that runs `process.binding('spawn_sync')` is
  caught by enforcement (proves the proxy isn't trivially bypassable
  via the bindings backdoor).
- `safenpm run --enforce-runtime -- npm test` passes for a real
  Node project with the default deny-list + the project's own
  needed allow-list entries.
- A documented escape (yes, there will be at least one) is filed as
  an open issue with an honest scope note.

### Rough effort estimate

- Loader + require monkeypatch with Proxy gating: ~4 weeks.
- Policy file format + parser + .safenpmrc extension: ~1 week.
- Per-package fixture suite: ~2 weeks.
- Honest "here's a known bypass" doc: ongoing.

**Risk:** this is the version most likely to ship later than
planned. The compatibility surface (every weird thing the npm
ecosystem does at runtime) is huge. If we hit that wall, the
honest answer is to ship trace-only enhancements as 0.3 and defer
enforcement to 0.4.

---

## 0.4 – 0.9 — Hardening, real adoption, and audit

The 0.x range is for "the API isn't stable yet but the project is
useful." Versions in here are loosely scheduled — they fire as
specific items complete.

| Version | Theme | Concrete deliverable |
|---|---|---|
| 0.4 | **External audit.** | Engage one of: Trail of Bits, Cure53, an indie reviewer with a public track record. Publish the report and the diff of fixes. Without this, 1.0 doesn't happen. |
| 0.5 | **Performance.** | Measure cold-install overhead vs. plain `npm install` on a 500-dep project. Optimise the static analyser and the parallel-fetch in `npm audit` until safenpm adds ≤ 15% overhead. |
| 0.6 | **Threat-intel network.** | First real-world test — partner with one mid-size open-source project that runs `safenpm install` in their CI. Surface the first 100 distinct signals. Decide whether the `distinctReporters ≥ 5` threshold is right by looking at false-positive rate. |
| 0.7 | **`.node` native-addon scanning.** | Static check on every `.node` file: signature comparison against npm registry, symbol-table inspection for known-dangerous imports (`fork`, `execvp`, `dlsym`). |
| 0.8 | **Bundler integration.** | Webpack / Vite / esbuild plugin that catches malicious code introduced at *build* time (the 0.1.0 SECURITY.md miss). |
| 0.9 | **Release candidate.** | Branch a `1.0.0-rc.1`, sit on it for 6+ weeks, fix only critical issues. If anything ships as 1.0.0, this is what becomes it. |

Order is suggestive, not strict. If 0.6 surfaces a critical Sybil
exploit, that becomes 0.6.1 and the rest slips. The point is the
*direction*: each version closes one item from the "Misses
(important)" list in SECURITY.md.

---

## 1.0 graduation criteria

Specific conditions that all need to be true before `package.json`
goes to `1.0.0`:

1. **External security audit completed.** A documented engagement
   with a third-party reviewer, with all critical findings closed
   and a public report.
2. **≥ 10 distinct external users**, defined as: people who are
   not the maintainer, who have opened an issue / PR / signal
   from a non-localhost machineId. The threat-intel network's own
   data is the source of truth.
3. **≥ 6 months in 0.9.x without a critical bug filed.** A
   critical bug is one that lets a known-malicious package script
   reach the network or filesystem outside the sandbox. The bar
   is intentionally high because the *whole point* of the tool is
   that this never happens.
4. **Documented public API.** What's stable: the CLI flags listed
   in `--help`, the JSON output shape (`JsonOutput` in
   `src/types.ts`), the `.safenpmrc` syntax, the runtime-tracer
   trace file format. What stays internal: every TypeScript export
   under `src/` that isn't reachable from the CLI.
5. **CI on at least three OS / package-manager combos** — macOS
   + npm, Linux + npm, Linux + pnpm. Windows graduates from
   experimental when this is feasible there too.

If any of these isn't met, the version stays in `0.x`. Calling it
1.0 just because the calendar says so is exactly the overconfidence
that made the original `1.0.0` publish in April 2026 a mistake.

---

## Cross-cutting themes

These don't fit a single milestone — they're work that happens
across every release.

### Security

- **Threat-model updates.** Every new feature gets a paragraph in
  `SECURITY.md` describing what it catches and (more importantly)
  what it doesn't.
- **Regression tests.** Every sandbox-escape or classifier bug we
  fix gets a named regression test that pins the specific failure
  mode (the SIGABRT case in `classify.test.ts` is the template).
- **No silent enforcement default changes.** Anything that could
  block a previously-working install needs an explicit major
  version bump or an opt-in flag.

### Performance

- **Cold-install benchmark in CI.** A `bench/cold-install.sh` that
  measures `safenpm install` vs `npm install` overhead on a fixed
  fixture project (~50 deps with native bindings). Reported as a
  CI artifact, surfaced in PR review when overhead grows > 10%
  vs. main.
- **Lazy-load the heavy paths.** The runtime tracer's lucide-sized
  modules don't need to load on every install; defer to first use.
- **`hashGetAll` is hot in the dashboard.** Already 30s edge-cached
  but worth a second look if the KV blob ever exceeds a few hundred
  flagged packages.

### Adoption

- **Build the demo before the pitch.** Each new release should ship
  with at least one concrete "we ran safenpm against historical
  attack X — here's what we caught" blog post. This is the only
  share-on-Slack content that survives scrutiny.
- **One real user before each minor.** No 0.x bump without at least
  one external person having tried the previous version on a real
  project. If we can't find someone, the version isn't ready.
- **Honest pre-1.0 status everywhere.** README, npm publishConfig
  (`next` tag, not `latest`), CHANGELOG, post-merge release notes.

### Community

- **Issue triage.** Solo maintainer rule: every issue gets a
  human-written response within 7 days, even if the response is
  "I'm not going to fix this and here's why." Silence is worse than
  a no.
- **Contribution path.** `CONTRIBUTING.md` doesn't exist yet
  (deliberately — premature for a no-contributor project). It gets
  written the first time someone opens a PR with non-trivial code.
- **Public roadmap.** This document. PR adjustments are explicitly
  invited; the document is wrong about something at any given moment
  and we'd rather know.

---

## What could kill this project

Honest list of failure modes that would mean walking away.

1. **A critical sandbox escape that we can't fix without a major
   rewrite.** If the macOS profile turns out to be fundamentally
   leaky (mach-lookup vectors we can't enumerate, kernel-level
   sandbox bugs we can't work around), the tool's main value
   evaporates. The honest move would be a deprecation notice and
   a pointer to whatever does this better.

2. **No adoption after 12 months of real outreach.** A supply-chain
   defence tool with zero users is a useful personal artefact but
   not a product. If 0.6 (the "first real users" milestone) doesn't
   find any, we stop fooling ourselves about the threat-intel
   network and ship the install-sandbox piece as a self-contained
   tool with the network parts removed.

3. **Cloudflare KV stops being the right backend.** If KV's
   per-key size limit, list-API lag, or pricing model makes the
   threat-intel layer unworkable, we need a different store. Pre-
   commitment: pick one (Cloudflare D1 / Turso / Vercel KV / a
   tiny self-hosted Postgres) before the constraint becomes a
   crisis.

4. **Maintainer burnout.** Solo project. The countermeasures are:
   (a) keep the scope honest, (b) don't ship features that can't
   be tested, (c) write enough docs that a successor maintainer
   could pick this up — `docs/architecture.md` and this roadmap
   are part of that insurance policy.

5. **A larger project ships the same idea better.** Socket.dev,
   Snyk, npm itself could roll out an install-sandbox tomorrow.
   That's fine — the win is the threat-model layer existing more
   broadly, not safenpm being the one that ships it. The honest
   response would be to deprecate, write a postmortem explaining
   what worked, and merge into whatever became canonical.

None of these are predictions. They're the failure modes that the
roadmap needs to survive.

---

## How to influence this roadmap

Open an issue at <https://github.com/abgnydn/safenpm/issues> with
the label `roadmap`. Specifically welcome:

- **"Did you consider X?"** — yes if there's a real argument for
  bumping its priority.
- **"You're going to slip 0.3 because of Y"** — almost certainly
  correct, would love to know what Y is before it bites.
- **"I want to use this on N projects"** — biggest signal we can
  receive. Determines what gets accelerated.

Don't open issues for: typos in this doc (PR is faster), opinions
about the version label (the `npm publish` constraint section in
the CHANGELOG already covers this), or generic "what about feature
X" without a use case.

---

Last updated: 2026-05-22 (post 0.1.0 ship).
