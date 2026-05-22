# Architecture

Quick navigation map of the codebase, plus the dataflow through a
typical `safenpm install` run. If you're contributing or reviewing,
read this first — it'll save you a `grep` round.

## Top-level layout

```
safenpm/
├── src/                         # CLI library (compiled to dist/)
├── functions/                   # Cloudflare Pages Functions (the threat-intel server)
├── site/                        # Static landing + showcase pages
├── test/
│   ├── run-tests.sh             # bash integration suite
│   └── golden/                  # byte-identity CLI snapshots
├── scripts/                     # ad-hoc dev scripts (og.png renderer)
└── docs/                        # this directory
```

The CLI is what ships to npm (`@abgunaydin/safenpm`). The Pages
Functions deploy to `safenpm.dev` (via Cloudflare Pages). The two
talk over HTTPS via `/api/v1/intel` (lookup) and `/api/v1/signal`
(report).

## CLI module layout (`src/`)

```
src/
├── cli/                    # argv parsing + per-command modules
│   ├── index.ts            # entry point — dispatches to commands/
│   ├── args.ts             # parseInstallArgs() + ParseError union
│   ├── help.ts             # VERSION_STRING + HELP_TEXT
│   ├── util.ts             # requireNodeModules() gate
│   └── commands/
│       ├── install.ts      # → src/install/index.ts
│       ├── scan.ts         # standalone scan
│       ├── doctor.ts       # health card
│       ├── fix.ts          # auto-fix
│       ├── diff.ts         # snapshot/diff
│       └── audit.ts        # ~/.safenpm/audit.log viewer
│
├── install/                # install orchestrator
│   ├── index.ts            # entry: install(opts)
│   ├── execute.ts          # Phase 2: per-package sandbox loop
│   └── json-output.ts      # frozen JSON shape builder
│
├── pipeline/               # declarative analysis pipeline
│   ├── types.ts            # Step<F>, AnalysisContext, Finding union
│   ├── runner.ts           # runPipeline(steps, ctx) + byKind helper
│   └── steps.ts            # PRE_SCRIPT_STEPS + POST_SCRIPT_STEPS
│
├── analysis/               # pure analysis modules (no fs writes)
│   ├── analyzer.ts         # static analysis on install scripts
│   ├── typosquat.ts        # name-distance + substitution check
│   ├── lockfile.ts         # package-lock.json audit
│   ├── reputation.ts       # package.json-only reputation heuristic
│   ├── npm-audit.ts        # `npm audit --json` wrapper
│   ├── diffing.ts          # script-cache diffing
│   └── pkgdiff.ts          # package snapshot/diff viewer
│
├── sandbox/                # OS-specific sandbox backends
│   ├── index.ts            # detectBackend + runInSandbox dispatch
│   ├── env.ts              # STRIPPED_ENV_KEYS + cleanEnv()
│   ├── classify.ts         # spawn result → blocked/clean decision
│   ├── macos.ts            # sandbox-exec TinyScheme profiles
│   ├── linux.ts            # firejail invocation
│   ├── windows.ts          # Windows Firewall + WSL firejail
│   └── unsandboxed.ts      # last-resort fallback (warned to user)
│
├── network/                # outbound HTTPS to safenpm.dev + npm registry
│   ├── threatintel.ts      # POST /api/v1/intel (+ local cache)
│   ├── maintainer.ts       # npm registry publisher lookup
│   └── signals.ts          # POST /api/v1/signal (anonymous report)
│
├── config/
│   └── allowlist.ts        # .safenpmrc parser (allowlist + ! ignores)
│
├── packages/               # node_modules walkers
│   ├── scripts.ts          # findInstallScripts()
│   └── names.ts            # getAllPackageNames() + validatePackageName()
│
├── fix/                    # auto-fix engine
│   └── autofix.ts          # generateFixes() + applyFix()
│
├── audit/                  # persistent run log
│   └── log.ts              # ~/.safenpm/audit.log JSON-lines writer
│
├── report/                 # terminal + JSON output
│   ├── reporter.ts         # Reporter interface + factory
│   ├── human.ts            # createHumanReporter() — ANSI rendering
│   ├── json.ts             # createJsonReporter() — every method no-ops
│   └── index.ts            # barrel
│
├── doctor/
│   └── index.ts            # health-card aggregator (`safenpm doctor`)
│
└── types.ts                # shared interfaces (PackageScript, JsonOutput, …)
```

## Dataflow: `safenpm install`

```
cli/index.ts main()
  └─ dispatches to cli/commands/install.ts
       └─ cli/args.ts parseInstallArgs()
       └─ install/index.ts install(opts)
            │
            ├─ report/index.ts getReporter(opts)         # human or JSON
            ├─ config/allowlist.ts loadAllowlist()
            │
            ├─ sandbox/index.ts isSandboxAvailable()
            │    └─ macos.ts / linux.ts / windows.ts isAvailable()
            │
            ├─ spawn `npm install --ignore-scripts`      # materialize node_modules
            ├─ packages/scripts.ts findInstallScripts()
            ├─ packages/names.ts getAllPackageNames()
            │
            ├─ Phase 1a — pre-script analyses (pipeline/runner runPipeline):
            │     typosquats → lockfile → reputation → npm-audit
            ├─ reportPreFindings(findings, reporter)
            │
            ├─ Phase 1b — post-script analyses (only if scripts > 0):
            │     analysis → behavior-diff → threat-intel → maintainers
            ├─ reportPostFindings(findings, reporter)
            │
            ├─ Phase 2 — install/execute.ts executeScripts(...):
            │   for each PackageScript:
            │     ├─ if allowlisted → run with cleanEnv(), no sandbox
            │     └─ else → sandbox/index.ts runInSandbox(pkg, strict)
            │                └─ macos.ts buildStrictProfile() → sandbox-exec
            │                     └─ sandbox/classify.ts classify(result)
            │                          └─ pattern + exit + signal → blocked / clean
            │
            ├─ audit/log.ts writeAuditLog(results)
            ├─ network/signals.ts reportBlocked(results)  # fire-and-forget
            │
            └─ reporter.summary(...) OR JSON.stringify(buildJsonOutput(...))
```

## The Reporter strategy

Every emit to stdout in the CLI goes through `Reporter`. There are
exactly two implementations:

- **`createHumanReporter()`** — ANSI colors, section headers, the works.
  Pinned by `test/golden/` snapshots.
- **`createJsonReporter()`** — every visual method is a no-op. JSON
  callers accumulate findings and emit a single `JSON.stringify()` at
  the end via `install/json-output.ts buildJsonOutput()`.

The factory `getReporter(opts)` picks based on `opts.json`. Call
sites stopped writing `if (!opts.json) ...` everywhere — wrong-mode
emits are now structurally impossible.

## The Pipeline + Step abstraction

`pipeline/types.ts` defines:

```ts
type Finding =
  | { kind: 'typosquats';   results: TyposquatResult[] }
  | { kind: 'lockfile';     result: LockfileAuditResult }
  | { kind: 'reputation';   summary: ReputationSummary }
  | { kind: 'npm-audit';    result: NpmAuditResult }
  | { kind: 'analysis';     results: AnalysisResult[] }
  | { kind: 'diffs';        results: DiffResult[] }
  | { kind: 'threat-intel'; results: ThreatIntelResult[] }
  | { kind: 'maintainers';  results: MaintainerInfo[] }

interface Step<F extends Finding> {
  name: string
  enabled(opts: InstallOptions): boolean
  run(ctx: AnalysisContext): Promise<F> | F
}
```

Each entry in `PRE_SCRIPT_STEPS` / `POST_SCRIPT_STEPS` is one Step.
`runPipeline()` walks the list and returns a `Finding[]`. The
orchestrator picks findings out of the list with `byKind(findings, K)`
which is a type-safe accessor that narrows the variant.

Adding a new check is a single PR:
1. Write the analysis module (`src/analysis/<name>.ts`)
2. Add a `{ kind: '<name>'; ... }` variant to the `Finding` union
3. Add a new `Step` in `pipeline/steps.ts`
4. Add reporter methods + wiring in `install/index.ts` + the JSON output

## The threat-intel server (`functions/`)

```
functions/
├── _lib/
│   ├── redis.ts            # Upstash REST client + CORS helpers
│   ├── types.ts            # FlaggedEntry / Signal / IntelQuery
│   └── validate.ts         # parseSignal / parseIntelQuery / parseFlaggedEntry
└── api/v1/
    ├── signal.ts           # POST /api/v1/signal — receive a block report
    ├── intel.ts            # POST /api/v1/intel — batch lookup
    ├── stats.ts            # GET  /api/v1/stats — dashboard payload
    └── admin.ts            # POST /api/v1/admin — bearer-token operations
```

Sybil-resistance:
- `distinctReporters` is backed by a Redis SET keyed
  `safenpm:reporters:<pkg>@<ver>` with a 90-day TTL. SADD returns 1
  only for new members.
- `validate.ts` enforces `MIN_MACHINE_ID_LEN = 16` and a strict
  `[a-zA-Z0-9_-]` character class.
- Reports under `'anonymous'` are accepted but never join the set.
- Flag threshold defaults to **5** distinct reporters (15 for the
  curated PROTECTED_PACKAGES list).

## Testing layout

```
test/
├── run-tests.sh                # 90-test bash integration suite
└── golden/
    ├── capture.sh              # snapshot recorder (--check or write mode)
    ├── normalize.mjs           # scrub timestamps / $HOME / mktemp paths
    ├── fixtures/               # 4 sample projects
    └── outputs/                # 24 normalized snapshots
```

Unit tests are colocated as `*.test.ts` next to the module they
exercise. Vitest config is at `vitest.config.ts`; tsconfig
**excludes** `*.test.ts` so the production build doesn't include
test code.
