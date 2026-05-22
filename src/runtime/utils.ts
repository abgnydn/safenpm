/**
 * Pure helpers for the runtime tracer. Kept in their own module so
 * unit tests can exercise them without booting the require()
 * monkeypatch in hook.ts.
 */
import path from 'path'

/**
 * Given an absolute filename, return the npm-package name that
 * "owns" it: `node_modules/foo/lib/x.js` → `foo`,
 * `node_modules/@scope/foo/x.js` → `@scope/foo`, anything outside a
 * `node_modules` segment → `<root>`.
 *
 * Uses the LAST occurrence of `node_modules/` so nested deps
 * (`node_modules/a/node_modules/b/...`) attribute to the innermost
 * package, which is what you want for "who actually executed this
 * require()".
 */
export function packageOfFile(filename: string | undefined): string {
  if (!filename) return '<root>'
  // Normalize to forward slashes so the path works on Windows too.
  const norm = filename.replace(/\\/g, '/')
  const marker = '/node_modules/'
  const idx = norm.lastIndexOf(marker)
  if (idx === -1) return '<root>'
  const rest = norm.slice(idx + marker.length)
  const parts = rest.split('/')
  const first = parts[0]
  if (!first) return '<root>'
  if (first.startsWith('@')) {
    const second = parts[1]
    return second ? `${first}/${second}` : '<root>'
  }
  return first
}

/**
 * Categorise a `require(id)` argument:
 *   - 'builtin'    → 'fs', 'https', 'child_process', etc.
 *   - 'relative'   → './foo', '../bar' (local file inside the same pkg)
 *   - 'absolute'   → '/abs/path'
 *   - 'package'    → 'lodash', '@scope/pkg' (named dep)
 *
 * The interesting buckets for security analysis are 'builtin' (which
 * Node modules a package reaches for) and 'package' (which deps it
 * pulls in transitively at runtime). 'relative' and 'absolute' get
 * recorded too but mean "internal to the package".
 */
export function classifyRequireId(id: string): 'builtin' | 'relative' | 'absolute' | 'package' {
  if (id.startsWith('./') || id.startsWith('../')) return 'relative'
  if (id.startsWith('/') || /^[A-Za-z]:[\\/]/.test(id)) return 'absolute'
  if (id.startsWith('node:')) return 'builtin'
  // Node's builtin module list is too long to keep in sync here, and
  // it's stable. Defer to the `require.resolve` heuristic: a builtin
  // ID never contains a path separator. Single-segment names that
  // aren't builtins are still 'package'.
  if (!id.includes('/') || (id.startsWith('@') && id.split('/').length === 2)) {
    // Could be either builtin ('fs', 'https') or package ('lodash').
    // Distinguish via a static list of Node ≥18 builtins. Keep this
    // small — additions are append-only.
    return BUILTINS.has(id) ? 'builtin' : 'package'
  }
  // Multi-segment without scope-prefix = subpath into a package.
  return 'package'
}

/**
 * Static list of Node.js builtin module names. Append-only. Drawn
 * from `module.builtinModules` on Node 22; older Nodes have a
 * subset. Anything new added by future Node versions will be
 * misclassified as 'package' until added here — better than
 * misclassifying an attacker-controlled name as 'builtin'.
 */
const BUILTINS: ReadonlySet<string> = new Set([
  'assert', 'async_hooks', 'buffer', 'child_process', 'cluster',
  'console', 'constants', 'crypto', 'dgram', 'diagnostics_channel',
  'dns', 'domain', 'events', 'fs', 'http', 'http2', 'https',
  'inspector', 'module', 'net', 'os', 'path', 'perf_hooks', 'process',
  'punycode', 'querystring', 'readline', 'repl', 'stream',
  'string_decoder', 'sys', 'test', 'timers', 'tls', 'trace_events',
  'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
])

/** Trace file shape — JSON written to ~/.safenpm/pkg-traces/. */
export interface RuntimeTrace {
  /** ISO timestamp when the traced process exited. */
  timestamp: string
  /** cwd at the time the trace started. */
  cwd: string
  /** Wall-clock duration of the traced process, in ms. */
  durationMs: number
  /** For each package observed: which IDs it required, bucketed. */
  packages: Record<string, PackageTrace>
}

export interface PackageTrace {
  builtin: string[]
  package: string[]
  relative: number    // count only — internal file requires aren't useful for a security audit
  absolute: number
}

/**
 * Convert the runtime-collected Map into the serializable trace
 * shape, with sorted arrays for stable diffing.
 */
export function buildTrace(
  observations: Map<string, Map<string, 'builtin' | 'relative' | 'absolute' | 'package'>>,
  meta: { startMs: number; cwd: string },
): RuntimeTrace {
  const packages: Record<string, PackageTrace> = {}
  for (const [pkg, ids] of observations) {
    const t: PackageTrace = { builtin: [], package: [], relative: 0, absolute: 0 }
    for (const [id, kind] of ids) {
      if (kind === 'builtin') t.builtin.push(id.replace(/^node:/, ''))
      else if (kind === 'package') t.package.push(id)
      else if (kind === 'relative') t.relative++
      else t.absolute++
    }
    t.builtin = [...new Set(t.builtin)].sort()
    t.package = [...new Set(t.package)].sort()
    packages[pkg] = t
  }
  return {
    timestamp: new Date().toISOString(),
    cwd: meta.cwd,
    durationMs: Date.now() - meta.startMs,
    packages,
  }
}

/**
 * Diff two runtime traces. Returns the per-package set of newly-
 * appearing builtin or package requires. Empty if nothing changed
 * (or the package didn't exist in `prev`).
 */
export interface TraceDiff {
  packageName: string
  newBuiltins: string[]
  newPackages: string[]
}

export function diffTraces(prev: RuntimeTrace, curr: RuntimeTrace): TraceDiff[] {
  const out: TraceDiff[] = []
  for (const [name, currPkg] of Object.entries(curr.packages)) {
    const prevPkg = prev.packages[name]
    const newBuiltins = prevPkg
      ? currPkg.builtin.filter((b) => !prevPkg.builtin.includes(b))
      : currPkg.builtin
    const newPackages = prevPkg
      ? currPkg.package.filter((p) => !prevPkg.package.includes(p))
      : currPkg.package
    if (newBuiltins.length > 0 || newPackages.length > 0) {
      out.push({ packageName: name, newBuiltins, newPackages })
    }
  }
  return out
}

/** Pure path builder for the trace output directory. */
export function defaultTraceDir(home: string): string {
  return path.join(home, '.safenpm', 'pkg-traces')
}

/**
 * Severity tiering for Node builtin module names. A package that
 * starts importing one of these for the first time is roughly
 * ordered by "how worried should I be":
 *
 *   critical — direct network / arbitrary-code paths
 *   high     — filesystem, crypto, OS-level access
 *   medium   — everything else
 *
 * Used by `safenpm trace --diff` to decide which newly-appearing
 * builtins should trigger a non-zero exit code.
 */
export type BuiltinSeverity = 'critical' | 'high' | 'medium'

const CRITICAL_BUILTINS: ReadonlySet<string> = new Set([
  'child_process', 'cluster', 'worker_threads',
  'http', 'https', 'http2', 'net', 'dgram', 'tls', 'dns',
  'vm', 'inspector', 'module',
])

const HIGH_BUILTINS: ReadonlySet<string> = new Set([
  'fs', 'fs/promises', 'crypto', 'os', 'process',
  'wasi', 'trace_events', 'perf_hooks',
])

export function categorizeBuiltin(name: string): BuiltinSeverity {
  const bare = name.replace(/^node:/, '')
  if (CRITICAL_BUILTINS.has(bare)) return 'critical'
  if (HIGH_BUILTINS.has(bare)) return 'high'
  return 'medium'
}

/**
 * Returns a list of trace files under `dir`, sorted ascending by
 * filename. Because the filename is prefixed with the ISO timestamp,
 * sorting by string is equivalent to sorting by trace time.
 * Returns [] on any IO error (missing dir, unreadable, etc).
 */
export function listTraceFiles(dir: string): string[] {
  try {
    // Use require-style import so this file stays usable in both the
    // runtime hook (which loads fs already) and the CLI command path.
    const fs = require('fs') as typeof import('fs')
    if (!fs.existsSync(dir)) return []
    return fs.readdirSync(dir)
      .filter((f) => f.endsWith('.json'))
      .sort()
      .map((f) => path.join(dir, f))
  } catch {
    return []
  }
}

/**
 * Reads and validates a trace file. Returns null on any failure
 * (missing, malformed JSON, wrong shape). Validation is intentionally
 * loose — we trust traces we wrote, but we don't trust against
 * tampering / format drift, so the consumer can rely on the basic
 * shape (timestamp + cwd + packages object).
 */
export function readTraceFile(file: string): RuntimeTrace | null {
  try {
    const fs = require('fs') as typeof import('fs')
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (!raw || typeof raw !== 'object') return null
    if (typeof raw.timestamp !== 'string') return null
    if (typeof raw.cwd !== 'string') return null
    if (!raw.packages || typeof raw.packages !== 'object') return null
    return raw as RuntimeTrace
  } catch {
    return null
  }
}
