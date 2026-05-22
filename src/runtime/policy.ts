/**
 * Runtime policy — pure, dependency-free. Tells the enforcement
 * hook (`runtime/enforce.ts`) whether a given package is allowed to
 * `require()` a given Node builtin.
 *
 * The model is:
 *   - There's a list of builtins that everyone gets by default
 *     (`pure-utility` ones — path, util, events, stream, assert).
 *   - There's a list of builtins that nobody gets without explicit
 *     allow (the `dangerous` tier — child_process, https, net, vm…).
 *   - Per-package `allow` overrides the dangerous list (e.g. bcrypt
 *     declares `child_process` because it shells out to node-gyp).
 *   - Per-package `deny` overrides the default-allow list (rare, but
 *     useful to lock down a package that has no business with crypto).
 *
 * The policy file is `<project>/.safenpm-policy.json` and the loader
 * accepts a missing file as "use defaults only."
 */
import fs from 'fs'
import path from 'path'

export const POLICY_FILE = '.safenpm-policy.json'

export interface PackagePolicy {
  /** Builtins this package is explicitly allowed to require (overrides defaultDeny). */
  allow?: string[]
  /** Builtins this package is explicitly denied (overrides defaultAllow). */
  deny?: string[]
}

export interface Policy {
  version: 1
  /** Builtins available to every package without an explicit entry. */
  defaultAllow: string[]
  /** Builtins denied unless a package explicitly allow-lists them. */
  defaultDeny: string[]
  packages: Record<string, PackagePolicy>
}

/**
 * Builtins safe enough that we default-allow them. These are
 * non-IO, non-network, non-exec utilities the entire ecosystem
 * needs. Refusing them would break every install.
 */
export const DEFAULT_ALLOW: readonly string[] = [
  'path', 'util', 'events', 'stream', 'assert', 'buffer',
  'string_decoder', 'querystring', 'url', 'punycode',
  'async_hooks', 'perf_hooks', 'timers', 'console',
  'fs',                  // most packages legitimately read files
  'os',                  // most packages check platform / arch
  'crypto',              // ubiquitous for hashing; we accept the dual-use risk
  'tty',                 // chalk, ora, etc.
  'readline',            // CLI tooling
  'zlib',                // compression — very common
  'process',             // every package touches process.env (we already strip secrets there)
]

/**
 * Builtins denied by default. A package must explicitly allow-list
 * any of these in its policy entry to use them. These are the
 * direct vectors for runtime-stage exfiltration.
 */
export const DEFAULT_DENY: readonly string[] = [
  'child_process', 'cluster', 'worker_threads',
  'http', 'https', 'http2', 'net', 'dgram', 'tls', 'dns',
  'vm', 'inspector', 'module',
  'wasi',                // sandbox escape via WASI
  'v8',                  // serialisation/heap-dump backdoor
]

export function defaultPolicy(): Policy {
  return {
    version: 1,
    defaultAllow: [...DEFAULT_ALLOW],
    defaultDeny: [...DEFAULT_DENY],
    packages: {},
  }
}

/**
 * Load a policy from `<projectDir>/.safenpm-policy.json`. Returns
 * the default policy on missing / malformed file — never throws.
 */
export function loadPolicy(projectDir: string = process.cwd()): Policy {
  const file = path.join(projectDir, POLICY_FILE)
  if (!fs.existsSync(file)) return defaultPolicy()
  try {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'))
    return normalizePolicy(raw)
  } catch {
    return defaultPolicy()
  }
}

/**
 * Coerce a loosely-typed JSON object into a valid Policy. Unknown
 * fields are dropped; invalid shapes fall back to defaults.
 * Exported for tests.
 */
export function normalizePolicy(raw: unknown): Policy {
  if (!raw || typeof raw !== 'object') return defaultPolicy()
  const p = raw as Record<string, unknown>
  const defaultAllow = Array.isArray(p.defaultAllow)
    ? p.defaultAllow.filter((x): x is string => typeof x === 'string')
    : [...DEFAULT_ALLOW]
  const defaultDeny = Array.isArray(p.defaultDeny)
    ? p.defaultDeny.filter((x): x is string => typeof x === 'string')
    : [...DEFAULT_DENY]
  const packages: Record<string, PackagePolicy> = {}
  if (p.packages && typeof p.packages === 'object') {
    for (const [name, entry] of Object.entries(p.packages as Record<string, unknown>)) {
      if (!entry || typeof entry !== 'object') continue
      const e = entry as Record<string, unknown>
      const pkgPol: PackagePolicy = {}
      if (Array.isArray(e.allow)) pkgPol.allow = e.allow.filter((x): x is string => typeof x === 'string')
      if (Array.isArray(e.deny))  pkgPol.deny  = e.deny.filter((x): x is string => typeof x === 'string')
      packages[name] = pkgPol
    }
  }
  return { version: 1, defaultAllow, defaultDeny, packages }
}

/**
 * Strip the `node:` prefix that newer code uses.
 */
export function normaliseBuiltin(id: string): string {
  return id.startsWith('node:') ? id.slice(5) : id
}

/**
 * The decision function — given the resolved policy, decide whether
 * `pkg` is allowed to `require(id)`. `id` is a builtin name (the
 * caller is expected to have classified it already).
 *
 * Resolution order:
 *   1. Per-package `deny` wins outright.
 *   2. Per-package `allow` is the next-strongest signal.
 *   3. Otherwise: default-deny tier blocks; default-allow tier permits;
 *      anything outside both tiers is permitted (unknown builtins
 *      default to allow so future Node releases don't break installs).
 */
export function isAllowed(policy: Policy, pkg: string, id: string): boolean {
  const name = normaliseBuiltin(id)
  const pkgPol = policy.packages[pkg]
  if (pkgPol?.deny?.includes(name)) return false
  if (pkgPol?.allow?.includes(name)) return true
  if (policy.defaultDeny.includes(name)) return false
  return true
}

/**
 * Persist a policy. Stable key order so diffs against a previous
 * generation stay readable.
 */
export function savePolicy(projectDir: string, policy: Policy): void {
  const sorted: Policy = {
    version: 1,
    defaultAllow: [...policy.defaultAllow].sort(),
    defaultDeny: [...policy.defaultDeny].sort(),
    packages: Object.fromEntries(
      Object.entries(policy.packages)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, {
          ...(v.allow ? { allow: [...v.allow].sort() } : {}),
          ...(v.deny ? { deny: [...v.deny].sort() } : {}),
        }]),
    ),
  }
  fs.writeFileSync(path.join(projectDir, POLICY_FILE), JSON.stringify(sorted, null, 2) + '\n', 'utf8')
}

/**
 * Generate a policy from a runtime trace. Every observed builtin
 * for a given package becomes an entry in its `allow` list — the
 * package gets to keep exactly the capabilities it was already
 * using, nothing more. This is the "lock what currently runs"
 * starting point.
 */
export function policyFromTrace(
  trace: { packages: Record<string, { builtin: string[] }> },
): Policy {
  const packages: Record<string, PackagePolicy> = {}
  for (const [name, pkg] of Object.entries(trace.packages)) {
    if (name === '<root>') continue
    // Only record builtins that the dangerous-tier default-deny would
    // have blocked. Allow-listing `path` for every package is noise.
    const dangerous = pkg.builtin.filter((b) => (DEFAULT_DENY as readonly string[]).includes(normaliseBuiltin(b)))
    if (dangerous.length > 0) packages[name] = { allow: dangerous }
  }
  return {
    version: 1,
    defaultAllow: [...DEFAULT_ALLOW],
    defaultDeny: [...DEFAULT_DENY],
    packages,
  }
}
