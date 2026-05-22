/**
 * Schema validators for every request body the Pages Functions accept.
 *
 * Each `parseX` returns the validated object on success or `null` on
 * failure — handlers translate that into 400. Keeping the validators
 * here (a) deduplicates the regexes and length caps that previously
 * lived inline in each handler and (b) gives us a single surface to
 * unit-test without spinning up a Workers runtime.
 *
 * `parseFlaggedEntry` does the opposite job — it takes the loosely-
 * typed Redis read (string OR object, depending on the client
 * library's deserializer) and returns a known-shape `FlaggedEntry` or
 * `null` so callers stop reaching for `as any`.
 */
import type { FlaggedEntry, IntelQuery, Signal } from './types'

// ── Constants — must match the npm-name spec and Redis caps ──────────

export const PACKAGE_NAME_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/
export const MAX_PACKAGE_NAME_LEN = 214
export const MAX_VERSION_LEN = 50
export const MIN_HASH_LEN = 16
export const MAX_HASH_LEN = 128

// MachineId: must be entropic enough to make a Sybil report inflation
// non-trivial. Reject single chars / obvious test values. The CLI
// generates a UUIDv4 (36 chars including dashes) — accept anything 16+
// chars matching a UUID-ish or hex shape.
export const MIN_MACHINE_ID_LEN = 16
export const MAX_MACHINE_ID_LEN = 64
export const MACHINE_ID_RE = /^[a-zA-Z0-9_-]+$/

export const MAX_INTEL_BATCH = 500
export const MAX_SCRIPT_PREVIEW_LEN = 500

export const VALID_REASONS: ReadonlySet<string> = new Set([
  'network access', 'credential exfiltration', 'reverse shell',
  'eval/obfuscation', 'ssh key theft', 'env var harvesting',
  'dns exfiltration', 'filesystem access', 'process spawn',
  'crypto mining', 'data exfiltration', 'suspicious behavior',
])

// ── Helpers ──────────────────────────────────────────────────────────

function isObject(x: unknown): x is Record<string, unknown> {
  return !!x && typeof x === 'object'
}

function isString(x: unknown): x is string {
  return typeof x === 'string'
}

function isNonEmptyString(x: unknown): x is string {
  return typeof x === 'string' && x.length > 0
}

function isValidPackageName(s: string): boolean {
  return s.length > 0 && s.length <= MAX_PACKAGE_NAME_LEN && PACKAGE_NAME_RE.test(s)
}

function isValidScriptHash(s: string): boolean {
  return s.length >= MIN_HASH_LEN && s.length <= MAX_HASH_LEN && /^[a-f0-9]+$/.test(s)
}

// ── Parsers ──────────────────────────────────────────────────────────

export function parseSignal(body: unknown): Signal | null {
  if (!isObject(body)) return null

  if (!isNonEmptyString(body.package) || !isValidPackageName(body.package)) return null
  if (!isNonEmptyString(body.version) || body.version.length > MAX_VERSION_LEN) return null
  if (!isNonEmptyString(body.reason) || !VALID_REASONS.has(body.reason)) return null
  if (!isNonEmptyString(body.scriptHash) || !isValidScriptHash(body.scriptHash)) return null

  // machineId rules:
  //   - 'anonymous' is allowed but reports under it never count toward
  //     distinctReporters (the server treats it as a single shared
  //     identity — see signal.ts).
  //   - any other value must be at least MIN_MACHINE_ID_LEN chars and
  //     match MACHINE_ID_RE, raising the cost of trivial Sybil
  //     inflation. Short or symbol-laced values are rejected outright.
  let machineId: string
  if (!isString(body.machineId)) {
    machineId = 'anonymous'
  } else if (body.machineId === 'anonymous') {
    machineId = 'anonymous'
  } else {
    if (body.machineId.length < MIN_MACHINE_ID_LEN) return null
    if (body.machineId.length > MAX_MACHINE_ID_LEN) return null
    if (!MACHINE_ID_RE.test(body.machineId)) return null
    machineId = body.machineId
  }

  const script = isString(body.script) ? body.script.slice(0, MAX_SCRIPT_PREVIEW_LEN) : ''

  return {
    machineId,
    package: body.package,
    version: body.version,
    hook: isString(body.hook) ? body.hook : 'unknown',
    script,
    scriptHash: body.scriptHash,
    scriptLength: typeof body.scriptLength === 'number' ? body.scriptLength : 0,
    reason: body.reason,
    timestamp: isString(body.timestamp) ? body.timestamp : new Date().toISOString(),
    platform: isString(body.platform) ? body.platform : 'unknown',
  }
}

export function parseIntelQuery(body: unknown): IntelQuery | null {
  if (!isObject(body)) return null
  if (!Array.isArray(body.packages)) return null
  if (body.packages.length > MAX_INTEL_BATCH) return null

  const out: Array<{ name: string; version: string }> = []
  for (const raw of body.packages) {
    if (!isObject(raw)) return null
    if (!isString(raw.name) || !isString(raw.version)) return null
    out.push({ name: raw.name, version: raw.version })
  }
  return { packages: out }
}

/**
 * Loosely-typed reads from Redis come back as either the original
 * JSON string or a pre-parsed object (depends on which Upstash
 * client builds the response). This function unifies the two and
 * verifies the minimal shape we depend on.
 */
export function parseFlaggedEntry(raw: unknown): FlaggedEntry | null {
  let parsed: unknown = raw
  if (typeof raw === 'string') {
    try {
      parsed = JSON.parse(raw)
    } catch {
      return null
    }
  }
  if (!isObject(parsed)) return null

  const reasons = isObject(parsed.reasons) ? (parsed.reasons as Record<string, number>) : null
  const platforms = isObject(parsed.platforms) ? (parsed.platforms as Record<string, number>) : null
  if (!reasons || !platforms) return null

  return {
    reportCount: typeof parsed.reportCount === 'number' ? parsed.reportCount : 0,
    distinctReporters: typeof parsed.distinctReporters === 'number'
      ? parsed.distinctReporters
      : (typeof parsed.reportCount === 'number' ? parsed.reportCount : 0),
    reasons,
    firstSeen: isString(parsed.firstSeen) ? parsed.firstSeen : '',
    lastSeen: isString(parsed.lastSeen) ? parsed.lastSeen : '',
    scriptHash: isString(parsed.scriptHash) ? parsed.scriptHash : '',
    scriptHashes: Array.isArray(parsed.scriptHashes)
      ? parsed.scriptHashes.filter(isString)
      : (isString(parsed.scriptHash) ? [parsed.scriptHash] : []),
    platforms,
  }
}
