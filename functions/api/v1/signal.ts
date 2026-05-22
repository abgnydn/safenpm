/**
 * POST /api/v1/signal
 *
 * Receives a malicious-package report from the safenpm CLI. Validates the
 * payload, rate-limits per machineId, dedupes identical (machineId, pkg)
 * reports in a 24h window, and updates the aggregate entry in KV.
 *
 * Sybil-resistance: `distinctReporters` is backed by a KV-modelled
 * "set" of machineIds (a JSON `string[]` keyed by pkg@ver). On each
 * report we check membership before incrementing, so the counter
 * genuinely reflects distinct identities — not just non-deduped
 * reports. The validator's machineId entropy floor
 * (`MIN_MACHINE_ID_LEN`) raises the cost of generating additional
 * Sybil identities, but does not eliminate it; pair this with the
 * conservative flag threshold in intel.ts.
 *
 * Reports under the literal id `'anonymous'` never increment the
 * counter — the server treats anonymous reporters as a single shared
 * identity to prevent trivial inflation from machines that opted out
 * of identifier persistence.
 */
import {
  getStorage,
  FLAGGED_PREFIX,
  STATS_PREFIX,
  RECENT_KEY,
  CATEGORIES_KEY,
  RATE_LIMIT_PREFIX,
  DEDUP_PREFIX,
  REPORTERS_PREFIX,
  json,
  preflight,
  type Env,
} from '../../_lib/storage'
import { parseSignal, parseFlaggedEntry } from '../../_lib/validate'
import type { FlaggedEntry } from '../../_lib/types'

const RATE_LIMIT_WINDOW = 3600 // 1 hour
const RATE_LIMIT_MAX = 20 // signals per machineId per hour
const DEDUP_TTL = 86400 // 24 hours
const REPORTERS_TTL = 90 * 86400 // 90 days

export const onRequestOptions = preflight

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  let body: unknown
  try {
    body = await request.json()
  } catch {
    return json({ error: 'invalid JSON' }, { status: 400 })
  }

  const signal = parseSignal(body)
  if (!signal) return json({ error: 'invalid signal' }, { status: 400 })

  const storage = getStorage(env)
  if (!storage) {
    // Graceful degradation: accept the report but don't persist it.
    // The CLI treats this as success so it doesn't spam the user.
    return json({ accepted: true, stored: false }, { status: 202 })
  }

  try {
    // Rate limit per machineId.
    const rateLimitKey = `${RATE_LIMIT_PREFIX}:${signal.machineId}`
    const currentCount = Number(await storage.getString(rateLimitKey)) || 0
    if (currentCount >= RATE_LIMIT_MAX) {
      return json(
        { error: 'rate limit exceeded', retryAfter: RATE_LIMIT_WINDOW },
        { status: 429 }
      )
    }

    // Dedupe: same machine, same package@version in 24h.
    const dedupKey = `${DEDUP_PREFIX}:${signal.machineId}:${signal.package}@${signal.version}`
    const alreadyReported = await storage.getString(dedupKey)
    if (alreadyReported) {
      return json({ accepted: true, stored: false, reason: 'duplicate' })
    }

    // Track distinct reporters as a set. Anonymous reports never join
    // the set, so they cannot inflate distinctReporters at all.
    const field = `${signal.package}@${signal.version}`
    const reportersKey = `${REPORTERS_PREFIX}:${field}`
    let isNewReporter = false
    if (signal.machineId !== 'anonymous') {
      isNewReporter = await storage.setAdd(reportersKey, signal.machineId, { ttlSec: REPORTERS_TTL })
    }

    const existing = parseFlaggedEntry(await storage.hashGet(FLAGGED_PREFIX, field))
    const entry: FlaggedEntry = existing
      ? mergeSignal(existing, signal, isNewReporter)
      : freshEntry(signal, isNewReporter)

    await Promise.all([
      storage.hashSet(FLAGGED_PREFIX, field, JSON.stringify(entry)),
      storage.hashIncrBy(STATS_PREFIX, 'totalSignals', 1),
      storage.listPush(RECENT_KEY, JSON.stringify({
        package: signal.package,
        version: signal.version,
        reason: signal.reason,
        platform: signal.platform,
        timestamp: signal.timestamp,
      })),
      storage.listTrim(RECENT_KEY, 0, 99),
      storage.sortedIncrBy(CATEGORIES_KEY, 1, signal.reason),
      storage.incrWithTtl(rateLimitKey, RATE_LIMIT_WINDOW),
      storage.setString(dedupKey, '1', { ttlSec: DEDUP_TTL }),
    ])

    const allFlagged = await storage.hashLen(FLAGGED_PREFIX)
    await storage.hashSet(STATS_PREFIX, 'totalPackages', String(allFlagged))

    return json({ accepted: true, stored: true })
  } catch (err) {
    console.error('signal store error:', err)
    return json({ accepted: true, stored: false }, { status: 202 })
  }
}

function freshEntry(
  signal: ReturnType<typeof parseSignal> & {},
  isNewReporter: boolean,
): FlaggedEntry {
  return {
    reportCount: 1,
    distinctReporters: isNewReporter ? 1 : 0,
    reasons: { [signal.reason]: 1 },
    firstSeen: signal.timestamp,
    lastSeen: signal.timestamp,
    scriptHash: signal.scriptHash,
    scriptHashes: [signal.scriptHash],
    platforms: { [signal.platform]: 1 },
  }
}

function mergeSignal(
  existing: FlaggedEntry,
  signal: ReturnType<typeof parseSignal> & {},
  isNewReporter: boolean,
): FlaggedEntry {
  const reasons = { ...existing.reasons }
  reasons[signal.reason] = (reasons[signal.reason] ?? 0) + 1

  const platforms = { ...existing.platforms }
  platforms[signal.platform] = (platforms[signal.platform] ?? 0) + 1

  const scriptHashes = existing.scriptHashes.includes(signal.scriptHash)
    ? existing.scriptHashes
    : [...existing.scriptHashes, signal.scriptHash]

  return {
    reportCount: existing.reportCount + 1,
    distinctReporters: existing.distinctReporters + (isNewReporter ? 1 : 0),
    reasons,
    firstSeen: existing.firstSeen,
    lastSeen: signal.timestamp,
    scriptHash: existing.scriptHash,
    scriptHashes,
    platforms,
  }
}
