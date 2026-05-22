/**
 * POST /api/v1/signal
 *
 * Receives a malicious-package report from the safenpm CLI. Validates the
 * payload, rate-limits per machineId, dedupes identical (machineId, pkg)
 * reports in a 24h window, and updates the aggregate entry in Upstash.
 *
 * Sybil-resistance: `distinctReporters` is backed by a Redis SET of the
 * machineIds that have ever reported this package@version. SADD returns
 * 1 only for new members, so the counter genuinely reflects distinct
 * identities — not just non-deduped reports. The validator's machineId
 * entropy floor (`MIN_MACHINE_ID_LEN`) raises the cost of generating
 * additional Sybil identities, but does not eliminate it; pair this with
 * the conservative flag threshold in intel.ts.
 *
 * Reports under the literal id `'anonymous'` never increment the
 * counter — the server treats anonymous reporters as a single shared
 * identity to prevent trivial inflation from machines that opted out
 * of identifier persistence.
 */
import {
  getRedis,
  FLAGGED_KEY,
  STATS_KEY,
  RECENT_KEY,
  CATEGORIES_KEY,
  json,
  preflight,
  type Env,
} from '../../_lib/redis'
import { parseSignal, parseFlaggedEntry } from '../../_lib/validate'
import type { FlaggedEntry } from '../../_lib/types'

const RATE_LIMIT_KEY = 'safenpm:ratelimit'
const RATE_LIMIT_WINDOW = 3600 // 1 hour
const RATE_LIMIT_MAX = 20 // signals per machineId per hour
const DEDUP_KEY = 'safenpm:dedup'
const DEDUP_TTL = 86400 // 24 hours
const REPORTERS_KEY = 'safenpm:reporters' // SET of distinct machineIds per pkg@ver
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

  const redis = getRedis(env)
  if (!redis) {
    // Graceful degradation: accept the report but don't persist it.
    // The CLI treats this as success so it doesn't spam the user.
    return json({ accepted: true, stored: false }, { status: 202 })
  }

  try {
    // Rate limit per machineId.
    const rateLimitKey = `${RATE_LIMIT_KEY}:${signal.machineId}`
    const currentCount = await redis.get<number>(rateLimitKey)
    if (currentCount !== null && currentCount >= RATE_LIMIT_MAX) {
      return json(
        { error: 'rate limit exceeded', retryAfter: RATE_LIMIT_WINDOW },
        { status: 429 }
      )
    }

    // Dedupe: same machine, same package@version in 24h.
    const dedupKey = `${DEDUP_KEY}:${signal.machineId}:${signal.package}@${signal.version}`
    const alreadyReported = await redis.get(dedupKey)
    if (alreadyReported) {
      return json({ accepted: true, stored: false, reason: 'duplicate' })
    }

    // Track distinct reporters as a SET. Anonymous reports never join
    // the set, so they cannot inflate distinctReporters at all.
    const key = `${signal.package}@${signal.version}`
    const reportersKey = `${REPORTERS_KEY}:${key}`
    let isNewReporter = false
    if (signal.machineId !== 'anonymous') {
      const added = await redis.sadd(reportersKey, signal.machineId)
      isNewReporter = added === 1
      await redis.expire(reportersKey, REPORTERS_TTL)
    }

    const existing = parseFlaggedEntry(await redis.hget<string>(FLAGGED_KEY, key))

    const entry: FlaggedEntry = existing
      ? mergeSignal(existing, signal, isNewReporter)
      : freshEntry(signal, isNewReporter)

    await Promise.all([
      redis.hset(FLAGGED_KEY, { [key]: JSON.stringify(entry) }),
      redis.hincrby(STATS_KEY, 'totalSignals', 1),
      redis.lpush(RECENT_KEY, JSON.stringify({
        package: signal.package,
        version: signal.version,
        reason: signal.reason,
        platform: signal.platform,
        timestamp: signal.timestamp,
      })),
      redis.ltrim(RECENT_KEY, 0, 99),
      redis.zincrby(CATEGORIES_KEY, 1, signal.reason),
      redis.incr(rateLimitKey),
      redis.expire(rateLimitKey, RATE_LIMIT_WINDOW),
      redis.set(dedupKey, '1', { ex: DEDUP_TTL }),
    ])

    const allFlagged = await redis.hlen(FLAGGED_KEY)
    await redis.hset(STATS_KEY, { totalPackages: allFlagged })

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
