/**
 * GET /api/v1/stats
 *
 * Aggregate dashboard payload — polled every ~30s by the safenpm.dev
 * homepage. Returns total counters, top-10 flagged packages, top reason
 * categories, and the last 20 signals for the live feed.
 *
 * Port of api/v1/stats.ts.
 */
import {
  getRedis,
  STATS_KEY,
  RECENT_KEY,
  CATEGORIES_KEY,
  FLAGGED_KEY,
  json,
  preflight,
  type Env,
} from '../../_lib/redis'
import { parseFlaggedEntry } from '../../_lib/validate'

const TOP_N_FLAGGED = 10
const TOP_N_CATEGORIES = 10
const RECENT_LIMIT = 20

interface FlaggedSummary {
  name: string
  reportCount: number
  topReason: string
}

interface CategoryCount {
  reason: string
  count: number
}

function emptyPayload(live: boolean) {
  return {
    totalSignals: 0,
    totalPackages: 0,
    categories: [] as CategoryCount[],
    recent: [] as unknown[],
    topFlagged: [] as FlaggedSummary[],
    live,
  }
}

function summarizeFlagged(allFlagged: Record<string, unknown>): FlaggedSummary[] {
  const out: FlaggedSummary[] = []
  for (const [key, raw] of Object.entries(allFlagged)) {
    const entry = parseFlaggedEntry(raw)
    if (!entry) continue
    const topReason = Object.entries(entry.reasons)
      .sort((a, b) => b[1] - a[1])[0]
    out.push({
      name: key,
      reportCount: entry.reportCount,
      topReason: topReason ? topReason[0] : 'unknown',
    })
  }
  out.sort((a, b) => b.reportCount - a.reportCount)
  return out
}

function decodeCategories(raw: unknown): CategoryCount[] {
  if (!Array.isArray(raw)) return []
  const out: CategoryCount[] = []
  for (let i = 0; i < raw.length; i += 2) {
    const reason = raw[i]
    const count = raw[i + 1]
    if (typeof reason !== 'string' || typeof count !== 'number') continue
    out.push({ reason, count })
  }
  return out
}

function decodeRecent(raw: unknown): unknown[] {
  if (!Array.isArray(raw)) return []
  return raw.map((r) => {
    if (typeof r !== 'string') return r
    try {
      return JSON.parse(r)
    } catch {
      return r
    }
  })
}

export const onRequestOptions = preflight

export const onRequestGet: PagesFunction<Env> = async ({ env }) => {
  const redis = getRedis(env)
  if (!redis) {
    return json(emptyPayload(false), {
      headers: { 'Cache-Control': 's-maxage=30, stale-while-revalidate=60' },
    })
  }

  try {
    const [stats, recent, categories, allFlagged] = await Promise.all([
      redis.hgetall(STATS_KEY),
      redis.lrange(RECENT_KEY, 0, RECENT_LIMIT - 1),
      redis.zrange(CATEGORIES_KEY, 0, -1, { withScores: true, rev: true }),
      redis.hgetall(FLAGGED_KEY),
    ])

    const flaggedEntries = allFlagged && typeof allFlagged === 'object'
      ? summarizeFlagged(allFlagged as Record<string, unknown>)
      : []
    const categoryList = decodeCategories(categories)
    const recentList = decodeRecent(recent)

    const statsObj = (stats && typeof stats === 'object') ? (stats as Record<string, unknown>) : {}
    const totalSignals = Number(statsObj['totalSignals'] ?? 0)
    const totalPackages = Number(statsObj['totalPackages'] ?? 0)

    return json(
      {
        totalSignals,
        totalPackages,
        categories: categoryList.slice(0, TOP_N_CATEGORIES),
        recent: recentList,
        topFlagged: flaggedEntries.slice(0, TOP_N_FLAGGED),
        live: true,
      },
      { headers: { 'Cache-Control': 's-maxage=30, stale-while-revalidate=60' } }
    )
  } catch (err) {
    console.error('stats error:', err)
    return json(emptyPayload(false))
  }
}
