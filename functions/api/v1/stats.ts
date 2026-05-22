/**
 * GET /api/v1/stats
 *
 * Aggregate dashboard payload — polled every ~30s by the safenpm.dev
 * homepage. Returns total counters, top-10 flagged packages, top
 * reason categories, and the last 20 signals for the live feed.
 *
 * KV-backed. Cached at the edge for 30s; `live: false` indicates
 * either "KV not bound" or "no signals yet — empty data".
 */
import {
  getStorage,
  STATS_PREFIX,
  RECENT_KEY,
  CATEGORIES_KEY,
  FLAGGED_PREFIX,
  json,
  preflight,
  type Env,
} from '../../_lib/storage'
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

function summarizeFlagged(allFlagged: Record<string, string>): FlaggedSummary[] {
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

function decodeRecent(raw: string[]): unknown[] {
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
  const storage = getStorage(env)
  if (!storage) {
    return json(emptyPayload(false), {
      headers: { 'Cache-Control': 's-maxage=30, stale-while-revalidate=60' },
    })
  }

  try {
    const [stats, recent, categories, allFlagged] = await Promise.all([
      storage.hashGetAll(STATS_PREFIX),
      storage.listRange(RECENT_KEY, 0, RECENT_LIMIT - 1),
      storage.sortedRange(CATEGORIES_KEY, { rev: true }),
      storage.hashGetAll(FLAGGED_PREFIX),
    ])

    const flaggedEntries = summarizeFlagged(allFlagged)
    const categoryList: CategoryCount[] = categories.map(([reason, count]) => ({ reason, count }))
    const recentList = decodeRecent(recent)

    const totalSignals = Number(stats['totalSignals'] ?? 0)
    const totalPackages = Number(stats['totalPackages'] ?? 0)

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
