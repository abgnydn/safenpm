import type { VercelRequest, VercelResponse } from '@vercel/node'
import { getRedis, STATS_KEY, RECENT_KEY, CATEGORIES_KEY, FLAGGED_KEY } from '../_lib/redis'

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  res.setHeader('Cache-Control', 's-maxage=30, stale-while-revalidate=60')
  if (req.method === 'OPTIONS') return res.status(200).end()
  if (req.method !== 'GET') return res.status(405).json({ error: 'method not allowed' })

  const redis = getRedis()
  if (!redis) {
    return res.status(200).json({
      totalSignals: 0,
      totalPackages: 0,
      categories: [],
      recent: [],
      topFlagged: [],
      live: false,
    })
  }

  try {
    const [stats, recent, categories, allFlagged] = await Promise.all([
      redis.hgetall(STATS_KEY),
      redis.lrange(RECENT_KEY, 0, 19),
      redis.zrange(CATEGORIES_KEY, 0, -1, { withScores: true, rev: true }),
      redis.hgetall(FLAGGED_KEY),
    ])

    // Build top flagged packages
    const flaggedEntries: { name: string; reportCount: number; topReason: string }[] = []
    if (allFlagged) {
      for (const [key, raw] of Object.entries(allFlagged)) {
        const entry = typeof raw === 'string' ? JSON.parse(raw) : raw as any
        const topReason = Object.entries(entry.reasons as Record<string, number>)
          .sort((a, b) => (b[1] as number) - (a[1] as number))[0]
        flaggedEntries.push({
          name: key,
          reportCount: entry.reportCount,
          topReason: topReason ? topReason[0] : 'unknown',
        })
      }
    }
    flaggedEntries.sort((a, b) => b.reportCount - a.reportCount)

    // Parse categories from sorted set
    const categoryList: { reason: string; count: number }[] = []
    if (Array.isArray(categories)) {
      for (let i = 0; i < categories.length; i += 2) {
        categoryList.push({
          reason: categories[i] as string,
          count: categories[i + 1] as number,
        })
      }
    }

    // Parse recent signals
    const recentList = (recent || []).map((r: any) => {
      if (typeof r === 'string') {
        try { return JSON.parse(r) } catch { return r }
      }
      return r
    })

    return res.status(200).json({
      totalSignals: Number((stats as any)?.totalSignals || 0),
      totalPackages: Number((stats as any)?.totalPackages || 0),
      categories: categoryList.slice(0, 10),
      recent: recentList,
      topFlagged: flaggedEntries.slice(0, 10),
      live: true,
    })
  } catch (err) {
    console.error('stats error:', err)
    return res.status(200).json({
      totalSignals: 0,
      totalPackages: 0,
      categories: [],
      recent: [],
      topFlagged: [],
      live: false,
    })
  }
}
