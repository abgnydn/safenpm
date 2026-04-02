import type { VercelRequest, VercelResponse } from '@vercel/node'
import { getRedis, FLAGGED_KEY, STATS_KEY, RECENT_KEY, CATEGORIES_KEY } from '../_lib/redis'

interface Signal {
  machineId: string
  package: string
  version: string
  hook: string
  script: string
  scriptHash: string
  scriptLength: number
  reason: string
  timestamp: string
  platform: string
}

function validateSignal(body: unknown): Signal | null {
  if (!body || typeof body !== 'object') return null
  const s = body as Record<string, unknown>
  if (typeof s.package !== 'string' || !s.package) return null
  if (typeof s.version !== 'string' || !s.version) return null
  if (typeof s.reason !== 'string' || !s.reason) return null
  if (typeof s.scriptHash !== 'string' || !s.scriptHash) return null
  return {
    machineId: typeof s.machineId === 'string' ? s.machineId : 'anonymous',
    package: s.package,
    version: s.version,
    hook: typeof s.hook === 'string' ? s.hook : 'unknown',
    script: typeof s.script === 'string' ? s.script.slice(0, 500) : '',
    scriptHash: s.scriptHash,
    scriptLength: typeof s.scriptLength === 'number' ? s.scriptLength : 0,
    reason: s.reason,
    timestamp: typeof s.timestamp === 'string' ? s.timestamp : new Date().toISOString(),
    platform: typeof s.platform === 'string' ? s.platform : 'unknown',
  }
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') return res.status(200).end()
  if (req.method !== 'POST') return res.status(405).json({ error: 'method not allowed' })

  const signal = validateSignal(req.body)
  if (!signal) return res.status(400).json({ error: 'invalid signal' })

  const redis = getRedis()
  if (!redis) {
    // No Redis configured — accept signal silently
    return res.status(202).json({ accepted: true, stored: false })
  }

  const key = `${signal.package}@${signal.version}`

  try {
    // Update flagged package entry
    const existing = await redis.hget<string>(FLAGGED_KEY, key)
    let entry: {
      reportCount: number
      reasons: Record<string, number>
      firstSeen: string
      lastSeen: string
      scriptHash: string
      platforms: Record<string, number>
    }

    if (existing) {
      entry = typeof existing === 'string' ? JSON.parse(existing) : existing as any
      entry.reportCount += 1
      entry.lastSeen = signal.timestamp
      entry.reasons[signal.reason] = (entry.reasons[signal.reason] || 0) + 1
      entry.platforms[signal.platform] = (entry.platforms[signal.platform] || 0) + 1
    } else {
      entry = {
        reportCount: 1,
        reasons: { [signal.reason]: 1 },
        firstSeen: signal.timestamp,
        lastSeen: signal.timestamp,
        scriptHash: signal.scriptHash,
        platforms: { [signal.platform]: 1 },
      }
    }

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
    ])

    // Update unique package count
    const allFlagged = await redis.hlen(FLAGGED_KEY)
    await redis.hset(STATS_KEY, { totalPackages: allFlagged })

    return res.status(200).json({ accepted: true, stored: true })
  } catch (err) {
    console.error('signal store error:', err)
    return res.status(202).json({ accepted: true, stored: false })
  }
}
