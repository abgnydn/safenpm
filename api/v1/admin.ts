import type { VercelRequest, VercelResponse } from '@vercel/node'
import { getRedis, FLAGGED_KEY, STATS_KEY, RECENT_KEY, CATEGORIES_KEY } from '../_lib/redis'

const DEDUP_PREFIX = 'safenpm:dedup'
const RATELIMIT_PREFIX = 'safenpm:ratelimit'

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  if (req.method !== 'POST') return res.status(405).json({ error: 'method not allowed' })

  // Require admin secret
  const secret = process.env.ADMIN_SECRET
  if (!secret) return res.status(500).json({ error: 'admin not configured' })

  const auth = req.headers.authorization
  if (auth !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'unauthorized' })
  }

  const redis = getRedis()
  if (!redis) return res.status(500).json({ error: 'redis not configured' })

  const action = req.body?.action
  if (action === 'flush') {
    // Flush all threat intel data
    await Promise.all([
      redis.del(FLAGGED_KEY),
      redis.del(STATS_KEY),
      redis.del(RECENT_KEY),
      redis.del(CATEGORIES_KEY),
    ])
    return res.status(200).json({ flushed: true })
  }

  if (action === 'remove' && typeof req.body?.package === 'string') {
    // Remove a specific package
    const pkg = req.body.package
    await redis.hdel(FLAGGED_KEY, pkg)
    const count = await redis.hlen(FLAGGED_KEY)
    await redis.hset(STATS_KEY, { totalPackages: count })
    return res.status(200).json({ removed: pkg })
  }

  return res.status(400).json({ error: 'unknown action', valid: ['flush', 'remove'] })
}
