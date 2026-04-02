import { Redis } from '@upstash/redis'

let redis: Redis | null = null

export function getRedis(): Redis | null {
  if (redis) return redis
  // Support all Upstash/Vercel naming conventions
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL || process.env.STORAGE_KV_REST_API_URL
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN || process.env.STORAGE_KV_REST_API_TOKEN
  if (!url || !token) return null
  redis = new Redis({ url, token })
  return redis
}

// Keys
export const SIGNALS_KEY = 'safenpm:signals'        // sorted set: package@version -> signal JSON
export const STATS_KEY = 'safenpm:stats'             // hash: totalSignals, totalPackages, etc.
export const FLAGGED_KEY = 'safenpm:flagged'         // hash: package@version -> { reportCount, reasons, firstSeen, lastSeen }
export const RECENT_KEY = 'safenpm:recent'           // list: last 100 signals (for dashboard feed)
export const CATEGORIES_KEY = 'safenpm:categories'   // sorted set: reason -> count
