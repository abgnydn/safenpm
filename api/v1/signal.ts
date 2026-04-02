import type { VercelRequest, VercelResponse } from '@vercel/node'
import { getRedis, FLAGGED_KEY, STATS_KEY, RECENT_KEY, CATEGORIES_KEY } from '../_lib/redis'

const RATE_LIMIT_KEY = 'safenpm:ratelimit'     // hash: machineId -> signal count this window
const RATE_LIMIT_WINDOW = 3600                  // 1 hour in seconds
const RATE_LIMIT_MAX = 20                       // max signals per machine per hour
const DEDUP_KEY = 'safenpm:dedup'               // set: machineId:package@version (prevents same machine reporting same pkg twice)
const DEDUP_TTL = 86400                         // 24 hours

// Packages with very high download counts that require elevated thresholds
// These are unlikely to have malicious install scripts
const PROTECTED_PACKAGES = new Set([
  'express', 'react', 'lodash', 'axios', 'typescript', 'webpack',
  'next', 'vue', 'angular', 'jquery', 'moment', 'chalk', 'commander',
  'debug', 'uuid', 'dotenv', 'cors', 'body-parser', 'mongoose',
  'pg', 'redis', 'socket.io', 'passport', 'jsonwebtoken', 'bcrypt',
  'nodemon', 'eslint', 'prettier', 'jest', 'mocha', 'chai',
  'rxjs', 'ramda', 'underscore', 'bluebird', 'async', 'glob',
  'minimist', 'yargs', 'inquirer', 'ora', 'fs-extra', 'rimraf',
  'mkdirp', 'semver', 'dayjs', 'date-fns', 'luxon',
])

// Flag threshold: how many distinct machines must report before a package is considered "flagged"
const FLAG_THRESHOLD_DEFAULT = 3
const FLAG_THRESHOLD_PROTECTED = 15

// Valid reasons — reject signals with unknown reasons
const VALID_REASONS = new Set([
  'network access', 'credential exfiltration', 'reverse shell',
  'eval/obfuscation', 'ssh key theft', 'env var harvesting',
  'dns exfiltration', 'filesystem access', 'process spawn',
  'crypto mining', 'data exfiltration', 'suspicious behavior',
])

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

  // Validate package name format (npm naming rules)
  const pkg = s.package as string
  if (pkg.length > 214) return null
  if (!/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(pkg)) return null

  // Validate version format (loose semver)
  const ver = s.version as string
  if (ver.length > 50) return null

  // Validate reason
  const reason = s.reason as string
  if (!VALID_REASONS.has(reason)) return null

  // Validate scriptHash (must look like a hash, not garbage)
  const hash = s.scriptHash as string
  if (hash.length < 16 || hash.length > 128) return null
  if (!/^[a-f0-9]+$/.test(hash)) return null

  // machineId must be a UUID-like string
  const machineId = typeof s.machineId === 'string' ? s.machineId : 'anonymous'
  if (machineId.length > 64) return null

  return {
    machineId,
    package: pkg,
    version: ver,
    hook: typeof s.hook === 'string' ? s.hook : 'unknown',
    script: typeof s.script === 'string' ? (s.script as string).slice(0, 500) : '',
    scriptHash: hash,
    scriptLength: typeof s.scriptLength === 'number' ? s.scriptLength : 0,
    reason,
    timestamp: typeof s.timestamp === 'string' ? s.timestamp : new Date().toISOString(),
    platform: typeof s.platform === 'string' ? s.platform : 'unknown',
  }
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') return res.status(200).end()
  if (req.method !== 'POST') return res.status(405).json({ error: 'method not allowed' })

  const signal = validateSignal(req.body)
  if (!signal) return res.status(400).json({ error: 'invalid signal' })

  const redis = getRedis()
  if (!redis) {
    return res.status(202).json({ accepted: true, stored: false })
  }

  try {
    // ── Rate limiting: max N signals per machineId per hour ──
    const rateLimitKey = `${RATE_LIMIT_KEY}:${signal.machineId}`
    const currentCount = await redis.get<number>(rateLimitKey)
    if (currentCount !== null && currentCount >= RATE_LIMIT_MAX) {
      return res.status(429).json({ error: 'rate limit exceeded', retryAfter: RATE_LIMIT_WINDOW })
    }

    // ── Deduplication: same machine can't report same package twice in 24h ──
    const dedupKey = `${DEDUP_KEY}:${signal.machineId}:${signal.package}@${signal.version}`
    const alreadyReported = await redis.get(dedupKey)
    if (alreadyReported) {
      // Accept silently but don't store — prevents inflation
      return res.status(200).json({ accepted: true, stored: false, reason: 'duplicate' })
    }

    const key = `${signal.package}@${signal.version}`

    // Update flagged package entry — track distinct reporters
    const existing = await redis.hget<string>(FLAGGED_KEY, key)
    let entry: {
      reportCount: number
      distinctReporters: number
      reasons: Record<string, number>
      firstSeen: string
      lastSeen: string
      scriptHash: string
      scriptHashes: string[]
      platforms: Record<string, number>
    }

    if (existing) {
      entry = typeof existing === 'string' ? JSON.parse(existing) : existing as any
      entry.reportCount += 1
      entry.distinctReporters = (entry.distinctReporters || 0) + 1
      entry.lastSeen = signal.timestamp
      entry.reasons[signal.reason] = (entry.reasons[signal.reason] || 0) + 1
      entry.platforms[signal.platform] = (entry.platforms[signal.platform] || 0) + 1
      // Track multiple script hashes to detect inconsistent reports
      if (!entry.scriptHashes) entry.scriptHashes = [entry.scriptHash]
      if (!entry.scriptHashes.includes(signal.scriptHash)) {
        entry.scriptHashes.push(signal.scriptHash)
      }
    } else {
      entry = {
        reportCount: 1,
        distinctReporters: 1,
        reasons: { [signal.reason]: 1 },
        firstSeen: signal.timestamp,
        lastSeen: signal.timestamp,
        scriptHash: signal.scriptHash,
        scriptHashes: [signal.scriptHash],
        platforms: { [signal.platform]: 1 },
      }
    }

    await Promise.all([
      // Store the signal
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
      // Set rate limit (increment + TTL)
      redis.incr(rateLimitKey),
      redis.expire(rateLimitKey, RATE_LIMIT_WINDOW),
      // Set dedup marker
      redis.set(dedupKey, '1', { ex: DEDUP_TTL }),
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
