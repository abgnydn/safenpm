import type { VercelRequest, VercelResponse } from '@vercel/node'
import { getRedis, FLAGGED_KEY } from '../_lib/redis'

// Must match signal.ts thresholds
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
const FLAG_THRESHOLD_DEFAULT = 3
const FLAG_THRESHOLD_PROTECTED = 15

interface IntelQuery {
  packages: { name: string; version: string }[]
}

interface IntelResult {
  name: string
  version: string
  flagged: boolean
  reportCount: number
  firstSeen: string | null
  lastSeen: string | null
  topReasons: string[]
  dataFresh: boolean
}

function validateQuery(body: unknown): IntelQuery | null {
  if (!body || typeof body !== 'object') return null
  const q = body as Record<string, unknown>
  if (!Array.isArray(q.packages)) return null
  if (q.packages.length > 500) return null
  for (const pkg of q.packages) {
    if (!pkg || typeof pkg !== 'object') return null
    if (typeof (pkg as any).name !== 'string') return null
    if (typeof (pkg as any).version !== 'string') return null
  }
  return q as unknown as IntelQuery
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') return res.status(200).end()
  if (req.method !== 'POST') return res.status(405).json({ error: 'method not allowed' })

  const query = validateQuery(req.body)
  if (!query) return res.status(400).json({ error: 'invalid query' })

  const redis = getRedis()
  if (!redis) {
    // No Redis — return unflagged for all
    return res.status(200).json({
      results: query.packages.map(p => ({
        name: p.name,
        version: p.version,
        flagged: false,
        reportCount: 0,
        firstSeen: null,
        lastSeen: null,
        topReasons: [],
        dataFresh: false,
      })),
    })
  }

  try {
    const results: IntelResult[] = []

    for (const pkg of query.packages) {
      const key = `${pkg.name}@${pkg.version}`
      const raw = await redis.hget<string>(FLAGGED_KEY, key)

      if (raw) {
        const entry = typeof raw === 'string' ? JSON.parse(raw) : raw as any
        const reasons = entry.reasons as Record<string, number>
        const topReasons = Object.entries(reasons)
          .sort((a, b) => (b[1] as number) - (a[1] as number))
          .slice(0, 5)
          .map(([reason]) => reason)

        // Determine if this package meets the flagging threshold
        const distinctReporters = entry.distinctReporters || entry.reportCount
        const threshold = PROTECTED_PACKAGES.has(pkg.name) ? FLAG_THRESHOLD_PROTECTED : FLAG_THRESHOLD_DEFAULT
        const isFlagged = distinctReporters >= threshold

        // Check for inconsistent reports (many different script hashes = likely spam)
        const hashCount = entry.scriptHashes ? entry.scriptHashes.length : 1
        const hashesConsistent = hashCount <= 3 // legitimate updates might change the hash a few times
        const flagged = isFlagged && hashesConsistent

        results.push({
          name: pkg.name,
          version: pkg.version,
          flagged,
          reportCount: entry.reportCount,
          firstSeen: entry.firstSeen,
          lastSeen: entry.lastSeen,
          topReasons,
          dataFresh: true,
        })
      } else {
        results.push({
          name: pkg.name,
          version: pkg.version,
          flagged: false,
          reportCount: 0,
          firstSeen: null,
          lastSeen: null,
          topReasons: [],
          dataFresh: true,
        })
      }
    }

    return res.status(200).json({ results })
  } catch (err) {
    console.error('intel query error:', err)
    return res.status(200).json({
      results: query.packages.map(p => ({
        name: p.name,
        version: p.version,
        flagged: false,
        reportCount: 0,
        firstSeen: null,
        lastSeen: null,
        topReasons: [],
        dataFresh: false,
      })),
    })
  }
}
