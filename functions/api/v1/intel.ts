/**
 * POST /api/v1/intel
 *
 * Batch reputation lookup. Called by the safenpm CLI during `npm install`
 * with up to 500 (package, version) pairs per request. Returns whether
 * each package has crossed the report threshold.
 *
 * Port of api/v1/intel.ts from Vercel Node to Cloudflare Pages Functions.
 * Thresholds and scoring logic unchanged.
 */
import { getRedis, FLAGGED_KEY, json, preflight, type Env } from '../../_lib/redis'
import { parseIntelQuery, parseFlaggedEntry } from '../../_lib/validate'
import type { IntelResult } from '../../_lib/types'

const PROTECTED_PACKAGES: ReadonlySet<string> = new Set([
  'express', 'react', 'lodash', 'axios', 'typescript', 'webpack',
  'next', 'vue', 'angular', 'jquery', 'moment', 'chalk', 'commander',
  'debug', 'uuid', 'dotenv', 'cors', 'body-parser', 'mongoose',
  'pg', 'redis', 'socket.io', 'passport', 'jsonwebtoken', 'bcrypt',
  'nodemon', 'eslint', 'prettier', 'jest', 'mocha', 'chai',
  'rxjs', 'ramda', 'underscore', 'bluebird', 'async', 'glob',
  'minimist', 'yargs', 'inquirer', 'ora', 'fs-extra', 'rimraf',
  'mkdirp', 'semver', 'dayjs', 'date-fns', 'luxon',
])
// Flag thresholds are deliberately conservative because the
// reputation network has limited Sybil-resistance — distinctReporters
// only counts machineIds that pass the entropy floor in validate.ts,
// but an attacker can still generate that many identifiers cheaply.
// Raise these as adoption grows and the false-positive cost of a low
// threshold drops.
const FLAG_THRESHOLD_DEFAULT = 5
const FLAG_THRESHOLD_PROTECTED = 15
const MAX_LEGIT_SCRIPT_HASHES = 3
const MAX_TOP_REASONS = 5

function emptyResults(
  packages: ReadonlyArray<{ name: string; version: string }>,
  dataFresh: boolean,
): IntelResult[] {
  return packages.map((p) => ({
    name: p.name,
    version: p.version,
    flagged: false,
    reportCount: 0,
    firstSeen: null,
    lastSeen: null,
    topReasons: [],
    dataFresh,
  }))
}

export const onRequestOptions = preflight

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  let body: unknown
  try {
    body = await request.json()
  } catch {
    return json({ error: 'invalid JSON' }, { status: 400 })
  }

  const query = parseIntelQuery(body)
  if (!query) return json({ error: 'invalid query' }, { status: 400 })

  const redis = getRedis(env)
  if (!redis) {
    return json({ results: emptyResults(query.packages, false) })
  }

  try {
    const results: IntelResult[] = []

    for (const pkg of query.packages) {
      const key = `${pkg.name}@${pkg.version}`
      const entry = parseFlaggedEntry(await redis.hget<string>(FLAGGED_KEY, key))

      if (!entry) {
        results.push({
          name: pkg.name, version: pkg.version,
          flagged: false, reportCount: 0,
          firstSeen: null, lastSeen: null,
          topReasons: [], dataFresh: true,
        })
        continue
      }

      const topReasons = Object.entries(entry.reasons)
        .sort((a, b) => b[1] - a[1])
        .slice(0, MAX_TOP_REASONS)
        .map(([reason]) => reason)

      const threshold = PROTECTED_PACKAGES.has(pkg.name)
        ? FLAG_THRESHOLD_PROTECTED
        : FLAG_THRESHOLD_DEFAULT
      const isFlagged = entry.distinctReporters >= threshold

      // Inconsistent script hashes = likely spam. Cap at MAX_LEGIT_SCRIPT_HASHES legit updates.
      const hashesConsistent = entry.scriptHashes.length <= MAX_LEGIT_SCRIPT_HASHES
      const flagged = isFlagged && hashesConsistent

      results.push({
        name: pkg.name,
        version: pkg.version,
        flagged,
        reportCount: entry.reportCount,
        firstSeen: entry.firstSeen || null,
        lastSeen: entry.lastSeen || null,
        topReasons,
        dataFresh: true,
      })
    }

    return json({ results })
  } catch (err) {
    console.error('intel query error:', err)
    return json({ results: emptyResults(query.packages, false) })
  }
}
