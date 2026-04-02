/**
 * Community threat intelligence — query the safenpm network
 * to check if any packages have been flagged by other users.
 * Also report back when we block packages to help others.
 */

import https from 'https'
import fs from 'fs'
import path from 'path'
import os from 'os'

const INTEL_HOST = 'safenpm.vercel.app'
const INTEL_PATH = '/api/v1/intel'
const CACHE_DIR = path.join(os.homedir(), '.safenpm', 'intel-cache')
const CACHE_TTL = 3600_000 // 1 hour

export interface ThreatIntelResult {
  name: string
  version: string
  flagged: boolean
  reportCount: number
  firstSeen: string | null
  lastSeen: string | null
  topReasons: string[]
  /** Whether this result came from a successful API response (vs cache or fallback) */
  dataFresh: boolean
}

/**
 * Check packages against the community threat intel database.
 * Uses a local cache to avoid hammering the API on every install.
 * Falls back gracefully if the network is unavailable.
 */
export async function checkThreatIntel(
  packages: { name: string; version: string }[]
): Promise<ThreatIntelResult[]> {
  if (packages.length === 0) return []

  // Check local cache first
  const results: ThreatIntelResult[] = []
  const uncached: { name: string; version: string }[] = []

  for (const pkg of packages) {
    const cached = readCache(pkg.name, pkg.version)
    if (cached) {
      results.push(cached)
    } else {
      uncached.push(pkg)
    }
  }

  // Fetch uncached from the network
  if (uncached.length > 0) {
    const fetched = await fetchIntel(uncached)
    for (const r of fetched) {
      writeCache(r)
      results.push(r)
    }
  }

  return results
}

/**
 * Fetch threat intel from the safenpm API.
 * POST /api/v1/intel with a list of package names.
 */
async function fetchIntel(
  packages: { name: string; version: string }[]
): Promise<ThreatIntelResult[]> {
  return new Promise((resolve) => {
    const body = JSON.stringify({
      packages: packages.map(p => ({ name: p.name, version: p.version })),
    })

    const req = https.request(
      {
        hostname: INTEL_HOST,
        path: INTEL_PATH,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'User-Agent': 'safenpm/0.4.0',
        },
        timeout: 5000,
      },
      (res) => {
        let data = ''
        res.on('data', (chunk: Buffer) => { data += chunk.toString() })
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data)
            if (Array.isArray(parsed.results)) {
              resolve(parsed.results as ThreatIntelResult[])
              return
            }
          } catch {
            logIntelWarning('threat intel API returned unparseable response')
          }
          // Fallback: return empty results for all packages
          resolve(packages.map(p => unflagged(p.name, p.version, false)))
        })
      }
    )

    req.on('error', (err) => {
      // Network unavailable — return unflagged for all, but mark as stale
      logIntelWarning(`threat intel API unreachable: ${err.message}`)
      resolve(packages.map(p => unflagged(p.name, p.version, false)))
    })
    req.on('timeout', () => {
      req.destroy()
      logIntelWarning('threat intel API timed out')
      resolve(packages.map(p => unflagged(p.name, p.version, false)))
    })

    req.write(body)
    req.end()
  })
}

function unflagged(name: string, version: string, dataFresh: boolean = true): ThreatIntelResult {
  return {
    name,
    version,
    flagged: false,
    reportCount: 0,
    firstSeen: null,
    lastSeen: null,
    topReasons: [],
    dataFresh,
  }
}

/**
 * Log a warning about threat intel degradation.
 * Writes to stderr so it doesn't pollute JSON output, and
 * appends to the audit log so users can see when checks failed.
 */
function logIntelWarning(message: string): void {
  const logDir = path.join(os.homedir(), '.safenpm')
  const logFile = path.join(logDir, 'intel-warnings.log')
  const entry = `${new Date().toISOString()} ${message}\n`
  try {
    if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true })
    fs.appendFileSync(logFile, entry, 'utf8')
  } catch { /* best effort */ }
  process.stderr.write(`  [safenpm] warning: ${message}\n`)
}

// ── Local cache ──

function cacheKey(name: string, version: string): string {
  return `${name}@${version}`.replace(/[^a-zA-Z0-9@._-]/g, '_')
}

function readCache(name: string, version: string): ThreatIntelResult | null {
  try {
    const file = path.join(CACHE_DIR, cacheKey(name, version) + '.json')
    if (!fs.existsSync(file)) return null
    const stat = fs.statSync(file)
    if (Date.now() - stat.mtimeMs > CACHE_TTL) return null
    return JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

function writeCache(result: ThreatIntelResult): void {
  try {
    if (!fs.existsSync(CACHE_DIR)) {
      fs.mkdirSync(CACHE_DIR, { recursive: true })
    }
    const file = path.join(CACHE_DIR, cacheKey(result.name, result.version) + '.json')
    fs.writeFileSync(file, JSON.stringify(result), 'utf8')
  } catch {
    // cache write is best-effort
  }
}

/**
 * Simulate threat intel for testing/offline mode.
 * In production this would be replaced by the real API.
 */
export function mockThreatIntel(
  packages: { name: string; version: string }[]
): ThreatIntelResult[] {
  return packages.map(p => unflagged(p.name, p.version))
}
