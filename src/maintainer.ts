/**
 * Maintainer change detection — queries the npm registry to check
 * if the publisher of a package version is different from the
 * previous version. A sudden maintainer swap can signal account
 * takeover or malicious publish.
 */

import https from 'https'
import fs from 'fs'
import path from 'path'
import os from 'os'

const CACHE_DIR = path.join(os.homedir(), '.safenpm', 'maintainer-cache')
const CACHE_TTL = 86400_000 // 24 hours

export interface MaintainerInfo {
  name: string
  version: string
  currentPublisher: string | null
  previousPublisher: string | null
  maintainerChanged: boolean
  isNewPackage: boolean
  publisherHistory: string[]    // last N distinct publishers
  accountAge: string | null     // when the npm user was created
}

/**
 * Check maintainer changes for a set of packages.
 * Queries the npm registry for version metadata.
 */
export async function checkMaintainerChanges(
  packages: { name: string; version: string }[]
): Promise<MaintainerInfo[]> {
  const results: MaintainerInfo[] = []

  for (const pkg of packages) {
    const cached = readCache(pkg.name)
    if (cached && cached.version === pkg.version) {
      results.push(cached)
      continue
    }

    const info = await fetchMaintainerInfo(pkg.name, pkg.version)
    writeCache(info)
    results.push(info)
  }

  return results
}

/**
 * Fetch version metadata from npm registry and extract publisher info.
 * GET https://registry.npmjs.org/{name} — abbreviated metadata
 */
async function fetchMaintainerInfo(
  name: string,
  version: string
): Promise<MaintainerInfo> {
  return new Promise((resolve) => {
    const encodedName = name.replace('/', '%2f')
    const req = https.get(
      `https://registry.npmjs.org/${encodedName}`,
      {
        headers: {
          Accept: 'application/json',
          'User-Agent': 'safenpm/0.4.0',
        },
        timeout: 8000,
      },
      (res) => {
        let data = ''
        res.on('data', (chunk: Buffer) => { data += chunk.toString() })
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data)
            resolve(extractMaintainerInfo(name, version, parsed))
          } catch {
            resolve(unknownInfo(name, version))
          }
        })
      }
    )

    req.on('error', (err) => {
      process.stderr.write(`  [safenpm] warning: maintainer check failed for ${name}: ${err.message}\n`)
      resolve(unknownInfo(name, version))
    })
    req.on('timeout', () => {
      req.destroy()
      process.stderr.write(`  [safenpm] warning: maintainer check timed out for ${name}\n`)
      resolve(unknownInfo(name, version))
    })
  })
}

/**
 * Extract publisher info from the npm registry response.
 * The `time` field gives us version publish dates.
 * The `versions[v]._npmUser` field gives us who published each version.
 */
function extractMaintainerInfo(
  name: string,
  version: string,
  registryData: any
): MaintainerInfo {
  const versions = registryData.versions || {}
  const time = registryData.time || {}

  // Get all version strings sorted by publish time
  const sortedVersions = Object.keys(time)
    .filter(v => v !== 'created' && v !== 'modified' && versions[v])
    .sort((a, b) => {
      const ta = new Date(time[a]).getTime()
      const tb = new Date(time[b]).getTime()
      return ta - tb
    })

  // Extract publisher (_npmUser.name) for each version
  const publishers: { version: string; publisher: string }[] = []
  for (const v of sortedVersions) {
    const npmUser = versions[v]?._npmUser
    if (npmUser?.name) {
      publishers.push({ version: v, publisher: npmUser.name })
    }
  }

  const currentIdx = publishers.findIndex(p => p.version === version)
  const currentPublisher = currentIdx >= 0 ? publishers[currentIdx].publisher : null
  const previousPublisher = currentIdx > 0 ? publishers[currentIdx - 1].publisher : null

  // Distinct publisher history (last 10)
  const distinctPublishers = [...new Set(publishers.map(p => p.publisher))].slice(-10)

  const maintainerChanged = !!(
    currentPublisher &&
    previousPublisher &&
    currentPublisher !== previousPublisher
  )

  return {
    name,
    version,
    currentPublisher,
    previousPublisher,
    maintainerChanged,
    isNewPackage: publishers.length <= 1,
    publisherHistory: distinctPublishers,
    accountAge: null, // Would need separate API call
  }
}

function unknownInfo(name: string, version: string): MaintainerInfo {
  return {
    name,
    version,
    currentPublisher: null,
    previousPublisher: null,
    maintainerChanged: false,
    isNewPackage: false,
    publisherHistory: [],
    accountAge: null,
  }
}

// ── Local cache ──

function readCache(name: string): MaintainerInfo | null {
  try {
    const file = path.join(CACHE_DIR, safeName(name) + '.json')
    if (!fs.existsSync(file)) return null
    const stat = fs.statSync(file)
    if (Date.now() - stat.mtimeMs > CACHE_TTL) return null
    return JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

function writeCache(info: MaintainerInfo): void {
  try {
    if (!fs.existsSync(CACHE_DIR)) {
      fs.mkdirSync(CACHE_DIR, { recursive: true })
    }
    const file = path.join(CACHE_DIR, safeName(info.name) + '.json')
    fs.writeFileSync(file, JSON.stringify(info), 'utf8')
  } catch {
    // best effort
  }
}

function safeName(name: string): string {
  return name.replace(/[^a-zA-Z0-9@._-]/g, '_')
}

/**
 * Filter to only packages with maintainer changes.
 */
export function flaggedMaintainerChanges(results: MaintainerInfo[]): MaintainerInfo[] {
  return results.filter(r => r.maintainerChanged)
}

/**
 * Mock maintainer info for offline/testing.
 */
export function mockMaintainerInfo(
  packages: { name: string; version: string }[]
): MaintainerInfo[] {
  return packages.map(p => unknownInfo(p.name, p.version))
}
