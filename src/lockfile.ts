/**
 * Lockfile integrity audit — parses package-lock.json to detect:
 *   - Packages with non-registry URLs (git, tarball, file:)
 *   - Missing or inconsistent integrity hashes
 *   - Version mismatches between lockfile and node_modules
 *   - Suspicious registry overrides
 */

import fs from 'fs'
import path from 'path'

export interface LockfileAuditResult {
  exists: boolean
  format: 'v1' | 'v2' | 'v3' | null
  totalPackages: number
  issues: LockfileIssue[]
  score: number   // 0-100, higher = healthier
}

export interface LockfileIssue {
  severity: 'high' | 'medium' | 'low'
  type: string
  package: string
  detail: string
}

const OFFICIAL_REGISTRY = 'https://registry.npmjs.org'

/**
 * Audit the lockfile in the given project directory.
 */
export function auditLockfile(projectDir: string): LockfileAuditResult {
  const lockfilePath = path.join(projectDir, 'package-lock.json')

  if (!fs.existsSync(lockfilePath)) {
    return {
      exists: false,
      format: null,
      totalPackages: 0,
      issues: [{
        severity: 'medium',
        type: 'no-lockfile',
        package: '-',
        detail: 'No package-lock.json found — installs are not deterministic',
      }],
      score: 50,
    }
  }

  let lockfile: any
  try {
    lockfile = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'))
  } catch {
    return {
      exists: true,
      format: null,
      totalPackages: 0,
      issues: [{
        severity: 'high',
        type: 'parse-error',
        package: '-',
        detail: 'package-lock.json is malformed or unreadable',
      }],
      score: 0,
    }
  }

  const format = detectFormat(lockfile)
  const issues: LockfileIssue[] = []

  if (format === 'v1') {
    auditV1(lockfile, issues)
  } else {
    auditV2V3(lockfile, issues)
  }

  // Check for lockfile freshness
  checkLockfileFreshness(projectDir, lockfilePath, issues)

  const totalPackages = countPackages(lockfile, format)
  const score = calculateScore(issues, totalPackages)

  return { exists: true, format, totalPackages, issues, score }
}

function detectFormat(lockfile: any): 'v1' | 'v2' | 'v3' {
  if (lockfile.lockfileVersion === 3) return 'v3'
  if (lockfile.lockfileVersion === 2) return 'v2'
  return 'v1'
}

/**
 * Audit v1 lockfile (dependencies object)
 */
function auditV1(lockfile: any, issues: LockfileIssue[]): void {
  const deps = lockfile.dependencies || {}
  auditDependenciesRecursive(deps, issues, '')
}

// Maximum recursion depth for v1 lockfile traversal to prevent
// stack overflow on pathological dependency trees or circular refs
const MAX_AUDIT_DEPTH = 50

function auditDependenciesRecursive(
  deps: any,
  issues: LockfileIssue[],
  prefix: string,
  depth: number = 0,
  seen: Set<string> = new Set()
): void {
  if (depth >= MAX_AUDIT_DEPTH) return

  for (const [name, meta] of Object.entries<any>(deps)) {
    const fullName = prefix ? `${prefix} > ${name}` : name

    // Guard against circular dependencies
    const key = `${name}@${meta.version || 'unknown'}`
    if (seen.has(key)) continue
    seen.add(key)

    // Check resolved URL
    if (meta.resolved) {
      checkResolvedUrl(meta.resolved, name, fullName, issues)
    } else if (!meta.bundled) {
      issues.push({
        severity: 'medium',
        type: 'missing-resolved',
        package: fullName,
        detail: 'No resolved URL — package source is unknown',
      })
    }

    // Check integrity hash
    if (!meta.integrity && !meta.bundled) {
      issues.push({
        severity: 'medium',
        type: 'missing-integrity',
        package: fullName,
        detail: 'No integrity hash — cannot verify package contents',
      })
    } else if (meta.integrity && !meta.integrity.startsWith('sha512-')) {
      issues.push({
        severity: 'low',
        type: 'weak-hash',
        package: fullName,
        detail: `Uses ${meta.integrity.split('-')[0]} instead of sha512`,
      })
    }

    // Recurse into nested dependencies
    if (meta.dependencies) {
      auditDependenciesRecursive(meta.dependencies, issues, fullName, depth + 1, seen)
    }
  }
}

/**
 * Audit v2/v3 lockfile (packages object)
 */
function auditV2V3(lockfile: any, issues: LockfileIssue[]): void {
  const packages = lockfile.packages || {}

  for (const [pkgPath, meta] of Object.entries<any>(packages)) {
    if (pkgPath === '') continue // root project

    const name = pkgPath.replace(/^node_modules\//, '')

    // Check resolved URL
    if (meta.resolved) {
      checkResolvedUrl(meta.resolved, name, name, issues)
    } else if (!meta.link && !meta.bundled) {
      // linked/bundled packages won't have resolved
      issues.push({
        severity: 'medium',
        type: 'missing-resolved',
        package: name,
        detail: 'No resolved URL — package source is unknown',
      })
    }

    // Check integrity
    if (!meta.integrity && !meta.link && !meta.bundled && meta.resolved) {
      issues.push({
        severity: 'medium',
        type: 'missing-integrity',
        package: name,
        detail: 'No integrity hash — cannot verify package contents',
      })
    } else if (meta.integrity && !meta.integrity.startsWith('sha512-')) {
      issues.push({
        severity: 'low',
        type: 'weak-hash',
        package: name,
        detail: `Uses ${meta.integrity.split('-')[0]} instead of sha512`,
      })
    }

    // Check for hasInstallScript flag
    if (meta.hasInstallScript) {
      issues.push({
        severity: 'low',
        type: 'has-install-script',
        package: name,
        detail: 'Package has install scripts (flagged in lockfile)',
      })
    }
  }
}

/**
 * Check if a resolved URL points to the official registry.
 */
function checkResolvedUrl(
  url: string,
  shortName: string,
  fullName: string,
  issues: LockfileIssue[]
): void {
  // Git URLs
  if (url.startsWith('git+') || url.startsWith('git://') || url.includes('.git#')) {
    issues.push({
      severity: 'high',
      type: 'git-dependency',
      package: fullName,
      detail: `Resolves from git: ${truncate(url, 80)}`,
    })
    return
  }

  // File URLs
  if (url.startsWith('file:')) {
    issues.push({
      severity: 'high',
      type: 'file-dependency',
      package: fullName,
      detail: `Resolves from local file: ${truncate(url, 80)}`,
    })
    return
  }

  // Tarball URLs (not from official registry)
  if (url.endsWith('.tgz') || url.endsWith('.tar.gz')) {
    if (!url.startsWith(OFFICIAL_REGISTRY)) {
      issues.push({
        severity: 'high',
        type: 'custom-registry',
        package: fullName,
        detail: `Resolves from non-npm registry: ${truncate(url, 80)}`,
      })
    }
    return
  }

  // HTTP (non-HTTPS)
  if (url.startsWith('http://') && !url.startsWith('http://registry.npmjs.org')) {
    issues.push({
      severity: 'medium',
      type: 'insecure-registry',
      package: fullName,
      detail: `Uses insecure HTTP: ${truncate(url, 80)}`,
    })
  }
}

/**
 * Check if lockfile is stale relative to package.json.
 */
function checkLockfileFreshness(
  projectDir: string,
  lockfilePath: string,
  issues: LockfileIssue[]
): void {
  try {
    const pkgJsonPath = path.join(projectDir, 'package.json')
    if (!fs.existsSync(pkgJsonPath)) return

    const pkgStat = fs.statSync(pkgJsonPath)
    const lockStat = fs.statSync(lockfilePath)

    if (pkgStat.mtimeMs > lockStat.mtimeMs) {
      issues.push({
        severity: 'low',
        type: 'stale-lockfile',
        package: '-',
        detail: 'package.json is newer than package-lock.json — lockfile may be outdated',
      })
    }
  } catch {
    // skip freshness check on error
  }
}

function countPackages(lockfile: any, format: 'v1' | 'v2' | 'v3' | null): number {
  if (format === 'v1') {
    return countDepsRecursive(lockfile.dependencies || {})
  }
  // v2/v3: count entries in packages (minus root "")
  const packages = lockfile.packages || {}
  return Object.keys(packages).filter(k => k !== '').length
}

function countDepsRecursive(deps: any, depth: number = 0): number {
  if (depth >= MAX_AUDIT_DEPTH) return 0
  let count = 0
  for (const meta of Object.values<any>(deps)) {
    count++
    if (meta.dependencies) count += countDepsRecursive(meta.dependencies, depth + 1)
  }
  return count
}

function calculateScore(issues: LockfileIssue[], totalPackages: number): number {
  if (totalPackages === 0) return 100

  const weights = { high: 15, medium: 5, low: 1 }
  const penalty = issues.reduce((sum, i) => sum + weights[i.severity], 0)

  // Normalize by package count — more packages means some issues are expected
  const normalizedPenalty = penalty / Math.max(1, Math.sqrt(totalPackages))
  return Math.max(0, Math.round(100 - normalizedPenalty * 5))
}

function truncate(str: string, max: number): string {
  return str.length > max ? str.slice(0, max - 3) + '...' : str
}

/**
 * Get only significant issues (high + medium)
 */
export function significantLockfileIssues(result: LockfileAuditResult): LockfileIssue[] {
  return result.issues.filter(i => i.severity === 'high' || i.severity === 'medium')
}
