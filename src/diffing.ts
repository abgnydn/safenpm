/**
 * Behavioral diffing — compares install scripts between the previously
 * installed version and the new version. Detects when a package suddenly
 * adds network calls, eval, or credential access that wasn't there before.
 */

import fs from 'fs'
import path from 'path'
import os from 'os'
import { PackageScript } from './types'
import { analyzeScript, AnalysisResult } from './analyzer'

const CACHE_DIR = path.join(os.homedir(), '.safenpm', 'script-cache')

export interface DiffResult {
  name: string
  previousVersion: string | null
  currentVersion: string
  previousScript: string | null
  currentScript: string
  scriptChanged: boolean
  newWarnings: string[]        // warning rules that are NEW (not in previous version)
  riskDelta: number            // how much the risk score increased
  isNewPackage: boolean
}

/**
 * Build a cache key that incorporates both the project directory
 * and the lockfile content, so switching branches invalidates the cache.
 */
function buildCacheKey(): string {
  const cwd = process.cwd()
  const cwdHash = simpleHash(cwd)

  // Include lockfile hash if available so branch switches invalidate cache
  const lockfilePath = path.join(cwd, 'package-lock.json')
  let lockfileHash = 'none'
  try {
    if (fs.existsSync(lockfilePath)) {
      const content = fs.readFileSync(lockfilePath, 'utf8')
      lockfileHash = simpleHash(content).slice(0, 8)
    }
  } catch { /* use 'none' */ }

  return `${cwdHash}-${lockfileHash}`
}

/**
 * Cache the current install scripts for future diffing.
 * Called after a successful install so the next install can compare.
 */
export function cacheScripts(scripts: PackageScript[]): void {
  try {
    if (!fs.existsSync(CACHE_DIR)) {
      fs.mkdirSync(CACHE_DIR, { recursive: true })
    }

    const cacheKey = buildCacheKey()
    const cacheFile = path.join(CACHE_DIR, `${cacheKey}.json`)

    const cache: Record<string, CachedScript> = {}
    for (const s of scripts) {
      cache[s.name] = {
        version: s.version,
        script: s.script,
        hook: s.hook,
      }
    }

    fs.writeFileSync(cacheFile, JSON.stringify(cache, null, 2), 'utf8')
  } catch {
    // caching is best-effort
  }
}

interface CachedScript {
  version: string
  script: string
  hook: string
}

/**
 * Load previously cached scripts for this project.
 * Tries current lockfile-aware key first, falls back to legacy cwd-only key.
 */
function loadCache(): Record<string, CachedScript> {
  try {
    // Try lockfile-aware cache key first
    const cacheKey = buildCacheKey()
    const cacheFile = path.join(CACHE_DIR, `${cacheKey}.json`)
    if (fs.existsSync(cacheFile)) {
      return JSON.parse(fs.readFileSync(cacheFile, 'utf8'))
    }

    // Fallback: legacy cache key (cwd-only) for backward compatibility
    const legacyKey = simpleHash(process.cwd())
    const legacyFile = path.join(CACHE_DIR, `${legacyKey}.json`)
    if (fs.existsSync(legacyFile)) {
      return JSON.parse(fs.readFileSync(legacyFile, 'utf8'))
    }

    return {}
  } catch {
    return {}
  }
}

/**
 * Compare current scripts against the cached previous versions.
 */
export function diffScripts(currentScripts: PackageScript[]): DiffResult[] {
  const previous = loadCache()
  const results: DiffResult[] = []

  for (const current of currentScripts) {
    const prev = previous[current.name]

    if (!prev) {
      // Brand new package with install scripts — note it
      const analysis = analyzeScript(current)
      results.push({
        name: current.name,
        previousVersion: null,
        currentVersion: current.version,
        previousScript: null,
        currentScript: current.script,
        scriptChanged: true,
        newWarnings: analysis.warnings.map(w => w.rule),
        riskDelta: analysis.riskScore,
        isNewPackage: true,
      })
      continue
    }

    // Same version, same script — no change
    if (prev.version === current.version && prev.script === current.script) {
      results.push({
        name: current.name,
        previousVersion: prev.version,
        currentVersion: current.version,
        previousScript: prev.script,
        currentScript: current.script,
        scriptChanged: false,
        newWarnings: [],
        riskDelta: 0,
        isNewPackage: false,
      })
      continue
    }

    // Script changed — diff the analysis
    const prevAnalysis = analyzeScript({
      ...current,
      version: prev.version,
      script: prev.script,
    })
    const currAnalysis = analyzeScript(current)

    const prevRules = new Set(prevAnalysis.warnings.map(w => w.rule))
    const newWarnings = currAnalysis.warnings
      .filter(w => !prevRules.has(w.rule))
      .map(w => w.rule)

    results.push({
      name: current.name,
      previousVersion: prev.version,
      currentVersion: current.version,
      previousScript: prev.script,
      currentScript: current.script,
      scriptChanged: true,
      newWarnings,
      riskDelta: currAnalysis.riskScore - prevAnalysis.riskScore,
      isNewPackage: false,
    })
  }

  return results
}

/**
 * Filter to only meaningful diffs (script changed or new warnings)
 */
export function significantDiffs(diffs: DiffResult[]): DiffResult[] {
  return diffs.filter(d => d.scriptChanged && (d.newWarnings.length > 0 || d.riskDelta > 0))
}

function simpleHash(str: string): string {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash |= 0
  }
  return Math.abs(hash).toString(36)
}
