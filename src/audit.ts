import fs from 'fs'
import path from 'path'
import os from 'os'
import { SandboxResult } from './types'
import { AnalysisResult } from './analyzer'

const AUDIT_DIR = path.join(os.homedir(), '.safenpm')
const AUDIT_FILE = path.join(AUDIT_DIR, 'audit.log')
const MAX_LOG_SIZE = 5 * 1024 * 1024 // 5MB — rotate after this

export interface AuditEntry {
  timestamp: string
  cwd: string
  backend: string
  packages: AuditPackageEntry[]
  summary: {
    total: number
    blocked: number
    allowed: number
    clean: number
  }
}

interface AuditPackageEntry {
  name: string
  version: string
  hook: string
  result: string      // 'clean' | 'blocked' | 'allowed'
  reason: string
  durationMs: number
  riskScore?: number
  warnings?: string[]
}

export function writeAuditLog(
  results: SandboxResult[],
  analyses: AnalysisResult[],
  backend: string,
): void {
  try {
    ensureDir()
    rotateIfNeeded()

    const analysisMap = new Map(analyses.map(a => [a.pkg.name, a]))

    const packages: AuditPackageEntry[] = results.map(r => {
      const analysis = analysisMap.get(r.pkg.name)
      return {
        name: r.pkg.name,
        version: r.pkg.version,
        hook: r.pkg.hook,
        result: r.blocked ? 'blocked' : r.skipped ? 'allowed' : 'clean',
        reason: r.reason,
        durationMs: r.durationMs,
        riskScore: analysis?.riskScore,
        warnings: analysis?.warnings.map(w => w.rule),
      }
    })

    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      cwd: process.cwd(),
      backend,
      packages,
      summary: {
        total: results.length,
        blocked: results.filter(r => r.blocked).length,
        allowed: results.filter(r => r.skipped).length,
        clean: results.filter(r => !r.blocked && !r.skipped).length,
      },
    }

    const line = JSON.stringify(entry) + '\n'
    fs.appendFileSync(AUDIT_FILE, line, 'utf8')
  } catch {
    // audit logging is best-effort — never fail the install
  }
}

function ensureDir(): void {
  if (!fs.existsSync(AUDIT_DIR)) {
    fs.mkdirSync(AUDIT_DIR, { recursive: true })
  }
}

function rotateIfNeeded(): void {
  try {
    if (!fs.existsSync(AUDIT_FILE)) return
    const stat = fs.statSync(AUDIT_FILE)
    if (stat.size > MAX_LOG_SIZE) {
      const rotated = AUDIT_FILE + '.1'
      // keep one rotation — overwrite previous
      if (fs.existsSync(rotated)) fs.unlinkSync(rotated)
      fs.renameSync(AUDIT_FILE, rotated)
    }
  } catch {
    // ignore rotation errors
  }
}

export function readAuditLog(limit: number = 20): AuditEntry[] {
  try {
    if (!fs.existsSync(AUDIT_FILE)) return []
    const content = fs.readFileSync(AUDIT_FILE, 'utf8')
    const lines = content.trim().split('\n').filter(Boolean)
    const entries = lines.map(l => {
      try { return JSON.parse(l) as AuditEntry }
      catch { return null }
    }).filter((e): e is AuditEntry => e !== null)
    return entries.slice(-limit)
  } catch {
    return []
  }
}
