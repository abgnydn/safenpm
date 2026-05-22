/**
 * `npm audit` integration — invokes `npm audit --json` against the
 * current project and parses the result into a structured shape the
 * Reporter can render and the JSON output can include.
 *
 * This module exists because the offline `reputation.ts` heuristic was
 * documented as decorative — package.json metadata alone is not a real
 * vulnerability signal. The npm registry's audit endpoint surfaces
 * actual CVE advisories tied to your installed versions; running it
 * here turns the `--scan` flow from "heuristic" into "heuristic + real
 * CVE data".
 *
 * Failure modes that produce an empty result (never throw):
 *   - `npm` not installed
 *   - no network connectivity to the registry
 *   - project has no `package.json` / `package-lock.json`
 *   - npm exits non-zero with parseable JSON (npm uses exit code 1 to
 *     signal "vulnerabilities found", so we read its JSON anyway)
 *   - malformed JSON output
 */
import { spawnSync } from 'child_process'

export type AuditSeverity = 'info' | 'low' | 'moderate' | 'high' | 'critical'

export interface AuditVulnerability {
  name: string
  severity: AuditSeverity
  via: string[]            // names of advisories or upstream vulnerable deps
  range: string            // affected version range, e.g. "<4.17.21"
  fixAvailable: boolean
}

export interface NpmAuditResult {
  ran: boolean             // true if npm audit produced parseable output
  totals: Record<AuditSeverity, number>
  total: number
  vulnerabilities: AuditVulnerability[]
}

const AUDIT_TIMEOUT_MS = 30_000

const EMPTY_RESULT: NpmAuditResult = {
  ran: false,
  totals: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 },
  total: 0,
  vulnerabilities: [],
}

export function runNpmAudit(projectDir: string): NpmAuditResult {
  const r = spawnSync('npm', ['audit', '--json', '--audit-level=info'], {
    cwd: projectDir,
    encoding: 'utf8',
    timeout: AUDIT_TIMEOUT_MS,
    // npm audit emits the JSON report on stdout and uses non-zero
    // exit codes to indicate vulnerabilities were found; we still
    // want the JSON either way.
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  const stdout = r.stdout ?? ''
  if (!stdout.trim()) return EMPTY_RESULT

  let parsed: unknown
  try {
    parsed = JSON.parse(stdout)
  } catch {
    return EMPTY_RESULT
  }

  return shapeAuditReport(parsed)
}

/**
 * Translate npm's wire JSON into our shape. npm has two distinct audit
 * formats (v1 and v2). We handle both by feature-detecting the keys.
 */
export function shapeAuditReport(raw: unknown): NpmAuditResult {
  if (!raw || typeof raw !== 'object') return EMPTY_RESULT
  const root = raw as Record<string, unknown>

  // v2 (auditReportVersion: 2): { vulnerabilities: { name: { severity, via, range, fixAvailable } }, metadata: { vulnerabilities: { critical, high, moderate, low, info, total } } }
  if (root['auditReportVersion'] === 2 || typeof root['vulnerabilities'] === 'object') {
    const vMap = (root['vulnerabilities'] && typeof root['vulnerabilities'] === 'object')
      ? root['vulnerabilities'] as Record<string, unknown>
      : {}
    const vulnerabilities: AuditVulnerability[] = []
    for (const [name, raw] of Object.entries(vMap)) {
      if (!raw || typeof raw !== 'object') continue
      const v = raw as Record<string, unknown>
      const severity = normalizeSeverity(v['severity'])
      if (!severity) continue
      vulnerabilities.push({
        name,
        severity,
        via: extractVia(v['via']),
        range: typeof v['range'] === 'string' ? v['range'] : '',
        fixAvailable: !!v['fixAvailable'],
      })
    }

    const meta = (root['metadata'] && typeof root['metadata'] === 'object')
      ? (root['metadata'] as Record<string, unknown>)['vulnerabilities']
      : null
    const totals = totalsFromMeta(meta) ?? totalsFromList(vulnerabilities)

    return {
      ran: true,
      totals,
      total: totals.info + totals.low + totals.moderate + totals.high + totals.critical,
      vulnerabilities: sortBySeverity(vulnerabilities),
    }
  }

  return EMPTY_RESULT
}

function extractVia(via: unknown): string[] {
  if (!Array.isArray(via)) return []
  const names: string[] = []
  for (const v of via) {
    if (typeof v === 'string') names.push(v)
    else if (v && typeof v === 'object') {
      const name = (v as Record<string, unknown>)['name']
      if (typeof name === 'string') names.push(name)
    }
  }
  return names
}

function normalizeSeverity(s: unknown): AuditSeverity | null {
  if (typeof s !== 'string') return null
  if (s === 'info' || s === 'low' || s === 'moderate' || s === 'high' || s === 'critical') return s
  return null
}

function totalsFromMeta(meta: unknown): Record<AuditSeverity, number> | null {
  if (!meta || typeof meta !== 'object') return null
  const m = meta as Record<string, unknown>
  const out: Record<AuditSeverity, number> = {
    info: numOr0(m['info']),
    low: numOr0(m['low']),
    moderate: numOr0(m['moderate']),
    high: numOr0(m['high']),
    critical: numOr0(m['critical']),
  }
  return out
}

function totalsFromList(list: AuditVulnerability[]): Record<AuditSeverity, number> {
  const out: Record<AuditSeverity, number> = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 }
  for (const v of list) out[v.severity]++
  return out
}

function numOr0(x: unknown): number {
  return typeof x === 'number' && Number.isFinite(x) ? x : 0
}

const SEVERITY_ORDER: Record<AuditSeverity, number> = {
  critical: 0, high: 1, moderate: 2, low: 3, info: 4,
}

function sortBySeverity(list: AuditVulnerability[]): AuditVulnerability[] {
  return [...list].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
}
