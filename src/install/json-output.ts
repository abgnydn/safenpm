/**
 * Assembles the `--json` payload from raw findings + sandbox results.
 *
 * The shape is frozen — CI scripts in the wild parse this — so any
 * change here is a breaking change. New optional fields go through
 * `JsonPackageResult`'s optional properties; never reshape existing
 * keys without bumping the JSON `version`.
 */
import type {
  JsonLockfileResult,
  JsonNpmAuditResult,
  JsonOutput,
  JsonPackageResult,
  JsonReputationSummary,
  JsonTyposquatResult,
  SandboxResult,
} from '../types'
import type { AnalysisResult } from '../analysis/analyzer'
import type { DiffResult } from '../analysis/diffing'
import type { LockfileAuditResult } from '../analysis/lockfile'
import type { NpmAuditResult } from '../analysis/npm-audit'
import type { ReputationSummary } from '../analysis/reputation'
import type { TyposquatResult } from '../analysis/typosquat'
import type { MaintainerInfo } from '../network/maintainer'
import type { ThreatIntelResult } from '../network/threatintel'

export interface JsonOutputInput {
  version: string
  backend: string
  results: SandboxResult[]
  analyses: AnalysisResult[]
  typosquats: TyposquatResult[]
  lockfile: LockfileAuditResult | null
  reputation: ReputationSummary | null
  npmAudit: NpmAuditResult | null
  diffs: DiffResult[]
  threatIntel: ThreatIntelResult[]
  maintainers: MaintainerInfo[]
}

export function buildJsonOutput(input: JsonOutputInput): JsonOutput {
  const analysisMap = new Map(input.analyses.map((a) => [a.pkg.name, a]))
  const threatMap = new Map(input.threatIntel.map((r) => [r.name, r]))
  const maintMap = new Map(input.maintainers.map((m) => [m.name, m]))
  const diffMap = new Map(input.diffs.map((d) => [d.name, d]))

  const packages: JsonPackageResult[] = input.results.map((r) => {
    const analysis = analysisMap.get(r.pkg.name)
    const threat = threatMap.get(r.pkg.name)
    const maint = maintMap.get(r.pkg.name)
    const diff = diffMap.get(r.pkg.name)

    const base: JsonPackageResult = {
      name: r.pkg.name,
      version: r.pkg.version,
      hook: r.pkg.hook,
      script: r.pkg.script,
      result: r.blocked ? 'blocked' : r.skipped ? 'allowed' : 'clean',
      reason: r.reason,
      durationMs: r.durationMs,
      riskScore: analysis?.riskScore ?? 0,
      warnings: (analysis?.warnings ?? []).map((w) => ({
        rule: w.rule,
        severity: w.severity,
        description: w.description,
      })),
    }

    if (threat) base.threatIntel = { flagged: threat.flagged, reportCount: threat.reportCount, topReasons: threat.topReasons }
    if (maint) base.maintainerChanged = maint.maintainerChanged
    if (diff) base.behaviorDiff = { newWarnings: diff.newWarnings, riskDelta: diff.riskDelta }

    return base
  })

  const output: JsonOutput = {
    version: input.version,
    backend: input.backend,
    timestamp: new Date().toISOString(),
    packages,
    typosquats: input.typosquats.map(toJsonTyposquat),
    lockfileAudit: input.lockfile ? toJsonLockfile(input.lockfile) : null,
    reputationSummary: input.reputation ? toJsonReputation(input.reputation) : null,
    summary: {
      total: input.results.length,
      blocked: input.results.filter((r) => r.blocked).length,
      allowed: input.results.filter((r) => r.skipped).length,
      clean: input.results.filter((r) => !r.blocked && !r.skipped).length,
      warnings: input.analyses.reduce((sum, a) => sum + a.warnings.length, 0),
      typosquats: input.typosquats.length,
      maintainerChanges: input.maintainers.filter((m) => m.maintainerChanged).length,
      lockfileIssues: input.lockfile?.issues.length ?? 0,
      reputationScore: input.reputation?.overallScore ?? 100,
    },
  }

  if (input.npmAudit?.ran) {
    output.npmAudit = toJsonNpmAudit(input.npmAudit)
  }

  return output
}

function toJsonNpmAudit(r: NpmAuditResult): JsonNpmAuditResult {
  return {
    ran: r.ran,
    total: r.total,
    totals: r.totals,
    vulnerabilities: r.vulnerabilities.map((v) => ({
      name: v.name,
      severity: v.severity,
      range: v.range,
      fixAvailable: v.fixAvailable,
      via: v.via,
    })),
  }
}

function toJsonTyposquat(t: TyposquatResult): JsonTyposquatResult {
  return { suspect: t.suspect, target: t.target, distance: t.distance, technique: t.technique, confidence: t.confidence }
}

function toJsonLockfile(l: LockfileAuditResult): JsonLockfileResult {
  return {
    exists: l.exists,
    format: l.format,
    totalPackages: l.totalPackages,
    score: l.score,
    issues: l.issues.map((i) => ({ severity: i.severity, type: i.type, package: i.package, detail: i.detail })),
  }
}

function toJsonReputation(r: ReputationSummary): JsonReputationSummary {
  return {
    overallScore: r.overallScore,
    totalPackages: r.totalPackages,
    averageScore: r.averageScore,
    tiers: r.tiers,
    riskiest: r.riskiest.map((p) => ({ name: p.name, version: p.version, score: p.score, tier: p.tier })),
  }
}
