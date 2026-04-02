import { spawnSync } from 'child_process'
import path from 'path'
import { logger } from './logger'
import { findInstallScripts } from './scripts'
import { runInSandbox, isSandboxAvailable, backendName } from './sandbox'
import { reportBlocked } from './reporter'
import { loadAllowlist, isAllowed } from './allowlist'
import { analyzeAll, riskLevel, AnalysisResult } from './analyzer'
import { writeAuditLog } from './audit'
import { checkAllTyposquats, TyposquatResult } from './typosquat'
import { diffScripts, significantDiffs, cacheScripts, DiffResult } from './diffing'
import { checkThreatIntel, ThreatIntelResult } from './threatintel'
import { checkMaintainerChanges, flaggedMaintainerChanges, MaintainerInfo } from './maintainer'
import { auditLockfile, significantLockfileIssues, LockfileAuditResult } from './lockfile'
import { scoreReputationFromNodeModules, ReputationSummary } from './reputation'
import {
  SandboxResult, InstallOptions, JsonOutput, JsonPackageResult,
  JsonTyposquatResult, JsonLockfileResult, JsonReputationSummary,
} from './types'
import { getAllPackageNames } from './packages'

export async function install(opts: InstallOptions): Promise<void> {
  const { packages, dryRun, allow, noReport, json, interactive, loose, scan } = opts
  const allowlist = loadAllowlist(allow)

  // ── dry run mode ──
  if (dryRun) {
    return dryRunFlow(packages, allowlist, json, scan)
  }

  if (!json) {
    logger.banner()
    logger.backendInfo(backendName())
    logger.allowlistInfo(allowlist.size)
  }

  // 1 — check sandbox is available
  if (!isSandboxAvailable()) {
    if (!json) {
      logger.warn('no sandbox backend found')
      logger.warn('macOS: sandbox-exec (built-in)')
      logger.warn('Linux: install firejail → sudo apt install firejail')
      logger.warn('falling back to plain npm install (no sandboxing)')
      console.log()
    }
    spawnSync('npm', ['install', ...packages], { stdio: json ? 'pipe' : 'inherit' })
    return
  }

  // 2 — run npm install with scripts disabled
  if (!json) logger.step('installing packages (scripts disabled)...')
  const npmResult = spawnSync(
    'npm',
    ['install', '--ignore-scripts', ...packages],
    { stdio: json ? 'pipe' : 'inherit' }
  )

  if (npmResult.status !== 0) {
    process.exit(npmResult.status ?? 1)
  }

  // 3 — find all packages that have install scripts
  const nodeModulesPath = path.join(process.cwd(), 'node_modules')
  const scripts = findInstallScripts(nodeModulesPath)

  // ── v0.4.0: typosquat detection (runs on ALL installed packages) ──
  let typosquats: TyposquatResult[] = []
  if (scan) {
    const allPkgNames = getAllPackageNames(nodeModulesPath)
    typosquats = checkAllTyposquats(allPkgNames)
    if (!json && typosquats.length > 0) {
      logger.typosquatHeader()
      for (const t of typosquats) {
        logger.typosquatResult(t)
      }
    }
  }

  // ── v0.4.0: lockfile integrity audit ──
  let lockfileResult: LockfileAuditResult | null = null
  if (scan) {
    lockfileResult = auditLockfile(process.cwd())
    if (!json) {
      const significant = significantLockfileIssues(lockfileResult)
      if (significant.length > 0 || !lockfileResult.exists) {
        logger.lockfileHeader()
        logger.lockfileResult(lockfileResult)
      }
    }
  }

  // ── v0.4.0: reputation scoring ──
  let reputationSummary: ReputationSummary | null = null
  if (scan) {
    reputationSummary = scoreReputationFromNodeModules(nodeModulesPath)
    if (!json && reputationSummary.totalPackages > 0) {
      logger.reputationHeader()
      logger.reputationResult(reputationSummary)
    }
  }

  if (scripts.length === 0) {
    if (json) {
      outputJson([], [], backendName(), typosquats, lockfileResult, reputationSummary, [], [], [])
    } else {
      logger.success('no install scripts found — nothing to sandbox')
      logger.summary(0, 0)
    }
    return
  }

  // 4 — static analysis
  const analyses = analyzeAll(scripts)
  const totalWarnings = analyses.reduce((sum, a) => sum + a.warnings.length, 0)

  if (!json && totalWarnings > 0) {
    logger.analysisHeader()
    for (const a of analyses) {
      if (a.warnings.length > 0) {
        logger.analysisResult(a)
      }
    }
    console.log()
  }

  // ── v0.4.0: behavioral diffing ──
  let diffs: DiffResult[] = []
  if (scan) {
    const allDiffs = diffScripts(scripts)
    diffs = significantDiffs(allDiffs)
    if (!json && diffs.length > 0) {
      logger.diffHeader()
      for (const d of diffs) {
        logger.diffResult(d)
      }
    }
  }

  // ── v0.4.0: threat intel ──
  let threatResults: ThreatIntelResult[] = []
  if (scan) {
    threatResults = await checkThreatIntel(
      scripts.map(s => ({ name: s.name, version: s.version }))
    )
    const flagged = threatResults.filter(r => r.flagged)
    if (!json && flagged.length > 0) {
      logger.threatIntelHeader()
      for (const r of flagged) {
        logger.threatIntelResult(r)
      }
    }
  }

  // ── v0.4.0: maintainer change detection ──
  let maintainerResults: MaintainerInfo[] = []
  if (scan) {
    maintainerResults = await checkMaintainerChanges(
      scripts.map(s => ({ name: s.name, version: s.version }))
    )
    const changed = flaggedMaintainerChanges(maintainerResults)
    if (!json && changed.length > 0) {
      logger.maintainerHeader()
      for (const m of changed) {
        logger.maintainerResult(m)
      }
    }
  }

  if (!json) {
    logger.step(`found ${scripts.length} install script${scripts.length !== 1 ? 's' : ''} — running in sandbox...`)
    console.log()
  }

  // 5 — run each script
  const results: SandboxResult[] = []
  let skippedCount = 0
  const strict = !loose

  for (const pkg of scripts) {
    if (isAllowed(pkg.name, allowlist)) {
      if (!json) logger.skipped(pkg.name, pkg.version)
      const start = Date.now()
      const r = spawnSync('sh', ['-c', pkg.script], {
        cwd: pkg.path,
        timeout: 30_000,
        encoding: 'utf8',
        stdio: 'pipe',
      })
      results.push({
        pkg,
        blocked: false,
        skipped: true,
        reason: 'allowed',
        output: [r.stdout, r.stderr].filter(Boolean).join('\n'),
        durationMs: Date.now() - start,
      })
      skippedCount++
      continue
    }

    const result = runInSandbox(pkg, strict)
    results.push(result)

    if (result.blocked) {
      if (!json) logger.blocked(pkg.name, pkg.version, pkg.hook, result.reason)

      // ── interactive mode ──
      if (interactive && !json && process.stdin.isTTY) {
        const choice = logger.interactivePrompt(pkg.name, pkg.version, pkg.hook)
        if (choice === 'r') {
          if (!json) logger.step(`retrying ${pkg.name} without sandbox...`)
          const start = Date.now()
          const retry = spawnSync('sh', ['-c', pkg.script], {
            cwd: pkg.path,
            timeout: 30_000,
            encoding: 'utf8',
            stdio: 'pipe',
          })
          results[results.length - 1] = {
            pkg,
            blocked: false,
            skipped: true,
            reason: 'allowed',
            output: [retry.stdout, retry.stderr].filter(Boolean).join('\n'),
            durationMs: Date.now() - start,
          }
          if (!json) logger.success(`${pkg.name} ran without sandbox`)
        } else if (choice === 'a') {
          if (!json) logger.error('aborted by user')
          process.exit(1)
        }
      }
    } else {
      if (!json) logger.allowed(pkg.name, pkg.version)
    }
  }

  // 6 — cache scripts for future diffing
  if (scan) {
    cacheScripts(scripts)
  }

  // 7 — report blocked signals
  const blockedCount = results.filter(r => r.blocked).length
  if (blockedCount > 0 && !noReport) {
    await reportBlocked(results)
  }

  // 8 — audit log
  writeAuditLog(results, analyses, backendName())
  if (!json) logger.auditInfo()

  // 9 — output
  if (json) {
    outputJson(results, analyses, backendName(), typosquats, lockfileResult, reputationSummary, diffs, threatResults, maintainerResults)
  } else {
    logger.summary(scripts.length, blockedCount, skippedCount, totalWarnings)
  }

  if (blockedCount > 0) {
    process.exit(1)
  }
}

// ── JSON output for CI ──

function outputJson(
  results: SandboxResult[],
  analyses: AnalysisResult[],
  backend: string,
  typosquats: TyposquatResult[],
  lockfileResult: LockfileAuditResult | null,
  reputationSummary: ReputationSummary | null,
  diffs: DiffResult[],
  threatResults: ThreatIntelResult[],
  maintainerResults: MaintainerInfo[],
): void {
  const analysisMap = new Map(analyses.map(a => [a.pkg.name, a]))
  const threatMap = new Map(threatResults.map(r => [r.name, r]))
  const maintainerMap = new Map(maintainerResults.map(r => [r.name, r]))
  const diffMap = new Map(diffs.map(d => [d.name, d]))

  const pkgResults: JsonPackageResult[] = results.map(r => {
    const analysis = analysisMap.get(r.pkg.name)
    const threat = threatMap.get(r.pkg.name)
    const maint = maintainerMap.get(r.pkg.name)
    const diff = diffMap.get(r.pkg.name)

    const base: JsonPackageResult = {
      name: r.pkg.name,
      version: r.pkg.version,
      hook: r.pkg.hook,
      script: r.pkg.script,
      result: r.blocked ? 'blocked' as const : r.skipped ? 'allowed' as const : 'clean' as const,
      reason: r.reason,
      durationMs: r.durationMs,
      riskScore: analysis?.riskScore ?? 0,
      warnings: (analysis?.warnings ?? []).map(w => ({
        rule: w.rule,
        severity: w.severity,
        description: w.description,
      })),
    }

    if (threat) {
      base.threatIntel = { flagged: threat.flagged, reportCount: threat.reportCount, topReasons: threat.topReasons }
    }
    if (maint) {
      base.maintainerChanged = maint.maintainerChanged
    }
    if (diff) {
      base.behaviorDiff = { newWarnings: diff.newWarnings, riskDelta: diff.riskDelta }
    }

    return base
  })

  const jsonTyposquats: JsonTyposquatResult[] = typosquats.map(t => ({
    suspect: t.suspect,
    target: t.target,
    distance: t.distance,
    technique: t.technique,
    confidence: t.confidence,
  }))

  const jsonLockfile: JsonLockfileResult | null = lockfileResult ? {
    exists: lockfileResult.exists,
    format: lockfileResult.format,
    totalPackages: lockfileResult.totalPackages,
    score: lockfileResult.score,
    issues: lockfileResult.issues.map(i => ({
      severity: i.severity,
      type: i.type,
      package: i.package,
      detail: i.detail,
    })),
  } : null

  const jsonReputation: JsonReputationSummary | null = reputationSummary ? {
    overallScore: reputationSummary.overallScore,
    totalPackages: reputationSummary.totalPackages,
    averageScore: reputationSummary.averageScore,
    tiers: reputationSummary.tiers,
    riskiest: reputationSummary.riskiest.map(r => ({
      name: r.name,
      version: r.version,
      score: r.score,
      tier: r.tier,
    })),
  } : null

  const output: JsonOutput = {
    version: '0.5.0',
    backend,
    timestamp: new Date().toISOString(),
    packages: pkgResults,
    typosquats: jsonTyposquats,
    lockfileAudit: jsonLockfile,
    reputationSummary: jsonReputation,
    summary: {
      total: results.length,
      blocked: results.filter(r => r.blocked).length,
      allowed: results.filter(r => r.skipped).length,
      clean: results.filter(r => !r.blocked && !r.skipped).length,
      warnings: analyses.reduce((sum, a) => sum + a.warnings.length, 0),
      typosquats: typosquats.length,
      maintainerChanges: maintainerResults.filter(m => m.maintainerChanged).length,
      lockfileIssues: lockfileResult?.issues.length ?? 0,
      reputationScore: reputationSummary?.overallScore ?? 100,
    },
  }

  console.log(JSON.stringify(output, null, 2))
}

// ── Dry run ──

function dryRunFlow(packages: string[], allowlist: Set<string>, json: boolean, scan: boolean): void {
  if (!json) {
    logger.dryRunBanner()
    logger.backendInfo(backendName())
    logger.allowlistInfo(allowlist.size)
  }

  if (!json) {
    if (packages.length > 0) {
      logger.step(`would run: npm install --ignore-scripts ${packages.join(' ')}`)
    } else {
      logger.step('would run: npm install --ignore-scripts')
    }
  }

  const nodeModulesPath = path.join(process.cwd(), 'node_modules')
  const scripts = findInstallScripts(nodeModulesPath)

  // v0.4.0 scans in dry run too
  let typosquats: TyposquatResult[] = []
  let lockfileResult: LockfileAuditResult | null = null
  let reputationSummary: ReputationSummary | null = null

  if (scan) {
    const allPkgNames = getAllPackageNames(nodeModulesPath)
    typosquats = checkAllTyposquats(allPkgNames)
    lockfileResult = auditLockfile(process.cwd())
    reputationSummary = scoreReputationFromNodeModules(nodeModulesPath)

    if (!json) {
      if (typosquats.length > 0) {
        logger.typosquatHeader()
        for (const t of typosquats) logger.typosquatResult(t)
      }
      const significant = significantLockfileIssues(lockfileResult)
      if (significant.length > 0 || !lockfileResult.exists) {
        logger.lockfileHeader()
        logger.lockfileResult(lockfileResult)
      }
      if (reputationSummary.totalPackages > 0) {
        logger.reputationHeader()
        logger.reputationResult(reputationSummary)
      }
    }
  }

  if (scripts.length === 0) {
    if (json) {
      outputJson([], [], backendName(), typosquats, lockfileResult, reputationSummary, [], [], [])
    } else {
      console.log()
      logger.success('no install scripts found in current node_modules')
      console.log()
    }
    return
  }

  // Static analysis in dry run too
  const analyses = analyzeAll(scripts)

  if (json) {
    const pkgResults: JsonPackageResult[] = scripts.map(pkg => {
      const analysis = analyses.find(a => a.pkg.name === pkg.name)
      const allowed = isAllowed(pkg.name, allowlist)
      return {
        name: pkg.name,
        version: pkg.version,
        hook: pkg.hook,
        script: pkg.script,
        result: allowed ? 'allowed' as const : 'clean' as const,
        reason: allowed ? 'allowlisted' : 'would-sandbox',
        durationMs: 0,
        riskScore: analysis?.riskScore ?? 0,
        warnings: (analysis?.warnings ?? []).map(w => ({
          rule: w.rule,
          severity: w.severity,
          description: w.description,
        })),
      }
    })

    const output: JsonOutput = {
      version: '0.5.0',
      backend: backendName(),
      timestamp: new Date().toISOString(),
      packages: pkgResults,
      typosquats: typosquats.map(t => ({ suspect: t.suspect, target: t.target, distance: t.distance, technique: t.technique, confidence: t.confidence })),
      lockfileAudit: lockfileResult ? { exists: lockfileResult.exists, format: lockfileResult.format, totalPackages: lockfileResult.totalPackages, score: lockfileResult.score, issues: lockfileResult.issues.map(i => ({ severity: i.severity, type: i.type, package: i.package, detail: i.detail })) } : null,
      reputationSummary: reputationSummary ? { overallScore: reputationSummary.overallScore, totalPackages: reputationSummary.totalPackages, averageScore: reputationSummary.averageScore, tiers: reputationSummary.tiers, riskiest: reputationSummary.riskiest.map(r => ({ name: r.name, version: r.version, score: r.score, tier: r.tier })) } : null,
      summary: {
        total: scripts.length,
        blocked: 0,
        allowed: pkgResults.filter(p => p.result === 'allowed').length,
        clean: pkgResults.filter(p => p.result === 'clean').length,
        warnings: analyses.reduce((sum, a) => sum + a.warnings.length, 0),
        typosquats: typosquats.length,
        maintainerChanges: 0,
        lockfileIssues: lockfileResult?.issues.length ?? 0,
        reputationScore: reputationSummary?.overallScore ?? 100,
      },
    }
    console.log(JSON.stringify(output, null, 2))
    return
  }

  // Analysis output
  const totalWarnings = analyses.reduce((sum, a) => sum + a.warnings.length, 0)
  if (totalWarnings > 0) {
    logger.analysisHeader()
    for (const a of analyses) {
      if (a.warnings.length > 0) {
        logger.analysisResult(a)
      }
    }
  }

  console.log()
  logger.step(`${scripts.length} install script${scripts.length !== 1 ? 's' : ''} found in node_modules:`)
  console.log()

  let wouldSandbox = 0
  let wouldAllow = 0

  for (const pkg of scripts) {
    const allowed = isAllowed(pkg.name, allowlist)
    logger.dryRunItem(pkg.name, pkg.version, pkg.hook, pkg.script, allowed)
    if (allowed) wouldAllow++
    else wouldSandbox++
  }

  console.log()
  logger.info(`${wouldSandbox} would be sandboxed, ${wouldAllow} would be allowlisted`)
  logger.info('run without --dry-run to execute')
  console.log()
}
