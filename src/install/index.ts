/**
 * Top-level `safenpm install` orchestrator.
 *
 * Shape:
 *   1. parse options + load allowlist
 *   2. fall through to plain `npm install` if no sandbox backend
 *   3. `npm install --ignore-scripts` to materialize node_modules
 *   4. Phase 1a — pre-script analysis pipeline (typosquat / lockfile / reputation)
 *   5. early-exit if no install scripts exist
 *   6. Phase 1b — script-dependent pipeline (analysis / diff / intel / maintainers)
 *   7. Phase 2 — per-script sandboxed execution
 *   8. cache + threat-intel-report + audit-log
 *   9. summary (human) or unified JSON dump
 *  10. exit(1) if anything was blocked
 *
 * Every visual emit goes through the injected Reporter; JSON mode is a
 * silent reporter that no-ops everything, and the unified JSON payload
 * is built once at the end via `buildJsonOutput()`. Golden snapshots
 * in test/golden/ pin the human renderer byte-for-byte — every
 * `reporter.X(...)` call here fires in the released order.
 */
import { spawnSync } from 'child_process'
import path from 'path'

import { findInstallScripts } from '../packages/scripts'
import { getAllPackageNames } from '../packages/names'
import { loadAllowlist } from '../config/allowlist'
import { getReporter, type Reporter } from '../report'
import { backendName, isSandboxAvailable } from '../sandbox'
import { reportBlocked } from '../network/signals'
import { writeAuditLog } from '../audit/log'
import { significantLockfileIssues } from '../analysis/lockfile'
import { cacheScripts } from '../analysis/diffing'
import { analyzeAll, type AnalysisResult } from '../analysis/analyzer'
import { checkAllTyposquats } from '../analysis/typosquat'
import { auditLockfile, type LockfileAuditResult } from '../analysis/lockfile'
import { runNpmAudit, type NpmAuditResult } from '../analysis/npm-audit'
import { scoreReputationFromNodeModules, type ReputationSummary } from '../analysis/reputation'
import type { TyposquatResult } from '../analysis/typosquat'

import { PRE_SCRIPT_STEPS, POST_SCRIPT_STEPS } from '../pipeline/steps'
import { byKind, runPipeline } from '../pipeline/runner'
import type { AnalysisContext, Finding } from '../pipeline/types'

import type { InstallOptions, JsonPackageResult, PackageScript, SandboxResult } from '../types'
import { executeScripts } from './execute'
import { buildJsonOutput } from './json-output'

const VERSION = '0.1.0'

// ── Public entry point ────────────────────────────────────────────────

export async function install(opts: InstallOptions): Promise<void> {
  const reporter = getReporter(opts)
  const allowlist = loadAllowlist(opts.allow)

  if (opts.dryRun) {
    await dryRunFlow(opts, allowlist, reporter)
    return
  }

  reporter.banner()
  reporter.backendInfo(backendName())
  reporter.allowlistInfo(allowlist.size)

  if (!isSandboxAvailable()) {
    fallbackToPlainNpm(opts, reporter)
    return
  }

  reporter.step('installing packages (scripts disabled)...')
  const npmResult = spawnSync(
    'npm',
    ['install', '--ignore-scripts', ...opts.packages],
    { stdio: opts.json ? 'pipe' : 'inherit' },
  )
  if (npmResult.status !== 0) {
    process.exit(npmResult.status ?? 1)
  }

  const nodeModulesPath = path.join(process.cwd(), 'node_modules')
  const scripts = findInstallScripts(nodeModulesPath)
  const ctx: AnalysisContext = {
    cwd: process.cwd(),
    nodeModulesPath,
    allPackageNames: getAllPackageNames(nodeModulesPath),
    scripts,
    opts,
  }

  // Phase 1a — pre-script analyses
  const preFindings = await runPipeline(PRE_SCRIPT_STEPS, ctx)
  reportPreFindings(preFindings, reporter)

  if (scripts.length === 0) {
    finalizeEmpty(preFindings, opts, reporter)
    return
  }

  // Phase 1b — script-dependent analyses
  const postFindings = await runPipeline(POST_SCRIPT_STEPS, ctx)
  reportPostFindings(postFindings, reporter)

  const analyses = byKind(postFindings, 'analysis')?.results ?? []
  const totalWarnings = analyses.reduce((sum, a) => sum + a.warnings.length, 0)

  reporter.step(`found ${scripts.length} install script${scripts.length !== 1 ? 's' : ''} — running in sandbox...`)
  reporter.blank()

  // Phase 2 — sandbox execution
  const { results, skippedCount } = executeScripts({ scripts, allowlist, opts, reporter })

  if (opts.scan) cacheScripts(scripts)

  const blockedCount = results.filter((r) => r.blocked).length
  if (blockedCount > 0 && !opts.noReport) {
    await reportBlocked(results)
  }

  writeAuditLog(results, analyses, backendName())
  reporter.auditInfo()

  if (opts.json) {
    emitJson({ results, analyses, findings: [...preFindings, ...postFindings] })
  } else {
    reporter.summary(scripts.length, blockedCount, skippedCount, totalWarnings)
  }

  if (blockedCount > 0) process.exit(1)
}

// ── Helpers: reporting ────────────────────────────────────────────────

function reportPreFindings(findings: readonly Finding[], reporter: Reporter): void {
  const typo = byKind(findings, 'typosquats')
  if (typo && typo.results.length > 0) {
    reporter.typosquatHeader()
    for (const t of typo.results) reporter.typosquatResult(t)
  }

  const lock = byKind(findings, 'lockfile')
  if (lock) {
    const significant = significantLockfileIssues(lock.result)
    if (significant.length > 0 || !lock.result.exists) {
      reporter.lockfileHeader()
      reporter.lockfileResult(lock.result)
    }
  }

  const rep = byKind(findings, 'reputation')
  if (rep && rep.summary.totalPackages > 0) {
    reporter.reputationHeader()
    reporter.reputationResult(rep.summary)
  }

  const audit = byKind(findings, 'npm-audit')
  if (audit && audit.result.ran) {
    reporter.npmAuditHeader()
    reporter.npmAuditResult(audit.result)
  }
}

function reportPostFindings(findings: readonly Finding[], reporter: Reporter): void {
  const analysis = byKind(findings, 'analysis')
  const totalWarnings = analysis?.results.reduce((s, a) => s + a.warnings.length, 0) ?? 0
  if (analysis && totalWarnings > 0) {
    reporter.analysisHeader()
    for (const a of analysis.results) {
      if (a.warnings.length > 0) reporter.analysisResult(a)
    }
    reporter.blank()
  }

  const diffs = byKind(findings, 'diffs')
  if (diffs && diffs.results.length > 0) {
    reporter.diffHeader()
    for (const d of diffs.results) reporter.diffResult(d)
  }

  const intel = byKind(findings, 'threat-intel')
  if (intel) {
    const flagged = intel.results.filter((r) => r.flagged)
    if (flagged.length > 0) {
      reporter.threatIntelHeader()
      for (const r of flagged) reporter.threatIntelResult(r)
    }
  }

  const maint = byKind(findings, 'maintainers')
  if (maint) {
    const changed = maint.results.filter((m) => m.maintainerChanged)
    if (changed.length > 0) {
      reporter.maintainerHeader()
      for (const m of changed) reporter.maintainerResult(m)
    }
  }
}

// ── Helpers: JSON serialization ───────────────────────────────────────

function emitJson(args: {
  results: SandboxResult[]
  analyses: AnalysisResult[]
  findings: readonly Finding[]
}): void {
  const payload = buildJsonOutput({
    version: VERSION,
    backend: backendName(),
    results: args.results,
    analyses: args.analyses,
    typosquats: byKind(args.findings, 'typosquats')?.results ?? [],
    lockfile: byKind(args.findings, 'lockfile')?.result ?? null,
    reputation: byKind(args.findings, 'reputation')?.summary ?? null,
    npmAudit: byKind(args.findings, 'npm-audit')?.result ?? null,
    diffs: byKind(args.findings, 'diffs')?.results ?? [],
    threatIntel: byKind(args.findings, 'threat-intel')?.results ?? [],
    maintainers: byKind(args.findings, 'maintainers')?.results ?? [],
  })
  console.log(JSON.stringify(payload, null, 2))
}

// ── Helpers: edge-case branches ───────────────────────────────────────

function fallbackToPlainNpm(opts: InstallOptions, reporter: Reporter): void {
  reporter.warn('no sandbox backend found')
  reporter.warn('macOS: sandbox-exec (built-in)')
  reporter.warn('Linux: install firejail → sudo apt install firejail')
  reporter.warn('falling back to plain npm install (no sandboxing)')
  reporter.blank()
  spawnSync('npm', ['install', ...opts.packages], { stdio: opts.json ? 'pipe' : 'inherit' })
}

function finalizeEmpty(
  preFindings: readonly Finding[],
  opts: InstallOptions,
  reporter: Reporter,
): void {
  if (opts.json) {
    emitJson({ results: [], analyses: [], findings: preFindings })
    return
  }
  reporter.success('no install scripts found — nothing to sandbox')
  reporter.summary(0, 0)
}

// ── Dry run ───────────────────────────────────────────────────────────

async function dryRunFlow(
  opts: InstallOptions,
  allowlist: Set<string>,
  reporter: Reporter,
): Promise<void> {
  reporter.dryRunBanner()
  reporter.backendInfo(backendName())
  reporter.allowlistInfo(allowlist.size)
  if (opts.packages.length > 0) {
    reporter.step(`would run: npm install --ignore-scripts ${opts.packages.join(' ')}`)
  } else {
    reporter.step('would run: npm install --ignore-scripts')
  }

  const nodeModulesPath = path.join(process.cwd(), 'node_modules')
  const scripts = findInstallScripts(nodeModulesPath)

  let typosquats: TyposquatResult[] = []
  let lockfileResult: LockfileAuditResult | null = null
  let reputationSummary: ReputationSummary | null = null
  let npmAuditResult: NpmAuditResult | null = null

  if (opts.scan) {
    typosquats = checkAllTyposquats(getAllPackageNames(nodeModulesPath))
    lockfileResult = auditLockfile(process.cwd())
    reputationSummary = scoreReputationFromNodeModules(nodeModulesPath)
    npmAuditResult = runNpmAudit(process.cwd())

    if (typosquats.length > 0) {
      reporter.typosquatHeader()
      for (const t of typosquats) reporter.typosquatResult(t)
    }
    const significant = significantLockfileIssues(lockfileResult)
    if (significant.length > 0 || !lockfileResult.exists) {
      reporter.lockfileHeader()
      reporter.lockfileResult(lockfileResult)
    }
    if (reputationSummary.totalPackages > 0) {
      reporter.reputationHeader()
      reporter.reputationResult(reputationSummary)
    }
    if (npmAuditResult.ran) {
      reporter.npmAuditHeader()
      reporter.npmAuditResult(npmAuditResult)
    }
  }

  if (scripts.length === 0) {
    if (opts.json) {
      emitDryRunJson({
        scripts: [], analyses: [], allowlist,
        typosquats, lockfile: lockfileResult, reputation: reputationSummary, npmAudit: npmAuditResult,
      })
      return
    }
    reporter.blank()
    reporter.success('no install scripts found in current node_modules')
    reporter.blank()
    return
  }

  const analyses = analyzeAll(scripts)

  if (opts.json) {
    emitDryRunJson({
      scripts, analyses, allowlist,
      typosquats, lockfile: lockfileResult, reputation: reputationSummary, npmAudit: npmAuditResult,
    })
    return
  }

  const totalWarnings = analyses.reduce((s, a) => s + a.warnings.length, 0)
  if (totalWarnings > 0) {
    reporter.analysisHeader()
    for (const a of analyses) {
      if (a.warnings.length > 0) reporter.analysisResult(a)
    }
  }

  reporter.blank()
  reporter.step(`${scripts.length} install script${scripts.length !== 1 ? 's' : ''} found in node_modules:`)
  reporter.blank()

  let wouldSandbox = 0
  let wouldAllow = 0
  for (const pkg of scripts) {
    const allowed = allowlist.has(pkg.name) || matchesScopeWildcard(pkg.name, allowlist)
    reporter.dryRunItem(pkg.name, pkg.version, pkg.hook, pkg.script, allowed)
    if (allowed) wouldAllow++
    else wouldSandbox++
  }
  reporter.blank()
  reporter.info(`${wouldSandbox} would be sandboxed, ${wouldAllow} would be allowlisted`)
  reporter.info('run without --dry-run to execute')
  reporter.blank()
}

function matchesScopeWildcard(name: string, allowlist: ReadonlySet<string>): boolean {
  for (const entry of allowlist) {
    if (entry.endsWith('/*') && name.startsWith(entry.slice(0, -2) + '/')) return true
  }
  return false
}

function emitDryRunJson(args: {
  scripts: PackageScript[]
  analyses: AnalysisResult[]
  allowlist: ReadonlySet<string>
  typosquats: TyposquatResult[]
  lockfile: LockfileAuditResult | null
  reputation: ReputationSummary | null
  npmAudit: NpmAuditResult | null
}): void {
  const fakeResults: SandboxResult[] = args.scripts.map((pkg) => {
    const allowed = args.allowlist.has(pkg.name) || matchesScopeWildcard(pkg.name, args.allowlist)
    return {
      pkg,
      blocked: false,
      skipped: allowed,
      reason: allowed ? 'allowed' : 'clean',
      output: '',
      durationMs: 0,
    }
  })

  // Mirror legacy dry-run JSON: `result` reflects the *planned* action
  // (`would-sandbox` vs `allowlisted`) instead of an actual execution.
  const payload = buildJsonOutput({
    version: VERSION,
    backend: backendName(),
    results: fakeResults,
    analyses: args.analyses,
    typosquats: args.typosquats,
    lockfile: args.lockfile,
    reputation: args.reputation,
    npmAudit: args.npmAudit,
    diffs: [],
    threatIntel: [],
    maintainers: [],
  })

  payload.packages = payload.packages.map((p): JsonPackageResult => ({
    ...p,
    result: p.result === 'allowed' ? 'allowed' : 'clean',
    reason: p.result === 'allowed' ? 'allowlisted' : 'would-sandbox',
  }))
  payload.summary.blocked = 0

  console.log(JSON.stringify(payload, null, 2))
}
