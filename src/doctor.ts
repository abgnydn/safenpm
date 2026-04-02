/**
 * safenpm doctor — comprehensive project health check.
 * Runs every analysis module and produces a letter grade (A+ to F)
 * with actionable recommendations.
 */

import path from 'path'
import fs from 'fs'
import { findInstallScripts } from './scripts'
import { analyzeAll, AnalysisResult, riskLevel } from './analyzer'
import { checkAllTyposquats, TyposquatResult } from './typosquat'
import { auditLockfile, significantLockfileIssues, LockfileAuditResult } from './lockfile'
import { scoreReputationFromNodeModules, ReputationSummary } from './reputation'
import { diffScripts, significantDiffs, DiffResult } from './diffing'
import { generateFixes, FixAction } from './autofix'
import { getAllPackageNames } from './packages'

export interface DoctorReport {
  grade: string                        // A+, A, B+, B, C+, C, D, F
  score: number                        // 0-100
  sections: DoctorSection[]
  fixes: FixAction[]
  summary: string
}

export interface DoctorSection {
  name: string
  score: number                        // 0-100 for this section
  weight: number                       // how much it contributes to overall
  status: 'pass' | 'warn' | 'fail'
  findings: DoctorFinding[]
}

export interface DoctorFinding {
  severity: 'critical' | 'warning' | 'info' | 'pass'
  message: string
  fix: string | null                   // actionable suggestion
}

/**
 * Run a full doctor check on the current project.
 *
 * Section weights (must sum to 100):
 *   Lockfile (20):        Deterministic builds prevent tampering via registry
 *   Install Scripts (25): Highest weight — scripts run arbitrary code at install time
 *   Typosquats (20):      Name confusion attacks are a top supply-chain vector
 *   Reputation (15):      Lower weight — currently heuristic-only (no registry data)
 *   Behavior (10):        Behavioral changes between versions catch takeovers
 *   Hygiene (10):         Project-level config best practices
 */
export function runDoctor(projectDir: string): DoctorReport {
  const nodeModulesPath = path.join(projectDir, 'node_modules')
  const hasNodeModules = fs.existsSync(nodeModulesPath)

  const sections: DoctorSection[] = []

  // ── 1. Lockfile health ──
  sections.push(checkLockfileHealth(projectDir))

  // ── 2. Install scripts ──
  sections.push(checkInstallScripts(nodeModulesPath, hasNodeModules))

  // ── 3. Typosquats ──
  sections.push(checkTyposquats(nodeModulesPath, hasNodeModules))

  // ── 4. Reputation ──
  sections.push(checkReputation(nodeModulesPath, hasNodeModules))

  // ── 5. Behavioral changes ──
  sections.push(checkBehavioralChanges(nodeModulesPath, hasNodeModules))

  // ── 6. Project hygiene ──
  sections.push(checkProjectHygiene(projectDir))

  // Calculate overall score
  const totalWeight = sections.reduce((s, sec) => s + sec.weight, 0)
  const weightedScore = sections.reduce((s, sec) => s + sec.score * sec.weight, 0)
  const score = Math.round(weightedScore / totalWeight)
  const grade = scoreToGrade(score)

  // Generate auto-fix suggestions
  const typosquats = hasNodeModules ? checkAllTyposquats(getAllPackageNames(nodeModulesPath)) : []
  const fixes = generateFixes(typosquats, [])

  const failCount = sections.filter(s => s.status === 'fail').length
  const warnCount = sections.filter(s => s.status === 'warn').length

  let summary: string
  if (failCount === 0 && warnCount === 0) {
    summary = 'Your project looks healthy. No critical issues found.'
  } else if (failCount === 0) {
    summary = `${warnCount} area${warnCount > 1 ? 's' : ''} could use attention, but no critical issues.`
  } else {
    summary = `${failCount} critical issue${failCount > 1 ? 's' : ''} found. Review the recommendations below.`
  }

  return { grade, score, sections, fixes, summary }
}

// ── Section checks ──

function checkLockfileHealth(projectDir: string): DoctorSection {
  const result = auditLockfile(projectDir)
  const findings: DoctorFinding[] = []

  if (!result.exists) {
    findings.push({
      severity: 'critical',
      message: 'No package-lock.json found',
      fix: 'Run `npm install` to generate a lockfile for deterministic builds',
    })
    return { name: 'Lockfile', score: 20, weight: 20, status: 'fail', findings }
  }

  const significant = significantLockfileIssues(result)
  const highIssues = significant.filter(i => i.severity === 'high')
  const mediumIssues = significant.filter(i => i.severity === 'medium')

  for (const issue of highIssues.slice(0, 3)) {
    findings.push({
      severity: 'critical',
      message: `${issue.package}: ${issue.detail}`,
      fix: issue.type === 'git-dependency' ? 'Pin to a registry version instead of a git URL'
        : issue.type === 'file-dependency' ? 'Publish the local package or use a workspace'
        : issue.type === 'custom-registry' ? 'Verify this registry is trusted and intentional'
        : null,
    })
  }

  for (const issue of mediumIssues.slice(0, 3)) {
    findings.push({
      severity: 'warning',
      message: `${issue.package}: ${issue.detail}`,
      fix: issue.type === 'missing-integrity' ? 'Delete package-lock.json and reinstall to regenerate hashes'
        : issue.type === 'weak-hash' ? 'Upgrade npm to generate sha512 hashes'
        : null,
    })
  }

  if (findings.length === 0) {
    findings.push({ severity: 'pass', message: `Lockfile healthy (${result.format}, ${result.totalPackages} packages)`, fix: null })
  }

  const status = highIssues.length > 0 ? 'fail' : mediumIssues.length > 0 ? 'warn' : 'pass'
  return { name: 'Lockfile', score: result.score, weight: 20, status, findings }
}

function checkInstallScripts(nodeModulesPath: string, hasNM: boolean): DoctorSection {
  const findings: DoctorFinding[] = []

  if (!hasNM) {
    findings.push({ severity: 'info', message: 'No node_modules — skipped', fix: null })
    return { name: 'Install Scripts', score: 100, weight: 25, status: 'pass', findings }
  }

  const scripts = findInstallScripts(nodeModulesPath)
  if (scripts.length === 0) {
    findings.push({ severity: 'pass', message: 'No install scripts found', fix: null })
    return { name: 'Install Scripts', score: 100, weight: 25, status: 'pass', findings }
  }

  const analyses = analyzeAll(scripts)
  const critical = analyses.filter(a => riskLevel(a.riskScore) === 'critical')
  const suspicious = analyses.filter(a => riskLevel(a.riskScore) === 'suspicious')

  for (const a of critical.slice(0, 3)) {
    findings.push({
      severity: 'critical',
      message: `${a.pkg.name}@${a.pkg.version} — risk ${a.riskScore}/100: ${a.warnings.map(w => w.description).join('; ')}`,
      fix: `Run \`safenpm install --scan\` to sandbox this package, or add to .safenpmrc if trusted`,
    })
  }

  for (const a of suspicious.slice(0, 3)) {
    findings.push({
      severity: 'warning',
      message: `${a.pkg.name}@${a.pkg.version} — risk ${a.riskScore}/100`,
      fix: null,
    })
  }

  const totalRisk = analyses.reduce((s, a) => s + a.riskScore, 0)
  const avgRisk = scripts.length > 0 ? totalRisk / scripts.length : 0
  const score = Math.max(0, Math.round(100 - avgRisk * 1.5))

  if (critical.length === 0 && suspicious.length === 0) {
    findings.push({ severity: 'pass', message: `${scripts.length} install scripts, all low-risk`, fix: null })
  }

  const status = critical.length > 0 ? 'fail' : suspicious.length > 0 ? 'warn' : 'pass'
  return { name: 'Install Scripts', score, weight: 25, status, findings }
}

function checkTyposquats(nodeModulesPath: string, hasNM: boolean): DoctorSection {
  const findings: DoctorFinding[] = []

  if (!hasNM) {
    findings.push({ severity: 'info', message: 'No node_modules — skipped', fix: null })
    return { name: 'Typosquats', score: 100, weight: 20, status: 'pass', findings }
  }

  const names = getAllPackageNames(nodeModulesPath)
  const typosquats = checkAllTyposquats(names)

  const high = typosquats.filter(t => t.confidence === 'high')
  const medium = typosquats.filter(t => t.confidence === 'medium')

  for (const t of high) {
    findings.push({
      severity: 'critical',
      message: `${t.suspect} looks like ${t.target} (${t.technique})`,
      fix: `Run \`safenpm fix\` to replace with ${t.target}, or \`npm uninstall ${t.suspect}\``,
    })
  }

  for (const t of medium) {
    findings.push({
      severity: 'warning',
      message: `${t.suspect} resembles ${t.target} (${t.technique})`,
      fix: `Verify this is the intended package`,
    })
  }

  if (typosquats.length === 0) {
    findings.push({ severity: 'pass', message: `${names.length} packages checked, no suspects`, fix: null })
  }

  const score = high.length > 0 ? 10 : medium.length > 0 ? 60 : 100
  const status = high.length > 0 ? 'fail' : medium.length > 0 ? 'warn' : 'pass'
  return { name: 'Typosquats', score, weight: 20, status, findings }
}

function checkReputation(nodeModulesPath: string, hasNM: boolean): DoctorSection {
  const findings: DoctorFinding[] = []

  if (!hasNM) {
    findings.push({ severity: 'info', message: 'No node_modules — skipped', fix: null })
    return { name: 'Reputation', score: 100, weight: 15, status: 'pass', findings }
  }

  const summary = scoreReputationFromNodeModules(nodeModulesPath)

  if (summary.totalPackages === 0) {
    findings.push({ severity: 'info', message: 'No packages to score', fix: null })
    return { name: 'Reputation', score: 100, weight: 15, status: 'pass', findings }
  }

  const risky = summary.riskiest.filter(r => r.score < 30)
  for (const r of risky.slice(0, 3)) {
    findings.push({
      severity: 'warning',
      message: `${r.name}@${r.version} scored ${r.score}/100 (${r.tier})`,
      fix: 'Review this package — check for a more established alternative',
    })
  }

  if (risky.length === 0) {
    findings.push({
      severity: 'pass',
      message: `${summary.totalPackages} packages, overall ${summary.overallScore}/100`,
      fix: null,
    })
  }

  const status = summary.overallScore < 30 ? 'fail' : summary.overallScore < 60 ? 'warn' : 'pass'
  return { name: 'Reputation', score: summary.overallScore, weight: 15, status, findings }
}

function checkBehavioralChanges(nodeModulesPath: string, hasNM: boolean): DoctorSection {
  const findings: DoctorFinding[] = []

  if (!hasNM) {
    findings.push({ severity: 'info', message: 'No node_modules — skipped', fix: null })
    return { name: 'Behavior', score: 100, weight: 10, status: 'pass', findings }
  }

  const scripts = findInstallScripts(nodeModulesPath)
  if (scripts.length === 0) {
    findings.push({ severity: 'pass', message: 'No install scripts to diff', fix: null })
    return { name: 'Behavior', score: 100, weight: 10, status: 'pass', findings }
  }

  const allDiffs = diffScripts(scripts)
  const sig = significantDiffs(allDiffs)

  for (const d of sig.slice(0, 3)) {
    const sev = d.riskDelta > 30 ? 'critical' as const : 'warning' as const
    findings.push({
      severity: sev,
      message: d.isNewPackage
        ? `${d.name}@${d.currentVersion} is new and has install scripts`
        : `${d.name} changed: ${d.newWarnings.length} new warnings, risk +${d.riskDelta}`,
      fix: 'Review the updated install script before trusting this version',
    })
  }

  if (sig.length === 0) {
    findings.push({ severity: 'pass', message: 'No behavioral changes detected', fix: null })
  }

  const score = sig.some(d => d.riskDelta > 30) ? 30 : sig.length > 0 ? 65 : 100
  const status = sig.some(d => d.riskDelta > 30) ? 'fail' : sig.length > 0 ? 'warn' : 'pass'
  return { name: 'Behavior', score, weight: 10, status, findings }
}

function checkProjectHygiene(projectDir: string): DoctorSection {
  const findings: DoctorFinding[] = []
  let score = 100

  // Check .safenpmrc exists
  const safenpmrcPath = path.join(projectDir, '.safenpmrc')
  if (!fs.existsSync(safenpmrcPath)) {
    findings.push({
      severity: 'info',
      message: 'No .safenpmrc file — consider creating one to allowlist trusted native packages',
      fix: 'Create .safenpmrc with packages like bcrypt, sharp that need install scripts',
    })
    score -= 10
  } else {
    findings.push({ severity: 'pass', message: '.safenpmrc found', fix: null })
  }

  // Check package.json exists
  const pkgJsonPath = path.join(projectDir, 'package.json')
  if (!fs.existsSync(pkgJsonPath)) {
    findings.push({ severity: 'critical', message: 'No package.json found', fix: 'Run `npm init` to create one' })
    score -= 40
  } else {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'))

      // Check engines field
      if (!pkg.engines) {
        findings.push({
          severity: 'info',
          message: 'No engines field — consider specifying a Node.js version',
          fix: 'Add `"engines": {"node": ">=18"}` to package.json',
        })
        score -= 5
      }

      // Check for * version ranges
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies }
      const starDeps = Object.entries(allDeps).filter(([, v]) => v === '*' || v === 'latest')
      if (starDeps.length > 0) {
        findings.push({
          severity: 'warning',
          message: `${starDeps.length} dependencies use "*" or "latest" versions: ${starDeps.map(([n]) => n).slice(0, 5).join(', ')}`,
          fix: 'Pin dependencies to specific version ranges for reproducible builds',
        })
        score -= 15
      }
    } catch {
      findings.push({ severity: 'warning', message: 'package.json is malformed', fix: 'Fix JSON syntax errors' })
      score -= 20
    }
  }

  // Check .npmrc for audit settings
  const npmrcPath = path.join(projectDir, '.npmrc')
  if (fs.existsSync(npmrcPath)) {
    try {
      const content = fs.readFileSync(npmrcPath, 'utf8')
      if (content.includes('ignore-scripts=true')) {
        findings.push({ severity: 'pass', message: '.npmrc has ignore-scripts=true', fix: null })
      }
    } catch { /* skip */ }
  }

  score = Math.max(0, score)
  const status = score < 50 ? 'fail' : score < 80 ? 'warn' : 'pass'
  return { name: 'Project Hygiene', score, weight: 10, status, findings }
}

// ── Helpers ──

function scoreToGrade(score: number): string {
  if (score >= 97) return 'A+'
  if (score >= 93) return 'A'
  if (score >= 90) return 'A-'
  if (score >= 87) return 'B+'
  if (score >= 83) return 'B'
  if (score >= 80) return 'B-'
  if (score >= 77) return 'C+'
  if (score >= 73) return 'C'
  if (score >= 70) return 'C-'
  if (score >= 60) return 'D'
  return 'F'
}

/**
 * JSON-friendly output of doctor report.
 */
export function doctorToJson(report: DoctorReport): object {
  return {
    grade: report.grade,
    score: report.score,
    summary: report.summary,
    sections: report.sections.map(s => ({
      name: s.name,
      score: s.score,
      status: s.status,
      findings: s.findings.map(f => ({
        severity: f.severity,
        message: f.message,
        fix: f.fix,
      })),
    })),
    fixes: report.fixes.map(f => ({
      type: f.type,
      package: f.package,
      replacement: f.replacement,
      detail: f.detail,
    })),
  }
}
