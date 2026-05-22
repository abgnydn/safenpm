/**
 * `safenpm scan` — runs deep analyses on an existing node_modules
 * without installing or sandboxing anything. Output mirrors what
 * `install --scan` would print plus a JSON shape used by CI.
 */
import { auditLockfile } from '../../analysis/lockfile'
import { runNpmAudit } from '../../analysis/npm-audit'
import { scoreReputationFromNodeModules } from '../../analysis/reputation'
import { checkAllTyposquats } from '../../analysis/typosquat'
import { getAllPackageNames } from '../../packages/names'
import { getReporter } from '../../report'
import { requireNodeModules } from '../util'

export async function run(args: readonly string[]): Promise<number> {
  const jsonFlag = args.includes('--json')
  const reporter = getReporter({ json: jsonFlag })
  const gate = requireNodeModules(jsonFlag)
  if ('exitCode' in gate) return gate.exitCode
  const { nodeModulesPath } = gate

  reporter.banner()
  reporter.blank()

  const allNames = getAllPackageNames(nodeModulesPath)
  const typosquats = checkAllTyposquats(allNames)
  if (typosquats.length > 0) {
    reporter.typosquatHeader()
    for (const t of typosquats) reporter.typosquatResult(t)
  } else {
    reporter.success('no typosquat suspects found')
  }

  const lockResult = auditLockfile(process.cwd())
  reporter.lockfileHeader()
  reporter.lockfileResult(lockResult)

  const repSummary = scoreReputationFromNodeModules(nodeModulesPath)
  if (repSummary.totalPackages > 0) {
    reporter.reputationHeader()
    reporter.reputationResult(repSummary)
  }

  const audit = runNpmAudit(process.cwd())
  if (audit.ran) {
    reporter.npmAuditHeader()
    reporter.npmAuditResult(audit)
  }

  if (jsonFlag) {
    console.log(JSON.stringify({
      typosquats: typosquats.map((t) => ({
        suspect: t.suspect, target: t.target, technique: t.technique, confidence: t.confidence,
      })),
      lockfile: {
        exists: lockResult.exists, format: lockResult.format,
        score: lockResult.score, issues: lockResult.issues.length,
      },
      reputation: {
        overallScore: repSummary.overallScore,
        totalPackages: repSummary.totalPackages,
        tiers: repSummary.tiers,
      },
      npmAudit: audit.ran ? {
        total: audit.total,
        totals: audit.totals,
        vulnerabilities: audit.vulnerabilities.length,
      } : null,
    }, null, 2))
  } else {
    reporter.blank()
  }
  return 0
}
