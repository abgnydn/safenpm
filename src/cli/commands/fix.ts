/**
 * `safenpm fix` — preview or apply auto-fixes for typosquats and
 * blocked packages. Standalone invocation only finds typosquats (no
 * blocked-script context available), which is why the second arg to
 * `generateFixes` is an empty array.
 */
import { applyAllFixes, generateFixes, type FixAction } from '../../fix/autofix'
import { checkAllTyposquats } from '../../analysis/typosquat'
import { getAllPackageNames } from '../../packages/names'
import { getReporter } from '../../report'
import { requireNodeModules } from '../util'

const RESET = '\x1b[0m'
const DIM = '\x1b[2m'
const RED = '\x1b[31m'
const GREEN = '\x1b[32m'
const CYAN = '\x1b[36m'

export async function run(args: readonly string[]): Promise<number> {
  const jsonFlag = args.includes('--json')
  const dryRun = args.includes('--dry-run') || args.includes('-n')
  const reporter = getReporter({ json: jsonFlag })

  const gate = requireNodeModules(jsonFlag)
  if ('exitCode' in gate) return gate.exitCode
  const { nodeModulesPath } = gate

  reporter.banner()
  reporter.blank()
  reporter.step('scanning for fixable issues...')
  reporter.blank()

  const typosquats = checkAllTyposquats(getAllPackageNames(nodeModulesPath))
  const fixes = generateFixes(typosquats, [])

  if (fixes.length === 0) {
    if (jsonFlag) {
      console.log(JSON.stringify({ fixes: [], applied: 0 }))
    } else {
      reporter.success('no fixable issues found')
      reporter.blank()
    }
    return 0
  }

  if (dryRun) {
    if (jsonFlag) {
      console.log(JSON.stringify({
        fixes: fixes.map((f) => ({
          type: f.type, package: f.package,
          replacement: f.replacement, detail: f.detail,
        })),
        dryRun: true,
      }))
    } else {
      const plural = fixes.length > 1 ? 'es' : ''
      reporter.step(`${fixes.length} fix${plural} available:`)
      reporter.blank()
      for (const f of fixes) printFixAction(f)
      reporter.blank()
      reporter.info('run `safenpm fix` without --dry-run to apply')
      reporter.blank()
    }
    return 0
  }

  const plural = fixes.length > 1 ? 'es' : ''
  reporter.step(`applying ${fixes.length} fix${plural}...`)
  reporter.blank()

  const applied = applyAllFixes(fixes, process.cwd())
  const successCount = applied.filter((f) => f.applied).length

  if (jsonFlag) {
    console.log(JSON.stringify({
      fixes: applied.map((f) => ({
        type: f.type, package: f.package, replacement: f.replacement,
        applied: f.applied, detail: f.detail,
      })),
      applied: successCount,
    }, null, 2))
  } else {
    for (const f of applied) printFixAction(f)
    reporter.blank()
    if (successCount === applied.length) {
      reporter.success(`all ${successCount} fixes applied`)
    } else {
      reporter.warn(`${successCount}/${applied.length} fixes applied`)
    }
    reporter.blank()
  }
  return 0
}

function printFixAction(fix: FixAction): void {
  const marker = fix.applied ? `${GREEN}✓${RESET}` : `${CYAN}→${RESET}`
  if (fix.type === 'replace-typosquat') {
    console.log(`  ${marker} ${RED}${fix.package}${RESET} → ${GREEN}${fix.replacement}${RESET} ${DIM}(typosquat)${RESET}`)
  } else {
    console.log(`  ${marker} remove ${RED}${fix.package}@${fix.version}${RESET} ${DIM}(${fix.detail})${RESET}`)
  }
}
