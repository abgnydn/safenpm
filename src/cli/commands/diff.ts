/**
 * `safenpm diff [--snapshot] [--json]` — track changes in a project's
 * dependencies. `--snapshot` saves the current state as a baseline;
 * the no-arg form prints a colored diff against the baseline.
 */
import {
  diffAllPackages,
  formatDiffForTerminal,
  snapshotAllPackages,
} from '../../analysis/pkgdiff'
import { getReporter } from '../../report'
import { requireNodeModules } from '../util'

export async function run(args: readonly string[]): Promise<number> {
  const jsonFlag = args.includes('--json')
  const snapshotFlag = args.includes('--snapshot')
  const reporter = getReporter({ json: jsonFlag })

  const gate = requireNodeModules(jsonFlag)
  if ('exitCode' in gate) return gate.exitCode
  const { nodeModulesPath } = gate

  if (snapshotFlag) {
    const count = snapshotAllPackages(nodeModulesPath)
    if (jsonFlag) {
      console.log(JSON.stringify({ action: 'snapshot', packages: count }))
    } else {
      reporter.success(`snapshot saved for ${count} packages`)
      reporter.info('future runs of `safenpm diff` will compare against this baseline')
      reporter.blank()
    }
    return 0
  }

  reporter.banner()
  reporter.blank()
  reporter.step('comparing packages against previous snapshot...')
  reporter.blank()

  const diffs = diffAllPackages(nodeModulesPath)

  if (diffs.length === 0) {
    if (jsonFlag) {
      console.log(JSON.stringify({ diffs: [], message: 'no changes detected' }))
    } else {
      reporter.success('no changes detected since last snapshot')
      reporter.info('run `safenpm diff --snapshot` to save current state')
      reporter.blank()
    }
    return 0
  }

  if (jsonFlag) {
    console.log(JSON.stringify({
      diffs: diffs.map((d) => ({
        name: d.name,
        previousVersion: d.previousVersion,
        currentVersion: d.currentVersion,
        summary: d.summary,
        scriptDiff: d.scriptDiff ? {
          hook: d.scriptDiff.hook,
          added: d.scriptDiff.added,
          removed: d.scriptDiff.removed,
          changed: d.scriptDiff.changed,
        } : null,
        depsDiff: d.depsDiff,
        fileDiff: d.fileDiff ? {
          added: d.fileDiff.added.length,
          removed: d.fileDiff.removed.length,
        } : null,
      })),
    }, null, 2))
    return 0
  }

  for (const d of diffs) {
    console.log(formatDiffForTerminal(d))
    console.log()
  }
  const plural = diffs.length > 1 ? 's' : ''
  reporter.info(`${diffs.length} package${plural} changed since last snapshot`)
  reporter.blank()
  return 0
}
