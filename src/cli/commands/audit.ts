/**
 * `safenpm audit` — show the last N runs from ~/.safenpm/audit.log.
 * Default limit is 20; a positional integer overrides it.
 */
import { readAuditLog } from '../../audit/log'

const RESET = '\x1b[0m'
const BOLD = '\x1b[1m'
const DIM = '\x1b[2m'
const RED = '\x1b[31m'
const GREEN = '\x1b[32m'

export async function run(args: readonly string[]): Promise<number> {
  const jsonFlag = args.includes('--json')
  const limit = Number.parseInt(args[0] ?? '', 10) || 20
  const entries = readAuditLog(limit)

  if (entries.length === 0) {
    if (jsonFlag) {
      console.log(JSON.stringify([]))
    } else {
      console.log('  no audit entries found')
      console.log('  run safenpm install to generate audit data')
    }
    return 0
  }

  if (jsonFlag) {
    console.log(JSON.stringify(entries, null, 2))
    return 0
  }

  console.log()
  console.log(`  ${BOLD}last ${entries.length} safenpm runs:${RESET}`)
  console.log()
  for (const entry of entries) {
    const date = new Date(entry.timestamp).toLocaleString()
    const blocked = entry.summary.blocked
    const color = blocked > 0 ? RED : GREEN
    console.log(`  ${date}  ${color}${blocked} blocked${RESET}  ${entry.summary.total} total  ${DIM}${entry.cwd}${RESET}`)
    if (blocked > 0) {
      for (const pkg of entry.packages) {
        if (pkg.result === 'blocked') {
          console.log(`    ${RED}✕${RESET} ${pkg.name}@${pkg.version} [${pkg.reason}]`)
        }
      }
    }
  }
  console.log()
  return 0
}
