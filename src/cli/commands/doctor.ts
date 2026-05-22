/**
 * `safenpm doctor` — full health card with letter grade.
 * The terminal renderer here is intentionally separate from the
 * doctor analyzer; the analyzer returns a structured `DoctorReport`
 * and only this file knows how to render it for humans.
 */
import { doctorToJson, runDoctor, type DoctorReport } from '../../doctor'
import { getReporter } from '../../report'

const RESET = '\x1b[0m'
const BOLD = '\x1b[1m'
const DIM = '\x1b[2m'
const RED = '\x1b[31m'
const GREEN = '\x1b[32m'
const YELLOW = '\x1b[33m'
const CYAN = '\x1b[36m'

export async function run(args: readonly string[]): Promise<number> {
  const jsonFlag = args.includes('--json')
  const reporter = getReporter({ json: jsonFlag })
  const projectDir = process.cwd()

  reporter.banner()
  reporter.blank()
  reporter.step('running health check...')
  reporter.blank()

  const report = runDoctor(projectDir)

  if (jsonFlag) {
    console.log(JSON.stringify(doctorToJson(report), null, 2))
  } else {
    printDoctorReport(report)
  }

  // Letter-grade gate: D or F is exit(1) so CI fails the build.
  return report.score < 60 ? 1 : 0
}

function printDoctorReport(report: DoctorReport): void {
  const gradeColor = report.score >= 80 ? GREEN : report.score >= 60 ? YELLOW : RED
  console.log(`  ${gradeColor}${BOLD}Grade: ${report.grade}${RESET}  ${DIM}(${report.score}/100)${RESET}`)
  console.log(`  ${DIM}${report.summary}${RESET}`)
  console.log()

  for (const section of report.sections) {
    const sColor = section.status === 'pass' ? GREEN : section.status === 'warn' ? YELLOW : RED
    const sIcon = section.status === 'pass' ? '✓' : section.status === 'warn' ? '!' : '✕'
    console.log(`  ${sColor}${sIcon}${RESET} ${BOLD}${section.name}${RESET} ${DIM}${section.score}/100${RESET}`)

    for (const finding of section.findings) {
      const fColor = finding.severity === 'critical' ? RED
        : finding.severity === 'warning' ? YELLOW
        : finding.severity === 'pass' ? GREEN : DIM
      const fIcon = finding.severity === 'critical' ? '  ✕'
        : finding.severity === 'warning' ? '  !'
        : finding.severity === 'pass' ? '  ✓' : '  ·'

      console.log(`  ${fColor}${fIcon}${RESET} ${finding.message}`)
      if (finding.fix) {
        console.log(`      ${CYAN}fix:${RESET} ${DIM}${finding.fix}${RESET}`)
      }
    }
    console.log()
  }

  if (report.fixes.length > 0) {
    const plural = report.fixes.length > 1 ? 's' : ''
    console.log(`  ${CYAN}→${RESET} ${report.fixes.length} auto-fixable issue${plural} found`)
    console.log(`  ${DIM}run \`safenpm fix\` to apply, or \`safenpm fix --dry-run\` to preview${RESET}`)
    console.log()
  }
}
