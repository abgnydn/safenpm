/**
 * `safenpm trace` — three modes:
 *
 *   safenpm trace -- <command>          run + record (default)
 *   safenpm trace --diff                compare the two most recent traces
 *   safenpm trace --list                list recent trace files
 *
 * Each run mode writes a JSON trace to ~/.safenpm/pkg-traces/.
 * `--diff` reads the two latest, computes new builtin / package
 * requires per dependency, and exits 1 if any newly-appearing
 * builtin is in the `critical` severity tier (child_process,
 * https, net, vm, …).
 */
import { spawn } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { getReporter } from '../../report'
import {
  categorizeBuiltin,
  defaultTraceDir,
  diffTraces,
  listTraceFiles,
  readTraceFile,
  type TraceDiff,
} from '../../runtime/utils'

const RESET = '\x1b[0m'
const DIM = '\x1b[2m'
const BOLD = '\x1b[1m'
const RED = '\x1b[31m'
const GREEN = '\x1b[32m'
const YELLOW = '\x1b[33m'
const BLUE = '\x1b[34m'

export async function run(args: readonly string[]): Promise<number> {
  if (args.includes('--list')) return runList(args.includes('--json'))
  if (args.includes('--diff')) return runDiff(args.includes('--json'))
  return runTraced(args)
}

// ── Mode 1: trace + record ────────────────────────────────────────────

async function runTraced(args: readonly string[]): Promise<number> {
  const sepIdx = args.indexOf('--')
  const cmdArgs = sepIdx >= 0 ? args.slice(sepIdx + 1) : args
  const jsonFlag = (sepIdx >= 0 ? args.slice(0, sepIdx) : []).includes('--json')
  const reporter = getReporter({ json: jsonFlag })

  if (cmdArgs.length === 0) {
    reporter.error('usage: safenpm trace -- <command> [args...]')
    reporter.info('examples:')
    reporter.info('  safenpm trace -- node app.js')
    reporter.info('  safenpm trace --diff           (compare two newest traces)')
    reporter.info('  safenpm trace --list           (list recent traces)')
    return 1
  }

  const hookPath = path.resolve(__dirname, '..', '..', 'runtime', 'hook.js')
  const existing = process.env.NODE_OPTIONS ?? ''
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_OPTIONS: `--require ${hookPath} ${existing}`.trim(),
  }

  if (!jsonFlag) {
    reporter.banner()
    reporter.step(`tracing: ${cmdArgs.join(' ')}`)
    reporter.info(`traces will be written to ${defaultTraceDir(os.homedir())}`)
    reporter.blank()
  }

  return new Promise<number>((resolve) => {
    const child = spawn(cmdArgs[0]!, cmdArgs.slice(1), { stdio: 'inherit', env })
    child.on('exit', (code, signal) => {
      if (jsonFlag) {
        console.log(JSON.stringify({
          traced: cmdArgs,
          exitCode: code,
          signal: signal ?? null,
          traceDir: defaultTraceDir(os.homedir()),
        }))
      } else {
        reporter.blank()
        if (code === 0) reporter.success('traced command exited cleanly (trace saved to ~/.safenpm/pkg-traces/)')
        else reporter.warn(`traced command exited ${code ?? signal} (trace saved to ~/.safenpm/pkg-traces/)`)
      }
      resolve(code ?? 1)
    })
    child.on('error', (err) => {
      reporter.error(`failed to spawn: ${err.message}`)
      resolve(1)
    })
  })
}

// ── Mode 2: --list ────────────────────────────────────────────────────

function runList(jsonFlag: boolean): number {
  const dir = defaultTraceDir(os.homedir())
  const files = listTraceFiles(dir)

  if (jsonFlag) {
    console.log(JSON.stringify({ traceDir: dir, files: files.map((f) => path.basename(f)) }))
    return 0
  }

  const reporter = getReporter({ json: false })
  reporter.banner()
  if (files.length === 0) {
    reporter.info(`no traces yet in ${dir}`)
    reporter.info('run `safenpm trace -- <cmd>` to record one')
    reporter.blank()
    return 0
  }
  reporter.step(`${files.length} trace${files.length === 1 ? '' : 's'} in ${dir}:`)
  reporter.blank()
  // Show newest first; cap at 20 to avoid pagination shenanigans.
  for (const file of files.slice(-20).reverse()) {
    const stat = safeStat(file)
    const trace = readTraceFile(file)
    const pkgCount = trace ? Object.keys(trace.packages).length : 0
    const size = stat ? `${(stat.size / 1024).toFixed(1)} kB` : '?'
    console.log(`  ${DIM}${path.basename(file)}${RESET}  ${pkgCount} pkgs  ${DIM}${size}${RESET}`)
  }
  reporter.blank()
  return 0
}

function safeStat(file: string): fs.Stats | null {
  try { return fs.statSync(file) } catch { return null }
}

// ── Mode 3: --diff ────────────────────────────────────────────────────

function runDiff(jsonFlag: boolean): number {
  const dir = defaultTraceDir(os.homedir())
  const files = listTraceFiles(dir)

  if (files.length < 2) {
    if (jsonFlag) {
      console.log(JSON.stringify({ error: 'need at least two traces to diff', traceCount: files.length }))
    } else {
      const reporter = getReporter({ json: false })
      reporter.error('need at least two traces to diff')
      reporter.info(`found ${files.length} trace${files.length === 1 ? '' : 's'} in ${dir}`)
      reporter.info('run `safenpm trace -- <cmd>` twice (across the dep change you want to inspect)')
      reporter.blank()
    }
    return 1
  }

  // listTraceFiles is sorted ascending by filename = ascending by time.
  const prev = readTraceFile(files[files.length - 2]!)
  const curr = readTraceFile(files[files.length - 1]!)
  if (!prev || !curr) {
    if (jsonFlag) console.log(JSON.stringify({ error: 'failed to read trace files' }))
    else getReporter({ json: false }).error('failed to read trace files (corrupted JSON?)')
    return 1
  }

  const diffs = diffTraces(prev, curr)
  const { criticalCount, highCount, mediumCount } = countSeverities(diffs)
  const hasCritical = criticalCount > 0

  if (jsonFlag) {
    console.log(JSON.stringify({
      previousTrace: path.basename(files[files.length - 2]!),
      currentTrace: path.basename(files[files.length - 1]!),
      diffs: diffs.map((d) => ({
        package: d.packageName,
        newBuiltins: d.newBuiltins.map((b) => ({ name: b, severity: categorizeBuiltin(b) })),
        newPackages: d.newPackages,
      })),
      summary: { critical: criticalCount, high: highCount, medium: mediumCount },
    }, null, 2))
    return hasCritical ? 1 : 0
  }

  printDiffHuman({ prev, curr, prevFile: files[files.length - 2]!, currFile: files[files.length - 1]!, diffs })
  return hasCritical ? 1 : 0
}

function countSeverities(diffs: TraceDiff[]): {
  criticalCount: number; highCount: number; mediumCount: number
} {
  let c = 0, h = 0, m = 0
  for (const d of diffs) {
    for (const b of d.newBuiltins) {
      const sev = categorizeBuiltin(b)
      if (sev === 'critical') c++
      else if (sev === 'high') h++
      else m++
    }
  }
  return { criticalCount: c, highCount: h, mediumCount: m }
}

function printDiffHuman(args: {
  prev: ReturnType<typeof readTraceFile> & {}
  curr: ReturnType<typeof readTraceFile> & {}
  prevFile: string
  currFile: string
  diffs: TraceDiff[]
}): void {
  const reporter = getReporter({ json: false })
  reporter.banner()
  reporter.step('runtime trace diff')
  reporter.blank()
  console.log(`  ${DIM}previous:${RESET} ${path.basename(args.prevFile)}  ${DIM}(${args.prev.timestamp})${RESET}`)
  console.log(`  ${DIM}current: ${RESET} ${path.basename(args.currFile)}  ${DIM}(${args.curr.timestamp})${RESET}`)
  reporter.blank()

  if (args.diffs.length === 0) {
    console.log(`  ${GREEN}no runtime-surface changes between the two traces${RESET}`)
    reporter.blank()
    return
  }

  for (const d of args.diffs) {
    console.log(`  ${BOLD}${d.packageName}${RESET}`)
    for (const b of d.newBuiltins) {
      const sev = categorizeBuiltin(b)
      const c = sev === 'critical' ? RED : sev === 'high' ? YELLOW : DIM
      const icon = sev === 'critical' ? '⚠' : sev === 'high' ? '!' : '+'
      console.log(`    ${c}${icon} new builtin: ${b}${RESET}  ${DIM}(${sev})${RESET}`)
    }
    for (const p of d.newPackages) {
      console.log(`    ${BLUE}+ new package: ${p}${RESET}`)
    }
    reporter.blank()
  }
}
