/**
 * `safenpm run -- <cmd>` — wraps the user's command with the runtime
 * enforcement hook so every require() goes through the policy.
 *
 * Three modes:
 *   safenpm run -- <cmd>                           (no enforcement; just trace-style runs)
 *   safenpm run --enforce-runtime -- <cmd>         (deny per policy file)
 *   safenpm run --generate-policy [--from-trace]   (write .safenpm-policy.json
 *                                                   from the most recent trace)
 *
 * The `--enforce-runtime` and `--generate-policy` flags are
 * mutually exclusive.
 */
import { spawn } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { getReporter } from '../../report'
import {
  defaultTraceDir,
  listTraceFiles,
  readTraceFile,
} from '../../runtime/utils'
import {
  POLICY_FILE,
  defaultPolicy,
  policyFromTrace,
  savePolicy,
} from '../../runtime/policy'

export async function run(args: readonly string[]): Promise<number> {
  if (args.includes('--generate-policy')) return runGeneratePolicy(args)
  return runSpawn(args)
}

// ── Mode 1: spawn (optionally with enforcement) ───────────────────────

async function runSpawn(args: readonly string[]): Promise<number> {
  const sepIdx = args.indexOf('--')
  const beforeSep = sepIdx >= 0 ? args.slice(0, sepIdx) : args
  const cmdArgs = sepIdx >= 0 ? args.slice(sepIdx + 1) : []
  const jsonFlag = beforeSep.includes('--json')
  const enforce = beforeSep.includes('--enforce-runtime')
  const reporter = getReporter({ json: jsonFlag })

  if (cmdArgs.length === 0) {
    reporter.error('usage: safenpm run [--enforce-runtime] [--json] -- <command> [args...]')
    reporter.info('       safenpm run --generate-policy [--from-trace]')
    return 1
  }

  const env: NodeJS.ProcessEnv = { ...process.env }
  if (enforce) {
    const hookPath = path.resolve(__dirname, '..', '..', 'runtime', 'enforce.js')
    if (!fs.existsSync(hookPath)) {
      reporter.error(`enforcement hook not found at ${hookPath} — was the build skipped?`)
      return 1
    }
    const existing = process.env.NODE_OPTIONS ?? ''
    env.NODE_OPTIONS = `--require ${hookPath} ${existing}`.trim()
  }

  if (!jsonFlag) {
    reporter.banner()
    reporter.step(enforce ? `running with enforcement: ${cmdArgs.join(' ')}` : `running: ${cmdArgs.join(' ')}`)
    if (enforce) {
      reporter.info(`policy: ${path.join(process.cwd(), POLICY_FILE)} (loads defaults if missing)`)
      reporter.info(`denies logged to ~/.safenpm/enforce-denies/`)
    }
    reporter.blank()
  }

  return new Promise<number>((resolve) => {
    const child = spawn(cmdArgs[0]!, cmdArgs.slice(1), { stdio: 'inherit', env })
    child.on('exit', (code, signal) => {
      if (jsonFlag) {
        console.log(JSON.stringify({
          ran: cmdArgs, enforce, exitCode: code, signal: signal ?? null,
        }))
      } else {
        reporter.blank()
        if (code === 0) reporter.success('exited cleanly')
        else reporter.warn(`exited ${code ?? signal}`)
      }
      resolve(code ?? 1)
    })
    child.on('error', (err) => {
      reporter.error(`failed to spawn: ${err.message}`)
      resolve(1)
    })
  })
}

// ── Mode 2: generate policy ───────────────────────────────────────────

function runGeneratePolicy(args: readonly string[]): number {
  const jsonFlag = args.includes('--json')
  const reporter = getReporter({ json: jsonFlag })
  const fromTrace = args.includes('--from-trace') || args.includes('--from-latest-trace')

  const target = path.join(process.cwd(), POLICY_FILE)
  if (fs.existsSync(target)) {
    if (jsonFlag) {
      console.log(JSON.stringify({ error: 'policy file already exists', path: target }))
    } else {
      reporter.error(`${POLICY_FILE} already exists — refusing to overwrite`)
      reporter.info(`delete it manually if you want to regenerate`)
    }
    return 1
  }

  let policy = defaultPolicy()
  let source = 'defaults'

  if (fromTrace) {
    const files = listTraceFiles(defaultTraceDir(os.homedir()))
    if (files.length === 0) {
      if (jsonFlag) console.log(JSON.stringify({ error: 'no traces found; run `safenpm trace -- <cmd>` first' }))
      else reporter.error('no traces found in ~/.safenpm/pkg-traces/')
      return 1
    }
    const latest = readTraceFile(files[files.length - 1]!)
    if (!latest) {
      reporter.error(`failed to read latest trace at ${files[files.length - 1]}`)
      return 1
    }
    policy = policyFromTrace(latest)
    source = `trace ${path.basename(files[files.length - 1]!)}`
  }

  savePolicy(process.cwd(), policy)

  if (jsonFlag) {
    console.log(JSON.stringify({ wrote: target, source, packages: Object.keys(policy.packages).length }))
  } else {
    reporter.banner()
    reporter.success(`wrote ${POLICY_FILE}`)
    reporter.info(`source: ${source}`)
    reporter.info(`packages with explicit allow-lists: ${Object.keys(policy.packages).length}`)
    reporter.info(`run \`safenpm run --enforce-runtime -- <cmd>\` to apply`)
    reporter.blank()
  }
  return 0
}
