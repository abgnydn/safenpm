/**
 * Per-package sandbox execution loop — the "Phase 2" of an install.
 *
 * Walks every package that declared an install script, classifies the
 * outcome (allowlisted / blocked / clean), and surfaces the
 * interactive prompt for `--interactive` mode. All terminal output
 * goes through the injected `Reporter`, which itself is a no-op in
 * JSON mode — no more `if (!opts.json)` guards in this file.
 *
 * Returning the raw results lets the caller decide downstream work
 * (audit log, threat-intel report, JSON serialization).
 */
import { spawnSync } from 'child_process'
import { isAllowed } from '../config/allowlist'
import type { Reporter } from '../report'
import { runInSandbox } from '../sandbox'
import type { InstallOptions, PackageScript, SandboxResult } from '../types'

const RETRY_TIMEOUT_MS = 30_000

export interface ExecuteOptions {
  scripts: readonly PackageScript[]
  allowlist: ReadonlySet<string>
  opts: InstallOptions
  reporter: Reporter
}

export interface ExecuteOutcome {
  results: SandboxResult[]
  /** Number of packages skipped because they were allowlisted. */
  skippedCount: number
}

export function executeScripts(args: ExecuteOptions): ExecuteOutcome {
  const { scripts, allowlist, opts, reporter } = args
  const strict = !opts.loose
  const results: SandboxResult[] = []
  let skippedCount = 0

  for (const pkg of scripts) {
    if (isAllowed(pkg.name, allowlist)) {
      results.push(runAllowlisted(pkg, reporter))
      skippedCount++
      continue
    }

    const result = runInSandbox(pkg, strict)
    results.push(result)

    if (!result.blocked) {
      reporter.allowed(pkg.name, pkg.version)
      continue
    }

    reporter.blocked(pkg.name, pkg.version, pkg.hook, result.reason)
    handleInteractive(pkg, result, results, opts, reporter)
  }

  return { results, skippedCount }
}

function runAllowlisted(pkg: PackageScript, reporter: Reporter): SandboxResult {
  reporter.skipped(pkg.name, pkg.version)
  const start = Date.now()
  const r = spawnSync('sh', ['-c', pkg.script], {
    cwd: pkg.path,
    timeout: RETRY_TIMEOUT_MS,
    encoding: 'utf8',
    stdio: 'pipe',
  })
  return {
    pkg,
    blocked: false,
    skipped: true,
    reason: 'allowed',
    output: [r.stdout, r.stderr].filter(Boolean).join('\n'),
    durationMs: Date.now() - start,
  }
}

/**
 * --interactive flow: after a block, prompt the user. 'r' retries
 * without sandboxing (the only escape hatch for legit native builds
 * that need network), 's' leaves the block in place, 'a' aborts.
 */
function handleInteractive(
  pkg: PackageScript,
  result: SandboxResult,
  results: SandboxResult[],
  opts: InstallOptions,
  reporter: Reporter,
): void {
  if (!opts.interactive || opts.json || !process.stdin.isTTY) return

  const choice = reporter.interactivePrompt(pkg.name, pkg.version, pkg.hook)
  if (choice === 'r') {
    reporter.step(`retrying ${pkg.name} without sandbox...`)
    const start = Date.now()
    const retry = spawnSync('sh', ['-c', pkg.script], {
      cwd: pkg.path,
      timeout: RETRY_TIMEOUT_MS,
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
    reporter.success(`${pkg.name} ran without sandbox`)
    return
  }

  if (choice === 'a') {
    reporter.error('aborted by user')
    process.exit(1)
  }

  // 's' or any other input — keep the block as-is.
  void result
}
