/**
 * Last-resort fallback. Runs the script with the user's normal shell,
 * applying *only* the env-var strip. Used when no platform backend is
 * detected; the caller is expected to have already warned the user.
 *
 * `clean: true` is a deliberate lie of omission — the script ran fine
 * but nothing about it was actually sandboxed. The "no sandbox"
 * warning surfaced in install.ts is what makes that explicit.
 */
import { spawnSync } from 'child_process'
import os from 'os'
import type { PackageScript, SandboxResult } from '../types'
import { cleanEnv } from './env'
import { SANDBOX_TIMEOUT_MS } from './classify'

export function run(pkg: PackageScript): SandboxResult {
  const start = Date.now()

  const isWindows = os.platform() === 'win32'
  const shell = isWindows ? 'cmd.exe' : 'sh'
  const shellArgs = isWindows ? ['/c', pkg.script] : ['-c', pkg.script]

  const result = spawnSync(shell, shellArgs, {
    cwd: pkg.path,
    env: cleanEnv(),
    timeout: SANDBOX_TIMEOUT_MS,
    encoding: 'utf8',
  })

  const output = [result.stdout, result.stderr].filter(Boolean).join('\n')

  return {
    pkg,
    blocked: false,
    skipped: false,
    reason: 'clean',
    output,
    durationMs: Date.now() - start,
  }
}
