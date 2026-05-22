/**
 * Linux firejail backend.
 *
 * firejail is the most widely-packaged unprivileged sandbox on desktop
 * Linux. We deliberately use `--noprofile` to avoid pulling in any
 * system-wide profile (which can lift restrictions we want kept), and
 * `--quiet` to suppress firejail's chatter so `classify()` only sees
 * the child's output.
 *
 * Strict mode adds a blacklist for the common credential directories
 * plus `--read-only=$HOME` so a compromised script can't drop a
 * persistence file in ~/.config or ~/.local.
 */
import { spawnSync } from 'child_process'
import os from 'os'
import type { PackageScript, SandboxResult } from '../types'
import { cleanEnv } from './env'
import { classify, SANDBOX_TIMEOUT_MS } from './classify'

export const HOME_BLACKLIST_PATHS: readonly string[] = [
  '.ssh', '.aws', '.gnupg', '.npmrc', '.netrc', '.docker', '.kube',
  '.bash_history', '.zsh_history', '.env',
]

export function isAvailable(): boolean {
  if (os.platform() !== 'linux') return false
  return spawnSync('which', ['firejail'], { encoding: 'utf8' }).status === 0
}

export function run(pkg: PackageScript, strict: boolean): SandboxResult {
  const start = Date.now()
  const home = os.homedir()

  const args: string[] = ['--net=none', '--quiet', '--noprofile']

  if (strict) {
    for (const rel of HOME_BLACKLIST_PATHS) {
      args.push(`--blacklist=${home}/${rel}`)
    }
    args.push(`--read-only=${home}`)
  }

  args.push('--', 'sh', '-c', pkg.script)

  const result = spawnSync('firejail', args, {
    cwd: pkg.path,
    env: cleanEnv(),
    timeout: SANDBOX_TIMEOUT_MS,
    encoding: 'utf8',
  })

  return classify(pkg, result, Date.now() - start)
}
