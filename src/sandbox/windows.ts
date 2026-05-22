/**
 * Windows backends — two flavors:
 *
 *   1. firewall+ACLs (`isFirewallAvailable`/`runFirewall`):
 *      A New-NetFirewallRule blocks outbound traffic for `node.exe` for
 *      the duration of the script. Combined with `icacls /deny` on the
 *      credential directories, this approximates the mac/linux denies.
 *      Requires elevated (admin) PowerShell; we detect that via
 *      `net session` which only succeeds when elevated.
 *
 *   2. WSL+firejail (`isWslFirejailAvailable`/`runWsl`):
 *      Fallback for non-admin Windows. We shell out into WSL and run
 *      the script under firejail there. Package paths get translated
 *      to /mnt/c/... form using `wsl wslpath -u` with a manual fallback.
 *
 * Both treat strict=false as a hint to drop the ACL portion but keep
 * the network restriction. The cleanup paths run in `finally` so we
 * never leak firewall rules or denied ACLs even if the script crashes
 * the parent process.
 */
import { spawnSync } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import type { PackageScript, SandboxResult } from '../types'
import { cleanEnv } from './env'
import { classify, SANDBOX_TIMEOUT_MS } from './classify'

// ── Firewall + ACLs (admin) ──────────────────────────────────────────

const SENSITIVE_DIRS_REL: readonly string[] = ['.ssh', '.aws', '.gnupg', '.docker', '.kube']
const SENSITIVE_FILES_REL: readonly string[] = ['.npmrc', '.netrc', '.bash_history', '.env']

function isAdmin(): boolean {
  try {
    const r = spawnSync('net', ['session'], {
      encoding: 'utf8',
      stdio: 'pipe',
      timeout: 5_000,
    })
    return r.status === 0
  } catch {
    return false
  }
}

export function isFirewallAvailable(): boolean {
  return os.platform() === 'win32' && isAdmin()
}

function sensitivePaths(): string[] {
  const home = os.homedir()
  return [
    ...SENSITIVE_DIRS_REL.map((d) => path.join(home, d)),
    ...SENSITIVE_FILES_REL.map((f) => path.join(home, f)),
  ]
}

export function runFirewall(pkg: PackageScript, strict: boolean): SandboxResult {
  const start = Date.now()
  const ruleName = `safenpm-block-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  const nodeExe = process.execPath

  const createRuleScript = `New-NetFirewallRule -DisplayName '${ruleName}' -Direction Outbound -Action Block -Program '${nodeExe.replace(/'/g, "''")}' -Enabled True -ErrorAction Stop | Out-Null`
  const ruleResult = spawnSync('powershell', ['-NoProfile', '-Command', createRuleScript], {
    encoding: 'utf8',
    stdio: 'pipe',
    timeout: 10_000,
  })

  if (ruleResult.status !== 0) {
    // Couldn't create the firewall rule (e.g. policy lock). Fall back to ACLs only.
    return runAclsOnly(pkg, strict, start)
  }

  return withAclsAndCleanup(pkg, strict, start, () => {
    spawnSync('powershell', [
      '-NoProfile', '-Command',
      `Remove-NetFirewallRule -DisplayName '${ruleName}' -ErrorAction SilentlyContinue`,
    ], { stdio: 'pipe', timeout: 10_000 })
  })
}

function runAclsOnly(pkg: PackageScript, strict: boolean, start: number): SandboxResult {
  return withAclsAndCleanup(pkg, strict, start, () => { /* no firewall to remove */ })
}

function withAclsAndCleanup(
  pkg: PackageScript,
  strict: boolean,
  start: number,
  afterRun: () => void,
): SandboxResult {
  const username = os.userInfo().username
  const aclsApplied: string[] = []
  let result: ReturnType<typeof spawnSync>

  try {
    if (strict) {
      for (const p of sensitivePaths()) {
        if (!fs.existsSync(p)) continue
        const r = spawnSync('icacls', [p, '/deny', `${username}:(R,W)`, '/T', '/C'], {
          encoding: 'utf8',
          stdio: 'pipe',
          timeout: 5_000,
        })
        if (r.status === 0) aclsApplied.push(p)
      }
    }

    result = spawnSync('cmd.exe', ['/c', pkg.script], {
      cwd: pkg.path,
      env: cleanEnv(),
      timeout: SANDBOX_TIMEOUT_MS,
      encoding: 'utf8',
    })
  } finally {
    afterRun()
    for (const p of aclsApplied) {
      spawnSync('icacls', [p, '/remove:d', username, '/T', '/C'], {
        stdio: 'pipe',
        timeout: 5_000,
      })
    }
  }

  return classify(pkg, result, Date.now() - start)
}

// ── WSL + firejail (non-admin fallback) ──────────────────────────────

export function isWslFirejailAvailable(): boolean {
  if (os.platform() !== 'win32') return false
  try {
    const r = spawnSync('wsl', ['which', 'firejail'], {
      encoding: 'utf8',
      stdio: 'pipe',
      timeout: 10_000,
    })
    return r.status === 0
  } catch {
    return false
  }
}

const WSL_HOME_BLACKLIST_PATHS: readonly string[] = [
  '.ssh', '.aws', '.gnupg', '.npmrc', '.netrc', '.docker', '.kube',
]

export function runWsl(pkg: PackageScript, strict: boolean): SandboxResult {
  const start = Date.now()
  const wslHome = windowsToWslPath(os.homedir())

  const args: string[] = ['firejail', '--net=none', '--quiet', '--noprofile']

  if (strict) {
    for (const rel of WSL_HOME_BLACKLIST_PATHS) {
      args.push(`--blacklist=${wslHome}/${rel}`)
    }
    args.push(`--read-only=${wslHome}`)
  }

  args.push('--', 'sh', '-c', pkg.script)

  const result = spawnSync('wsl', args, {
    cwd: pkg.path,
    env: cleanEnv(),
    timeout: SANDBOX_TIMEOUT_MS,
    encoding: 'utf8',
  })

  return classify(pkg, result, Date.now() - start)
}

function windowsToWslPath(winPath: string): string {
  try {
    const r = spawnSync('wsl', ['wslpath', '-u', winPath], {
      encoding: 'utf8',
      stdio: 'pipe',
      timeout: 5_000,
    })
    if (r.status === 0 && r.stdout.trim()) return r.stdout.trim()
  } catch { /* fall through to manual translation */ }

  const normalized = winPath.replace(/\\/g, '/')
  const match = normalized.match(/^([A-Z]):\/(.*)$/i)
  if (match) return `/mnt/${match[1]!.toLowerCase()}/${match[2]!}`
  return normalized
}
